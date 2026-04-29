#!/usr/bin/env python3
"""
phase5_daily_digest.py — Barry University Daily SOC Digest

Runs at 8am daily. Reads new SOC emails from the last 24 hours,
sorts them into Outlook subfolders based on suppression tier, then
sends a clean HTML digest email summarizing actionable vs suppressed items.

Required Microsoft Graph Application permissions:
  - Mail.ReadWrite
  - Mail.Send
  - SecurityIncident.Read.All
"""

import logging
import os
import sys
import time
from datetime import datetime, timezone, timedelta

import msal
import requests

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
TENANT_ID = os.environ.get("TENANT_ID", "")
CLIENT_ID = os.environ.get("CLIENT_ID", "")
CLIENT_SECRET = os.environ.get("CLIENT_SECRET", "")

MAILBOX_UPN = os.environ.get("MAILBOX_UPN", "jmoses@barry.edu")
DIGEST_TO = os.environ.get("DIGEST_TO", "jmoses@barry.edu,jbaldwin@barry.edu")
DIGEST_FROM = os.environ.get("DIGEST_FROM", "jmoses@barry.edu")
SOC_SENDER = "soc@oculusit.com"
LOOKBACK_HOURS = int(os.environ.get("LOOKBACK_HOURS", "24"))
GRAPH_BASE = "https://graph.microsoft.com/v1.0"
RATE_DELAY = 0.3

# ---------------------------------------------------------------------------
# Subfolder names
# ---------------------------------------------------------------------------
FOLDER_ACTIVE = "SOC-Active"
FOLDER_DIGEST = "SOC-Digest"
FOLDER_SUPPRESSED = "SOC-Suppressed"
FOLDER_CONDITIONAL = "SOC-Conditional"

TIER_FOLDER_MAP = {
    "KEEP": FOLDER_ACTIVE,
    "T3": FOLDER_DIGEST,
    "T1": FOLDER_SUPPRESSED,
    "T2": FOLDER_CONDITIONAL,
}

# ---------------------------------------------------------------------------
# Suppression keyword lists (case-insensitive substring match)
# ---------------------------------------------------------------------------
TIER1_SUPPRESS = [
    "anomalous token",
    "sign-in from anonymous proxy",
    "password-spray ip",
    "from password spray ip",
]

TIER2_CONDITIONAL = [
    "sign-in from anonymous ip",
    "unfamiliar sign-in properties",
    "unfamiliar features",
    "defense evasion",
    "onestart",
    "potentially unwanted",
    "process injection",
    "roblox",
    "riot games",
    "valorant",
]

TIER3_DIGEST = [
    "password spray",
    "malicious url",
    "multi-stage incident",
    "multi stage incident",
    "malware detected",
    "threat detected",
]


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------
def get_access_token() -> str:
    """Acquire an app-only access token via MSAL client credentials flow."""
    app = msal.ConfidentialClientApplication(
        CLIENT_ID,
        authority=f"https://login.microsoftonline.com/{TENANT_ID}",
        client_credential=CLIENT_SECRET,
    )
    result = app.acquire_token_for_client(scopes=["https://graph.microsoft.com/.default"])
    if "access_token" not in result:
        log.error("Auth failed: %s", result.get("error_description", result))
        sys.exit(1)
    return result["access_token"]


# ---------------------------------------------------------------------------
# Graph HTTP helpers
# ---------------------------------------------------------------------------
def graph_get(token: str, url: str, params: dict = None):
    """GET a Graph endpoint. Returns (status_code, json_body)."""
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    resp = requests.get(url, headers=headers, params=params, timeout=30)
    try:
        body = resp.json()
    except Exception:
        body = {}
    return resp.status_code, body


def graph_post(token: str, url: str, body: dict):
    """POST to a Graph endpoint. Returns (status_code, json_body)."""
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    resp = requests.post(url, headers=headers, json=body, timeout=30)
    try:
        data = resp.json()
    except Exception:
        data = {}
    return resp.status_code, data


def graph_patch(token: str, url: str, body: dict):
    """PATCH a Graph endpoint. Returns (status_code, json_body)."""
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    resp = requests.patch(url, headers=headers, json=body, timeout=30)
    try:
        data = resp.json()
    except Exception:
        data = {}
    return resp.status_code, data


# ---------------------------------------------------------------------------
# Subfolder management
# ---------------------------------------------------------------------------
def ensure_subfolder(token: str, mailbox: str, folder_name: str) -> str:
    """
    Find or create a child folder under Inbox for the given mailbox.
    Returns the folder id.
    """
    url = f"{GRAPH_BASE}/users/{mailbox}/mailFolders/inbox/childFolders"
    params = {"$top": 100}
    status, data = graph_get(token, url, params)
    if status != 200:
        log.error("Failed to list child folders for %s: %s %s", mailbox, status, data)
        sys.exit(1)

    for folder in data.get("value", []):
        if folder.get("displayName", "").lower() == folder_name.lower():
            log.info("Subfolder '%s' already exists (id=%s)", folder_name, folder["id"])
            return folder["id"]

    # Folder not found — create it
    time.sleep(RATE_DELAY)
    create_url = f"{GRAPH_BASE}/users/{mailbox}/mailFolders/inbox/childFolders"
    status, created = graph_post(token, create_url, {"displayName": folder_name})
    if status not in (200, 201):
        log.error("Failed to create folder '%s': %s %s", folder_name, status, created)
        sys.exit(1)
    log.info("Created subfolder '%s' (id=%s)", folder_name, created["id"])
    return created["id"]


# ---------------------------------------------------------------------------
# Categorization
# ---------------------------------------------------------------------------
def categorize_email(subject: str) -> tuple:
    """
    Match email subject against suppression tier keyword lists.
    Returns (tier, folder_key) where tier is 'T1'/'T2'/'T3'/'KEEP'.
    Tier 1 is checked first (highest suppression priority).
    """
    lower = subject.lower()

    for kw in TIER1_SUPPRESS:
        if kw in lower:
            return ("T1", "T1")

    for kw in TIER2_CONDITIONAL:
        if kw in lower:
            return ("T2", "T2")

    for kw in TIER3_DIGEST:
        if kw in lower:
            return ("T3", "T3")

    return ("KEEP", "KEEP")


def categorize_incident(incident_dict: dict) -> tuple:
    """
    Same tier logic as categorize_email but applied to incident
    displayName and first_alert_title fields.
    Returns (tier, folder_key).
    """
    name = incident_dict.get("displayName", "")
    alert_title = incident_dict.get("first_alert_title", "")
    combined = f"{name} {alert_title}".lower()

    for kw in TIER1_SUPPRESS:
        if kw in combined:
            return ("T1", "T1")

    for kw in TIER2_CONDITIONAL:
        if kw in combined:
            return ("T2", "T2")

    for kw in TIER3_DIGEST:
        if kw in combined:
            return ("T3", "T3")

    return ("KEEP", "KEEP")


# ---------------------------------------------------------------------------
# Email fetching and moving
# ---------------------------------------------------------------------------
def get_recent_soc_emails(token: str, mailbox: str, since_dt: datetime) -> list:
    """
    Fetch messages sent from SOC_SENDER received after since_dt.
    Returns a list of message dicts with id, subject, receivedDateTime, isRead.
    Pages through results using $skip.
    """
    since_str = since_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    filter_expr = (
        f"from/emailAddress/address eq '{SOC_SENDER}' "
        f"and receivedDateTime ge {since_str}"
    )
    select_fields = "id,subject,receivedDateTime,isRead"
    url = f"{GRAPH_BASE}/users/{mailbox}/messages"

    messages = []
    skip = 0
    page_size = 50

    while True:
        params = {
            "$filter": filter_expr,
            "$select": select_fields,
            "$top": page_size,
            "$skip": skip,
        }
        status, data = graph_get(token, url, params)
        if status != 200:
            log.error("Failed to fetch SOC emails (skip=%d): %s %s", skip, status, data)
            break

        batch = data.get("value", [])
        messages.extend(batch)
        log.info("Fetched %d SOC emails (page starting at skip=%d)", len(batch), skip)

        if len(batch) < page_size:
            break
        skip += page_size
        time.sleep(RATE_DELAY)

    return messages


def move_email(token: str, mailbox: str, message_id: str, folder_id: str) -> bool:
    """
    Move a message to the specified folder.
    Returns True on success, False on failure (logs warning, does not raise).
    """
    url = f"{GRAPH_BASE}/users/{mailbox}/messages/{message_id}/move"
    status, data = graph_post(token, url, {"destinationId": folder_id})
    if status not in (200, 201):
        log.warning("Failed to move message %s to folder %s: %s %s",
                    message_id, folder_id, status, data)
        return False
    return True


# ---------------------------------------------------------------------------
# Security incidents
# ---------------------------------------------------------------------------
def get_recent_incidents(token: str, since_dt: datetime) -> list:
    """
    Fetch security incidents created since since_dt, expanding alerts.
    Pages through results using $skip.
    Returns list of dicts with keys:
      id, displayName, severity, status, classification, category,
      created, assignedTo, alert_count, first_alert_title
    """
    since_str = since_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    url = f"{GRAPH_BASE}/security/incidents"
    page_size = 25
    skip = 0
    incidents = []

    while True:
        params = {
            "$filter": f"createdDateTime ge {since_str}",
            "$expand": "alerts",
            "$top": page_size,
            "$skip": skip,
        }
        status, data = graph_get(token, url, params)
        if status != 200:
            log.error("Failed to fetch incidents (skip=%d): %s %s", skip, status, data)
            break

        batch = data.get("value", [])
        for inc in batch:
            alerts = inc.get("alerts", [])
            first_alert_title = alerts[0].get("title", "") if alerts else ""
            incidents.append({
                "id": inc.get("id", ""),
                "displayName": inc.get("displayName", ""),
                "severity": inc.get("severity", "unknown"),
                "status": inc.get("status", "unknown"),
                "classification": inc.get("classification", ""),
                "category": inc.get("category", ""),
                "created": inc.get("createdDateTime", ""),
                "assignedTo": inc.get("assignedTo", ""),
                "alert_count": len(alerts),
                "first_alert_title": first_alert_title,
            })

        log.info("Fetched %d incidents (page starting at skip=%d)", len(batch), skip)

        if len(batch) < page_size:
            break
        skip += page_size
        time.sleep(RATE_DELAY)

    return incidents


# ---------------------------------------------------------------------------
# HTML digest builder
# ---------------------------------------------------------------------------
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}


def _severity_badge(severity: str) -> str:
    """Return an inline-styled severity badge span."""
    colors = {
        "critical": "#dc3545",
        "high": "#fd7e14",
        "medium": "#ffc107",
        "low": "#6c757d",
    }
    bg = colors.get(severity.lower(), "#6c757d")
    label = severity.upper() if severity else "UNKNOWN"
    return (
        f'<span style="background:{bg};color:#fff;padding:2px 7px;'
        f'border-radius:3px;font-size:11px;font-weight:bold;">{label}</span>'
    )


def _fmt_time(iso_str: str) -> str:
    """Format ISO datetime string to human-readable HH:MM UTC."""
    if not iso_str:
        return ""
    try:
        dt = datetime.fromisoformat(iso_str.replace("Z", "+00:00"))
        return dt.strftime("%Y-%m-%d %H:%M UTC")
    except Exception:
        return iso_str


def build_digest_html(
    date_str: str,
    email_stats: dict,
    incident_stats: dict,
    active_items: list,
) -> str:
    """
    Build the full HTML digest email body.

    email_stats:    {"active": N, "digest": N, "suppressed": N, "total": N}
    incident_stats: {"active": N, "digest": N, "suppressed": N, "total": N,
                     "digest_categories": {"category": count, ...}}
    active_items:   list of incident dicts (KEEP tier), sorted by severity
    """
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    # Combined totals for stat boxes
    total_active = email_stats["active"] + incident_stats["active"]
    total_digest = email_stats["digest"] + incident_stats["digest"]
    total_suppressed = email_stats["suppressed"] + incident_stats["suppressed"]
    grand_total = email_stats["total"] + incident_stats["total"]

    # Stat boxes row
    def stat_box(label, value, color):
        return (
            f'<td style="text-align:center;padding:16px 24px;">'
            f'<div style="background:{color};color:#fff;border-radius:8px;'
            f'padding:20px 28px;min-width:110px;">'
            f'<div style="font-size:36px;font-weight:bold;">{value}</div>'
            f'<div style="font-size:13px;margin-top:4px;">{label}</div>'
            f"</div></td>"
        )

    stat_row = (
        stat_box("Active (Triage)", total_active, "#dc3545")
        + stat_box("Daily Digest", total_digest, "#fd7e14")
        + stat_box("Suppressed", total_suppressed, "#28a745")
        + stat_box("Total", grand_total, "#0d6efd")
    )

    # Triage table rows
    sorted_active = sorted(
        active_items,
        key=lambda i: SEVERITY_ORDER.get(i.get("severity", "unknown").lower(), 4),
    )

    th_style = (
        'style="background:#343a40;color:#fff;padding:8px 12px;'
        'text-align:left;font-size:13px;"'
    )
    triage_rows = ""
    for item in sorted_active:
        category = item.get("category") or item.get("classification") or "N/A"
        triage_rows += (
            f"<tr>"
            f'<td style="padding:8px 12px;border-bottom:1px solid #dee2e6;">'
            f'{_severity_badge(item.get("severity", ""))}</td>'
            f'<td style="padding:8px 12px;border-bottom:1px solid #dee2e6;font-weight:bold;">'
            f'{item.get("displayName", "N/A")}</td>'
            f'<td style="padding:8px 12px;border-bottom:1px solid #dee2e6;">'
            f'{category}</td>'
            f'<td style="padding:8px 12px;border-bottom:1px solid #dee2e6;white-space:nowrap;">'
            f'{_fmt_time(item.get("created", ""))}</td>'
            f'<td style="padding:8px 12px;border-bottom:1px solid #dee2e6;">'
            f'{item.get("status", "N/A")}</td>'
            f"</tr>"
        )
    if not triage_rows:
        triage_rows = (
            '<tr><td colspan="5" style="padding:16px 12px;color:#6c757d;">'
            "No active incidents require triage in this period.</td></tr>"
        )

    triage_table = f"""
    <table width="100%" cellpadding="0" cellspacing="0"
           style="border-collapse:collapse;font-size:13px;">
      <tr>
        <th {th_style}>Severity</th>
        <th {th_style}>Incident / Alert</th>
        <th {th_style}>Category</th>
        <th {th_style}>Time</th>
        <th {th_style}>Status</th>
      </tr>
      {triage_rows}
    </table>"""

    # Digest category count table
    digest_cats = incident_stats.get("digest_categories", {})
    digest_rows = ""
    for cat, count in sorted(digest_cats.items(), key=lambda x: -x[1]):
        digest_rows += (
            f"<tr>"
            f'<td style="padding:7px 12px;border-bottom:1px solid #dee2e6;">{cat}</td>'
            f'<td style="padding:7px 12px;border-bottom:1px solid #dee2e6;'
            f'text-align:right;font-weight:bold;">{count}</td>'
            f"</tr>"
        )
    if not digest_rows:
        digest_rows = (
            '<tr><td colspan="2" style="padding:12px;color:#6c757d;">'
            "No digest-tier incidents in this period.</td></tr>"
        )

    digest_table = f"""
    <table width="50%" cellpadding="0" cellspacing="0"
           style="border-collapse:collapse;font-size:13px;">
      <tr>
        <th {th_style}>Category</th>
        <th {th_style} style="text-align:right;">Count</th>
      </tr>
      {digest_rows}
    </table>"""

    total_moved = email_stats["suppressed"]
    suppressed_note = (
        f"<p style='color:#555;font-size:13px;'>"
        f"{total_moved} email(s) were sorted to <strong>SOC-Suppressed</strong> "
        f"and <strong>SOC-Conditional</strong> subfolders. No action required.</p>"
    )

    section_style = (
        "background:#f8f9fa;border-left:4px solid {color};"
        "padding:10px 16px;margin:20px 0 8px 0;"
        "font-size:15px;font-weight:bold;color:#212529;"
    )

    html = f"""<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"></head>
<body style="font-family:Arial,sans-serif;background:#ffffff;margin:0;padding:0;">
<table width="100%" cellpadding="0" cellspacing="0"
       style="max-width:800px;margin:0 auto;background:#ffffff;">
  <tr>
    <td style="background:#0d6efd;padding:24px 32px;">
      <div style="color:#fff;font-size:22px;font-weight:bold;">
        Barry University IT &mdash; Daily SOC Digest
      </div>
      <div style="color:#cfe2ff;font-size:14px;margin-top:4px;">{date_str}</div>
    </td>
  </tr>
  <tr>
    <td style="padding:24px 32px;">
      <table width="100%" cellpadding="0" cellspacing="0">
        <tr>{stat_row}</tr>
      </table>

      <div style="{section_style.format(color='#dc3545')}">REQUIRES TRIAGE TODAY</div>
      {triage_table}

      <div style="{section_style.format(color='#fd7e14')}">DAILY DIGEST ITEMS</div>
      {digest_table}

      <div style="{section_style.format(color='#28a745')}">SUPPRESSED TODAY</div>
      {suppressed_note}

      <hr style="border:none;border-top:1px solid #dee2e6;margin:32px 0 16px 0;">
      <p style="font-size:11px;color:#6c757d;">
        Generated by Barry University AI Automation &mdash; {now_str}
        &nbsp;|&nbsp; Reply to
        <a href="mailto:jmoses@barry.edu">jmoses@barry.edu</a>
        to adjust suppression rules.
      </p>
    </td>
  </tr>
</table>
</body>
</html>"""
    return html


# ---------------------------------------------------------------------------
# Send digest email
# ---------------------------------------------------------------------------
def send_digest_email(
    token: str,
    from_addr: str,
    to_addrs: list,
    subject: str,
    html_body: str,
) -> bool:
    """
    Send the digest email via Graph /sendMail.
    to_addrs is a list of email address strings.
    Returns True on success, False on failure.
    """
    recipients = [
        {"emailAddress": {"address": addr.strip()}}
        for addr in to_addrs
        if addr.strip()
    ]
    message = {
        "message": {
            "subject": subject,
            "body": {
                "contentType": "HTML",
                "content": html_body,
            },
            "toRecipients": recipients,
        },
        "saveToSentItems": True,
    }
    url = f"{GRAPH_BASE}/users/{from_addr}/sendMail"
    status, data = graph_post(token, url, message)
    if status not in (200, 202):
        log.error("Failed to send digest email: %s %s", status, data)
        return False
    log.info("Digest email sent to: %s", ", ".join(to_addrs))
    return True


# ---------------------------------------------------------------------------
# Main orchestration
# ---------------------------------------------------------------------------
def main():
    """
    Orchestrate the daily SOC digest:
      1. Validate env vars
      2. Acquire token
      3. Compute lookback window
      4. Ensure all 4 subfolders exist
      5. Fetch and categorize SOC emails → move to subfolders
      6. Fetch and categorize security incidents
      7. Build digest HTML
      8. Send digest
      9. Print summary
    """
    # 1. Validate required env vars
    missing = [v for v in ("TENANT_ID", "CLIENT_ID", "CLIENT_SECRET") if not os.environ.get(v)]
    if missing:
        log.error("Missing required environment variables: %s", ", ".join(missing))
        sys.exit(1)

    # 2. Acquire token
    token = get_access_token()

    # 3. Compute lookback window
    now_utc = datetime.now(timezone.utc)
    since_dt = now_utc - timedelta(hours=LOOKBACK_HOURS)
    date_str = now_utc.strftime("%A, %B %d, %Y")
    log.info("Running daily digest for %s — lookback: %d hours", date_str, LOOKBACK_HOURS)

    # 4. Ensure all 4 subfolders exist
    folder_ids = {}
    for tier, folder_name in TIER_FOLDER_MAP.items():
        folder_ids[tier] = ensure_subfolder(token, MAILBOX_UPN, folder_name)
        time.sleep(RATE_DELAY)

    # 5. Fetch and categorize SOC emails
    emails = get_recent_soc_emails(token, MAILBOX_UPN, since_dt)
    log.info("Total SOC emails retrieved: %d", len(emails))

    email_stats = {"active": 0, "digest": 0, "suppressed": 0, "total": len(emails)}

    for msg in emails:
        subject = msg.get("subject", "")
        msg_id = msg.get("id", "")
        tier, folder_key = categorize_email(subject)

        dest_folder_id = folder_ids[folder_key]
        success = move_email(token, MAILBOX_UPN, msg_id, dest_folder_id)
        if not success:
            log.warning("Skipping tally for message %s due to move failure.", msg_id)
            time.sleep(RATE_DELAY)
            continue

        if tier == "KEEP":
            email_stats["active"] += 1
        elif tier == "T3":
            email_stats["digest"] += 1
        else:
            # T1 and T2 both count as suppressed
            email_stats["suppressed"] += 1

        time.sleep(RATE_DELAY)

    # 6. Fetch and categorize security incidents
    incidents = get_recent_incidents(token, since_dt)
    log.info("Total incidents retrieved: %d", len(incidents))

    incident_stats = {
        "active": 0,
        "digest": 0,
        "suppressed": 0,
        "total": len(incidents),
        "digest_categories": {},
    }
    active_items = []

    for inc in incidents:
        tier, _ = categorize_incident(inc)
        if tier == "KEEP":
            incident_stats["active"] += 1
            active_items.append(inc)
        elif tier == "T3":
            incident_stats["digest"] += 1
            cat = inc.get("category") or inc.get("displayName", "Unknown")
            incident_stats["digest_categories"][cat] = (
                incident_stats["digest_categories"].get(cat, 0) + 1
            )
        else:
            incident_stats["suppressed"] += 1

    # 7. Build digest HTML
    digest_subject = f"Barry IT — Daily SOC Digest | {date_str}"
    html_body = build_digest_html(date_str, email_stats, incident_stats, active_items)

    # 8. Send digest
    to_addrs = [a.strip() for a in DIGEST_TO.split(",") if a.strip()]
    sent = send_digest_email(token, DIGEST_FROM, to_addrs, digest_subject, html_body)

    # 9. Print summary
    print(
        f"\nProcessed {email_stats['total']} emails: "
        f"{email_stats['active']} active, "
        f"{email_stats['digest']} digest, "
        f"{email_stats['suppressed']} suppressed | "
        f"{incident_stats['total']} incidents: "
        f"{incident_stats['active']} active | "
        f"Digest {'sent' if sent else 'FAILED'} to: {DIGEST_TO}"
    )


if __name__ == "__main__":
    main()
