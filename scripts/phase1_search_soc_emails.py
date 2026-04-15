#!/usr/bin/env python3
"""
Phase 1: Search and Categorize SOC Emails from soc@oculusit.com
Barry University - Cybersecurity Incident Dashboard

Uses Microsoft Graph API with client credentials to search a mailbox
for all messages from soc@oculusit.com, process them in weekly increments
to handle thousands of emails, then categorize and count by alert type.

Required environment variables:
  TENANT_ID      - Azure AD Tenant ID
  CLIENT_ID      - Azure AD App Registration Client ID
  CLIENT_SECRET  - Azure AD App Registration Client Secret
  MAILBOX_UPN    - UPN/email of the mailbox to search (e.g. jbaldwin@barry.edu)

Optional environment variables:
  SEARCH_START_DATE  - ISO date to start search from (default: 2024-01-01)
  SEARCH_END_DATE    - ISO date to end search (default: today)
  OUTPUT_DIR         - Directory for output files (default: ./output)
"""

import os
import sys
import json
import csv
import re
import time
import logging
from datetime import datetime, timedelta, timezone
from collections import defaultdict

import msal
import requests
from dateutil.parser import parse as parse_date

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

TENANT_ID = os.environ.get("TENANT_ID", "")
CLIENT_ID = os.environ.get("CLIENT_ID", "")
CLIENT_SECRET = os.environ.get("CLIENT_SECRET", "")
MAILBOX_UPN = os.environ.get("MAILBOX_UPN", "")
SOC_SENDER = "soc@oculusit.com"

SEARCH_START_DATE = os.environ.get("SEARCH_START_DATE", "2024-01-01")
SEARCH_END_DATE = os.environ.get("SEARCH_END_DATE", datetime.now(timezone.utc).strftime("%Y-%m-%d"))
OUTPUT_DIR = os.environ.get("OUTPUT_DIR", "./output")

GRAPH_BASE = "https://graph.microsoft.com/v1.0"
GRAPH_SCOPE = ["https://graph.microsoft.com/.default"]
PAGE_SIZE = 100   # Max items per Graph API page
WEEK_DAYS = 7
RATE_LIMIT_DELAY = 0.2   # seconds between paginated requests

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
# SOC Email Categorization
# ---------------------------------------------------------------------------

# Each tuple: (category_name, list_of_regex_patterns_matched_against_subject)
# Patterns are checked in order; first match wins.
CATEGORY_RULES = [
    # --- Severity-based categories (often in subject) ---
    ("Critical Alert",          [r"\bcritical\b"]),
    ("High Severity Alert",     [r"\bhigh\s*(severity|alert|risk)\b", r"\bHigh\b.*alert"]),
    ("Medium Severity Alert",   [r"\bmedium\s*(severity|alert|risk)\b"]),
    ("Low Severity Alert",      [r"\blow\s*(severity|alert|risk)\b"]),

    # --- Alert type categories ---
    ("Malware / Ransomware",    [r"\bmalware\b", r"\bransomware\b", r"\btrojan\b", r"\bvirus\b", r"\bworm\b"]),
    ("Phishing / Spoofing",     [r"\bphish", r"\bspoof", r"\bimpersonat", r"\bvish"]),
    ("Suspicious Login / MFA",  [r"\bsuspicious.{0,20}(sign|login|logon|auth)\b",
                                  r"\bmfa\b", r"\bmulti.?factor\b", r"\bunusual.{0,20}(sign|login)\b",
                                  r"\bfailed.{0,20}(login|auth|sign)\b"]),
    ("Credential / Identity",   [r"\bcredential", r"\bidentity\b", r"\bpassword\b", r"\bhijack\b",
                                  r"\baccount.{0,20}(compromise|breach|takeover)\b"]),
    ("Data Exfiltration",       [r"\bexfil", r"\bdata.{0,20}(breach|leak|loss|theft)\b",
                                  r"\bdlp\b", r"\bdata.{0,20}prevent"]),
    ("Endpoint / EDR Alert",    [r"\bendpoint\b", r"\bedr\b", r"\bdefender\b", r"\bantivirus\b",
                                  r"\bav\s*alert\b", r"\bmdatp\b", r"\bmde\b"]),
    ("Network / Firewall",      [r"\bfirewall\b", r"\bids\b", r"\bips\b", r"\bintrusion\b",
                                  r"\bnetwork.{0,20}(alert|detect|attack)\b", r"\bport.{0,15}scan"]),
    ("Vulnerability / Patch",   [r"\bvulnerab", r"\bpatch\b", r"\bcve-\d{4}", r"\bexploit\b",
                                  r"\bzero.?day\b"]),
    ("Email Security",          [r"\bemail.{0,20}(threat|secur|block|quarantin)\b",
                                  r"\bspam\b", r"\bquarantin"]),
    ("Cloud / Azure / M365",    [r"\bazure\b", r"\bm365\b", r"\bmicrosoft\s*365\b",
                                  r"\bcloud.{0,20}(alert|threat|secur)\b", r"\bsharepoint\b",
                                  r"\bteams.{0,20}alert"]),
    ("Incident Report",         [r"\bincident\b", r"\bticket\b", r"\bcase\s*#?\d", r"\bsoc\s*alert"]),
    ("Auto-Remediated",         [r"\bauto.?remediati", r"\bremediat", r"\bcontained\b",
                                  r"\bblocked\b.*auto", r"\bauto.?resolv"]),
    ("Informational / Advisory",[r"\badvisory\b", r"\bnotice\b", r"\binformation", r"\breport\b",
                                  r"\bweekly\b", r"\bmonthly\b", r"\bsummary\b", r"\bdigest\b"]),
    ("False Positive",          [r"\bfalse.?positive\b", r"\bfp\b", r"\bnot.{0,20}threat\b",
                                  r"\bwhitelist\b", r"\bexclu[ds]"]),
    ("Resolved / Closed",       [r"\bresolved\b", r"\bclosed\b", r"\bno.{0,10}action.{0,10}required\b",
                                  r"\bno.{0,10}further\b"]),
]

CATEGORY_UNCATEGORIZED = "Uncategorized"


def categorize_subject(subject: str) -> str:
    """Return the first matching category for a subject line, or 'Uncategorized'."""
    subject_lower = (subject or "").lower()
    for category, patterns in CATEGORY_RULES:
        for pattern in patterns:
            if re.search(pattern, subject_lower, re.IGNORECASE):
                return category
    return CATEGORY_UNCATEGORIZED


def extract_incident_number(subject: str) -> str:
    """Try to extract a ticket/incident number from the subject."""
    patterns = [
        r"(?:incident|ticket|case|#|INC|TKT|SOC)[:\s#-]*(\d{4,10})",
        r"\[(\d{4,10})\]",
        r"(?:^|\s)(\d{5,10})(?:\s|$)",
    ]
    for p in patterns:
        m = re.search(p, subject or "", re.IGNORECASE)
        if m:
            return m.group(1)
    return ""


def extract_severity(subject: str) -> str:
    """Extract severity level from subject if present."""
    m = re.search(r"\b(critical|high|medium|low|informational|info)\b", subject or "", re.IGNORECASE)
    return m.group(1).capitalize() if m else ""


# ---------------------------------------------------------------------------
# Microsoft Graph API helpers
# ---------------------------------------------------------------------------

def get_access_token() -> str:
    """Acquire an access token via client credentials flow."""
    authority = f"https://login.microsoftonline.com/{TENANT_ID}"
    app = msal.ConfidentialClientApplication(
        CLIENT_ID,
        authority=authority,
        client_credential=CLIENT_SECRET,
    )
    result = app.acquire_token_for_client(scopes=GRAPH_SCOPE)
    if "access_token" not in result:
        error = result.get("error_description", result.get("error", "Unknown error"))
        raise RuntimeError(f"Failed to acquire token: {error}")
    log.info("Access token acquired successfully.")
    return result["access_token"]


def graph_get(token: str, url: str, params: dict = None) -> dict:
    """GET a Graph API URL, returning parsed JSON. Raises on HTTP error."""
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
    resp = requests.get(url, headers=headers, params=params, timeout=60)
    if resp.status_code == 429:
        retry_after = int(resp.headers.get("Retry-After", "10"))
        log.warning("Rate limited. Waiting %d seconds...", retry_after)
        time.sleep(retry_after)
        return graph_get(token, url, params)
    if resp.status_code == 401:
        raise RuntimeError("401 Unauthorized. Check that the app has Mail.Read application permission.")
    resp.raise_for_status()
    return resp.json()


def refresh_token_if_needed(token: str, token_acquired_at: datetime) -> tuple[str, datetime]:
    """Refresh token if it's been > 50 minutes (tokens expire at 60 min)."""
    elapsed = (datetime.now() - token_acquired_at).total_seconds()
    if elapsed > 3000:  # 50 minutes
        log.info("Token approaching expiry, refreshing...")
        token = get_access_token()
        token_acquired_at = datetime.now()
    return token, token_acquired_at


# ---------------------------------------------------------------------------
# Email search - weekly windowed approach
# ---------------------------------------------------------------------------

def search_emails_for_week(
    token: str,
    mailbox: str,
    week_start: datetime,
    week_end: datetime,
) -> list[dict]:
    """
    Fetch all emails from SOC_SENDER in [week_start, week_end).
    Handles pagination via @odata.nextLink.
    Returns list of simplified email records.
    """
    week_start_str = week_start.strftime("%Y-%m-%dT00:00:00Z")
    week_end_str   = week_end.strftime("%Y-%m-%dT00:00:00Z")

    url = f"{GRAPH_BASE}/users/{mailbox}/messages"
    params = {
        "$filter": (
            f"from/emailAddress/address eq '{SOC_SENDER}' "
            f"and receivedDateTime ge {week_start_str} "
            f"and receivedDateTime lt {week_end_str}"
        ),
        "$select": "id,subject,receivedDateTime,from,isRead,categories,importance,hasAttachments,bodyPreview",
        "$top": PAGE_SIZE,
        "$orderby": "receivedDateTime asc",
    }

    emails = []
    page = 1
    current_url = url
    current_params = params

    while current_url:
        data = graph_get(token, current_url, current_params if page == 1 else None)
        batch = data.get("value", [])
        emails.extend(batch)
        next_link = data.get("@odata.nextLink")
        current_url = next_link if next_link else None
        current_params = None  # nextLink already has params encoded
        page += 1
        if next_link:
            time.sleep(RATE_LIMIT_DELAY)

    return emails


def process_email(raw: dict) -> dict:
    """Extract and enrich a single email record."""
    subject = raw.get("subject", "") or ""
    received = raw.get("receivedDateTime", "")
    try:
        received_dt = parse_date(received)
    except Exception:
        received_dt = None

    category = categorize_subject(subject)
    severity = extract_severity(subject)
    incident_num = extract_incident_number(subject)

    return {
        "id": raw.get("id", ""),
        "subject": subject,
        "received": received,
        "received_date": received_dt.strftime("%Y-%m-%d") if received_dt else "",
        "received_week": received_dt.strftime("%Y-W%W") if received_dt else "",
        "category": category,
        "severity": severity,
        "incident_number": incident_num,
        "is_read": raw.get("isRead", False),
        "importance": raw.get("importance", ""),
        "has_attachments": raw.get("hasAttachments", False),
        "body_preview": (raw.get("bodyPreview", "") or "")[:200],
    }


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

def write_csv(records: list[dict], filepath: str) -> None:
    if not records:
        log.warning("No records to write to CSV.")
        return
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    with open(filepath, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=records[0].keys())
        writer.writeheader()
        writer.writerows(records)
    log.info("Wrote %d records to %s", len(records), filepath)


def write_json(data, filepath: str) -> None:
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, default=str)
    log.info("Wrote JSON summary to %s", filepath)


def print_summary(records: list[dict], counts_by_category: dict, counts_by_week: dict) -> None:
    print("\n" + "=" * 70)
    print(f"  SOC EMAIL SEARCH RESULTS - Phase 1 Summary")
    print(f"  Sender:   {SOC_SENDER}")
    print(f"  Mailbox:  {MAILBOX_UPN}")
    print(f"  Period:   {SEARCH_START_DATE}  to  {SEARCH_END_DATE}")
    print("=" * 70)
    print(f"\n  TOTAL EMAILS FOUND: {len(records)}")

    print("\n  BREAKDOWN BY CATEGORY:")
    print("  " + "-" * 50)
    for cat, count in sorted(counts_by_category.items(), key=lambda x: -x[1]):
        bar = "#" * min(count, 40)
        print(f"  {cat:<35} {count:>5}  {bar}")

    print("\n  BREAKDOWN BY WEEK (top 10 busiest):")
    print("  " + "-" * 50)
    top_weeks = sorted(counts_by_week.items(), key=lambda x: -x[1])[:10]
    for week, count in top_weeks:
        print(f"  {week:<15} {count:>5} emails")

    print("\n" + "=" * 70 + "\n")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def validate_config() -> None:
    missing = []
    if not TENANT_ID:
        missing.append("TENANT_ID")
    if not CLIENT_ID:
        missing.append("CLIENT_ID")
    if not CLIENT_SECRET:
        missing.append("CLIENT_SECRET")
    if not MAILBOX_UPN:
        missing.append("MAILBOX_UPN")
    if missing:
        print(f"\nERROR: Missing required environment variables: {', '.join(missing)}")
        print("\nSet them before running:")
        for v in missing:
            print(f"  export {v}=<value>")
        if "MAILBOX_UPN" in missing:
            print("\n  MAILBOX_UPN should be the email address of the mailbox to search,")
            print("  e.g.: export MAILBOX_UPN=jbaldwin@barry.edu")
        sys.exit(1)


def main() -> None:
    validate_config()

    os.makedirs(OUTPUT_DIR, exist_ok=True)

    log.info("Starting Phase 1: SOC email search from %s", SOC_SENDER)
    log.info("Mailbox: %s", MAILBOX_UPN)
    log.info("Date range: %s to %s", SEARCH_START_DATE, SEARCH_END_DATE)

    # Acquire token
    token = get_access_token()
    token_acquired_at = datetime.now()

    # Build weekly windows
    start = datetime.fromisoformat(SEARCH_START_DATE)
    end   = datetime.fromisoformat(SEARCH_END_DATE)
    windows = []
    cursor = start
    while cursor < end:
        window_end = min(cursor + timedelta(days=WEEK_DAYS), end + timedelta(days=1))
        windows.append((cursor, window_end))
        cursor = window_end

    log.info("Processing %d weekly windows...", len(windows))

    all_records = []
    counts_by_category = defaultdict(int)
    counts_by_week = defaultdict(int)

    for i, (wk_start, wk_end) in enumerate(windows, 1):
        label = wk_start.strftime("%Y-%m-%d")
        log.info("[%d/%d] Searching week starting %s...", i, len(windows), label)

        # Refresh token if needed
        token, token_acquired_at = refresh_token_if_needed(token, token_acquired_at)

        try:
            raw_emails = search_emails_for_week(token, MAILBOX_UPN, wk_start, wk_end)
        except Exception as e:
            log.error("Error fetching week %s: %s", label, e)
            continue

        week_count = len(raw_emails)
        log.info("  Found %d emails for week %s", week_count, label)

        for raw in raw_emails:
            record = process_email(raw)
            all_records.append(record)
            counts_by_category[record["category"]] += 1
            if record["received_week"]:
                counts_by_week[record["received_week"]] += 1

        time.sleep(RATE_LIMIT_DELAY)

    log.info("Search complete. Total emails found: %d", len(all_records))

    # Write outputs
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    csv_path  = os.path.join(OUTPUT_DIR, f"phase1_soc_emails_{timestamp}.csv")
    json_path = os.path.join(OUTPUT_DIR, f"phase1_soc_summary_{timestamp}.json")

    write_csv(all_records, csv_path)

    summary = {
        "run_timestamp": timestamp,
        "mailbox": MAILBOX_UPN,
        "sender": SOC_SENDER,
        "search_start": SEARCH_START_DATE,
        "search_end": SEARCH_END_DATE,
        "total_emails": len(all_records),
        "counts_by_category": dict(sorted(counts_by_category.items(), key=lambda x: -x[1])),
        "counts_by_week": dict(sorted(counts_by_week.items())),
        "output_csv": csv_path,
    }
    write_json(summary, json_path)

    print_summary(all_records, counts_by_category, counts_by_week)

    print(f"  Output files:")
    print(f"    CSV:  {csv_path}")
    print(f"    JSON: {json_path}\n")


if __name__ == "__main__":
    main()
