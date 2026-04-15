#!/usr/bin/env python3
"""
Phase 1: Search and Categorize SOC Emails from soc@oculusit.com
Barry University - Cybersecurity Incident Dashboard

Uses Microsoft Graph API $search (KQL) with monthly windows to retrieve all
messages from soc@oculusit.com. High-volume months auto-split into weekly
windows to stay under the Graph API search result cap (~275 per query).

Data range: April 2024 - present (2,387 emails as of Apr 2026).

Required environment variables:
  TENANT_ID      - Azure AD Tenant ID
  CLIENT_ID      - Azure AD App Registration Client ID
  CLIENT_SECRET  - Azure AD App Registration Client Secret
  MAILBOX_UPN    - Mailbox to search (jmoses@barry.edu)

Optional:
  SEARCH_START_DATE  - ISO date to start (default: 2024-04-01)
  SEARCH_END_DATE    - ISO date to end   (default: today)
  OUTPUT_DIR         - Output directory  (default: ./output)
  VOLUME_CAP         - Monthly email count that triggers weekly split (default: 200)
"""

import os
import sys
import json
import csv
import re
import time
import calendar
import logging
from datetime import datetime, timedelta, timezone, date
from collections import defaultdict

import msal
import requests

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

TENANT_ID     = os.environ.get("TENANT_ID", "")
CLIENT_ID     = os.environ.get("CLIENT_ID", "")
CLIENT_SECRET = os.environ.get("CLIENT_SECRET", "")
MAILBOX_UPN   = os.environ.get("MAILBOX_UPN", "jmoses@barry.edu")
SOC_SENDER    = "soc@oculusit.com"

SEARCH_START_DATE = os.environ.get("SEARCH_START_DATE", "2024-04-01")
SEARCH_END_DATE   = os.environ.get("SEARCH_END_DATE",
                                   datetime.now(timezone.utc).strftime("%Y-%m-%d"))
OUTPUT_DIR   = os.environ.get("OUTPUT_DIR", "./output")
VOLUME_CAP   = int(os.environ.get("VOLUME_CAP", "200"))   # split to weekly if >= this

GRAPH_BASE   = "https://graph.microsoft.com/v1.0"
PAGE_SIZE    = 999    # max for $search queries
RATE_DELAY   = 0.3   # seconds between requests

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
# SOC Email Categorization (tuned to real OIT-SOC subject patterns)
#
# Subject format: "Service Ticket #NNNNNN - Barry [University] || SECURITY ALERT - [Type] || OIT-SOC"
# Categories are matched against the full subject, case-insensitive.
# ---------------------------------------------------------------------------

CATEGORY_RULES = [
    # -----------------------------------------------------------------------
    # Identity & Sign-in Threats  (most common at Barry)
    # -----------------------------------------------------------------------
    ("Anomalous Token",               [r"anomalous\s*token"]),
    ("Pass-the-Ticket / Kerberos",    [r"pass.the.ticket", r"kerberos"]),
    ("Stolen Session Cookie",         [r"stolen.{0,20}session", r"session.{0,20}cookie"]),
    ("User at Risk",                  [r"user.{0,10}at.{0,10}risk"]),
    ("Unfamiliar Sign-in Properties", [r"unfamiliar.{0,20}sign.?in"]),
    ("Unusual Sign-in Location",      [r"unusual.{0,20}sign.?in", r"outside.{0,10}us.{0,10}location",
                                       r"multiple.{0,20}location",
                                       r"anomalous.{0,20}sign.?in.{0,20}location"]),
    ("Sign-in from Anonymous IP",     [r"anonymous.{0,10}ip\b"]),
    ("Sign-in from Anonymous Proxy",  [r"anonymous.{0,10}proxy", r"activity.{0,20}proxy"]),
    ("Sign-in from Botnet IP",        [r"botnet"]),
    ("Sign-in from Password-Spray IP",[r"password.?spray.{0,30}ip"]),
    ("Sign-in from Tor / Malware C2", [r"\btor\b", r"malware.{0,10}c&c", r"malware.{0,10}command"]),
    ("Sign-in from Malicious IP",     [r"malicious.{0,10}ip", r"malicious.{0,10}address",
                                       r"suspicious.{0,10}ip", r"successful.{0,20}auth.{0,20}suspicious"]),
    ("Sign-in Disabled Accounts",     [r"disabled.{0,10}account", r"sign.?in.{0,20}disabled"]),
    ("Password Spray Attack",         [r"password.?spray(?!.{0,30}ip)", r"brute.?force",
                                       r"bruteforce"]),

    # -----------------------------------------------------------------------
    # Multi-stage / Complex Incidents
    # -----------------------------------------------------------------------
    ("Multi-stage Incident",          [r"multi.?stage\s*incident",
                                       r"multi.?stage.{0,30}(initial|credential|execution|defense|lateral)"]),

    # -----------------------------------------------------------------------
    # Credential & Account Compromise
    # -----------------------------------------------------------------------
    ("Credential Phishing / AiTM",    [r"credential.{0,20}phish", r"adversary.{0,20}middle",
                                       r"aitm\b", r"phish"]),
    ("Suspicious Activity / Auth",    [r"suspicious.{0,20}activit", r"suspicious.{0,20}auth",
                                       r"suspicious.{0,20}sign.?in"]),

    # -----------------------------------------------------------------------
    # Email / Mail Compromise
    # -----------------------------------------------------------------------
    ("Mail Forwarding / Inbox Rule",  [r"\bforward(ing|ed)?\b", r"inbox.{0,20}rule",
                                       r"inbox.{0,20}manipulat", r"email.{0,20}forward"]),
    ("Suspicious Email Sending",      [r"suspicious.{0,20}email.{0,20}send",
                                       r"email.{0,20}send.{0,20}pattern"]),
    ("Email Security",                [r"email.{0,20}(threat|block|quarantin|secur)", r"\bspam\b"]),

    # -----------------------------------------------------------------------
    # Endpoint & Execution
    # -----------------------------------------------------------------------
    ("Malicious PowerShell",          [r"powershell", r"ps\s*cmdlet"]),
    ("Malware Detected",              [r"\bmalware\b(?!.*c&c)", r"\bransomware\b", r"\btrojan\b",
                                       r"\bvirus\b", r"defender.{0,20}alert"]),
    ("Malicious URL Click",           [r"malicious.{0,20}url", r"url.{0,20}click",
                                       r"url.{0,20}detect", r"url.{0,20}malicious"]),
    ("Suspicious Service / Process",  [r"suspicious.{0,20}service", r"suspicious.{0,20}process",
                                       r"service.{0,20}registr", r"suspicious.{0,20}wordpress",
                                       r"wordpress.{0,20}theme"]),
    ("Vulnerability / Exploit",       [r"vulnerab", r"\bcve-\d{4}", r"\bexploit\b",
                                       r"zero.?day", r"manageengine", r"fortinet"]),

    # -----------------------------------------------------------------------
    # Network & Infrastructure
    # -----------------------------------------------------------------------
    ("Network Reconnaissance",        [r"reconnaissance", r"network.{0,20}mapp", r"port.{0,10}scan",
                                       r"external.{0,20}connect"]),
    ("Unauthorized Access",           [r"unauthorized.{0,20}access", r"bot.{0,10}site.{0,10}access"]),

    # -----------------------------------------------------------------------
    # Data / DLP
    # -----------------------------------------------------------------------
    ("Sensitive Files / DLP",         [r"sensitive.{0,20}(file|information|data)", r"\bdlp\b",
                                       r"custom.{0,20}file"]),

    # -----------------------------------------------------------------------
    # Microsoft Defender / Graph API alerts
    # -----------------------------------------------------------------------
    ("MS Graph API Alert",            [r"\bms[\s\-\.]*graph\b", r"\bmicrosoft[\s\-\.]*graph\b"]),
    ("Microsoft Defender Alert",      [r"\bms.{0,5}defender\b", r"\bmicrosoft.{0,5}defender\b",
                                       r"\bdefender.{0,10}365\b"]),

    # -----------------------------------------------------------------------
    # Advanced Endpoint / Execution Threats
    # -----------------------------------------------------------------------
    ("Process Injection / Code Exec", [r"process.{0,20}inject", r"process.{0,20}creat.{0,20}anomal",
                                       r"injected.{0,20}code"]),
    ("Defense Evasion",               [r"hide.{0,20}(use|tool|dual)", r"dual.?purpose.{0,20}tool",
                                       r"evasion", r"asep.{0,20}registry", r"registry.{0,20}anomal"]),
    ("Initial Access Incident",       [r"initial.{0,15}access.{0,20}incident"]),
    ("Suspicious File / Process",     [r"suspicious.{0,20}file", r"malicious.{0,20}file",
                                       r"suspicious.{0,20}ldap", r"suspicious.{0,20}network.{0,20}conn"]),
    ("Log4j / Known CVE Exploit",     [r"log4j", r"log4shell", r"cve.{0,5}2021", r"cve.{0,5}2022"]),

    # -----------------------------------------------------------------------
    # Email / Messaging Attacks
    # -----------------------------------------------------------------------
    ("BEC / Credential Harvesting",   [r"\bbec\b", r"business.{0,20}email.{0,20}comprom",
                                       r"credential.{0,20}harvest"]),
    ("Mail Bombing",                  [r"mail.{0,15}bombing", r"mail.{0,15}flood"]),
    ("Malicious Email Not Removed",   [r"malicious.{0,20}(entity|email).{0,20}not.{0,15}remov",
                                       r"not.{0,15}remov.{0,20}after.{0,15}delivery"]),

    # -----------------------------------------------------------------------
    # Network Communication Threats
    # -----------------------------------------------------------------------
    ("Suspicious DNS / C2 Comms",     [r"dns.{0,20}(suspicious|communicat|exfil)",
                                       r"suspicious.{0,20}(dns|communicat)",
                                       r"communication.{0,20}over.{0,20}dns",
                                       r"encrypting.{0,20}file.{0,20}system"]),

    # -----------------------------------------------------------------------
    # Cloud / App Anomalies
    # -----------------------------------------------------------------------
    ("Compromised Account Activity",  [r"compromised.{0,20}(user|account)",
                                       r"app.{0,20}activity.{0,20}exchange",
                                       r"increase.{0,20}app.{0,20}activit"]),
    ("AI / Copilot Misuse",           [r"copilot", r"ai.{0,15}(unethical|misuse|abuse)",
                                       r"unethical.{0,20}(behavior|copilot)"]),
    ("AWS / Cloud Alert",             [r"\baws\b", r"\bcloud.{0,20}alert\b"]),

    # -----------------------------------------------------------------------
    # OSSEC / SIEM infrastructure
    # -----------------------------------------------------------------------
    ("OSSEC / Agent Disconnected",    [r"\bossec\b", r"agent.{0,20}disconnect",
                                       r"disconnected.{0,20}agent"]),

    # -----------------------------------------------------------------------
    # Account Actions & Remediation
    # -----------------------------------------------------------------------
    ("Account Suspended / Remediated",[r"\bsuspend\b", r"\bremediat\b", r"\bcontained\b",
                                       r"auto.?remediati", r"\bblocked\b"]),

    # -----------------------------------------------------------------------
    # Security Bulletins / Reports / Informational
    # -----------------------------------------------------------------------
    ("Security Bulletin / Report",    [r"security.{0,20}bulletin", r"cyber.{0,20}hygiene",
                                       r"security.{0,20}news", r"cisa.{0,20}(alert|vuln|update)",
                                       r"action.{0,20}required.{0,20}(vuln|update|cisa)"]),
    ("Maintenance / Informational",   [r"\bmaintenance\b", r"\badvisory\b", r"\bnotice\b",
                                       r"\binformati", r"\bsummary\b", r"\bdigest\b",
                                       r"\bweekly\b", r"\bmonthly\b", r"compliance.{0,20}alert",
                                       r"office.{0,10}365.{0,20}(security|alert|compliance)"]),
]

CATEGORY_UNCATEGORIZED = "Uncategorized"

# Ticket subject prefix patterns
_TICKET_RE   = re.compile(r"(?:service\s*ticket\s*#?|ticket\s*#?|TKT|INC)[\s#]*(\d{5,10})", re.I)
_RECALL_RE   = re.compile(r"^recall\s*:", re.I)
_REPLY_RE    = re.compile(r"^re\s*:", re.I)


def categorize_subject(subject: str) -> str:
    s = (subject or "").lower()
    for category, patterns in CATEGORY_RULES:
        for p in patterns:
            if re.search(p, s, re.IGNORECASE):
                return category
    return CATEGORY_UNCATEGORIZED


def extract_ticket_number(subject: str) -> str:
    m = _TICKET_RE.search(subject or "")
    return m.group(1) if m else ""


def classify_email_type(subject: str) -> str:
    """New Ticket, Reply/Update, or Recall."""
    s = subject or ""
    if _RECALL_RE.match(s):
        return "Recall"
    if _REPLY_RE.match(s):
        return "Reply/Update"
    return "New Ticket"


# ---------------------------------------------------------------------------
# Microsoft Graph API helpers
# ---------------------------------------------------------------------------

def get_access_token() -> str:
    authority = f"https://login.microsoftonline.com/{TENANT_ID}"
    app = msal.ConfidentialClientApplication(
        CLIENT_ID, authority=authority, client_credential=CLIENT_SECRET
    )
    result = app.acquire_token_for_client(scopes=["https://graph.microsoft.com/.default"])
    if "access_token" not in result:
        raise RuntimeError(f"Token error: {result.get('error_description', result)}")
    return result["access_token"]


def graph_search(token: str, kql: str) -> list[dict]:
    """
    Search messages via Graph API $search with KQL.
    Paginates via @odata.nextLink until exhausted.
    Returns list of raw message dicts.
    """
    url = f"{GRAPH_BASE}/users/{MAILBOX_UPN}/messages"
    params = {
        "$search": f'"{kql}"',
        "$select": "id,subject,receivedDateTime,from,isRead,importance,hasAttachments,bodyPreview,parentFolderId",
        "$top": PAGE_SIZE,
    }
    headers = {
        "Authorization": f"Bearer {token}",
        "ConsistencyLevel": "eventual",
    }

    results = []
    page = 1
    current_url = url
    current_params = params

    while current_url:
        resp = requests.get(current_url, headers=headers,
                            params=current_params if page == 1 else None,
                            timeout=60)
        if resp.status_code == 429:
            wait = int(resp.headers.get("Retry-After", "15"))
            log.warning("Rate limited. Waiting %ds...", wait)
            time.sleep(wait)
            continue
        resp.raise_for_status()
        data = resp.json()
        batch = data.get("value", [])
        results.extend(batch)
        next_link = data.get("@odata.nextLink")
        current_url = next_link if next_link else None
        current_params = None
        page += 1
        if next_link:
            time.sleep(RATE_DELAY)

    return results


def refresh_token_if_stale(token: str, acquired_at: datetime) -> tuple[str, datetime]:
    if (datetime.now() - acquired_at).total_seconds() > 3000:
        log.info("Refreshing access token...")
        token = get_access_token()
        acquired_at = datetime.now()
    return token, acquired_at


# ---------------------------------------------------------------------------
# Window building  (monthly, auto-splitting high-volume months to weekly)
# ---------------------------------------------------------------------------

def build_monthly_windows(start_str: str, end_str: str) -> list[tuple[str, str, str]]:
    """
    Returns list of (label, start_date, end_date) tuples for monthly windows.
    start/end are strings in YYYY-MM-DD format.
    """
    start = date.fromisoformat(start_str)
    end   = date.fromisoformat(end_str)

    windows = []
    cur = date(start.year, start.month, 1)
    while cur <= end:
        last_day   = calendar.monthrange(cur.year, cur.month)[1]
        month_end  = date(cur.year, cur.month, last_day)
        win_end    = min(month_end, end)
        label      = cur.strftime("%Y-%m")
        windows.append((label, cur.strftime("%Y-%m-%d"), win_end.strftime("%Y-%m-%d")))
        # advance to first of next month
        if cur.month == 12:
            cur = date(cur.year + 1, 1, 1)
        else:
            cur = date(cur.year, cur.month + 1, 1)
    return windows


def build_weekly_sub_windows(month_start: str, month_end: str) -> list[tuple[str, str, str]]:
    """Split a single month into ~weekly windows."""
    start = date.fromisoformat(month_start)
    end   = date.fromisoformat(month_end)
    windows = []
    cur = start
    while cur <= end:
        win_end = min(cur + timedelta(days=6), end)
        label   = f"{cur.strftime('%Y-%m-%d')}w"
        windows.append((label, cur.strftime("%Y-%m-%d"), win_end.strftime("%Y-%m-%d")))
        cur = win_end + timedelta(days=1)
    return windows


# ---------------------------------------------------------------------------
# Processing
# ---------------------------------------------------------------------------

def process_email(raw: dict) -> dict:
    subject     = raw.get("subject", "") or ""
    received    = raw.get("receivedDateTime", "") or ""
    received_dt = None
    try:
        received_dt = datetime.fromisoformat(received.replace("Z", "+00:00"))
    except Exception:
        pass

    return {
        "id":             raw.get("id", ""),
        "subject":        subject,
        "received":       received,
        "received_date":  received_dt.strftime("%Y-%m-%d") if received_dt else "",
        "received_month": received_dt.strftime("%Y-%m") if received_dt else "",
        "received_week":  received_dt.strftime("%Y-W%W") if received_dt else "",
        "email_type":     classify_email_type(subject),
        "ticket_number":  extract_ticket_number(subject),
        "category":       categorize_subject(subject),
        "importance":     raw.get("importance", ""),
        "is_read":        raw.get("isRead", False),
        "has_attachments":raw.get("hasAttachments", False),
        "body_preview":   (raw.get("bodyPreview", "") or "")[:200],
    }


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

def write_csv(records: list[dict], filepath: str) -> None:
    if not records:
        log.warning("No records to write.")
        return
    os.makedirs(os.path.dirname(os.path.abspath(filepath)), exist_ok=True)
    with open(filepath, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(records[0].keys()))
        writer.writeheader()
        writer.writerows(records)
    log.info("CSV written: %s (%d rows)", filepath, len(records))


def write_json(data: dict, filepath: str) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(filepath)), exist_ok=True)
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, default=str)
    log.info("JSON written: %s", filepath)


def print_summary(records: list[dict], by_category: dict, by_month: dict,
                  by_type: dict) -> None:
    total_tickets = len({r["ticket_number"] for r in records if r["ticket_number"]})

    print("\n" + "=" * 72)
    print("  SOC EMAIL SEARCH RESULTS  -  Phase 1 Summary")
    print(f"  Sender:          {SOC_SENDER}")
    print(f"  Mailbox:         {MAILBOX_UPN}")
    print(f"  Period:          {SEARCH_START_DATE}  to  {SEARCH_END_DATE}")
    print("=" * 72)
    print(f"\n  TOTAL EMAILS:         {len(records):,}")
    print(f"  Unique ticket #s:     {total_tickets:,}")
    print(f"  New Tickets:          {by_type.get('New Ticket', 0):,}")
    print(f"  Replies/Updates:      {by_type.get('Reply/Update', 0):,}")
    print(f"  Recalls:              {by_type.get('Recall', 0):,}")

    print("\n  BREAKDOWN BY CATEGORY:")
    print("  " + "-" * 60)
    for cat, count in sorted(by_category.items(), key=lambda x: -x[1]):
        pct = count / len(records) * 100 if records else 0
        bar = "=" * int(pct / 2)
        print(f"  {cat:<40} {count:>5}  ({pct:4.1f}%)  {bar}")

    print("\n  VOLUME BY MONTH:")
    print("  " + "-" * 40)
    for month in sorted(by_month.keys()):
        count = by_month[month]
        bar   = "#" * int(count / 5)
        print(f"  {month}  {count:>4}  {bar}")

    print("\n" + "=" * 72 + "\n")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def validate_config() -> None:
    missing = [v for v in ["TENANT_ID", "CLIENT_ID", "CLIENT_SECRET"]
               if not os.environ.get(v)]
    if not MAILBOX_UPN:
        missing.append("MAILBOX_UPN")
    if missing:
        sys.exit(f"\nERROR: Missing environment variables: {', '.join(missing)}\n")


def main() -> None:
    validate_config()
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    log.info("Phase 1: SOC email search starting")
    log.info("Mailbox:  %s", MAILBOX_UPN)
    log.info("Range:    %s  to  %s", SEARCH_START_DATE, SEARCH_END_DATE)

    token = get_access_token()
    token_at = datetime.now()

    # Build initial monthly windows
    monthly_windows = build_monthly_windows(SEARCH_START_DATE, SEARCH_END_DATE)
    log.info("Initial windows: %d monthly", len(monthly_windows))

    all_records: list[dict] = []
    seen_ids:    set[str]   = set()  # deduplicate across overlapping windows
    by_category: dict       = defaultdict(int)
    by_month:    dict       = defaultdict(int)
    by_type:     dict       = defaultdict(int)
    window_counts:list      = []

    total_windows = len(monthly_windows)
    i = 0

    while i < len(monthly_windows):
        label, wstart, wend = monthly_windows[i]

        token, token_at = refresh_token_if_stale(token, token_at)

        kql = f"from:{SOC_SENDER} AND received:{wstart}..{wend}"
        log.info("[%d/%d] Searching %s  (%s to %s)...",
                 i + 1, len(monthly_windows), label, wstart, wend)

        try:
            raw_emails = graph_search(token, kql)
        except Exception as exc:
            log.error("Error on window %s: %s", label, exc)
            i += 1
            continue

        count = len(raw_emails)
        log.info("  -> %d emails found", count)

        # If near/at cap, replace this window with weekly sub-windows and retry
        if count >= VOLUME_CAP and not label.endswith("w"):
            log.warning("  Volume %d >= cap %d for %s. Splitting into weekly windows.",
                        count, VOLUME_CAP, label)
            weekly = build_weekly_sub_windows(wstart, wend)
            monthly_windows = monthly_windows[:i] + weekly + monthly_windows[i + 1:]
            log.info("  New total windows: %d", len(monthly_windows))
            continue  # re-process from same index (now a weekly window)

        window_counts.append({"window": label, "start": wstart, "end": wend, "count": count})

        for raw in raw_emails:
            msg_id = raw.get("id", "")
            if msg_id in seen_ids:
                continue
            seen_ids.add(msg_id)
            rec = process_email(raw)
            all_records.append(rec)
            by_category[rec["category"]] += 1
            by_month[rec["received_month"]] += 1
            by_type[rec["email_type"]] += 1

        time.sleep(RATE_DELAY)
        i += 1

    log.info("Search complete. Total unique emails: %d", len(all_records))

    # Write outputs
    ts       = datetime.now().strftime("%Y%m%d_%H%M%S")
    csv_path = os.path.join(OUTPUT_DIR, f"phase1_soc_emails_{ts}.csv")
    jsn_path = os.path.join(OUTPUT_DIR, f"phase1_soc_summary_{ts}.json")

    write_csv(all_records, csv_path)

    summary = {
        "run_timestamp":       ts,
        "mailbox":             MAILBOX_UPN,
        "sender":              SOC_SENDER,
        "search_start":        SEARCH_START_DATE,
        "search_end":          SEARCH_END_DATE,
        "total_emails":        len(all_records),
        "unique_ticket_numbers": len({r["ticket_number"] for r in all_records if r["ticket_number"]}),
        "by_email_type":       dict(by_type),
        "by_category":         dict(sorted(by_category.items(), key=lambda x: -x[1])),
        "by_month":            dict(sorted(by_month.items())),
        "window_counts":       window_counts,
        "output_csv":          csv_path,
    }
    write_json(summary, jsn_path)

    print_summary(all_records, by_category, by_month, by_type)
    print(f"  Output files:")
    print(f"    CSV:     {csv_path}")
    print(f"    JSON:    {jsn_path}\n")


if __name__ == "__main__":
    main()
