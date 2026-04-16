#!/usr/bin/env python3
"""
Phase 2: Search Microsoft Security/Defender emails and correlate with SOC data
Barry University - Cybersecurity Incident Dashboard

Searches these mail folders for Microsoft security-sourced alerts:
  1. Inbox > Microsoft Security      (defender-noreply@microsoft.com)     ~7,550
  2. Inbox > Microsoft 365 Defender   (defender-noreply@microsoft.com)     ~1,019
  3. TOP:  Microsoft Security         (MSSecurity-noreply@microsoft.com)     ~993
  4. TOP:  Office365 Alerts           (Office365Alerts@microsoft.com)        ~989
  5. Inbox > Office365 Alerts         (Office365Alerts@microsoft.com)        ~614

Uses folder-based $filter on receivedDateTime (no 275-result cap) with monthly
windows and proper pagination.

Required environment variables:
  TENANT_ID, CLIENT_ID, CLIENT_SECRET, MAILBOX_UPN

Optional:
  SEARCH_START_DATE  (default: 2024-04-01)
  SEARCH_END_DATE    (default: today)
  OUTPUT_DIR         (default: ./output)
  PHASE1_CSV         (default: auto-detect latest in OUTPUT_DIR)
"""

import os
import sys
import json
import csv
import re
import time
import calendar
import logging
import glob as globmod
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

SEARCH_START_DATE = os.environ.get("SEARCH_START_DATE", "2024-04-01")
SEARCH_END_DATE   = os.environ.get("SEARCH_END_DATE",
                                   datetime.now(timezone.utc).strftime("%Y-%m-%d"))
OUTPUT_DIR = os.environ.get("OUTPUT_DIR", "./output")
PHASE1_CSV = os.environ.get("PHASE1_CSV", "")

GRAPH_BASE = "https://graph.microsoft.com/v1.0"
PAGE_SIZE  = 100
RATE_DELAY = 0.25

# Folders to search: (label, location, folder_display_name)
# location = "inbox_sub" (subfolder of Inbox) or "toplevel"
FOLDER_TARGETS = [
    ("Inbox > Microsoft Security",    "inbox_sub", "Microsoft Security"),
    ("Inbox > Microsoft 365 Defender","inbox_sub", "Microsoft 365 Defender"),
    ("TOP: Microsoft Security",       "toplevel",  "Microsoft Security"),
    ("TOP: Office365 Alerts",         "toplevel",  "Office365 Alerts"),
    ("Inbox > Office365 Alerts",      "inbox_sub", "Office365 Alerts"),
]

# Known Microsoft security senders
MS_SENDERS = {
    "defender-noreply@microsoft.com",
    "mssecurity-noreply@microsoft.com",
    "office365alerts@microsoft.com",
}

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
# Microsoft Alert Categorization
# ---------------------------------------------------------------------------

MS_CATEGORY_RULES = [
    # Defender for Identity / workspace alerts
    ("Passwords Exposed in Cleartext",  [r"password.{0,20}(exposed|cleartext|clear\s*text)"]),
    ("Lateral Movement Path",           [r"lateral.{0,20}movement"]),
    ("Sensitive Group Modification",    [r"modif.{0,30}sensitive", r"sensitive.{0,20}group"]),
    ("Sensor Issue / Disconnected",     [r"sensor.{0,20}(memory|reach|issue|disconnect)",
                                         r"sensor\s+v\d", r"rpc\s*audit"]),
    ("ADFS / Config Audit",            [r"\badfs\b", r"configuration\s+container",
                                         r"auditing.{0,20}(config|adfs)"]),
    ("Directory Services / AD",         [r"directory\s+services", r"\bad\b.{0,15}(object|replication)"]),

    # Defender for Identity - Infrastructure health
    ("Sensor Stopped / Service Failed", [r"sensor.{0,20}stopped", r"sensor.{0,20}service.{0,20}fail",
                                         r"sensor.{0,20}power"]),
    ("Network Config / DC Unreachable", [r"network.{0,20}config.{0,20}mismatch",
                                         r"domain.{0,20}controller.{0,20}unreachable"]),
    ("Syslog / ETW Issues",            [r"syslog.{0,20}notif", r"etw.{0,20}event"]),
    ("AAD Sync Health",                 [r"aadsync", r"health\s+service.{0,20}data"]),

    # Defender for Endpoint
    ("Vulnerability Notification",      [r"vulnerabilit.{0,20}(notification|update|report|found|have)",
                                         r"new\s+vulnerabilit",
                                         r"vulnerabilit.{0,20}(disclosed|exploit|public)",
                                         r"vulnerability\s+assessment"]),
    ("Suspicious PowerShell",           [r"suspicious.{0,20}(process|powershell).{0,20}(exec|invok)",
                                         r"powershell"]),
    ("Malware Detected",                [r"\bmalware\b", r"\bransomware\b"]),

    # Defender for Cloud Apps
    ("Cloud Apps Policy Match",         [r"cloud\s*apps?.{0,20}(policy|match|detect)",
                                         r"new\s+policy\s+match"]),
    ("Cloud Apps Suspicious Session",   [r"cloud\s*apps?.{0,20}suspicious",
                                         r"suspicious\s+session"]),
    ("Cloud Apps Alert",                [r"cloud\s*apps?.{0,20}alert"]),

    # Microsoft 365 Defender multi-incident
    ("M365 Defender Threat Detected",   [r"defender.{0,20}(detected|security\s+threat)",
                                         r"detected.{0,20}security\s+threat"]),
    ("M365 Defender Incidents Merged",  [r"merged.{0,20}incident", r"incident.{0,20}merged"]),

    # Entra ID Protection / PIM (MSSecurity-noreply)
    ("Entra ID Protection Digest",      [r"(entra|azure\s*ad).{0,20}protection.{0,20}digest",
                                         r"weekly\s+digest"]),
    ("PIM Role Assignment",             [r"\bpim\b", r"privileged.{0,20}(role|directory|identity)",
                                         r"role\s+assignment", r"activated.{0,20}role"]),
    ("Access Review",                   [r"access\s+review"]),
    ("Recommendation / Advisory",       [r"\brecommendation\b", r"\badvisory\b"]),
    ("Sync Errors / Directory",         [r"synchronization\s+error", r"sync.{0,20}error"]),
    ("App Certificate Renewal",         [r"renew.{0,20}(application|app).{0,20}certificate",
                                         r"certificate.{0,20}(expir|renew)"]),
    ("Risky Sign-in / User at Risk",    [r"risky.{0,20}sign", r"user.{0,10}at.{0,10}risk",
                                         r"identity\s+protection"]),

    # Office365 alerts
    ("DLP Policy Match",               [r"dlp\s+polic", r"matches\s+detected.{0,20}dlp"]),
    ("Malicious URL Click",            [r"malicious.{0,20}url.{0,20}click",
                                         r"url.{0,20}click.{0,20}detected"]),
    ("Admin Submission Result",         [r"admin\s+submission"]),
    ("Phishing / Spam Alert",          [r"\bphish", r"\bspam\b", r"zap.{0,10}phish"]),
    ("Email Forwarding Rule",          [r"forward.{0,20}(rule|creat)", r"inbox.{0,20}rule"]),

    # Severity-based catch-alls
    ("High Severity Alert",            [r"high.?severity\s+alert"]),
    ("Medium Severity Alert",          [r"medium.?severity\s+alert"]),
    ("Low Severity Alert",             [r"low.?severity\s+alert"]),
    ("Informational Alert",            [r"informational.?severity\s+alert"]),
]

MS_CATEGORY_UNCATEGORIZED = "Uncategorized MS Alert"


def categorize_ms_subject(subject: str) -> str:
    s = (subject or "").lower()
    for category, patterns in MS_CATEGORY_RULES:
        for p in patterns:
            if re.search(p, s, re.IGNORECASE):
                return category
    return MS_CATEGORY_UNCATEGORIZED


def extract_severity_from_subject(subject: str) -> str:
    m = re.search(r"\b(high|medium|low|informational|critical)\b[\s\-]*severity", subject or "", re.I)
    if m:
        return m.group(1).capitalize()
    m2 = re.search(r"\[(High|Medium|Low|Critical|Info)\]", subject or "", re.I)
    if m2:
        return m2.group(1).capitalize()
    return ""


def extract_ms_incident_id(subject: str) -> str:
    """Try to extract Microsoft incident/alert IDs from subject."""
    patterns = [
        r"(?:incident|alert)\s*(?:id)?[\s:#-]*(\d{5,15})",
        r"INC[\s-]*(\d{5,})",
    ]
    for p in patterns:
        m = re.search(p, subject or "", re.I)
        if m:
            return m.group(1)
    return ""


# ---------------------------------------------------------------------------
# Graph API helpers
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


def graph_get(token: str, url: str, params: dict = None) -> dict:
    headers = {"Authorization": f"Bearer {token}"}
    resp = requests.get(url, headers=headers, params=params, timeout=60)
    if resp.status_code == 429:
        wait = int(resp.headers.get("Retry-After", "15"))
        log.warning("Rate limited. Waiting %ds...", wait)
        time.sleep(wait)
        return graph_get(token, url, params)
    resp.raise_for_status()
    return resp.json()


def get_folder_id(token: str, label: str, location: str, folder_name: str) -> str:
    """Resolve a folder display name to its Graph ID."""
    if location == "toplevel":
        data = graph_get(token, f"{GRAPH_BASE}/users/{MAILBOX_UPN}/mailFolders",
                         {"$top": 50, "$select": "id,displayName"})
    else:
        inbox_data = graph_get(token, f"{GRAPH_BASE}/users/{MAILBOX_UPN}/mailFolders/Inbox",
                               {"$select": "id"})
        inbox_id = inbox_data["id"]
        data = graph_get(token, f"{GRAPH_BASE}/users/{MAILBOX_UPN}/mailFolders/{inbox_id}/childFolders",
                         {"$top": 70, "$select": "id,displayName"})

    for f in data.get("value", []):
        if f["displayName"] == folder_name:
            return f["id"]
    return ""


def fetch_folder_month(token: str, folder_id: str, year: int, month: int) -> list[dict]:
    """Fetch all messages in a folder for a given month using $filter + pagination."""
    last_day = calendar.monthrange(year, month)[1]
    start = f"{year}-{month:02d}-01T00:00:00Z"
    end   = f"{year}-{month:02d}-{last_day}T23:59:59Z"

    url = f"{GRAPH_BASE}/users/{MAILBOX_UPN}/mailFolders/{folder_id}/messages"
    params = {
        "$filter": f"receivedDateTime ge {start} and receivedDateTime le {end}",
        "$select": "id,subject,receivedDateTime,from,importance,isRead,hasAttachments,bodyPreview",
        "$top": PAGE_SIZE,
        "$orderby": "receivedDateTime asc",
    }

    results = []
    page = 1
    current_url = url
    current_params = params

    while current_url:
        data = graph_get(token, current_url, current_params if page == 1 else None)
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
        log.info("Refreshing token...")
        token = get_access_token()
        acquired_at = datetime.now()
    return token, acquired_at


# ---------------------------------------------------------------------------
# Processing
# ---------------------------------------------------------------------------

def process_ms_email(raw: dict, source_folder: str) -> dict:
    subject  = raw.get("subject", "") or ""
    received = raw.get("receivedDateTime", "") or ""
    sender   = (raw.get("from", {}).get("emailAddress", {}).get("address", "") or "").lower()

    received_dt = None
    try:
        received_dt = datetime.fromisoformat(received.replace("Z", "+00:00"))
    except Exception:
        pass

    return {
        "id":              raw.get("id", ""),
        "subject":         subject,
        "received":        received,
        "received_date":   received_dt.strftime("%Y-%m-%d") if received_dt else "",
        "received_month":  received_dt.strftime("%Y-%m") if received_dt else "",
        "sender":          sender,
        "source_folder":   source_folder,
        "ms_category":     categorize_ms_subject(subject),
        "severity":        extract_severity_from_subject(subject),
        "ms_incident_id":  extract_ms_incident_id(subject),
        "importance":      raw.get("importance", ""),
        "is_read":         raw.get("isRead", False),
        "has_attachments": raw.get("hasAttachments", False),
        "body_preview":    (raw.get("bodyPreview", "") or "")[:200],
    }


# ---------------------------------------------------------------------------
# Correlation with Phase 1
# ---------------------------------------------------------------------------

def load_phase1_data(csv_path: str) -> list[dict]:
    if not csv_path or not os.path.exists(csv_path):
        return []
    with open(csv_path, encoding="utf-8") as f:
        return list(csv.DictReader(f))


def find_phase1_csv() -> str:
    """Auto-detect the latest Phase 1 CSV in OUTPUT_DIR."""
    pattern = os.path.join(OUTPUT_DIR, "phase1_soc_emails_*.csv")
    files = sorted(globmod.glob(pattern))
    return files[-1] if files else ""


def correlate_soc_and_ms(soc_records: list[dict], ms_records: list[dict]) -> dict:
    """
    Correlate SOC tickets with Microsoft alerts by date proximity.
    Returns summary of correlated vs uncorrelated counts.
    """
    # Build a date-indexed lookup for MS alerts
    ms_by_date = defaultdict(list)
    for r in ms_records:
        d = r.get("received_date", "")
        if d:
            ms_by_date[d].append(r)

    # For each SOC ticket, check if there's a MS alert within +/- 1 day
    correlated_soc = 0
    uncorrelated_soc = 0
    for soc in soc_records:
        soc_date = soc.get("received_date", "")
        if not soc_date:
            uncorrelated_soc += 1
            continue
        try:
            d = date.fromisoformat(soc_date)
        except Exception:
            uncorrelated_soc += 1
            continue

        found = False
        for offset in range(0, 3):  # same day, +1, +2
            check = (d + timedelta(days=offset)).isoformat()
            check_before = (d - timedelta(days=offset)).isoformat()
            if ms_by_date.get(check) or ms_by_date.get(check_before):
                found = True
                break
        if found:
            correlated_soc += 1
        else:
            uncorrelated_soc += 1

    return {
        "total_soc_emails": len(soc_records),
        "soc_with_ms_alert_nearby": correlated_soc,
        "soc_without_ms_alert": uncorrelated_soc,
        "correlation_rate": f"{correlated_soc / len(soc_records) * 100:.1f}%" if soc_records else "N/A",
    }


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

def write_csv(records: list[dict], filepath: str) -> None:
    if not records:
        return
    os.makedirs(os.path.dirname(os.path.abspath(filepath)), exist_ok=True)
    with open(filepath, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(records[0].keys()))
        writer.writeheader()
        writer.writerows(records)
    log.info("CSV: %s (%d rows)", filepath, len(records))


def write_json(data: dict, filepath: str) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(filepath)), exist_ok=True)
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, default=str)
    log.info("JSON: %s", filepath)


def print_summary(records: list[dict], by_folder: dict, by_category: dict,
                  by_sender: dict, correlation: dict) -> None:
    print("\n" + "=" * 72)
    print("  MICROSOFT SECURITY EMAILS  -  Phase 2 Summary")
    print(f"  Mailbox:  {MAILBOX_UPN}")
    print(f"  Period:   {SEARCH_START_DATE}  to  {SEARCH_END_DATE}")
    print("=" * 72)
    print(f"\n  TOTAL MS SECURITY EMAILS:  {len(records):,}")

    print("\n  BY SOURCE FOLDER:")
    print("  " + "-" * 55)
    for folder, count in sorted(by_folder.items(), key=lambda x: -x[1]):
        print(f"  {folder:<45} {count:>5}")

    print("\n  BY SENDER:")
    print("  " + "-" * 55)
    for sender, count in sorted(by_sender.items(), key=lambda x: -x[1]):
        print(f"  {sender:<45} {count:>5}")

    print("\n  BY ALERT CATEGORY (top 20):")
    print("  " + "-" * 55)
    for cat, count in sorted(by_category.items(), key=lambda x: -x[1])[:20]:
        pct = count / len(records) * 100 if records else 0
        print(f"  {cat:<45} {count:>5}  ({pct:4.1f}%)")

    if correlation:
        print("\n  CORRELATION WITH SOC (Phase 1):")
        print("  " + "-" * 55)
        for k, v in correlation.items():
            print(f"  {k:<45} {v}")

    print("\n" + "=" * 72 + "\n")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    if not all([TENANT_ID, CLIENT_ID, CLIENT_SECRET]):
        sys.exit("ERROR: Missing TENANT_ID, CLIENT_ID, or CLIENT_SECRET")

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    log.info("Phase 2: Microsoft Security email search")
    log.info("Mailbox: %s  |  Range: %s to %s", MAILBOX_UPN, SEARCH_START_DATE, SEARCH_END_DATE)

    token = get_access_token()
    token_at = datetime.now()

    # Resolve folder IDs (cached for reuse)
    folder_ids = {}
    for label, location, fname in FOLDER_TARGETS:
        fid = get_folder_id(token, label, location, fname)
        if fid:
            folder_ids[label] = fid
            log.info("Resolved: %s -> %s...", label, fid[:20])
        else:
            log.warning("Could not find folder: %s", label)

    # Build month list
    start_d = date.fromisoformat(SEARCH_START_DATE)
    end_d   = date.fromisoformat(SEARCH_END_DATE)
    months = []
    cur = date(start_d.year, start_d.month, 1)
    while cur <= end_d:
        months.append((cur.year, cur.month))
        if cur.month == 12:
            cur = date(cur.year + 1, 1, 1)
        else:
            cur = date(cur.year, cur.month + 1, 1)

    all_records: list[dict] = []
    seen_ids: set[str] = set()
    by_folder:   dict = defaultdict(int)
    by_category: dict = defaultdict(int)
    by_sender:   dict = defaultdict(int)
    by_month:    dict = defaultdict(int)

    # Process each folder, each month
    for label, fid in folder_ids.items():
        log.info("--- Processing folder: %s ---", label)
        folder_total = 0

        for year, month in months:
            token, token_at = refresh_token_if_stale(token, token_at)

            log.info("  [%s] %d-%02d ...", label[:25], year, month)
            try:
                raw = fetch_folder_month(token, fid, year, month)
            except Exception as exc:
                log.error("    Error: %s", exc)
                continue

            new_count = 0
            for r in raw:
                msg_id = r.get("id", "")
                if msg_id in seen_ids:
                    continue
                seen_ids.add(msg_id)
                rec = process_ms_email(r, label)
                all_records.append(rec)
                by_folder[label] += 1
                by_category[rec["ms_category"]] += 1
                by_sender[rec["sender"]] += 1
                by_month[rec["received_month"]] += 1
                new_count += 1

            if new_count > 0:
                log.info("    -> %d new emails", new_count)
                folder_total += new_count

            time.sleep(RATE_DELAY)

        log.info("  Folder total: %d", folder_total)

    log.info("All folders done. Total unique MS security emails: %d", len(all_records))

    # Correlation with Phase 1
    p1_csv = PHASE1_CSV or find_phase1_csv()
    correlation = {}
    if p1_csv:
        log.info("Loading Phase 1 data from %s", p1_csv)
        soc_data = load_phase1_data(p1_csv)
        if soc_data:
            correlation = correlate_soc_and_ms(soc_data, all_records)
            log.info("Correlation: %s", correlation)
    else:
        log.info("No Phase 1 CSV found - skipping correlation.")

    # Write outputs
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    csv_path = os.path.join(OUTPUT_DIR, f"phase2_ms_security_{ts}.csv")
    jsn_path = os.path.join(OUTPUT_DIR, f"phase2_ms_summary_{ts}.json")

    write_csv(all_records, csv_path)

    summary = {
        "run_timestamp":   ts,
        "mailbox":         MAILBOX_UPN,
        "search_start":    SEARCH_START_DATE,
        "search_end":      SEARCH_END_DATE,
        "total_ms_emails": len(all_records),
        "by_folder":       dict(by_folder),
        "by_sender":       dict(by_sender),
        "by_category":     dict(sorted(by_category.items(), key=lambda x: -x[1])),
        "by_month":        dict(sorted(by_month.items())),
        "correlation":     correlation,
        "output_csv":      csv_path,
    }
    write_json(summary, jsn_path)

    print_summary(all_records, by_folder, by_category, by_sender, correlation)
    print(f"  Output files:")
    print(f"    CSV:  {csv_path}")
    print(f"    JSON: {jsn_path}\n")


if __name__ == "__main__":
    main()
