#!/usr/bin/env python3
"""
Phase 4: Export Microsoft Security Incidents via Graph API
Barry University - Cybersecurity Incident Dashboard

Queries https://graph.microsoft.com/v1.0/security/incidents with $expand=alerts
to pull full incident details. Correlates with Phase 1 SOC tickets by date and
alert title similarity.

Requires SecurityIncident.Read.All application permission.

Required environment variables:
  TENANT_ID, CLIENT_ID, CLIENT_SECRET

Optional:
  INCIDENT_START_DATE  - Filter from this date (default: 2024-04-01)
  INCIDENT_END_DATE    - Filter to this date   (default: today)
  PHASE1_CSV           - Path to Phase 1 combined CSV (auto-detect if not set)
  PHASE3_CSV           - Path to Phase 3 Baldwin CSV  (auto-detect if not set)
  OUTPUT_DIR           - Output directory (default: ./output)
"""

import os
import sys
import json
import csv
import re
import time
import logging
import glob as globmod
from datetime import datetime, timedelta, timezone
from collections import defaultdict, Counter

import msal
import requests

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

TENANT_ID     = os.environ.get("TENANT_ID", "")
CLIENT_ID     = os.environ.get("CLIENT_ID", "")
CLIENT_SECRET = os.environ.get("CLIENT_SECRET", "")

INCIDENT_START = os.environ.get("INCIDENT_START_DATE", "2024-04-01")
INCIDENT_END   = os.environ.get("INCIDENT_END_DATE",
                                datetime.now(timezone.utc).strftime("%Y-%m-%d"))
OUTPUT_DIR = os.environ.get("OUTPUT_DIR", "./output")
PHASE1_CSV = os.environ.get("PHASE1_CSV", "")
PHASE3_CSV = os.environ.get("PHASE3_CSV", "")

GRAPH_BASE = "https://graph.microsoft.com/v1.0"
PAGE_SIZE  = 50       # incidents per page (with alerts expanded, keep moderate)
RATE_DELAY = 0.35     # seconds between paginated requests

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
# Auth
# ---------------------------------------------------------------------------

def get_access_token():
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
# Graph helpers
# ---------------------------------------------------------------------------

def graph_get(token, url, params=None, retries=3):
    """GET with retry on 429/5xx."""
    for attempt in range(retries):
        r = requests.get(
            url,
            headers={"Authorization": f"Bearer {token}"},
            params=params,
            timeout=60,
        )
        if r.status_code == 200:
            return r.json()
        if r.status_code == 429:
            wait = int(r.headers.get("Retry-After", 10))
            log.warning("  429 throttled, waiting %ds...", wait)
            time.sleep(wait)
            continue
        if r.status_code >= 500:
            log.warning("  %d server error, retry %d/%d", r.status_code, attempt + 1, retries)
            time.sleep(2 ** attempt)
            continue
        # Non-retryable error
        log.error("  HTTP %d: %s", r.status_code, r.text[:300])
        return None
    log.error("  Exhausted retries for %s", url[:120])
    return None


def fetch_incidents_page(token, filter_str, skip=0):
    """Fetch one page of incidents with alerts expanded using $skip pagination."""
    params = {
        "$top": PAGE_SIZE,
        "$skip": skip,
        "$expand": "alerts",
        "$orderby": "createdDateTime desc",
    }
    if filter_str:
        params["$filter"] = filter_str

    url = f"{GRAPH_BASE}/security/incidents"
    return graph_get(token, url, params=params)


# ---------------------------------------------------------------------------
# Evidence extraction helpers
# ---------------------------------------------------------------------------

def extract_users_from_evidence(evidence_list):
    """Pull unique user accounts from alert evidence."""
    users = set()
    if not evidence_list:
        return users
    for ev in evidence_list:
        etype = ev.get("@odata.type", "")
        if "userEvidence" in etype:
            acct = ev.get("userAccount", {})
            name = acct.get("accountName", "")
            domain = acct.get("domainName", "")
            if name:
                users.add(f"{name}@{domain}" if domain else name)
        elif "mailboxEvidence" in etype:
            upn = ev.get("userAccount", {}).get("accountName", "")
            if upn:
                users.add(upn)
    return users


def extract_devices_from_evidence(evidence_list):
    """Pull unique device names from alert evidence."""
    devices = set()
    if not evidence_list:
        return devices
    for ev in evidence_list:
        etype = ev.get("@odata.type", "")
        if "deviceEvidence" in etype:
            name = ev.get("deviceDnsName", "") or ev.get("azureAdDeviceId", "")
            if name:
                devices.add(name)
    return devices


def extract_ips_from_evidence(evidence_list):
    """Pull unique IP addresses from alert evidence."""
    ips = set()
    if not evidence_list:
        return ips
    for ev in evidence_list:
        etype = ev.get("@odata.type", "")
        if "ipEvidence" in etype:
            addr = ev.get("ipAddress", "")
            if addr:
                ips.add(addr)
    return ips


# ---------------------------------------------------------------------------
# Load Phase 1 & Phase 3 data for correlation
# ---------------------------------------------------------------------------

def find_latest_csv(pattern):
    matches = sorted(globmod.glob(os.path.join(OUTPUT_DIR, pattern)))
    return matches[-1] if matches else None


def load_phase1_data():
    """Load Phase 1 SOC tickets for correlation."""
    path = PHASE1_CSV or find_latest_csv("phase1_combined_soc_emails_*.csv")
    if not path or not os.path.exists(path):
        log.warning("Phase 1 CSV not found - correlation will be skipped")
        return {}
    log.info("Loading Phase 1 data from %s", path)
    tickets = {}  # ticket_number -> {category, received, subject}
    with open(path, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            tn = row.get("ticket_number", "").strip()
            if tn:
                if tn not in tickets:
                    tickets[tn] = {
                        "category": row.get("category", ""),
                        "received": row.get("received", ""),
                        "subject": row.get("subject", ""),
                    }
    log.info("  Loaded %d unique SOC tickets", len(tickets))
    return tickets


def load_phase3_data():
    """Load Phase 3 Baldwin triage data for enrichment."""
    path = PHASE3_CSV or find_latest_csv("phase3_baldwin_responses_*.csv")
    if not path or not os.path.exists(path):
        log.warning("Phase 3 CSV not found - triage enrichment will be skipped")
        return {}
    log.info("Loading Phase 3 data from %s", path)
    triage = {}  # ticket_number -> {triage_action, response_hours}
    with open(path, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            tn = row.get("ticket_number", "").strip()
            if tn and tn not in triage:
                triage[tn] = {
                    "triage_action": row.get("triage_action", ""),
                    "response_hours": row.get("response_hours", ""),
                }
    log.info("  Loaded %d unique triage records", len(triage))
    return triage


# ---------------------------------------------------------------------------
# Incident categorization (map incident displayName to dashboard category)
# ---------------------------------------------------------------------------

INCIDENT_CATEGORY_RULES = [
    # Identity & Sign-in
    ("Anomalous Token",               [r"anomalous\s*token"]),
    ("Unfamiliar Sign-in Properties", [r"unfamiliar\s*sign.?in"]),
    ("Unusual Sign-in Location",      [r"atypical\s*travel", r"impossible\s*travel",
                                       r"unusual.{0,20}sign.?in",
                                       r"anomalous\s+sign.?in\s+location"]),
    ("Sign-in from Anonymous IP",     [r"anonymous\s*ip\s*address"]),
    ("Sign-in from Malicious IP",     [r"malicious\s*ip\s*address"]),
    ("Sign-in Disabled Accounts",     [r"sign.?ins?\s+(from|to)\s+.*disabled\s+account"]),
    ("Password Spray Attack",         [r"password\s*spray", r"brute.?force"]),
    ("Suspicious Sign-in",            [r"sign.?in.{0,20}(suspicious|risk|anomal)"]),

    # Email threats
    ("User Email Report",             [r"email\s+reported\s+by\s+user\s+as\s+(not\s+)?junk"]),
    ("Malicious URL in Email",        [r"malicious\s+url.{0,20}(removed|detected|click)",
                                       r"potentially\s+malicious\s+url\s+click"]),
    ("Malicious File in Email",       [r"malicious\s+file.{0,20}(removed|detected)"]),
    ("Email Campaign Removed",        [r"email\s*messages.{0,20}(removed|campaign)",
                                       r"campaign\s*removed"]),
    ("Phishing",                      [r"phish", r"credential.{0,20}harvest"]),
    ("BEC / Financial Fraud",         [r"\bbec\b", r"business\s*email\s*compromise",
                                       r"financial\s*fraud"]),

    # Data protection
    ("Data Loss Prevention",          [r"\bdlp\b", r"data\s*loss", r"protection\s*policy",
                                       r"sensitive\s+information",
                                       r"purview\s+irm"]),
    ("AI Policy Violation",           [r"unethical\s+behavior\s+in\s+ai",
                                       r"unethical\s+behavior\s+in\s+copilot",
                                       r"cc_dspm\s+for\s+ai", r"cc_ai\s+hub"]),

    # Mail rules
    ("Suspicious Inbox Rule",         [r"inbox\s*(forwarding|rule)", r"suspicious.*forwarding",
                                       r"forwarding\s+created",
                                       r"mail\s+forwarding\s+alert"]),

    # Incidents
    ("Multi-stage Incident",          [r"multi.?stage"]),
    ("Initial Access",                [r"initial\s+access\s+incident"]),
    ("Compromised Account",           [r"compromis"]),

    # Admin / manual actions
    ("Admin Action",                  [r"admin.{0,20}(action|triggered|submitted)",
                                       r"manual\s+investigation\s+of\s+email"]),

    # Endpoint threats
    ("Malware",                       [r"malware", r"ransomware", r"trojan",
                                       r"process\s+(was\s+)?injected.{0,20}malicious"]),
    ("Exploitation",                  [r"exploit.{0,20}(vuln|manage.?engine|cve)"]),
    ("Suspicious Network Activity",   [r"suspicious\s+connection\s+blocked",
                                       r"network\s+protection",
                                       r"suspicious\s+ldap"]),
    ("Unauthorized Access",           [r"unauthorized\s+access"]),

    # Advanced threats
    ("Evasion / Tampering",           [r"evasion", r"tamper"]),
    ("Exfiltration",                  [r"exfiltrat"]),
    ("Privilege Escalation",          [r"privilege\s*escalat", r"elevation"]),
    ("Lateral Movement",              [r"lateral\s*movement"]),
    ("Reconnaissance",                [r"reconnaiss", r"enumerat", r"\bsearches\b"]),
]

INCIDENT_UNCATEGORIZED = "Other Incident"


def categorize_incident(display_name):
    text = (display_name or "").lower()
    for label, patterns in INCIDENT_CATEGORY_RULES:
        for p in patterns:
            if re.search(p, text, re.IGNORECASE):
                return label
    return INCIDENT_UNCATEGORIZED


# ---------------------------------------------------------------------------
# SOC ticket correlation by date + category keyword overlap
# ---------------------------------------------------------------------------

def correlate_with_soc(incident, soc_tickets):
    """Try to find matching SOC tickets for an incident by date proximity
    and keyword overlap in subject/displayName."""
    if not soc_tickets:
        return []

    inc_created = incident.get("createdDateTime", "")
    if not inc_created:
        return []

    try:
        inc_dt = datetime.fromisoformat(inc_created.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return []

    inc_name = (incident.get("displayName", "") or "").lower()
    inc_words = set(re.findall(r"[a-z]{3,}", inc_name))

    matches = []
    for tn, info in soc_tickets.items():
        soc_received = info.get("received", "")
        if not soc_received:
            continue
        try:
            soc_dt = datetime.fromisoformat(soc_received.replace("Z", "+00:00"))
        except (ValueError, TypeError):
            continue

        # Within 3-day window
        delta = abs((inc_dt - soc_dt).total_seconds()) / 3600.0
        if delta > 72:
            continue

        # Check keyword overlap between incident name and SOC subject
        soc_subject = (info.get("subject", "") or "").lower()
        soc_words = set(re.findall(r"[a-z]{3,}", soc_subject))
        overlap = inc_words & soc_words
        # Require at least 2 meaningful keyword matches
        noise = {"barry", "university", "security", "alert", "service", "ticket", "oculusit", "soc", "the", "and"}
        meaningful = overlap - noise
        if len(meaningful) >= 2 or delta <= 2:  # very close in time = likely match
            matches.append({
                "ticket_number": tn,
                "soc_category": info.get("category", ""),
                "time_delta_hours": round(delta, 1),
                "keyword_overlap": sorted(meaningful) if meaningful else [],
            })

    # Sort by time proximity
    matches.sort(key=lambda m: m["time_delta_hours"])
    return matches[:5]  # cap at 5 best matches


# ---------------------------------------------------------------------------
# Process a raw incident into a flat record
# ---------------------------------------------------------------------------

def process_incident(raw, soc_tickets, triage_data):
    alerts = raw.get("alerts", [])

    # Aggregate evidence across all alerts
    all_users = set()
    all_devices = set()
    all_ips = set()
    all_mitre = set()
    alert_titles = []
    alert_categories = []
    service_sources = set()

    for alert in alerts:
        alert_titles.append(alert.get("title", ""))
        cat = alert.get("category", "")
        if cat:
            alert_categories.append(cat)
        src = alert.get("serviceSource", "")
        if src:
            service_sources.add(src)
        for t in (alert.get("mitreTechniques", []) or []):
            all_mitre.add(t)
        all_users |= extract_users_from_evidence(alert.get("evidence", []))
        all_devices |= extract_devices_from_evidence(alert.get("evidence", []))
        all_ips |= extract_ips_from_evidence(alert.get("evidence", []))

    # Correlate with SOC tickets
    soc_matches = correlate_with_soc(raw, soc_tickets)
    matched_tickets = [m["ticket_number"] for m in soc_matches]

    # Enrich with Baldwin triage
    triage_actions = []
    for tn in matched_tickets:
        if tn in triage_data:
            triage_actions.append(triage_data[tn]["triage_action"])

    record = {
        "incident_id": raw.get("id", ""),
        "display_name": raw.get("displayName", ""),
        "severity": raw.get("severity", ""),
        "status": raw.get("status", ""),
        "classification": raw.get("classification", ""),
        "determination": raw.get("determination", ""),
        "created": raw.get("createdDateTime", ""),
        "created_date": (raw.get("createdDateTime", "") or "")[:10],
        "last_updated": raw.get("lastUpdateDateTime", ""),
        "assigned_to": raw.get("assignedTo", "") or "",
        "incident_url": raw.get("incidentWebUrl", ""),
        "redirect_id": raw.get("redirectIncidentId", "") or "",
        "dashboard_category": categorize_incident(raw.get("displayName", "")),
        "alert_count": len(alerts),
        "alert_titles": " | ".join(alert_titles),
        "alert_categories": " | ".join(sorted(set(alert_categories))),
        "service_sources": " | ".join(sorted(service_sources)),
        "mitre_techniques": " | ".join(sorted(all_mitre)),
        "affected_users": " | ".join(sorted(all_users)),
        "affected_devices": " | ".join(sorted(all_devices)),
        "source_ips": " | ".join(sorted(all_ips)),
        "soc_ticket_matches": " | ".join(matched_tickets),
        "soc_match_count": len(soc_matches),
        "triage_actions": " | ".join(triage_actions) if triage_actions else "",
    }
    return record


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    log.info("=" * 60)
    log.info("Phase 4: Microsoft Security Incidents Export")
    log.info("=" * 60)

    if not all([TENANT_ID, CLIENT_ID, CLIENT_SECRET]):
        log.error("Set TENANT_ID, CLIENT_ID, CLIENT_SECRET env vars.")
        sys.exit(1)

    os.makedirs(OUTPUT_DIR, exist_ok=True)

    # Authenticate
    log.info("Acquiring access token...")
    token = get_access_token()
    log.info("  Token acquired.")

    # Load correlation data
    soc_tickets = load_phase1_data()
    triage_data = load_phase3_data()

    # Build date filter
    filter_str = (
        f"createdDateTime ge {INCIDENT_START}T00:00:00Z"
        f" and createdDateTime le {INCIDENT_END}T23:59:59Z"
    )
    log.info("Filter: %s", filter_str)

    # Fetch all incidents with $skip pagination (API max $top=50, no nextLink)
    log.info("Fetching incidents (page size %d, $skip pagination)...", PAGE_SIZE)
    all_records = []
    skip = 0
    page = 0

    while True:
        page += 1
        data = fetch_incidents_page(token, filter_str, skip=skip)
        if data is None:
            log.error("Failed to fetch page %d (skip=%d), stopping.", page, skip)
            break

        incidents = data.get("value", [])
        if not incidents:
            log.info("  Page %d: 0 incidents (done)", page)
            break

        for raw in incidents:
            record = process_incident(raw, soc_tickets, triage_data)
            all_records.append(record)

        log.info("  Page %d: %d incidents, skip=%d (total so far: %d)",
                 page, len(incidents), skip, len(all_records))

        if len(incidents) < PAGE_SIZE:
            break  # last page

        skip += PAGE_SIZE
        time.sleep(RATE_DELAY)

    log.info("Fetched %d total incidents.", len(all_records))

    if not all_records:
        log.warning("No incidents found. Check date range and permissions.")
        return

    # Write incidents CSV
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    csv_path = os.path.join(OUTPUT_DIR, f"phase4_security_incidents_{ts}.csv")
    fieldnames = list(all_records[0].keys())
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(all_records)
    log.info("Wrote %d incidents to %s", len(all_records), csv_path)

    # Build summary
    severity_counts = Counter(r["severity"] for r in all_records)
    status_counts = Counter(r["status"] for r in all_records)
    classification_counts = Counter(r["classification"] for r in all_records)
    determination_counts = Counter(r["determination"] for r in all_records)
    category_counts = Counter(r["dashboard_category"] for r in all_records)
    source_counts = Counter()
    mitre_counts = Counter()
    for r in all_records:
        for src in r["service_sources"].split(" | "):
            if src:
                source_counts[src] += 1
        for t in r["mitre_techniques"].split(" | "):
            if t:
                mitre_counts[t] += 1

    # Monthly trend
    monthly = Counter(r["created_date"][:7] for r in all_records if r["created_date"])

    # Correlation stats
    matched = [r for r in all_records if r["soc_match_count"] > 0]
    total_unique_soc_matched = set()
    for r in all_records:
        for tn in r["soc_ticket_matches"].split(" | "):
            if tn.strip():
                total_unique_soc_matched.add(tn.strip())

    # Affected users
    user_counts = Counter()
    for r in all_records:
        for u in r["affected_users"].split(" | "):
            if u.strip():
                user_counts[u.strip()] += 1

    summary = {
        "phase": "Phase 4 - Security Incidents",
        "run_timestamp": ts,
        "date_range": f"{INCIDENT_START} to {INCIDENT_END}",
        "total_incidents": len(all_records),
        "severity_breakdown": dict(severity_counts.most_common()),
        "status_breakdown": dict(status_counts.most_common()),
        "classification_breakdown": dict(classification_counts.most_common()),
        "determination_breakdown": dict(determination_counts.most_common()),
        "dashboard_category_breakdown": dict(category_counts.most_common()),
        "service_source_breakdown": dict(source_counts.most_common(20)),
        "top_mitre_techniques": dict(mitre_counts.most_common(20)),
        "monthly_trend": dict(sorted(monthly.items())),
        "correlation": {
            "incidents_with_soc_match": len(matched),
            "incidents_without_soc_match": len(all_records) - len(matched),
            "unique_soc_tickets_matched": len(total_unique_soc_matched),
            "total_soc_tickets_available": len(soc_tickets),
        },
        "top_affected_users": dict(user_counts.most_common(25)),
        "output_files": {
            "incidents_csv": csv_path,
        },
    }

    json_path = os.path.join(OUTPUT_DIR, f"phase4_incidents_summary_{ts}.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, default=str)
    log.info("Wrote summary to %s", json_path)

    # Print summary to console
    log.info("")
    log.info("=" * 60)
    log.info("PHASE 4 SUMMARY")
    log.info("=" * 60)
    log.info("Total incidents:  %d", len(all_records))
    log.info("")
    log.info("Severity:")
    for sev, cnt in severity_counts.most_common():
        log.info("  %-20s %d", sev, cnt)
    log.info("")
    log.info("Status:")
    for st, cnt in status_counts.most_common():
        log.info("  %-20s %d", st, cnt)
    log.info("")
    log.info("Top Dashboard Categories:")
    for cat, cnt in category_counts.most_common(15):
        log.info("  %-35s %d", cat, cnt)
    log.info("")
    log.info("Top MITRE Techniques:")
    for t, cnt in mitre_counts.most_common(10):
        log.info("  %-15s %d", t, cnt)
    log.info("")
    log.info("SOC Correlation: %d incidents matched to %d unique SOC tickets",
             len(matched), len(total_unique_soc_matched))
    log.info("")
    log.info("Top Affected Users:")
    for u, cnt in user_counts.most_common(10):
        log.info("  %-40s %d", u, cnt)
    log.info("")
    log.info("Output: %s", csv_path)
    log.info("Summary: %s", json_path)


if __name__ == "__main__":
    main()
