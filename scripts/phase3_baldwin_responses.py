#!/usr/bin/env python3
"""
Phase 3: Analyze John Baldwin's response patterns to SOC emails
Barry University - Cybersecurity Incident Dashboard

Searches jbaldwin@barry.edu Sent Items for all replies to soc@oculusit.com,
classifies triage actions from body previews, correlates with Phase 1 SOC
tickets, and calculates response times.

Required environment variables:
  TENANT_ID, CLIENT_ID, CLIENT_SECRET

Optional:
  SEARCH_START_DATE  (default: 2024-04-01)
  SEARCH_END_DATE    (default: today)
  OUTPUT_DIR         (default: ./output)
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
JB_MAILBOX    = "jbaldwin@barry.edu"
SOC_SENDER    = "soc@oculusit.com"

SEARCH_START_DATE = os.environ.get("SEARCH_START_DATE", "2024-04-01")
SEARCH_END_DATE   = os.environ.get("SEARCH_END_DATE",
                                   datetime.now(timezone.utc).strftime("%Y-%m-%d"))
OUTPUT_DIR = os.environ.get("OUTPUT_DIR", "./output")

GRAPH_BASE = "https://graph.microsoft.com/v1.0"
RATE_DELAY = 0.3

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s",
                    datefmt="%Y-%m-%d %H:%M:%S")
log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Triage Action Classification
#
# Matched against bodyPreview (first ~200 chars of the response).
# Order matters: first match wins.
# ---------------------------------------------------------------------------

TRIAGE_RULES = [
    # -----------------------------------------------------------------------
    # Clearly dismissed / no action needed
    # -----------------------------------------------------------------------
    ("False Positive",       [r"false\s+positive", r"fp\b", r"not\s+a\s+threat",
                              r"matches\s+previous\s+user\s+activity",
                              r"no\s+concern", r"nothing\s+to\s+worry",
                              r"can\s+close\s+this", r"please\s+close",
                              r"no\s+action\s+(needed|required)",
                              r"no\s+detection", r"no\s+malicious",
                              r"full\s+scan.{0,30}no\s+detect",
                              r"scan.{0,20}completed.{0,20}no\s+detect",
                              r"scan.{0,20}clean"]),

    ("Auto-Remediated",      [r"auto[\s\-]?(mitigat|remediat|resolv|block)",
                              r"already\s+(mitigat|remediat|resolv|block)",
                              r"self[\s\-]?heal",
                              r"automatically\s+(block|mitigat|resolv)",
                              r"blocked\s+by\s+defender",
                              r"defender.{0,20}block",
                              r"mfa.{0,20}not\s+completed",
                              r"mfa.{0,20}block",
                              r"sign.?in.{0,20}(failed|block)",
                              r"no\s+indication\s+of\s+compromise"]),

    # -----------------------------------------------------------------------
    # Investigated - benign finding (Baldwin's most common pattern)
    # "Good morning Oculus team. I investigated this..."
    # -----------------------------------------------------------------------
    ("Investigated - Benign", [
        # IP investigation patterns
        r"ip.{0,30}(registered\s+to|belongs?\s+to|associated\s+with)",
        r"ip.{0,30}(isp|carrier|provider|tele)",
        r"login.{0,30}(successful|looks?\s+legit|appears?\s+normal)",
        r"logins?\s+(were|was|are)\s+(successful|coming\s+from)",
        # User behavior patterns
        r"private\s+vpn",
        r"using\s+(a\s+)?(vpn|proxy|tor)",
        r"(student|user|person).{0,30}(travel|abroad|overseas|vacation|jamaica|costa|colom)",
        r"(esport|gaming|game|medal\s+app|screen\s+capture)",
        r"appears?\s+to\s+be\s+(a\s+)?(shared|legit|normal|benign|safe)",
        r"intra.?org",
        # Investigation conclusion patterns
        r"(just\s+)?finished\s+investigat",
        r"investigated\s+this\s+(this\s+)?(morning|afternoon|evening|yesterday|today|incident)",
        r"evidence\s+suggests",
        r"checked\s+sign.?in\s+logs",
        r"checked\s+the\s+incident",
        r"(spoke|chatted)\s+with\s+the\s+(person|user|student|employee)",
        r"(remoted|connected)\s+to\s+the\s+(computer|machine|device)",
        r"(she|he|they|user)\s+(got|received|opened|clicked|downloaded)\s+(an?\s+)?email",
    ]),

    # -----------------------------------------------------------------------
    # Known / expected activity
    # -----------------------------------------------------------------------
    ("Known / Expected",     [r"not\s+much\s+we\s+can\s+do",
                              r"looks?\s+(like\s+)?activity\s+from",
                              r"looks?\s+(like\s+)?(a\s+)?legit",
                              r"consumer\s+isp",
                              r"this\s+is\s+(just|normal|expected)",
                              r"(he|she|they|user)\s+(is|was|were)\s+travel",
                              r"same\s+(student|user|person)\s+(as|from)\s+earlier",
                              r"associated\s+with.{0,20}(account|activity)\s+I\s+(updated|mentioned)"]),

    ("Verified with User",   [r"was\s+this\s+you", r"can\s+you\s+(confirm|verify)",
                              r"confirmed\s+(it\s+was|by|with)",
                              r"checked\s+with\s+(the\s+)?user",
                              r"user\s+confirmed", r"verified\s+with",
                              r"(he|she|they)\s+confirm",
                              r"please\s+review.{0,20}confirm"]),

    ("Duplicate / Already Handled", [r"duplicate", r"already\s+(address|handl|report|work)",
                              r"same\s+(as|incident|ticket|issue)",
                              r"covered\s+in\s+(previous|earlier)",
                              r"part\s+of\s+(the\s+)?same",
                              r"same\s+(student|user).{0,20}earlier\s+this\s+morning"]),

    # -----------------------------------------------------------------------
    # Active action taken
    # -----------------------------------------------------------------------
    ("Account Action Taken", [r"(account|user).{0,30}(block|disabl|lock|suspend|reset)",
                              r"password\s+(has\s+been\s+)?reset",
                              r"mfa\s+(enforc|enabl|requir)",
                              r"revok.{0,20}(session|token|access)",
                              r"force.{0,20}(sign.?out|logoff|password)",
                              r"compromised.{0,30}(block|disabl|reset|lock)"]),

    ("Remediation Applied",  [r"(remediat|mitigat|contain|clean|remov|quarantin).{0,15}(appli|complet|done|success)",
                              r"rule\s+(has\s+been\s+)?(remov|delet|disabl)",
                              r"forward.{0,20}(remov|delet|disabl)",
                              r"taken\s+action", r"action\s+has\s+been\s+taken"]),

    ("Monitoring / Watching", [r"(monitor|watch|keep.{0,10}eye|track).{0,20}(this|the|for|going)",
                              r"will\s+(monitor|watch|keep)",
                              r"continue\s+to\s+(monitor|watch)",
                              r"we.{0,10}(are|will\s+be)\s+(monitor|watch)"]),

    ("Escalated / Referred", [r"escalat", r"refer.{0,10}to", r"forward.{0,20}to\s+(team|vendor|microsoft)",
                              r"loop.{0,10}(in|team)", r"engage.{0,10}(microsoft|vendor|support)",
                              r"open.{0,15}(case|ticket)\s+with"]),

    # -----------------------------------------------------------------------
    # Investigating / in progress
    # -----------------------------------------------------------------------
    ("Investigating",        [r"(i.?m\s+|am\s+)?(investigat|look|check|review|analyz)(ing|ed)",
                              r"(taking|took)\s+a\s+look",
                              r"update\s+soon", r"will\s+update",
                              r"i.{0,5}(am|m)\s+(on\s+it|checking|reviewing)",
                              r"looking\s+(into|at)\s+(this|it|the)"]),

    # -----------------------------------------------------------------------
    # Information request / follow-up
    # -----------------------------------------------------------------------
    ("Info Request / Query",  [r"can\s+you\s+(provide|send|share|check|look)",
                              r"(please|pls)\s+(provide|send|share|check)",
                              r"need.{0,20}(more\s+)?info",
                              r"do\s+(you|we)\s+(have|know)",
                              r"is\s+this\s+(yours?|your\s+account)",
                              r"please\s+confirm",
                              r"detected\s+under\s+your\s+account"]),

    ("Acknowledgment Only",  [r"^(thank|thanks|noted|received|acknowledged|got\s+it|copy)\b",
                              r"^will\s+do\b"]),
]

TRIAGE_UNCATEGORIZED = "Unclassified Response"


def classify_triage(body_preview: str) -> str:
    text = (body_preview or "").lower()
    for action, patterns in TRIAGE_RULES:
        for p in patterns:
            if re.search(p, text, re.IGNORECASE):
                return action
    return TRIAGE_UNCATEGORIZED


def extract_ticket_number(subject: str) -> str:
    m = re.search(r"(?:service\s*ticket\s*#?|ticket\s*#?)[\s#]*(\d{5,10})", subject or "", re.I)
    return m.group(1) if m else ""


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


def graph_search_monthly(token: str, mailbox: str, kql_template: str,
                         year: int, month: int) -> list[dict]:
    """Search messages via $search with KQL for a given month."""
    last_day = calendar.monthrange(year, month)[1]
    kql = kql_template.format(start=f"{year}-{month:02d}-01", end=f"{year}-{month:02d}-{last_day}")

    url = f"{GRAPH_BASE}/users/{mailbox}/messages"
    params = {
        "$search": f'"{kql}"',
        "$select": "id,subject,receivedDateTime,from,toRecipients,bodyPreview,importance",
        "$top": 999,
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
                            params=current_params if page == 1 else None, timeout=60)
        if resp.status_code == 429:
            time.sleep(int(resp.headers.get("Retry-After", "15")))
            continue
        resp.raise_for_status()
        data = resp.json()
        results.extend(data.get("value", []))
        next_link = data.get("@odata.nextLink")
        current_url = next_link if next_link else None
        current_params = None
        page += 1
        if next_link:
            time.sleep(RATE_DELAY)

    return results


# ---------------------------------------------------------------------------
# Correlation with Phase 1
# ---------------------------------------------------------------------------

def load_phase1_data() -> dict:
    """Load combined SOC data, indexed by ticket number."""
    import glob as globmod
    pattern = os.path.join(OUTPUT_DIR, "phase1_combined_soc_emails_*.csv")
    files = sorted(globmod.glob(pattern))
    if not files:
        pattern = os.path.join(OUTPUT_DIR, "phase1_soc_emails_*.csv")
        files = sorted(globmod.glob(pattern))
    if not files:
        return {}
    path = files[-1]
    log.info("Loading SOC data from %s", path)
    with open(path, encoding="utf-8") as f:
        rows = list(csv.DictReader(f))

    # Index by ticket number - keep the EARLIEST (original) email per ticket
    by_ticket = {}
    for r in rows:
        tn = r.get("ticket_number", "")
        if not tn:
            continue
        if tn not in by_ticket:
            by_ticket[tn] = r
        else:
            existing_date = by_ticket[tn].get("received", "")
            new_date = r.get("received", "")
            if new_date < existing_date:
                by_ticket[tn] = r
    return by_ticket


def calc_response_hours(soc_received: str, jb_sent: str) -> float:
    """Calculate hours between SOC email and Baldwin's response."""
    try:
        soc_dt = datetime.fromisoformat(soc_received.replace("Z", "+00:00"))
        jb_dt  = datetime.fromisoformat(jb_sent.replace("Z", "+00:00"))
        delta = (jb_dt - soc_dt).total_seconds() / 3600
        return round(delta, 1) if delta >= 0 else None
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    if not all([TENANT_ID, CLIENT_ID, CLIENT_SECRET]):
        sys.exit("ERROR: Missing credentials")

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    log.info("Phase 3: Baldwin SOC response analysis")
    log.info("Mailbox: %s  |  Range: %s to %s", JB_MAILBOX, SEARCH_START_DATE, SEARCH_END_DATE)

    token = get_access_token()
    token_at = datetime.now()

    # Load Phase 1 SOC data for correlation
    soc_by_ticket = load_phase1_data()
    log.info("SOC tickets loaded: %d", len(soc_by_ticket))

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

    # Search Baldwin's sent items for SOC responses
    kql_template = "to:soc@oculusit.com AND received:{start}..{end}"

    all_records = []
    seen_ids = set()

    for year, month in months:
        if (datetime.now() - token_at).total_seconds() > 3000:
            token = get_access_token()
            token_at = datetime.now()

        log.info("Searching jbaldwin sent %d-%02d...", year, month)
        raw = graph_search_monthly(token, JB_MAILBOX, kql_template, year, month)
        new_count = 0

        for r in raw:
            msg_id = r.get("id", "")
            if msg_id in seen_ids:
                continue
            seen_ids.add(msg_id)

            subject  = r.get("subject", "") or ""
            received = r.get("receivedDateTime", "") or ""
            bp       = (r.get("bodyPreview", "") or "")
            sender   = (r.get("from", {}).get("emailAddress", {}).get("address", "") or "").lower()

            ticket_num    = extract_ticket_number(subject)
            triage_action = classify_triage(bp)

            # Correlate with SOC ticket
            soc_match     = soc_by_ticket.get(ticket_num, {})
            soc_received  = soc_match.get("received", "")
            soc_category  = soc_match.get("category", "")
            response_hrs  = calc_response_hours(soc_received, received) if soc_received else None

            rec = {
                "id":              msg_id,
                "subject":         subject,
                "sent_datetime":   received,
                "sent_date":       received[:10] if received else "",
                "sender":          sender,
                "ticket_number":   ticket_num,
                "triage_action":   triage_action,
                "body_preview":    bp[:300],
                "soc_received":    soc_received,
                "soc_category":    soc_category,
                "response_hours":  response_hrs,
                "sent_month":      received[:7] if received else "",
            }
            all_records.append(rec)
            new_count += 1

        if new_count > 0:
            log.info("  -> %d responses", new_count)
        time.sleep(RATE_DELAY)

    log.info("Done. Total Baldwin responses: %d", len(all_records))

    # --- Analysis ---
    by_triage   = defaultdict(int)
    by_month    = defaultdict(int)
    response_times = []
    tickets_responded = set()
    by_soc_cat  = defaultdict(lambda: defaultdict(int))  # soc_category -> triage_action -> count

    for r in all_records:
        by_triage[r["triage_action"]] += 1
        by_month[r["sent_month"]] += 1
        if r["ticket_number"]:
            tickets_responded.add(r["ticket_number"])
        if r["response_hours"] is not None and 0 <= r["response_hours"] < 720:  # < 30 days
            response_times.append(r["response_hours"])
        if r["soc_category"]:
            by_soc_cat[r["soc_category"]][r["triage_action"]] += 1

    # Response time stats
    avg_hrs = sum(response_times) / len(response_times) if response_times else 0
    sorted_rt = sorted(response_times)
    median_hrs = sorted_rt[len(sorted_rt) // 2] if sorted_rt else 0
    p90_hrs = sorted_rt[int(len(sorted_rt) * 0.9)] if sorted_rt else 0

    # SOC ticket coverage
    total_soc_tickets = len(soc_by_ticket)
    responded_count   = len(tickets_responded & set(soc_by_ticket.keys()))
    response_rate     = responded_count / total_soc_tickets * 100 if total_soc_tickets else 0

    # Write outputs
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    csv_path = os.path.join(OUTPUT_DIR, f"phase3_baldwin_responses_{ts}.csv")
    jsn_path = os.path.join(OUTPUT_DIR, f"phase3_baldwin_summary_{ts}.json")

    if all_records:
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=list(all_records[0].keys()))
            writer.writeheader()
            writer.writerows(all_records)
        log.info("CSV: %s (%d rows)", csv_path, len(all_records))

    # Top triage action per SOC category
    cat_triage_summary = {}
    for soc_cat, actions in by_soc_cat.items():
        top_action = max(actions.items(), key=lambda x: x[1])
        cat_triage_summary[soc_cat] = {
            "top_triage_action": top_action[0],
            "top_action_count": top_action[1],
            "total_responses": sum(actions.values()),
            "all_actions": dict(sorted(actions.items(), key=lambda x: -x[1])),
        }

    summary = {
        "run_timestamp":       ts,
        "baldwin_mailbox":     JB_MAILBOX,
        "search_start":        SEARCH_START_DATE,
        "search_end":          SEARCH_END_DATE,
        "total_responses":     len(all_records),
        "unique_tickets_responded": len(tickets_responded),
        "soc_ticket_coverage": {
            "total_soc_tickets": total_soc_tickets,
            "tickets_with_response": responded_count,
            "response_rate": f"{response_rate:.1f}%",
        },
        "response_time_hours": {
            "mean": round(avg_hrs, 1),
            "median": round(median_hrs, 1),
            "p90": round(p90_hrs, 1),
            "samples": len(response_times),
        },
        "by_triage_action": dict(sorted(by_triage.items(), key=lambda x: -x[1])),
        "by_month": dict(sorted(by_month.items())),
        "triage_by_soc_category": cat_triage_summary,
        "output_csv": csv_path,
    }
    with open(jsn_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, default=str)
    log.info("JSON: %s", jsn_path)

    # --- Print summary ---
    print("\n" + "=" * 72)
    print("  BALDWIN SOC RESPONSE ANALYSIS  -  Phase 3 Summary")
    print(f"  Analyst:   {JB_MAILBOX}")
    print(f"  Period:    {SEARCH_START_DATE}  to  {SEARCH_END_DATE}")
    print("=" * 72)

    print(f"\n  TOTAL RESPONSES:               {len(all_records):,}")
    print(f"  Unique tickets responded:      {len(tickets_responded):,}")
    print(f"  SOC ticket coverage:           {responded_count:,} / {total_soc_tickets:,} ({response_rate:.1f}%)")

    print(f"\n  RESPONSE TIME (hours):")
    print(f"    Mean:     {avg_hrs:>8.1f}")
    print(f"    Median:   {median_hrs:>8.1f}")
    print(f"    P90:      {p90_hrs:>8.1f}")
    print(f"    Samples:  {len(response_times):>8}")

    print(f"\n  TRIAGE ACTION BREAKDOWN:")
    print("  " + "-" * 55)
    for action, count in sorted(by_triage.items(), key=lambda x: -x[1]):
        pct = count / len(all_records) * 100 if all_records else 0
        bar = "=" * int(pct / 2)
        print(f"  {action:<35} {count:>5}  ({pct:4.1f}%)  {bar}")

    print(f"\n  RESPONSES BY MONTH:")
    print("  " + "-" * 35)
    for month in sorted(by_month.keys()):
        count = by_month[month]
        bar = "#" * (count // 3)
        print(f"  {month}  {count:>4}  {bar}")

    print(f"\n  TOP TRIAGE ACTION PER SOC CATEGORY (top 10):")
    print("  " + "-" * 60)
    for soc_cat, info in sorted(cat_triage_summary.items(),
                                key=lambda x: -x[1]["total_responses"])[:10]:
        print(f"  {soc_cat:<35} -> {info['top_triage_action']:<25} ({info['top_action_count']}/{info['total_responses']})")

    print("\n" + "=" * 72)
    print(f"\n  Output files:")
    print(f"    CSV:  {csv_path}")
    print(f"    JSON: {jsn_path}\n")


if __name__ == "__main__":
    main()
