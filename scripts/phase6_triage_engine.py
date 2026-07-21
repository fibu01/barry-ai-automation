#!/usr/bin/env python3
"""
phase6_triage_engine.py -- Barry University SOC Triage Engine
Correlates SOC_Incidents.xlsx -> Microsoft Defender -> applies workflow decision tree.
Generates two artifacts:
  1. Full HTML report uploaded to SharePoint (SOC_Incidents folder)
  2. Concise action-first email digest sent to DIGEST_TO recipients

Required permissions: SecurityIncident.Read.All, Sites.ReadWrite.All, Mail.Send
Optional (unlock full automation):
  AuditLog.Read.All              -> auto-pull sign-in logs for credential alerts
  DeviceManagementManagedDevices.Read.All -> auto-check Intune ownership for malware
"""
import sys
import os
import json
import time
import logging
from datetime import datetime, timezone, timedelta
from collections import defaultdict

import openpyxl
import msal
import requests

# ---------------------------------------------------------------------------
# Configuration -- all from environment variables, no hardcoding
# ---------------------------------------------------------------------------
TENANT_ID     = os.environ.get("TENANT_ID", "")
CLIENT_ID     = os.environ.get("CLIENT_ID", "")
CLIENT_SECRET = os.environ.get("CLIENT_SECRET", "")
MAILBOX_UPN   = os.environ.get("MAILBOX_UPN", "jmoses@barry.edu")
DIGEST_TO     = os.environ.get("DIGEST_TO", "jmoses@barry.edu,jbaldwin@barry.edu")
DIGEST_FROM   = os.environ.get("DIGEST_FROM", "jmoses@barry.edu")
GRAPH_BASE    = "https://graph.microsoft.com/v1.0"
RATE_DELAY    = 0.3
SLA_THRESHOLD_DAYS = int(os.environ.get("SLA_THRESHOLD_DAYS", "14"))

# SharePoint upload target -- values discovered via Graph API; override via env if path changes
SHAREPOINT_DRIVE_ID    = os.environ.get(
    "SHAREPOINT_DRIVE_ID",
    "b!7sYDkKxfpkuu1wL5ZtLyTHakOtL0TK9FlekK43eqTAZyVgg_51lXQooJvwr9p7ox",
)
SHAREPOINT_FOLDER_PATH = os.environ.get(
    "SHAREPOINT_FOLDER_PATH",
    "Security and Risk Management/Operations/SOC_Incidents",
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Auth + Graph helpers
# ---------------------------------------------------------------------------

def get_access_token():
    """Acquire an app-only access token via MSAL client credentials."""
    if not all([TENANT_ID, CLIENT_ID, CLIENT_SECRET]):
        log.error("Missing TENANT_ID / CLIENT_ID / CLIENT_SECRET environment variables.")
        sys.exit(1)
    authority = f"https://login.microsoftonline.com/{TENANT_ID}"
    app = msal.ConfidentialClientApplication(
        CLIENT_ID,
        authority=authority,
        client_credential=CLIENT_SECRET,
    )
    result = app.acquire_token_for_client(scopes=["https://graph.microsoft.com/.default"])
    if "access_token" not in result:
        log.error("Token acquisition failed: %s", result.get("error_description", result))
        sys.exit(1)
    log.info("Access token acquired.")
    return result["access_token"]


def graph_get(token, url, params=None):
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
    resp = requests.get(url, headers=headers, params=params, timeout=30)
    if resp.status_code == 429:
        retry_after = int(resp.headers.get("Retry-After", "10"))
        log.warning("Rate limited -- waiting %ds", retry_after)
        time.sleep(retry_after)
        resp = requests.get(url, headers=headers, params=params, timeout=30)
    if resp.status_code == 200:
        try:
            return 200, resp.json()
        except Exception:
            return 200, {}
    return resp.status_code, None


def graph_post(token, url, body):
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    resp = requests.post(url, headers=headers, json=body, timeout=30)
    try:
        data = resp.json()
    except Exception:
        data = {}
    return resp.status_code, data


# ---------------------------------------------------------------------------
# Workflow classification
# ---------------------------------------------------------------------------

WORKFLOW_RULES = [
    ("MALWARE",      ["malware", "threat detected", "virus", "ransomware", "trojan"]),
    ("CREDENTIAL",   ["password spray", "anonymous ip", "anonymous proxy", "anomalous token",
                      "unfamiliar sign-in", "unfamiliar features", "suspicious ip",
                      "atypical travel", "impossible travel", "sign-in from"]),
    ("URL",          ["malicious url", "phishing", "potentially malicious url"]),
    ("EXFILTRATION", ["exfiltration", "data loss", "dlp"]),
    ("LATERAL",      ["lateral movement", "pass-the-ticket", "kerberos", "credential access"]),
    ("RECON",        ["reconnaissance", "network scan", "discovery"]),
    ("PERSISTENCE",  ["persistence", "forwarding rule", "inbox rule", "mail forwarding"]),
]


def classify_workflow(incident_name, alert_titles):
    combined = (incident_name + " " + " ".join(alert_titles)).lower()
    for wtype, keywords in WORKFLOW_RULES:
        if any(kw in combined for kw in keywords):
            return wtype
    return "OTHER"


# ---------------------------------------------------------------------------
# User domain classification
# ---------------------------------------------------------------------------

def classify_user_domain(email):
    if not email:
        return ("UNKNOWN", "Manual lookup required")
    e = email.lower()
    if e.endswith("@barry.edu"):
        return ("STAFF_FACULTY", "Contact user directly, schedule on-site scan if malware")
    if e.endswith("@mymail.barry.edu"):
        return ("STUDENT", "Email student, recommend they scan device")
    if e.endswith("@law.barry.edu"):
        return ("LAW_STUDENT", "Email student AND CC Law IT staff")
    return ("EXTERNAL", "External account -- investigate if Barry systems accessed")


# ---------------------------------------------------------------------------
# Deep-link builders -- all use TENANT_ID from env var
# ---------------------------------------------------------------------------

def defender_incident_url(incident_id):
    return f"https://security.microsoft.com/incident2/{incident_id}/overview?tid={TENANT_ID}"


def defender_alert_url(alert_id):
    return f"https://security.microsoft.com/alerts/{alert_id}?tid={TENANT_ID}"


def azure_ad_user_url(upn=None):
    return "https://portal.azure.com/#view/Microsoft_AAD_UsersAndTenants/UserManagementMenuBlade/~/AllUsers"


def intune_devices_url():
    return "https://intune.microsoft.com/#view/Microsoft_Intune_DeviceSettings/DevicesMenu/~/allDevices"


def signin_logs_url(upn=None):
    return "https://portal.azure.com/#view/Microsoft_AAD_IAM/SignInEventsV3Blade"


def threat_explorer_url():
    return f"https://security.microsoft.com/threatexplorerv3?tid={TENANT_ID}"


# ---------------------------------------------------------------------------
# Defender incident fetcher
# ---------------------------------------------------------------------------

def fetch_defender_incident(token, defender_id):
    """Fetch a Defender incident with expanded alerts. Returns dict or None."""
    url = f"{GRAPH_BASE}/security/incidents/{defender_id}?$expand=alerts"
    status, data = graph_get(token, url)
    if status == 200:
        return data
    if status == 404:
        return None  # expired -- Defender retains ~180 days
    log.warning("Defender incident %s: HTTP %s", defender_id, status)
    return None


# ---------------------------------------------------------------------------
# Sign-in log fetcher + analyzer (requires AuditLog.Read.All)
# ---------------------------------------------------------------------------

def fetch_signin_logs(token, upn, top=50):
    status, data = graph_get(token, f"{GRAPH_BASE}/auditLogs/signIns", params={
        "$filter": f"userPrincipalName eq '{upn}'",
        "$top": top,
        "$select": ("id,createdDateTime,ipAddress,location,status,deviceDetail,"
                    "authenticationRequirement,resourceDisplayName,riskLevelAggregated"),
    })
    if status == 200:
        return data.get("value", [])
    log.warning("Sign-in logs for %s: HTTP %s", upn, status)
    return []


def analyze_signin_logs(logs, alert_dt=None):
    if not logs:
        return {"classification": "UNKNOWN", "summary": "No sign-in logs available",
                "known_devices": [], "suspicious_events": []}

    successful = [s for s in logs if s.get("status", {}).get("errorCode") == 0]
    failed     = [s for s in logs if s.get("status", {}).get("errorCode") != 0]

    known_os_browsers = set()
    for s in successful:
        d = s.get("deviceDetail", {})
        fp = f"{d.get('operatingSystem','')}/{d.get('browser','')}"
        if fp != "/":
            known_os_browsers.add(fp)

    suspicious = []
    for s in logs:
        loc = s.get("location", {})
        country = loc.get("countryOrRegion", "")
        if country and country not in ("US", "United States", ""):
            suspicious.append({
                "time":     s.get("createdDateTime", "")[:16],
                "ip":       s.get("ipAddress", ""),
                "location": f"{loc.get('city','')}, {country}",
                "result":   "Success" if s.get("status", {}).get("errorCode") == 0 else "Failed",
                "resource": s.get("resourceDisplayName", ""),
            })

    successful_non_us = [s for s in suspicious if s["result"] == "Success"]
    failed_wrong_pw   = [
        s for s in failed
        if "incorrect password" in (s.get("status", {}).get("failureReason", "")).lower()
    ]

    if not suspicious:
        return {
            "classification": "FP",
            "summary": "All sign-ins from US locations. No anomalous geography detected.",
            "known_devices": sorted(known_os_browsers),
            "suspicious_events": [],
        }

    if successful_non_us:
        non_o365 = [
            s for s in successful_non_us
            if "office" not in s["resource"].lower() and "microsoft" not in s["resource"].lower()
        ]
        if non_o365:
            clf = "ESCALATE"
            summary = (
                f"Successful login from {successful_non_us[0]['location']} to non-O365 service "
                f"({non_o365[0]['resource']}). Possible account compromise -- escalate."
            )
        else:
            clf = "POSSIBLE_COMPROMISE"
            summary = (
                f"Successful login from {successful_non_us[0]['location']} "
                f"({successful_non_us[0]['ip']}). Check for phishing sent from account."
            )
    elif failed_wrong_pw:
        clf = "NO_COMPROMISE"
        summary = (
            f"{len(failed_wrong_pw)} failed login attempt(s) with incorrect password from outside US. "
            f"Account not compromised -- contact user to change password."
        )
    else:
        clf = "NO_COMPROMISE"
        summary = f"{len(suspicious)} suspicious sign-in(s) detected, all failed. Account not compromised."

    return {
        "classification": clf,
        "summary": summary,
        "known_devices": sorted(known_os_browsers),
        "suspicious_events": suspicious[:5],
    }


# ---------------------------------------------------------------------------
# Intune device ownership checker (requires DeviceManagementManagedDevices.Read.All)
# ---------------------------------------------------------------------------

def check_intune_ownership(token, upn=None, device_name=None):
    params = {
        "$select": "id,deviceName,managedDeviceOwnerType,operatingSystem,lastSyncDateTime,complianceState",
    }
    if upn:
        params["$filter"] = f"userPrincipalName eq '{upn}'"
    elif device_name:
        params["$filter"] = f"deviceName eq '{device_name}'"
    else:
        return []

    status, data = graph_get(token, f"{GRAPH_BASE}/deviceManagement/managedDevices", params=params)
    if status == 200:
        return data.get("value", [])
    log.warning("Intune lookup (upn=%s, device=%s): HTTP %s", upn, device_name, status)
    return []


# ---------------------------------------------------------------------------
# Evidence extractor
# ---------------------------------------------------------------------------

def extract_evidence(incident):
    users, devices, ips, files = set(), set(), set(), set()
    alert_titles = []

    for alert in incident.get("alerts", []):
        title = alert.get("title", "")
        if title:
            alert_titles.append(title)

        for ev in alert.get("evidence", []):
            t = ev.get("@odata.type", "").lower()
            if "user" in t:
                upn = ev.get("userAccount", {}).get("userPrincipalName", "")
                if upn:
                    users.add(upn)
            if "device" in t:
                dn = ev.get("deviceDnsName", "") or ev.get("mdeDeviceId", "")
                if dn:
                    devices.add(dn)
            if "ip" in t:
                ip = ev.get("ipAddress", "")
                if ip:
                    ips.add(ip)
            if "file" in t:
                fn = ev.get("fileName", "") or ev.get("sha256", "")
                if fn:
                    files.add(fn[:60])

    return {
        "users":        sorted(users),
        "devices":      sorted(devices),
        "ips":          sorted(ips),
        "files":        sorted(files),
        "alert_titles": alert_titles,
    }


# ---------------------------------------------------------------------------
# Triage card builder -- severity from live Defender data, not Excel
# ---------------------------------------------------------------------------

def build_triage_card(soc_row, defender_inc, evidence, workflow, token=None):
    ticket      = str(soc_row.get("Ticket #") or "")
    title       = str(soc_row.get("Title") or "")
    alert_date  = soc_row.get("Alert Date UTC")
    defender_id = str(soc_row.get("Defender Incident ID") or "")

    # Severity: prefer live Defender data; expired incidents get "aged, unavailable"
    if defender_inc is not None:
        raw_sev = defender_inc.get("severity", "") or ""
        severity = raw_sev.capitalize() if raw_sev else (str(soc_row.get("Severity") or "Unknown"))
    else:
        excel_sev = str(soc_row.get("Severity") or "")
        severity = "aged, unavailable" if not excel_sev or excel_sev.lower() in ("unknown", "none") else excel_sev

    age_days = None
    if isinstance(alert_date, datetime):
        age_days = (datetime.now() - alert_date.replace(tzinfo=None)).days

    steps = build_workflow_steps(workflow, evidence, soc_row, token=token)

    draft_email = None
    if evidence["users"]:
        draft_email = build_draft_email(workflow, evidence["users"][0], ticket, title, alert_date)

    return {
        "ticket":         ticket,
        "title":          title,
        "severity":       severity,
        "age_days":       age_days,
        "alert_date":     (alert_date.strftime("%Y-%m-%d %H:%M UTC")
                           if isinstance(alert_date, datetime) else ""),
        "defender_id":    defender_id,
        "defender_found": defender_inc is not None,
        "workflow":       workflow,
        "users":          evidence["users"],
        "devices":        evidence["devices"],
        "ips":            evidence["ips"],
        "files":          evidence["files"],
        "alert_titles":   evidence["alert_titles"],
        "steps":          steps,
        "draft_email":    draft_email,
        "defender_url":   defender_incident_url(defender_id) if defender_id else "",
        "outlook_link":   str(soc_row.get("Latest Outlook Link") or ""),
    }


# ---------------------------------------------------------------------------
# Workflow steps builder
# ---------------------------------------------------------------------------

def build_workflow_steps(workflow, evidence, soc_row, token=None):
    steps = []
    users    = evidence["users"]
    devices  = evidence["devices"]
    ips      = evidence["ips"]
    alert_dt = soc_row.get("Alert Date UTC")

    if workflow == "MALWARE":
        steps.append({"label": "Incident type identified: Malware Detected",
                       "status": "auto", "detail": "Matches malware workflow", "link": ""})
        intune_checked = False
        for user in users[:2]:
            if token:
                for d in check_intune_ownership(token, upn=user):
                    ownership = d.get("managedDeviceOwnerType", "unknown")
                    dev_name  = d.get("deviceName", "?")
                    last_sync = str(d.get("lastSyncDateTime", ""))[:10]
                    verdict   = ("Barry-owned -- run scan" if ownership == "company"
                                 else "Personal device -- not our responsibility")
                    steps.append({
                        "label":  f"Intune: {dev_name} -> {ownership.upper()} ({verdict})",
                        "status": "auto",
                        "detail": f"Last sync: {last_sync} | Compliance: {d.get('complianceState','')}",
                        "link":   intune_devices_url(),
                    })
                    intune_checked = True
        if not intune_checked:
            for dev in devices[:3]:
                steps.append({"label": f"Check device in Intune: {dev}", "status": "manual",
                               "detail": "Personal = not our device | Corporate = Barry device",
                               "link": intune_devices_url()})
            if not devices:
                steps.append({"label": "Device not found in Defender evidence", "status": "manual",
                               "detail": "Open incident in Defender to identify device manually",
                               "link": ""})
        for user in users[:2]:
            domain_type, action = classify_user_domain(user)
            steps.append({"label": f"Notify user: {user}",
                           "status": "auto" if domain_type != "UNKNOWN" else "manual",
                           "detail": action, "link": ""})
        steps.append({"label": "Trigger scan via Intune", "status": "manual",
                       "detail": "If Corporate device: open in Intune -> Quick Scan or Full Scan",
                       "link": intune_devices_url()})

    elif workflow == "CREDENTIAL":
        steps.append({"label": "Incident type: Credential/Sign-in Alert",
                       "status": "auto", "detail": "Matches credential workflow", "link": ""})
        if users:
            for user in users[:2]:
                if token:
                    logs = fetch_signin_logs(token, user)
                    analysis = analyze_signin_logs(logs, alert_dt)
                    clf = analysis["classification"]
                    clf_labels = {
                        "FP": "FALSE POSITIVE",
                        "NO_COMPROMISE": "NO COMPROMISE",
                        "POSSIBLE_COMPROMISE": "POSSIBLE COMPROMISE",
                        "ESCALATE": "ESCALATE",
                    }
                    steps.append({
                        "label":  f"Sign-in analysis for {user}: {clf_labels.get(clf, clf)}",
                        "status": "auto",
                        "detail": analysis["summary"],
                        "link":   signin_logs_url(user),
                    })
                    if analysis["suspicious_events"]:
                        locs = ", ".join(
                            f"{e['location']} ({e['result']})"
                            for e in analysis["suspicious_events"][:3]
                        )
                        steps.append({
                            "label":  f"Suspicious locations: {locs}",
                            "status": "auto",
                            "detail": (f"{len(logs)} total sign-ins analyzed. "
                                       f"Known devices: {', '.join(analysis['known_devices'][:2]) or 'none'}"),
                            "link":   "",
                        })
                    if clf in ("POSSIBLE_COMPROMISE", "ESCALATE"):
                        steps.append({
                            "label":  "Check Threat Explorer for phishing sent from account",
                            "status": "manual",
                            "detail": f"Filter by sender {user} from alert date",
                            "link":   threat_explorer_url(),
                        })
                else:
                    steps.append({"label": f"Pull sign-in logs for {user}", "status": "manual",
                                   "detail": "Review last 30 days of sign-ins in Azure AD",
                                   "link": signin_logs_url(user)})
                steps.append({"label": f"Check auth methods for {user}", "status": "manual",
                               "detail": "Note default MFA method and registered devices",
                               "link": azure_ad_user_url(user)})
        if ips:
            steps.append({"label": f"Suspicious IPs: {', '.join(ips[:3])}", "status": "auto",
                           "detail": "IPs extracted from Defender evidence", "link": ""})

    elif workflow == "URL":
        steps.append({"label": "Incident type: Malicious URL",
                       "status": "auto", "detail": "Matches URL workflow", "link": ""})
        steps.append({"label": "Submit URL to VirusTotal", "status": "manual",
                       "detail": "Submit the URL from the alert to confirm classification",
                       "link": "https://www.virustotal.com/gui/home/url"})
        steps.append({"label": "Search Threat Explorer for related emails", "status": "manual",
                       "detail": "Filter by sender and date -- multiple emails with same subject = phishing campaign",
                       "link": threat_explorer_url()})
        for user in users[:2]:
            steps.append({"label": f"Check if account compromised: {user}", "status": "manual",
                           "detail": "Follow credential compromise checklist for this user", "link": ""})

    elif workflow == "PERSISTENCE":
        steps.append({"label": "Incident type: Persistence / Mail Rule", "status": "auto",
                       "detail": "Mail forwarding or inbox rule -- HIGH priority, possible BEC",
                       "link": ""})
        for user in users[:2]:
            steps.append({"label": f"Audit mailbox rules for {user}", "status": "manual",
                           "detail": "Check Outlook rules and forwarding settings immediately",
                           "link": azure_ad_user_url(user)})
        steps.append({"label": "Check for outbound phishing from affected account", "status": "manual",
                       "detail": "Use Threat Explorer to look for sent emails on the alert date",
                       "link": threat_explorer_url()})

    else:
        steps.append({"label": f"Workflow type: {workflow}", "status": "manual",
                       "detail": "No automated steps for this alert type -- manual review required",
                       "link": ""})

    return steps


# ---------------------------------------------------------------------------
# Draft email builder
# ---------------------------------------------------------------------------

def build_draft_email(workflow, user_email, ticket, incident_title, alert_date):
    domain_type, _ = classify_user_domain(user_email)
    date_str = (alert_date.strftime("%B %d, %Y") if isinstance(alert_date, datetime) else "recently")

    if workflow == "MALWARE":
        if domain_type == "STAFF_FACULTY":
            return {
                "to": user_email, "cc": "",
                "subject": f"Action Required: Security Alert on Your Device -- Ticket {ticket}",
                "body": (
                    f"Hi,\n\nOur security monitoring system detected a potential malware alert associated "
                    f"with your account or device on {date_str} (Ticket #{ticket}).\n\n"
                    f"We need to schedule a time to scan your device. Please reply so we can coordinate.\n\n"
                    f"In the meantime:\n"
                    f"- Do not open unexpected attachments or click unfamiliar links.\n"
                    f"- If your computer is behaving unusually, please let us know immediately.\n\n"
                    f"This is not an accusation -- malware can reach any device through email, websites, or USB drives. "
                    f"We are here to help resolve it quickly.\n\n"
                    f"Barry University IT Security\njmoses@barry.edu"
                ),
            }
        else:
            cc = "lawit@barry.edu" if domain_type == "LAW_STUDENT" else ""
            return {
                "to": user_email, "cc": cc,
                "subject": f"Important: Security Alert -- Please Scan Your Device (Ticket {ticket})",
                "body": (
                    f"Hi,\n\nOur security system detected a potential issue associated with your account "
                    f"on {date_str} (Ticket #{ticket}).\n\n"
                    f"We recommend you scan your device as soon as possible:\n"
                    f"1. Windows: Open Windows Security > Virus and Threat Protection > Quick Scan\n"
                    f"2. Mac: Run Malwarebytes Free (malwarebytes.com)\n\n"
                    f"If you need help or your device is acting strangely, contact helpdesk@barry.edu.\n\n"
                    f"Barry University IT Security"
                ),
            }

    elif workflow == "CREDENTIAL":
        return {
            "to": user_email, "cc": "",
            "subject": f"Security Notice: Unusual Sign-In Activity on Your Account (Ticket {ticket})",
            "body": (
                f"Hi,\n\nWe detected unusual sign-in activity on your Barry University account "
                f"on {date_str} (Ticket #{ticket}).\n\n"
                f"Please take action:\n"
                f"1. Log in to mybarry.barry.edu and change your password immediately.\n"
                f"2. Review recent sign-in activity at https://mysignins.microsoft.com/security-info\n"
                f"3. If you did not attempt to log in from an unusual location, reply to this email immediately.\n\n"
                f"Barry University IT Security"
            ),
        }

    return None


# ---------------------------------------------------------------------------
# Triage classification: ESCALATE / MANUAL / AUTO_TRIAGED
# ---------------------------------------------------------------------------

def compute_card_classification(card):
    """Derive triage bucket from step analysis output."""
    if not card["defender_found"]:
        return "MANUAL"

    steps = card.get("steps", [])
    if not steps:
        return "MANUAL"

    # Explicit escalation check first
    for s in steps:
        combined = (s.get("label", "") + " " + s.get("detail", "")).upper()
        if "ESCALATE" in combined or "POSSIBLE COMPROMISE" in combined:
            return "ESCALATE"

    # Auto-resolved by sign-in analysis
    for s in steps:
        label_upper = s.get("label", "").upper()
        if s.get("status") == "auto" and (
            "FALSE POSITIVE" in label_upper or "NO COMPROMISE" in label_upper
        ):
            return "AUTO_TRIAGED"

    return "MANUAL"


# ---------------------------------------------------------------------------
# Repeat-user detection
# ---------------------------------------------------------------------------

def compute_repeat_users(cards):
    """Return set of user emails appearing in more than one open incident."""
    counts = defaultdict(int)
    for c in cards:
        if c["defender_found"]:
            for u in c["users"]:
                counts[u] += 1
    return {u for u, n in counts.items() if n > 1}


# ---------------------------------------------------------------------------
# Out-of-sequence Defender ID detection
# ---------------------------------------------------------------------------

def flag_oob_ids(cards):
    """
    Flag Defender incident IDs that are statistical outliers vs. the rest of the batch.
    Uses 3*IQR rule. Returns set of string IDs.
    """
    ids = []
    for c in cards:
        try:
            ids.append(int(c["defender_id"]))
        except (ValueError, TypeError):
            pass

    if len(ids) < 4:
        return set()

    ids_sorted = sorted(ids)
    n  = len(ids_sorted)
    q1 = ids_sorted[n // 4]
    q3 = ids_sorted[(3 * n) // 4]
    iqr = q3 - q1
    if iqr == 0:
        return set()

    median    = ids_sorted[n // 2]
    threshold = 3 * iqr
    flagged   = set()
    for c in cards:
        try:
            did = int(c["defender_id"])
            if abs(did - median) > threshold:
                flagged.add(c["defender_id"])
        except (ValueError, TypeError):
            pass
    return flagged


# ---------------------------------------------------------------------------
# SharePoint upload
# ---------------------------------------------------------------------------

def upload_to_sharepoint(token, content_bytes, filename="triage_report.html"):
    """
    Upload content_bytes to SHAREPOINT_FOLDER_PATH/filename via Graph PUT.
    Returns the webUrl from the response on success, empty string on failure.
    """
    encoded_path = f"{SHAREPOINT_FOLDER_PATH}/{filename}"
    url = f"{GRAPH_BASE}/drives/{SHAREPOINT_DRIVE_ID}/root:/{encoded_path}:/content"
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "text/html"}
    try:
        resp = requests.put(url, headers=headers, data=content_bytes, timeout=120)
        if resp.status_code in (200, 201):
            web_url = resp.json().get("webUrl", "")
            log.info("SharePoint upload OK: %s", web_url)
            return web_url
        log.error("SharePoint upload failed: HTTP %s -- %s", resp.status_code, resp.text[:300])
        return ""
    except Exception as exc:
        log.error("SharePoint upload exception: %s", exc)
        return ""


# ---------------------------------------------------------------------------
# HTML escape helper (shared by email digest and report renderer)
# ---------------------------------------------------------------------------

def _esc(s):
    return (str(s)
            .replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))


# ---------------------------------------------------------------------------
# Email digest builder
# ---------------------------------------------------------------------------

SEV_ORDER  = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "aged, unavailable": 4, "Unknown": 5}
TIER_ORDER = {"ESCALATE": 0, "MANUAL": 1, "AUTO_TRIAGED": 2}


def _sev_badge_email(severity):
    colors = {
        "Critical": "#7b1fa2", "High": "#dc3545",
        "Medium": "#fd7e14", "Low": "#28a745",
        "aged, unavailable": "#6c757d", "Unknown": "#6c757d",
    }
    bg = colors.get(severity, "#6c757d")
    return (
        f'<span style="background:{bg};color:#fff;padding:2px 7px;'
        f'border-radius:3px;font-size:11px;font-weight:bold;">{_esc(severity.upper())}</span>'
    )


def build_email_digest(cards, report_url, date_str,
                       open_count, sla_breach_count, new_today_count, carried_count):
    """
    Build the action-first SOC triage email digest HTML.
    Sections: header, lead line, ESCALATE, MANUAL ACTION, queue health,
              auto-triaged counts, aged/expired count.
    """
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    escalate_cards = [c for c in cards if c.get("_triage_class") == "ESCALATE"]
    manual_cards   = [c for c in cards if c.get("_triage_class") == "MANUAL" and c["defender_found"]]
    auto_cards     = [c for c in cards if c.get("_triage_class") == "AUTO_TRIAGED"]
    aged_cards     = [c for c in cards if not c["defender_found"]]
    action_count   = len(escalate_cards) + len(manual_cards)

    report_link_html = ""
    if report_url:
        report_link_html = (
            f'<a href="{_esc(report_url)}" '
            f'style="color:#0d6efd;font-weight:600;">View full triage report on SharePoint</a>'
        )

    parts = []

    # Header (Barry-branded, consistent with phase5 style, no em dashes)
    parts.append(f"""<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"></head>
<body style="font-family:Arial,sans-serif;background:#ffffff;margin:0;padding:0;">
<table width="100%" cellpadding="0" cellspacing="0"
       style="max-width:800px;margin:0 auto;background:#ffffff;">
  <tr>
    <td style="background:#0d1b2a;padding:24px 32px;">
      <div style="color:#fff;font-size:22px;font-weight:bold;">
        Barry University IT -- SOC Triage Digest
      </div>
      <div style="color:#90caf9;font-size:14px;margin-top:4px;">{_esc(date_str)}</div>
    </td>
  </tr>
  <tr>
    <td style="padding:24px 32px;">""")

    # Lead line
    noun = "incident" if action_count == 1 else "incidents"
    verb = "needs" if action_count == 1 else "need"
    parts.append(
        f'<p style="font-size:16px;font-weight:600;color:#212529;margin:0 0 12px 0;">'
        f'{action_count} {noun} {verb} action today '
        f'({len(escalate_cards)} ESCALATE, {len(manual_cards)} MANUAL ACTION).'
        f'</p>'
    )
    if report_url:
        parts.append(f'<p style="margin:0 0 24px 0;font-size:13px;">{report_link_html}</p>')

    # Section 1: ESCALATE
    parts.append(
        '<div style="background:#fff3cd;border-left:4px solid #dc3545;padding:10px 16px;'
        'margin:0 0 8px 0;font-size:15px;font-weight:bold;color:#212529;">ESCALATE NOW</div>'
    )
    if escalate_cards:
        for c in escalate_cards:
            users_str  = ", ".join(c["users"][:3]) if c["users"] else "unknown user"
            dom_type   = classify_user_domain(c["users"][0])[0] if c["users"] else "UNKNOWN"
            alert_list = "; ".join(c["alert_titles"][:3]) if c["alert_titles"] else "see Defender"
            rec_action = next(
                (s["label"] for s in c["steps"] if s.get("status") == "manual"),
                "Review in Defender",
            )
            parts.append(
                f'<div style="border:1px solid #f5c2c7;border-radius:6px;padding:12px 16px;'
                f'margin:0 0 10px 0;background:#fff8f8;">'
                f'<div style="margin-bottom:6px;">'
                f'{_sev_badge_email(c["severity"])}'
                f'&nbsp;<strong>#{_esc(c["defender_id"] or c["ticket"])}</strong>'
                f'&nbsp;<span style="font-size:13px;">{_esc(c["title"][:70])}</span>'
                f'</div>'
                f'<div style="font-size:13px;color:#555;margin-bottom:4px;">'
                f'<strong>User:</strong> {_esc(users_str)} '
                f'<span style="color:#888;">({_esc(dom_type)})</span></div>'
                f'<div style="font-size:13px;color:#555;margin-bottom:4px;">'
                f'<strong>Alerts:</strong> {_esc(alert_list)}</div>'
                f'<div style="font-size:13px;color:#555;margin-bottom:8px;">'
                f'<strong>Action:</strong> {_esc(rec_action)}</div>'
            )
            if c.get("defender_url"):
                parts.append(
                    f'<a href="{_esc(c["defender_url"])}" target="_blank" '
                    f'style="background:#dc3545;color:#fff;padding:5px 12px;border-radius:4px;'
                    f'font-size:12px;font-weight:600;text-decoration:none;">Open in Defender</a>'
                )
            parts.append('</div>')
    else:
        parts.append('<p style="color:#6c757d;font-size:13px;padding:8px 0;">No ESCALATE incidents this run.</p>')

    # Section 2: MANUAL ACTION (compact table, one deep link per row)
    parts.append(
        '<div style="background:#e2e3e5;border-left:4px solid #fd7e14;padding:10px 16px;'
        'margin:16px 0 8px 0;font-size:15px;font-weight:bold;color:#212529;">'
        'MANUAL ACTION REQUIRED</div>'
    )
    if manual_cards:
        th = ('style="background:#343a40;color:#fff;padding:7px 10px;'
              'text-align:left;font-size:12px;"')
        td = ('style="padding:7px 10px;border-bottom:1px solid #dee2e6;'
              'font-size:12px;vertical-align:top;"')
        parts.append(
            f'<table width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse;">'
            f'<tr><th {th}>ID</th><th {th}>User</th><th {th}>Required Step</th><th {th}>Link</th></tr>'
        )
        for c in manual_cards:
            user_str   = c["users"][0] if c["users"] else "unknown"
            step_label = next(
                (s["label"] for s in c["steps"] if s.get("status") == "manual"),
                "Review in Defender",
            )
            link_td = ""
            if c.get("defender_url"):
                link_td = (
                    f'<a href="{_esc(c["defender_url"])}" target="_blank" '
                    f'style="color:#0d6efd;font-size:11px;">Defender</a>'
                )
            parts.append(
                f'<tr>'
                f'<td {td}><strong>#{_esc(c["defender_id"] or c["ticket"])}</strong></td>'
                f'<td {td}>{_esc(user_str)}</td>'
                f'<td {td}>{_esc(step_label[:80])}</td>'
                f'<td {td}>{link_td}</td>'
                f'</tr>'
            )
        parts.append('</table>')
    else:
        parts.append(
            '<p style="color:#6c757d;font-size:13px;padding:8px 0;">'
            'No manual-action incidents this run.</p>'
        )

    # Section 3: Queue health (one line)
    parts.append(
        '<div style="background:#e8f4fd;border-left:4px solid #0d6efd;padding:10px 16px;'
        'margin:16px 0 8px 0;font-size:15px;font-weight:bold;color:#212529;">QUEUE HEALTH</div>'
    )
    parts.append(
        f'<p style="font-size:13px;color:#333;margin:4px 0 16px 0;">'
        f'Open: <strong>{open_count}</strong> | '
        f'Past SLA ({SLA_THRESHOLD_DAYS}d): <strong>{sla_breach_count}</strong> | '
        f'New today: <strong>{new_today_count}</strong> | '
        f'Carried over: <strong>{carried_count}</strong>'
        f'</p>'
    )

    # Section 4: Auto-triaged counts only
    fp_count = sum(
        1 for c in auto_cards
        if any("FALSE POSITIVE" in s.get("label", "").upper() for s in c.get("steps", []))
    )
    nc_count = len(auto_cards) - fp_count
    parts.append(
        '<div style="background:#d1e7dd;border-left:4px solid #28a745;padding:10px 16px;'
        'margin:0 0 8px 0;font-size:15px;font-weight:bold;color:#212529;">'
        'AUTO-TRIAGED (NO ACTION NEEDED)</div>'
    )
    auto_line = f'FP: {fp_count} | No Compromise: {nc_count} | Total: {len(auto_cards)}'
    if report_url:
        auto_line += (
            f' -- <a href="{_esc(report_url)}" style="color:#0d6efd;">full detail in report</a>'
        )
    parts.append(f'<p style="font-size:13px;color:#333;margin:4px 0 16px 0;">{auto_line}</p>')

    # Section 5: Aged/expired count only
    parts.append(
        '<div style="background:#f8d7da;border-left:4px solid #6c757d;padding:10px 16px;'
        'margin:0 0 8px 0;font-size:15px;font-weight:bold;color:#212529;">'
        'AGED / EXPIRED (EXCLUDED)</div>'
    )
    parts.append(
        f'<p style="font-size:13px;color:#333;margin:4px 0 16px 0;">'
        f'{len(aged_cards)} incident(s) no longer found in Defender '
        f'(past 180-day retention). Excluded from action sections above.</p>'
    )

    # Footer
    parts.append(
        f'<hr style="border:none;border-top:1px solid #dee2e6;margin:24px 0 16px 0;">'
        f'<p style="font-size:11px;color:#6c757d;">'
        f'Generated by Barry University AI Automation -- {_esc(now_str)}. '
        f'Reply to <a href="mailto:jmoses@barry.edu">jmoses@barry.edu</a> to adjust rules.'
        f'</p></td></tr></table></body></html>'
    )

    return "\n".join(parts)


# ---------------------------------------------------------------------------
# Send email via Graph sendMail
# ---------------------------------------------------------------------------

def send_email(token, from_addr, to_addrs, subject, html_body):
    recipients = [{"emailAddress": {"address": a.strip()}} for a in to_addrs if a.strip()]
    payload = {
        "message": {
            "subject": subject,
            "body": {"contentType": "HTML", "content": html_body},
            "toRecipients": recipients,
        },
        "saveToSentItems": True,
    }
    url = f"{GRAPH_BASE}/users/{from_addr}/sendMail"
    status, data = graph_post(token, url, payload)
    if status in (200, 202):
        log.info("Digest sent to: %s", ", ".join(to_addrs))
        return True
    log.error("sendMail failed: %s -- %s", status, data)
    return False


# ---------------------------------------------------------------------------
# HTML rendering helpers (full SharePoint report)
# ---------------------------------------------------------------------------

SEV_COLORS = {
    "Critical": "#7b1fa2", "High": "#dc3545",
    "Medium": "#fd7e14",   "Low": "#28a745",
    "aged, unavailable": "#6c757d", "Unknown": "#6c757d",
}
WF_COLORS = {
    "MALWARE": "#c62828", "CREDENTIAL": "#1565c0", "URL": "#e65100",
    "PERSISTENCE": "#880e4f", "EXFILTRATION": "#4a148c",
    "RECON": "#2e7d32", "LATERAL": "#4e342e", "OTHER": "#546e7a",
}


def _badge(text, color, small=False):
    fs  = "11px" if small else "12px"
    pad = "1px 5px" if small else "2px 8px"
    return (
        f'<span style="background:{color};color:#fff;border-radius:4px;'
        f'font-size:{fs};font-weight:700;padding:{pad};white-space:nowrap">'
        f'{_esc(text)}</span>'
    )


def _age_badge(age_days):
    if age_days is None:
        return _badge("age?", "#adb5bd", small=True)
    color = "#dc3545" if age_days > 180 else "#fd7e14" if age_days > 30 else "#28a745"
    return _badge(f"{age_days}d", color, small=True)


def _step_row(step):
    icons  = {"auto": "&#x2705;", "manual": "&#x26A0;&#xFE0F;", "blocked": "&#x1F512;"}
    colors = {"auto": "#1b5e20",  "manual": "#e65100",           "blocked": "#c62828"}
    icon   = icons.get(step["status"], "&#x2022;")
    color  = colors.get(step["status"], "#333")
    link_html = ""
    if step.get("link"):
        link_html = (
            f' <a href="{_esc(step["link"])}" target="_blank" '
            f'style="font-size:11px;color:#1565c0">[open portal]</a>'
        )
    blocked_note = ""
    if step["status"] == "blocked":
        blocked_note = ' <em style="font-size:11px;color:#c62828">(grant permission to automate)</em>'
    return (
        f'<div style="margin:4px 0;padding:4px 6px;border-left:3px solid {color};background:#fafafa">'
        f'<span style="color:{color};font-weight:600">{icon} {_esc(step["label"])}</span>'
        f'{link_html}{blocked_note}'
        f'<div style="font-size:12px;color:#555;margin-top:2px">{_esc(step["detail"])}</div>'
        f'</div>'
    )


# ---------------------------------------------------------------------------
# render_html -- full report for SharePoint
# ---------------------------------------------------------------------------

def render_html(cards, defender_found, defender_expired, oob_ids, repeat_users):
    ts    = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    total = len(cards)

    wf_counts  = defaultdict(int)
    sev_counts = defaultdict(int)
    for c in cards:
        wf_counts[c["workflow"]]  += 1
        sev_counts[c["severity"]] += 1

    wf_labels  = json.dumps(list(wf_counts.keys()))
    wf_values  = json.dumps(list(wf_counts.values()))
    wf_clrs    = json.dumps([WF_COLORS.get(k, "#546e7a") for k in wf_counts])
    sev_labels = json.dumps(list(sev_counts.keys()))
    sev_values = json.dumps(list(sev_counts.values()))
    sev_clrs   = json.dumps([SEV_COLORS.get(k, "#6c757d") for k in sev_counts])

    css = """
    body{font-family:system-ui,sans-serif;margin:0;padding:0;background:#f4f6f8;color:#212529}
    .header{background:#0d1b2a;color:#fff;padding:18px 28px}
    .header h1{margin:0;font-size:1.5rem}
    .header .sub{font-size:0.82rem;color:#90caf9;margin-top:4px}
    .stats{display:flex;gap:14px;padding:16px 28px;flex-wrap:wrap}
    .stat-box{background:#fff;border-radius:8px;padding:12px 20px;min-width:130px;
              box-shadow:0 1px 4px rgba(0,0,0,.12);text-align:center}
    .stat-box .num{font-size:2rem;font-weight:700;color:#0d1b2a}
    .stat-box .lbl{font-size:0.76rem;color:#666;margin-top:2px}
    .charts{display:flex;gap:14px;padding:0 28px 16px;flex-wrap:wrap}
    .chart-wrap{background:#fff;border-radius:8px;padding:12px;
                box-shadow:0 1px 4px rgba(0,0,0,.12);flex:1;min-width:280px}
    .cards{padding:0 28px 40px}
    .section-hdr{padding:10px 16px;font-size:14px;font-weight:bold;
                 color:#fff;margin:16px 0 6px 0;border-radius:4px}
    details{background:#fff;border-radius:8px;margin-bottom:10px;
            box-shadow:0 1px 4px rgba(0,0,0,.1);overflow:hidden}
    details[open]{box-shadow:0 2px 8px rgba(0,0,0,.18)}
    summary{cursor:pointer;padding:10px 16px;list-style:none;display:flex;
            align-items:center;gap:8px;flex-wrap:wrap;user-select:none;background:#fff}
    summary::-webkit-details-marker{display:none}
    summary:hover{background:#f0f4ff}
    .card-body{padding:12px 16px;border-top:1px solid #e9ecef}
    .two-col{display:flex;gap:16px;flex-wrap:wrap}
    .col-facts{flex:1;min-width:240px}
    .col-steps{flex:1.4;min-width:260px}
    .fact-label{font-size:11px;color:#888;text-transform:uppercase;
                letter-spacing:.5px;margin-top:8px}
    .fact-value{font-size:13px;margin:2px 0 0}
    .portal-row{margin-top:12px;display:flex;gap:8px;flex-wrap:wrap}
    .portal-btn{display:inline-block;padding:5px 12px;border-radius:4px;font-size:12px;
                font-weight:600;text-decoration:none;color:#fff;background:#1565c0}
    .portal-btn.grey{background:#546e7a}
    .email-pre{white-space:pre-wrap;font-family:monospace;font-size:12px;
               background:#f8f9fa;border:1px solid #dee2e6;border-radius:4px;
               padding:10px;margin-top:6px;max-height:220px;overflow-y:auto}
    .copy-btn{margin-top:6px;padding:4px 10px;font-size:11px;cursor:pointer;
              background:#e3f2fd;border:1px solid #90caf9;border-radius:4px}
    """

    head = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Barry University -- SOC Triage Report</title>
<script src="https://cdn.plot.ly/plotly-2.27.0.min.js"></script>
<style>{css}</style>
</head>
<body>
<div class="header">
  <h1>Barry University -- SOC Triage Engine</h1>
  <div class="sub">Generated: {_esc(ts)} | SecurityIncident.Read.All</div>
</div>
"""
    return head + _render_body(
        cards, total, defender_found, defender_expired,
        wf_labels, wf_values, wf_clrs,
        sev_labels, sev_values, sev_clrs,
        oob_ids, repeat_users,
    )


def _render_body(cards, total, defender_found, defender_expired,
                 wf_labels, wf_values, wf_clrs, sev_labels, sev_values, sev_clrs,
                 oob_ids, repeat_users):
    parts = []

    escalate_cnt = sum(1 for c in cards if c.get("_triage_class") == "ESCALATE")
    manual_cnt   = sum(1 for c in cards if c.get("_triage_class") == "MANUAL" and c["defender_found"])
    auto_cnt     = sum(1 for c in cards if c.get("_triage_class") == "AUTO_TRIAGED")

    parts.append('<div class="stats">')
    for num, lbl in [
        (total,          "Total Processed"),
        (defender_found, "In Defender"),
        (defender_expired, "Expired / Not Found"),
        (escalate_cnt,   "ESCALATE"),
        (manual_cnt,     "Manual Action"),
        (auto_cnt,       "Auto-Triaged"),
    ]:
        parts.append(
            f'<div class="stat-box"><div class="num">{num}</div>'
            f'<div class="lbl">{lbl}</div></div>'
        )
    parts.append('</div>')

    parts.append(
        '<div class="charts">'
        '<div class="chart-wrap"><div id="wf-chart" style="height:220px"></div></div>'
        '<div class="chart-wrap"><div id="sev-chart" style="height:220px"></div></div>'
        '</div>'
    )

    if oob_ids:
        parts.append(
            f'<div style="background:#fff3cd;border:1px solid #ffc107;border-radius:6px;'
            f'padding:10px 16px;margin:0 28px 16px;font-size:13px;">'
            f'<strong>Out-of-sequence Defender IDs:</strong> '
            f'{_esc(", ".join(sorted(oob_ids)))} -- verify not cross-tenant or mistyped.'
            f'</div>'
        )

    parts.append('<div class="cards">')

    sections = [
        ("ESCALATE",     "#dc3545", "ESCALATE NOW"),
        ("MANUAL",       "#fd7e14", "MANUAL ACTION REQUIRED"),
        ("AUTO_TRIAGED", "#28a745", "AUTO-TRIAGED"),
    ]
    for tier, color, label in sections:
        if tier == "MANUAL":
            tier_cards = [c for c in cards if c.get("_triage_class") == tier and c["defender_found"]]
        else:
            tier_cards = [c for c in cards if c.get("_triage_class") == tier]
        if not tier_cards:
            continue
        parts.append(
            f'<div class="section-hdr" style="background:{color}">{label} ({len(tier_cards)})</div>'
        )
        for idx, c in enumerate(tier_cards):
            _render_card(parts, c, f"{tier}-{idx}", repeat_users, oob_ids)

    expired_cards = [c for c in cards if not c["defender_found"]]
    if expired_cards:
        parts.append('<div class="section-hdr" style="background:#6c757d">AGED / EXPIRED</div>')
        for idx, c in enumerate(expired_cards):
            _render_card(parts, c, f"exp-{idx}", repeat_users, oob_ids)

    parts.append('</div>')  # cards
    return "\n".join(parts) + _render_js(wf_labels, wf_values, wf_clrs, sev_labels, sev_values, sev_clrs)


def _render_card(parts, c, idx, repeat_users, oob_ids):
    sev_color  = SEV_COLORS.get(c["severity"], "#6c757d")
    wf_color   = WF_COLORS.get(c["workflow"], "#546e7a")
    tier       = c.get("_triage_class", "MANUAL")
    open_attr  = ' open' if tier == "ESCALATE" or c["severity"] in ("Critical", "High") else ''
    title_short = _esc(c["title"][:80] + ("..." if len(c["title"]) > 80 else ""))

    repeat_flag = ""
    if c["users"] and any(u in repeat_users for u in c["users"]):
        repeat_flag = (
            ' &nbsp;<span style="color:#e65100;font-size:11px;font-weight:700">REPEAT USER</span>'
        )
    oob_flag = ""
    if c.get("defender_id") and c["defender_id"] in oob_ids:
        oob_flag = (
            ' &nbsp;<span style="color:#c62828;font-size:11px;font-weight:700">ID OUT-OF-SEQ</span>'
        )

    summary_line = (
        f'{_badge(c["severity"], sev_color)}'
        f' &nbsp;{_badge(c["workflow"], wf_color, small=True)}'
        f' &nbsp;<strong style="font-size:13px">#{_esc(c["ticket"])}</strong>'
        f' &nbsp;<span style="font-size:13px">{title_short}</span>'
        f' &nbsp;{_age_badge(c["age_days"])}'
        f'{repeat_flag}{oob_flag}'
    )
    if not c["defender_found"]:
        summary_line += ' &nbsp;<span style="color:#dc3545;font-size:11px">&#x26A0; Expired</span>'

    parts.append(f'<details{open_attr}><summary>{summary_line}</summary>')
    parts.append('<div class="card-body"><div class="two-col">')

    # Left: facts
    parts.append('<div class="col-facts">')
    parts.append(
        f'<div class="fact-label">Alert Date</div>'
        f'<div class="fact-value">{_esc(c["alert_date"])}</div>'
    )
    if c["defender_id"] and c.get("defender_url"):
        parts.append(
            f'<div class="fact-label">Defender Incident</div>'
            f'<div class="fact-value"><a href="{_esc(c["defender_url"])}" '
            f'target="_blank">#{_esc(c["defender_id"])}</a></div>'
        )
    if c["users"]:
        parts.append('<div class="fact-label">Users</div>')
        for u in c["users"]:
            dt, _ = classify_user_domain(u)
            marker = " (REPEAT)" if u in repeat_users else ""
            parts.append(
                f'<div class="fact-value">{_esc(u)} '
                f'<span style="color:#888;font-size:11px">({_esc(dt)}{_esc(marker)})</span></div>'
            )
    if c["devices"]:
        parts.append('<div class="fact-label">Devices</div>')
        for d in c["devices"]:
            parts.append(f'<div class="fact-value">{_esc(d)}</div>')
    if c["ips"]:
        parts.append('<div class="fact-label">IPs</div>')
        for ip in c["ips"][:5]:
            parts.append(f'<div class="fact-value">{_esc(ip)}</div>')
    if c["files"]:
        parts.append('<div class="fact-label">Files / Hashes</div>')
        for f_ in c["files"][:4]:
            parts.append(
                f'<div class="fact-value" style="font-family:monospace;font-size:11px">{_esc(f_)}</div>'
            )
    if c["alert_titles"]:
        parts.append('<div class="fact-label">Alert Titles</div>')
        for at in c["alert_titles"][:4]:
            parts.append(f'<div class="fact-value">{_esc(at)}</div>')
    parts.append('</div>')  # col-facts

    # Right: steps
    parts.append('<div class="col-steps">')
    parts.append('<div style="font-weight:600;font-size:13px;margin-bottom:6px">Triage Checklist</div>')
    for step in c["steps"]:
        parts.append(_step_row(step))

    if c.get("draft_email"):
        em  = c["draft_email"]
        eid = f"email-{idx}"
        parts.append(
            f'<details style="margin-top:10px">'
            f'<summary style="font-size:12px;font-weight:600;cursor:pointer;color:#1565c0">'
            f'&#x2709; Draft Notification Email</summary>'
            f'<div style="margin-top:6px;font-size:12px">'
            f'<strong>To:</strong> {_esc(em["to"])}<br>'
        )
        if em.get("cc"):
            parts.append(f'<strong>CC:</strong> {_esc(em["cc"])}<br>')
        parts.append(
            f'<strong>Subject:</strong> {_esc(em["subject"])}<br>'
            f'<pre class="email-pre" id="{_esc(str(eid))}">{_esc(em["body"])}</pre>'
            f'<button class="copy-btn" onclick="copyEmail(\'{_esc(str(eid))}\')">'
            f'Copy email body</button></div></details>'
        )

    parts.append('</div>')  # col-steps
    parts.append('</div>')  # two-col

    parts.append('<div class="portal-row">')
    if c.get("defender_url"):
        parts.append(
            f'<a class="portal-btn" href="{_esc(c["defender_url"])}" target="_blank">Open in Defender</a>'
        )
    if c.get("outlook_link"):
        parts.append(
            f'<a class="portal-btn grey" href="{_esc(c["outlook_link"])}" target="_blank">Open Oculus Email</a>'
        )
    parts.append(f'<a class="portal-btn grey" href="{_esc(intune_devices_url())}" target="_blank">Search Intune</a>')
    parts.append(f'<a class="portal-btn grey" href="{_esc(signin_logs_url())}" target="_blank">Sign-in Logs</a>')
    parts.append(f'<a class="portal-btn grey" href="{_esc(threat_explorer_url())}" target="_blank">Threat Explorer</a>')
    parts.append('</div>')
    parts.append('</div></details>')  # card-body + details


def _render_js(wf_labels, wf_values, wf_clrs, sev_labels, sev_values, sev_clrs):
    return f"""
<script>
function copyEmail(id) {{
  var el = document.getElementById(id);
  if (!el) return;
  var text = el.innerText;
  navigator.clipboard.writeText(text).then(function() {{
    alert('Email body copied to clipboard.');
  }}, function() {{
    var ta = document.createElement('textarea');
    ta.value = text;
    document.body.appendChild(ta);
    ta.select();
    document.execCommand('copy');
    document.body.removeChild(ta);
    alert('Email body copied.');
  }});
}}
var wfData = [{{
  type: 'pie', labels: {wf_labels}, values: {wf_values},
  marker: {{ colors: {wf_clrs} }}, hole: 0.45,
  textinfo: 'label+value', textfont: {{ size: 11 }}
}}];
Plotly.newPlot('wf-chart', wfData, {{
  title: {{ text: 'By Workflow Type', font: {{ size: 13 }} }},
  margin: {{ t: 36, l: 10, r: 10, b: 10 }}, showlegend: false, paper_bgcolor: '#fff'
}}, {{ responsive: true, displayModeBar: false }});
var sevData = [{{
  type: 'bar', x: {sev_labels}, y: {sev_values},
  marker: {{ color: {sev_clrs} }}
}}];
Plotly.newPlot('sev-chart', sevData, {{
  title: {{ text: 'By Severity', font: {{ size: 13 }} }},
  margin: {{ t: 36, l: 30, r: 10, b: 40 }},
  paper_bgcolor: '#fff', plot_bgcolor: '#fff', yaxis: {{ title: '' }}
}}, {{ responsive: true, displayModeBar: false }});
</script>
</body>
</html>"""


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    xlsx_path = (sys.argv[1] if len(sys.argv) > 1
                 else "/root/.claude/uploads/c707679a-00ba-51ba-9f90-5f1368b412ce/6b75bfd8-SOC_Incidents.xlsx")
    log.info("Loading: %s", xlsx_path)

    wb = openpyxl.load_workbook(xlsx_path)
    ws = wb["Incidents"]
    headers = [ws.cell(1, c).value for c in range(1, ws.max_column + 1)]
    rows = [
        {headers[c - 1]: ws.cell(r, c).value for c in range(1, ws.max_column + 1)}
        for r in range(2, ws.max_row + 1)
    ]

    now_utc   = datetime.now(timezone.utc)
    now_naive = now_utc.replace(tzinfo=None)
    yesterday = now_naive - timedelta(days=1)

    all_pending = [
        r for r in rows
        if r.get("Status") == "Pending Triage" and r.get("Defender Incident ID")
    ]
    open_count = len([r for r in rows if r.get("Status") == "Pending Triage"])

    new_today_count = sum(
        1 for r in all_pending
        if isinstance(r.get("Alert Date UTC"), datetime)
        and r["Alert Date UTC"].replace(tzinfo=None) >= yesterday
    )
    carried_count    = open_count - new_today_count
    sla_breach_count = sum(
        1 for r in all_pending
        if isinstance(r.get("Alert Date UTC"), datetime)
        and (now_naive - r["Alert Date UTC"].replace(tzinfo=None)).days > SLA_THRESHOLD_DAYS
    )

    # Sort oldest-first (most actionable priority within each tier)
    pending = sorted(
        all_pending,
        key=lambda r: r.get("Alert Date UTC") or datetime.min,
        reverse=False,
    )
    log.info("Pending with Defender ID: %d of %d total rows", len(pending), len(rows))

    token = get_access_token()

    cards            = []
    defender_found   = 0
    defender_expired = 0
    cap = min(len(pending), 100)

    for i, soc_row in enumerate(pending[:cap]):
        did = str(soc_row.get("Defender Incident ID"))
        log.info("[%d/%d] Fetching Defender incident %s ...", i + 1, cap, did)

        inc = fetch_defender_incident(token, did)
        if inc:
            defender_found += 1
            ev = extract_evidence(inc)
        else:
            defender_expired += 1
            ev  = {"users": [], "devices": [], "ips": [], "files": [], "alert_titles": []}
            inc = None

        inc_name = (inc or {}).get("displayName", "") or str(soc_row.get("Title") or "")
        workflow = classify_workflow(inc_name, ev["alert_titles"])
        card     = build_triage_card(soc_row, inc, ev, workflow, token=token)
        cards.append(card)
        time.sleep(RATE_DELAY)

    log.info("Processed %d: %d in Defender, %d expired", len(cards), defender_found, defender_expired)

    # Classify, flag, sort
    for c in cards:
        c["_triage_class"] = compute_card_classification(c)

    oob_ids      = flag_oob_ids(cards)
    repeat_users = compute_repeat_users(cards)

    if oob_ids:
        log.warning("Out-of-sequence Defender IDs: %s", ", ".join(sorted(oob_ids)))
    if repeat_users:
        log.info("Repeat users across incidents: %s", ", ".join(sorted(repeat_users)))

    def sort_key(c):
        tier_rank = TIER_ORDER.get(c.get("_triage_class", "MANUAL"), 1)
        sev_rank  = SEV_ORDER.get(c["severity"], 5)
        age       = c["age_days"] or 0
        return (tier_rank, sev_rank, -age)  # oldest-actionable first within each bucket

    cards.sort(key=sort_key)

    # Build and save full HTML report locally
    html = render_html(cards, defender_found, defender_expired, oob_ids, repeat_users)
    os.makedirs("output", exist_ok=True)
    local_out = "output/triage_report.html"
    with open(local_out, "w", encoding="utf-8") as fh:
        fh.write(html)
    size_kb = len(html.encode("utf-8")) // 1024
    log.info("Written locally: %s (%d KB)", local_out, size_kb)

    # Upload full report to SharePoint
    report_url = upload_to_sharepoint(token, html.encode("utf-8"), "triage_report.html")
    if report_url:
        with open("output/sharepoint_url.txt", "w") as fh:
            fh.write(report_url)
        log.info("SharePoint URL saved to output/sharepoint_url.txt")

    # Build and send email digest
    date_str = now_utc.strftime("%A, %B %d, %Y")
    digest_html = build_email_digest(
        cards, report_url, date_str,
        open_count, sla_breach_count, new_today_count, carried_count,
    )
    to_addrs = [a.strip() for a in DIGEST_TO.split(",") if a.strip()]
    sent = send_email(token, DIGEST_FROM, to_addrs,
                      f"Barry IT -- SOC Triage Digest | {date_str}", digest_html)

    escalate_cnt = sum(1 for c in cards if c.get("_triage_class") == "ESCALATE")
    manual_cnt   = sum(1 for c in cards if c.get("_triage_class") == "MANUAL" and c["defender_found"])
    auto_cnt     = sum(1 for c in cards if c.get("_triage_class") == "AUTO_TRIAGED")
    aged_cnt     = sum(1 for c in cards if not c["defender_found"])

    print(f"\nTriage report : {local_out} ({size_kb} KB)")
    print(f"SharePoint    : {report_url or 'upload failed'}")
    print(f"Cards         : {len(cards)}")
    print(f"  ESCALATE    : {escalate_cnt}")
    print(f"  MANUAL      : {manual_cnt}")
    print(f"  AUTO-TRIAGED: {auto_cnt}")
    print(f"  AGED/EXPIRED: {aged_cnt}")
    print(f"OOB IDs       : {', '.join(sorted(oob_ids)) or 'none'}")
    print(f"Repeat users  : {', '.join(sorted(repeat_users)) or 'none'}")
    print(f"Digest        : {'sent' if sent else 'FAILED'} to {DIGEST_TO}")


if __name__ == "__main__":
    main()
