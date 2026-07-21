#!/usr/bin/env python3
"""
phase6_triage_engine.py — Barry University SOC Triage Engine
Correlates SOC_Incidents.xlsx → Microsoft Defender → applies workflow decision tree
Generates output/triage_report.html with pre-filled triage cards for each pending incident

Required permissions: SecurityIncident.Read.All
Optional (unlock full automation):
  AuditLog.Read.All              → auto-pull sign-in logs for credential alerts
  DeviceManagementManagedDevices.Read.All → auto-check Intune ownership for malware
"""
import sys, os, json, time, logging
from datetime import datetime, timezone
from collections import defaultdict
import openpyxl
import msal
import requests

TENANT_ID = os.environ.get("TENANT_ID", "")
CLIENT_ID = os.environ.get("CLIENT_ID", "")
CLIENT_SECRET = os.environ.get("CLIENT_SECRET", "")
TENANT_DISPLAY_ID = "75492414-66ff-4a7c-a7f1-6c6787413d30"
MAILBOX_UPN = os.environ.get("MAILBOX_UPN", "jmoses@barry.edu")
GRAPH_BASE = "https://graph.microsoft.com/v1.0"
RATE_DELAY = 0.3

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
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
    """
    Perform a GET against the Graph API.
    Returns (status_code, data_dict_or_None).
    Retries once on 429 with Retry-After header.
    """
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
    resp = requests.get(url, headers=headers, params=params, timeout=30)
    if resp.status_code == 429:
        retry_after = int(resp.headers.get("Retry-After", "10"))
        log.warning("Rate limited — waiting %ds", retry_after)
        time.sleep(retry_after)
        resp = requests.get(url, headers=headers, params=params, timeout=30)
    if resp.status_code == 200:
        try:
            return 200, resp.json()
        except Exception:
            return 200, {}
    return resp.status_code, None


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
    """Returns workflow type string based on incident name and alert titles."""
    combined = (incident_name + " " + " ".join(alert_titles)).lower()
    for wtype, keywords in WORKFLOW_RULES:
        if any(kw in combined for kw in keywords):
            return wtype
    return "OTHER"


# ---------------------------------------------------------------------------
# User domain classification
# ---------------------------------------------------------------------------

def classify_user_domain(email):
    """Returns (domain_type, contact_action) based on email domain."""
    if not email:
        return ("UNKNOWN", "Manual lookup required")
    e = email.lower()
    if e.endswith("@barry.edu"):
        return ("STAFF_FACULTY", "Contact user directly, schedule on-site scan if malware")
    if e.endswith("@mymail.barry.edu"):
        return ("STUDENT", "Email student, recommend they scan device")
    if e.endswith("@law.barry.edu"):
        return ("LAW_STUDENT", "Email student AND CC Law IT staff")
    return ("EXTERNAL", "External account — investigate if Barry systems accessed")


# ---------------------------------------------------------------------------
# Deep-link builders
# ---------------------------------------------------------------------------

def defender_incident_url(incident_id):
    return f"https://security.microsoft.com/incident2/{incident_id}/overview?tid={TENANT_DISPLAY_ID}"


def defender_alert_url(alert_id):
    return f"https://security.microsoft.com/alerts/{alert_id}?tid={TENANT_DISPLAY_ID}"


def azure_ad_user_url(upn):
    return "https://portal.azure.com/#view/Microsoft_AAD_UsersAndTenants/UserManagementMenuBlade/~/AllUsers"


def intune_devices_url():
    return "https://intune.microsoft.com/#view/Microsoft_Intune_DeviceSettings/DevicesMenu/~/allDevices"


def signin_logs_url(upn=None):
    return "https://portal.azure.com/#view/Microsoft_AAD_IAM/SignInEventsV3Blade"


def threat_explorer_url():
    return f"https://security.microsoft.com/threatexplorerv3?tid={TENANT_DISPLAY_ID}"


# ---------------------------------------------------------------------------
# Defender incident fetcher
# ---------------------------------------------------------------------------

def fetch_defender_incident(token, defender_id):
    """Fetch a Defender incident with expanded alerts and evidence. Returns dict or None."""
    url = f"{GRAPH_BASE}/security/incidents/{defender_id}?$expand=alerts"
    status, data = graph_get(token, url)
    if status == 200:
        return data
    if status == 404:
        return None  # expired — Defender keeps ~180 days
    log.warning("Defender incident %s: HTTP %s", defender_id, status)
    return None


# ---------------------------------------------------------------------------
# Sign-in log fetcher + analyzer (requires AuditLog.Read.All)
# ---------------------------------------------------------------------------

def fetch_signin_logs(token, upn, top=50):
    """Fetch recent sign-in logs for a user. Returns list of sign-in dicts."""
    status, data = graph_get(token, f"{GRAPH_BASE}/auditLogs/signIns", params={
        "$filter": f"userPrincipalName eq '{upn}'",
        "$top": top,
        "$select": "id,createdDateTime,ipAddress,location,status,deviceDetail,"
                   "authenticationRequirement,resourceDisplayName,riskLevelAggregated",
    })
    if status == 200:
        return data.get("value", [])
    log.warning("Sign-in logs for %s: HTTP %s", upn, status)
    return []


def analyze_signin_logs(logs, alert_dt=None):
    """
    Apply the account compromise decision tree from the workflow doc.
    Returns dict with: classification, summary, known_devices, suspicious_events.
    Classifications: FP | NO_COMPROMISE | POSSIBLE_COMPROMISE | ESCALATE
    """
    if not logs:
        return {"classification": "UNKNOWN", "summary": "No sign-in logs available",
                "known_devices": [], "suspicious_events": []}

    # Split into successful vs failed
    successful = [s for s in logs if s.get("status", {}).get("errorCode") == 0]
    failed     = [s for s in logs if s.get("status", {}).get("errorCode") != 0]

    # Collect known good device fingerprints from successful logins before alert
    known_os_browsers = set()
    for s in successful:
        d = s.get("deviceDetail", {})
        fp = f"{d.get('operatingSystem','')}/{d.get('browser','')}"
        if fp != "/": known_os_browsers.add(fp)

    # Find suspicious events near alert time
    suspicious = []
    for s in logs:
        loc = s.get("location", {})
        country = loc.get("countryOrRegion", "")
        if country and country not in ("US", "United States", ""):
            suspicious.append({
                "time": s.get("createdDateTime", "")[:16],
                "ip": s.get("ipAddress", ""),
                "location": f"{loc.get('city','')}, {country}",
                "result": "Success" if s.get("status", {}).get("errorCode") == 0 else "Failed",
                "resource": s.get("resourceDisplayName", ""),
            })

    # Classification logic
    classification = "UNKNOWN"
    summary = ""

    successful_non_us = [s for s in suspicious if s["result"] == "Success"]
    failed_wrong_pw = [s for s in failed
                       if "incorrect password" in (s.get("status",{}).get("failureReason","")).lower()]

    if not suspicious:
        classification = "FP"
        summary = "All sign-ins from US locations. No anomalous geography detected."
    elif successful_non_us:
        non_o365 = [s for s in successful_non_us
                    if "office" not in s["resource"].lower() and "microsoft" not in s["resource"].lower()]
        if non_o365:
            classification = "ESCALATE"
            summary = (f"Successful login from {successful_non_us[0]['location']} to non-O365 service "
                       f"({non_o365[0]['resource']}). Possible account compromise — escalate.")
        else:
            classification = "POSSIBLE_COMPROMISE"
            summary = (f"Successful login from {successful_non_us[0]['location']} "
                       f"({successful_non_us[0]['ip']}). Check for phishing sent from account.")
    elif failed_wrong_pw:
        classification = "NO_COMPROMISE"
        summary = (f"{len(failed_wrong_pw)} failed login attempt(s) with incorrect password from "
                   f"outside US. Account not compromised — contact user to change password.")
    else:
        classification = "NO_COMPROMISE"
        summary = f"{len(suspicious)} suspicious sign-in(s) detected, all failed. Account not compromised."

    return {
        "classification": classification,
        "summary": summary,
        "known_devices": sorted(known_os_browsers),
        "suspicious_events": suspicious[:5],
    }


# ---------------------------------------------------------------------------
# Intune device ownership checker (requires DeviceManagementManagedDevices.Read.All)
# ---------------------------------------------------------------------------

def check_intune_ownership(token, upn=None, device_name=None):
    """
    Look up Intune managed devices by UPN or device name.
    Returns list of dicts with deviceName, managedDeviceOwnerType, operatingSystem, lastSyncDateTime.
    """
    params = {"$select": "id,deviceName,managedDeviceOwnerType,operatingSystem,lastSyncDateTime,complianceState"}
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
    """Extract users, devices, IPs, file hashes from all alerts in an incident."""
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
        "users": sorted(users),
        "devices": sorted(devices),
        "ips": sorted(ips),
        "files": sorted(files),
        "alert_titles": alert_titles,
    }


# ---------------------------------------------------------------------------
# Triage card builder
# ---------------------------------------------------------------------------

def build_triage_card(soc_row, defender_inc, evidence, workflow, token=None):
    """Build a triage card dict for one incident."""
    ticket     = str(soc_row.get("Ticket #") or "")
    title      = str(soc_row.get("Title") or "")
    severity   = str(soc_row.get("Severity") or "Unknown")
    alert_date = soc_row.get("Alert Date UTC")
    defender_id = str(soc_row.get("Defender Incident ID") or "")

    # Age in days
    age_days = None
    if isinstance(alert_date, datetime):
        age_days = (datetime.now() - alert_date.replace(tzinfo=None)).days

    # Workflow-specific next steps (with live API calls when token provided)
    steps = build_workflow_steps(workflow, evidence, soc_row, token=token)

    # Draft notification email if user known
    draft_email = None
    if evidence["users"]:
        draft_email = build_draft_email(
            workflow, evidence["users"][0], ticket, title, alert_date
        )

    return {
        "ticket":         ticket,
        "title":          title,
        "severity":       severity,
        "age_days":       age_days,
        "alert_date":     alert_date.strftime("%Y-%m-%d %H:%M UTC")
                          if isinstance(alert_date, datetime) else "",
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
    """
    Return list of step dicts:
      {"label": str, "status": "auto"|"manual"|"blocked", "detail": str, "link": str}
    Pass token to enable live sign-in log and Intune lookups.
    """
    steps = []
    users   = evidence["users"]
    devices = evidence["devices"]
    ips     = evidence["ips"]
    alert_dt = soc_row.get("Alert Date UTC")

    if workflow == "MALWARE":
        steps.append({"label": "Incident type identified: Malware Detected",
                      "status": "auto",
                      "detail": "Matches malware workflow",
                      "link": ""})
        # Intune ownership check — now automated
        intune_checked = False
        for user in users[:2]:
            if token:
                devices_intune = check_intune_ownership(token, upn=user)
                for d in devices_intune:
                    ownership = d.get("managedDeviceOwnerType", "unknown")
                    dev_name  = d.get("deviceName", "?")
                    last_sync = str(d.get("lastSyncDateTime", ""))[:10]
                    verdict   = "Barry-owned — run scan" if ownership == "company" else "Personal device — not our responsibility"
                    steps.append({"label": f"Intune: {dev_name} → {ownership.upper()} ({verdict})",
                                   "status": "auto",
                                   "detail": f"Last sync: {last_sync} | Compliance: {d.get('complianceState','')}",
                                   "link": intune_devices_url()})
                    intune_checked = True
        if not intune_checked:
            for dev in devices[:3]:
                steps.append({"label": f"Check device in Intune: {dev}",
                               "status": "manual",
                               "detail": "Ownership: Personal = not our device | Corporate = Barry device",
                               "link": intune_devices_url()})
            if not devices:
                steps.append({"label": "Device not found in Defender evidence",
                               "status": "manual",
                               "detail": "Open incident in Defender to identify device manually",
                               "link": ""})
        for user in users[:2]:
            domain_type, action = classify_user_domain(user)
            steps.append({"label": f"Notify user: {user}",
                           "status": "auto" if domain_type != "UNKNOWN" else "manual",
                           "detail": action, "link": ""})
        steps.append({"label": "Trigger scan via Intune",
                       "status": "manual",
                       "detail": "If Corporate device: open device in Intune → top menu → Quick Scan or Full Scan",
                       "link": intune_devices_url()})

    elif workflow == "CREDENTIAL":
        steps.append({"label": "Incident type: Credential/Sign-in Alert",
                       "status": "auto",
                       "detail": "Matches credential workflow",
                       "link": ""})
        if users:
            for user in users[:2]:
                if token:
                    # Live sign-in log fetch and analysis
                    logs = fetch_signin_logs(token, user)
                    analysis = analyze_signin_logs(logs, alert_dt)
                    clf = analysis["classification"]
                    clf_colors = {"FP": "✅ FALSE POSITIVE", "NO_COMPROMISE": "⚠️ NO COMPROMISE",
                                  "POSSIBLE_COMPROMISE": "🔴 POSSIBLE COMPROMISE", "ESCALATE": "🚨 ESCALATE"}
                    steps.append({"label": f"Sign-in analysis for {user}: {clf_colors.get(clf, clf)}",
                                   "status": "auto",
                                   "detail": analysis["summary"],
                                   "link": signin_logs_url(user)})
                    if analysis["suspicious_events"]:
                        locs = ", ".join(f"{e['location']} ({e['result']})" for e in analysis["suspicious_events"][:3])
                        steps.append({"label": f"Suspicious locations detected: {locs}",
                                       "status": "auto",
                                       "detail": f"{len(logs)} total sign-ins analyzed. Known devices: {', '.join(analysis['known_devices'][:2]) or 'none'}",
                                       "link": ""})
                    if clf in ("POSSIBLE_COMPROMISE", "ESCALATE"):
                        steps.append({"label": "Check Threat Explorer for phishing sent from account",
                                       "status": "manual",
                                       "detail": f"Filter by sender {user} from alert date",
                                       "link": threat_explorer_url()})
                else:
                    steps.append({"label": f"Pull sign-in logs for {user}",
                                   "status": "manual",
                                   "detail": "Review last 30 days of sign-ins in Azure AD",
                                   "link": signin_logs_url(user)})
                steps.append({"label": f"Check auth methods for {user}",
                               "status": "manual",
                               "detail": "Note default MFA method and registered devices",
                               "link": azure_ad_user_url(user)})
        if ips:
            steps.append({"label": f"Suspicious IPs: {', '.join(ips[:3])}",
                           "status": "auto",
                           "detail": "IPs extracted from Defender evidence",
                           "link": ""})

    elif workflow == "URL":
        steps.append({"label": "Incident type: Malicious URL",
                       "status": "auto",
                       "detail": "Matches URL workflow",
                       "link": ""})
        steps.append({"label": "Submit URL to VirusTotal",
                       "status": "manual",
                       "detail": "Open VirusTotal and submit the URL from the alert to confirm malware classification",
                       "link": "https://www.virustotal.com/gui/home/url"})
        steps.append({"label": "Search Threat Explorer for related emails",
                       "status": "manual",
                       "detail": "Filter by sender and date — if multiple emails with same subject, could be phishing campaign",
                       "link": threat_explorer_url()})
        for user in users[:2]:
            steps.append({"label": f"Check if account compromised: {user}",
                           "status": "manual",
                           "detail": "Follow credential compromise checklist for this user",
                           "link": ""})

    elif workflow == "PERSISTENCE":
        steps.append({"label": "Incident type: Persistence / Mail Rule",
                       "status": "auto",
                       "detail": "Mail forwarding or inbox rule — HIGH priority, possible BEC",
                       "link": ""})
        for user in users[:2]:
            steps.append({"label": f"Audit mailbox rules for {user}",
                           "status": "manual",
                           "detail": "Check Outlook rules and forwarding settings immediately",
                           "link": azure_ad_user_url(user)})
        steps.append({"label": "Check for outbound phishing from affected account",
                       "status": "manual",
                       "detail": "Use Threat Explorer to look for sent emails on the alert date",
                       "link": threat_explorer_url()})

    else:
        steps.append({"label": f"Workflow type: {workflow}",
                       "status": "manual",
                       "detail": "No automated steps for this alert type — manual review required",
                       "link": ""})

    return steps


# ---------------------------------------------------------------------------
# Draft email builder
# ---------------------------------------------------------------------------

def build_draft_email(workflow, user_email, ticket, incident_title, alert_date):
    """Build a draft notification email dict for the affected user."""
    domain_type, _ = classify_user_domain(user_email)
    date_str = (alert_date.strftime("%B %d, %Y")
                if isinstance(alert_date, datetime) else "recently")

    if workflow == "MALWARE":
        if domain_type in ("STAFF_FACULTY",):
            return {
                "to": user_email,
                "cc": "",
                "subject": f"Action Required: Security Alert on Your Device — Ticket {ticket}",
                "body": f"""Hi,

Our security monitoring system detected a potential malware alert associated with your account or device on {date_str} (Ticket #{ticket}).

We need to schedule a time to scan your device. Please reply to this email so we can coordinate.

In the meantime:
- Do not open any unexpected attachments or click unfamiliar links.
- If your computer is behaving unusually (slow, unexpected pop-ups, programs running on their own), please let us know immediately.

This is not an accusation — malware can reach any device through email, websites, or USB drives. We're here to help resolve it quickly.

Please reply to schedule an on-site scan.

Barry University IT Security
jmoses@barry.edu""",
            }
        else:
            cc = "lawit@barry.edu" if domain_type == "LAW_STUDENT" else ""
            return {
                "to": user_email,
                "cc": cc,
                "subject": f"Important: Security Alert — Please Scan Your Device (Ticket {ticket})",
                "body": f"""Hi,

Our security system detected a potential issue associated with your account on {date_str} (Ticket #{ticket}).

We recommend you scan your device as soon as possible:
1. Windows: Open Windows Security > Virus & Threat Protection > Quick Scan
2. Mac: Run Malwarebytes Free (malwarebytes.com)

If you need help or your device is acting strangely, contact the Help Desk at helpdesk@barry.edu.

Barry University IT Security""",
            }

    elif workflow == "CREDENTIAL":
        return {
            "to": user_email,
            "cc": "",
            "subject": f"Security Notice: Unusual Sign-In Activity on Your Account (Ticket {ticket})",
            "body": f"""Hi,

We detected unusual sign-in activity on your Barry University account on {date_str} (Ticket #{ticket}).

Please review this and take action:
1. Log in to mybarry.barry.edu and change your password immediately.
2. Review your recent sign-in activity at https://mysignins.microsoft.com/security-info
3. If you did not attempt to log in from an unusual location or device, reply to this email immediately.

If you believe your account has been compromised, contact IT Security at jmoses@barry.edu right away.

Barry University IT Security""",
        }

    return None


# ---------------------------------------------------------------------------
# HTML rendering helpers
# ---------------------------------------------------------------------------

SEV_COLORS = {
    "Critical": "#7b1fa2", "High": "#dc3545",
    "Medium": "#fd7e14",   "Low": "#28a745", "Unknown": "#6c757d",
}
WF_COLORS = {
    "MALWARE": "#c62828", "CREDENTIAL": "#1565c0", "URL": "#e65100",
    "PERSISTENCE": "#880e4f", "EXFILTRATION": "#4a148c",
    "RECON": "#2e7d32", "LATERAL": "#4e342e", "OTHER": "#546e7a",
}


def _esc(s):
    """HTML-escape a string."""
    return (str(s)
            .replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))


def _badge(text, color, small=False):
    fs = "11px" if small else "12px"
    pad = "1px 5px" if small else "2px 8px"
    return (f'<span style="background:{color};color:#fff;border-radius:4px;'
            f'font-size:{fs};font-weight:700;padding:{pad};white-space:nowrap">'
            f'{_esc(text)}</span>')


def _age_badge(age_days):
    if age_days is None:
        return _badge("age?", "#adb5bd", small=True)
    color = "#dc3545" if age_days > 180 else "#fd7e14" if age_days > 30 else "#28a745"
    return _badge(f"{age_days}d", color, small=True)


def _step_row(step):
    icons = {"auto": "&#x2705;", "manual": "&#x26A0;&#xFE0F;", "blocked": "&#x1F512;"}
    colors = {"auto": "#1b5e20", "manual": "#e65100", "blocked": "#c62828"}
    icon = icons.get(step["status"], "&#x2022;")
    color = colors.get(step["status"], "#333")
    link_html = ""
    if step.get("link"):
        link_html = (f' <a href="{_esc(step["link"])}" target="_blank" '
                     f'style="font-size:11px;color:#1565c0">[open portal]</a>')
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
# render_html — main HTML assembly
# ---------------------------------------------------------------------------

def render_html(cards, defender_found, defender_expired):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    total = len(cards)

    # Summary counts
    wf_counts = defaultdict(int)
    sev_counts = defaultdict(int)
    for c in cards:
        wf_counts[c["workflow"]] += 1
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
    .chart-wrap{background:#fff;border-radius:8px;padding:12px;box-shadow:0 1px 4px rgba(0,0,0,.12);flex:1;min-width:280px}
    .cards{padding:0 28px 40px}
    details{background:#fff;border-radius:8px;margin-bottom:10px;box-shadow:0 1px 4px rgba(0,0,0,.1);overflow:hidden}
    details[open]{box-shadow:0 2px 8px rgba(0,0,0,.18)}
    summary{cursor:pointer;padding:10px 16px;list-style:none;display:flex;align-items:center;
            gap:8px;flex-wrap:wrap;user-select:none;background:#fff}
    summary::-webkit-details-marker{display:none}
    summary:hover{background:#f0f4ff}
    .card-body{padding:12px 16px;border-top:1px solid #e9ecef}
    .two-col{display:flex;gap:16px;flex-wrap:wrap}
    .col-facts{flex:1;min-width:240px}
    .col-steps{flex:1.4;min-width:260px}
    .fact-label{font-size:11px;color:#888;text-transform:uppercase;letter-spacing:.5px;margin-top:8px}
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
<title>Barry University — SOC Triage Report</title>
<script src="https://cdn.plot.ly/plotly-2.27.0.min.js"></script>
<style>{css}</style>
</head>
<body>
<div class="header">
  <h1>Barry University &mdash; SOC Triage Engine</h1>
  <div class="sub">Generated: {_esc(ts)} &nbsp;|&nbsp; SecurityIncident.Read.All</div>
</div>
"""
    return head + _render_body(cards, total, defender_found, defender_expired,
                               wf_labels, wf_values, wf_clrs,
                               sev_labels, sev_values, sev_clrs)


def _render_body(cards, total, defender_found, defender_expired,
                 wf_labels, wf_values, wf_clrs, sev_labels, sev_values, sev_clrs):
    parts = []

    # Stats bar
    parts.append('<div class="stats">')
    for num, lbl in [
        (total, "Total Processed"),
        (defender_found, "In Defender"),
        (defender_expired, "Expired / Not Found"),
    ]:
        parts.append(f'<div class="stat-box"><div class="num">{num}</div>'
                     f'<div class="lbl">{lbl}</div></div>')
    parts.append('</div>')

    # Charts
    parts.append('<div class="charts">'
                 '<div class="chart-wrap"><div id="wf-chart" style="height:220px"></div></div>'
                 '<div class="chart-wrap"><div id="sev-chart" style="height:220px"></div></div>'
                 '</div>')

    # Triage cards
    parts.append('<div class="cards">')
    for idx, c in enumerate(cards):
        sev_color = SEV_COLORS.get(c["severity"], "#6c757d")
        wf_color  = WF_COLORS.get(c["workflow"], "#546e7a")
        open_attr = ' open' if c["severity"] in ("Critical", "High") else ''
        title_short = _esc(c["title"][:80] + ("…" if len(c["title"]) > 80 else ""))

        summary_line = (
            f'{_badge(c["severity"], sev_color)}'
            f' &nbsp;{_badge(c["workflow"], wf_color, small=True)}'
            f' &nbsp;<strong style="font-size:13px">#{_esc(c["ticket"])}</strong>'
            f' &nbsp;<span style="font-size:13px">{title_short}</span>'
            f' &nbsp;{_age_badge(c["age_days"])}'
        )
        if not c["defender_found"]:
            summary_line += ' &nbsp;<span style="color:#dc3545;font-size:11px">&#x26A0; Expired</span>'

        parts.append(f'<details{open_attr}><summary>{summary_line}</summary>')
        parts.append('<div class="card-body"><div class="two-col">')

        # --- Left column: facts ---
        parts.append('<div class="col-facts">')
        parts.append(f'<div class="fact-label">Alert Date</div>'
                     f'<div class="fact-value">{_esc(c["alert_date"])}</div>')
        if c["defender_id"] and c["defender_url"]:
            parts.append(f'<div class="fact-label">Defender Incident</div>'
                         f'<div class="fact-value"><a href="{_esc(c["defender_url"])}" '
                         f'target="_blank">#{_esc(c["defender_id"])}</a></div>')
        if c["users"]:
            parts.append('<div class="fact-label">Users</div>')
            for u in c["users"]:
                dt, _ = classify_user_domain(u)
                parts.append(f'<div class="fact-value">{_esc(u)} '
                              f'<span style="color:#888;font-size:11px">({_esc(dt)})</span></div>')
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
                parts.append(f'<div class="fact-value" style="font-family:monospace;font-size:11px">{_esc(f_)}</div>')
        if c["alert_titles"]:
            parts.append('<div class="fact-label">Alert Titles</div>')
            for at in c["alert_titles"][:4]:
                parts.append(f'<div class="fact-value">{_esc(at)}</div>')
        parts.append('</div>')  # col-facts

        # --- Right column: steps ---
        parts.append('<div class="col-steps">')
        parts.append('<div style="font-weight:600;font-size:13px;margin-bottom:6px">Triage Checklist</div>')
        for step in c["steps"]:
            parts.append(_step_row(step))

        # Draft email
        if c.get("draft_email"):
            em = c["draft_email"]
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
                f'<pre class="email-pre" id="{_esc(eid)}">{_esc(em["body"])}</pre>'
                f'<button class="copy-btn" onclick="copyEmail(\'{_esc(eid)}\')">'
                f'Copy email body</button></div></details>'
            )

        parts.append('</div>')  # col-steps
        parts.append('</div>')  # two-col

        # Portal links row
        parts.append('<div class="portal-row">')
        if c["defender_url"]:
            parts.append(f'<a class="portal-btn" href="{_esc(c["defender_url"])}" target="_blank">Open in Defender</a>')
        if c["outlook_link"]:
            parts.append(f'<a class="portal-btn grey" href="{_esc(c["outlook_link"])}" target="_blank">Open Oculus Email</a>')
        parts.append(f'<a class="portal-btn grey" href="{_esc(intune_devices_url())}" target="_blank">Search Intune</a>')
        parts.append(f'<a class="portal-btn grey" href="{_esc(signin_logs_url())}" target="_blank">Sign-in Logs</a>')
        parts.append(f'<a class="portal-btn grey" href="{_esc(threat_explorer_url())}" target="_blank">Threat Explorer</a>')
        parts.append('</div>')

        parts.append('</div></details>')  # card-body + details

    parts.append('</div>')  # cards
    return "\n".join(parts) + _render_js(wf_labels, wf_values, wf_clrs, sev_labels, sev_values, sev_clrs)


def _render_js(wf_labels, wf_values, wf_clrs, sev_labels, sev_values, sev_clrs):
    return f"""
<script>
// Copy-to-clipboard for draft emails
function copyEmail(id) {{
  var el = document.getElementById(id);
  if (!el) return;
  var text = el.innerText;
  navigator.clipboard.writeText(text).then(function() {{
    alert('Email body copied to clipboard.');
  }}, function() {{
    // Fallback
    var ta = document.createElement('textarea');
    ta.value = text;
    document.body.appendChild(ta);
    ta.select();
    document.execCommand('copy');
    document.body.removeChild(ta);
    alert('Email body copied.');
  }});
}}

// Plotly charts
var wfData = [{{
  type: 'pie',
  labels: {wf_labels},
  values: {wf_values},
  marker: {{ colors: {wf_clrs} }},
  hole: 0.45,
  textinfo: 'label+value',
  textfont: {{ size: 11 }}
}}];
Plotly.newPlot('wf-chart', wfData, {{
  title: {{ text: 'By Workflow Type', font: {{ size: 13 }} }},
  margin: {{ t: 36, l: 10, r: 10, b: 10 }},
  showlegend: false,
  paper_bgcolor: '#fff'
}}, {{ responsive: true, displayModeBar: false }});

var sevData = [{{
  type: 'bar',
  x: {sev_labels},
  y: {sev_values},
  marker: {{ color: {sev_clrs} }}
}}];
Plotly.newPlot('sev-chart', sevData, {{
  title: {{ text: 'By Severity', font: {{ size: 13 }} }},
  margin: {{ t: 36, l: 30, r: 10, b: 40 }},
  paper_bgcolor: '#fff',
  plot_bgcolor: '#fff',
  yaxis: {{ title: '' }}
}}, {{ responsive: true, displayModeBar: false }});
</script>
</body>
</html>"""


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    # 1. Load SOC incidents
    xlsx_path = sys.argv[1] if len(sys.argv) > 1 else \
        "/root/.claude/uploads/c707679a-00ba-51ba-9f90-5f1368b412ce/6b75bfd8-SOC_Incidents.xlsx"
    log.info("Loading: %s", xlsx_path)

    wb = openpyxl.load_workbook(xlsx_path)
    ws = wb["Incidents"]
    headers = [ws.cell(1, c).value for c in range(1, ws.max_column + 1)]
    rows = [
        {headers[c - 1]: ws.cell(r, c).value for c in range(1, ws.max_column + 1)}
        for r in range(2, ws.max_row + 1)
    ]

    # 2. Filter to Pending Triage rows that have a Defender ID
    pending = [
        r for r in rows
        if r.get("Status") == "Pending Triage" and r.get("Defender Incident ID")
    ]
    # Sort most recent first (more likely to still be in Defender's ~180-day window)
    pending.sort(
        key=lambda r: r.get("Alert Date UTC") or datetime.min,
        reverse=True,
    )
    log.info("Pending with Defender ID: %d of %d total", len(pending), len(rows))

    # 3. Acquire token
    token = get_access_token()

    # 4. Process each incident
    cards = []
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
            ev = {"users": [], "devices": [], "ips": [], "files": [], "alert_titles": []}
            inc = None

        inc_name = (inc or {}).get("displayName", "") or str(soc_row.get("Title") or "")
        workflow = classify_workflow(inc_name, ev["alert_titles"])
        card = build_triage_card(soc_row, inc, ev, workflow, token=token)
        cards.append(card)
        time.sleep(RATE_DELAY)

    log.info(
        "Processed %d incidents: %d in Defender, %d expired/not found",
        len(cards), defender_found, defender_expired,
    )

    # 5. Sort: Critical first, then High, then by age descending
    sev_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Unknown": 4}
    cards.sort(key=lambda c: (sev_order.get(c["severity"], 4), -(c["age_days"] or 0)))

    # 6. Build and write HTML report
    html = render_html(cards, defender_found, defender_expired)
    os.makedirs("output", exist_ok=True)
    out = "output/triage_report.html"
    with open(out, "w", encoding="utf-8") as f:
        f.write(html)

    size_kb = len(html.encode("utf-8")) // 1024
    log.info("Written: %s (%d KB)", out, size_kb)
    print(f"\nTriage report : {out}")
    print(f"Cards         : {len(cards)}")
    print(f"Defender found: {defender_found}")
    print(f"Expired       : {defender_expired}")
    print(f"HTML size     : {size_kb} KB")


if __name__ == "__main__":
    main()
