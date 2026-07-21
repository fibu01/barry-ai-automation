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

def build_triage_card(soc_row, defender_inc, evidence, workflow):
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

    # Workflow-specific next steps
    steps = build_workflow_steps(workflow, evidence, soc_row)

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

def build_workflow_steps(workflow, evidence, soc_row):
    """
    Return list of step dicts:
      {"label": str, "status": "auto"|"manual"|"blocked", "detail": str, "link": str}
    """
    steps = []
    users   = evidence["users"]
    devices = evidence["devices"]
    ips     = evidence["ips"]

    if workflow == "MALWARE":
        steps.append({"label": "Incident type identified: Malware Detected",
                      "status": "auto",
                      "detail": "Matches malware workflow",
                      "link": ""})
        if devices:
            for dev in devices[:3]:
                steps.append({"label": f"Check device in Intune: {dev}",
                               "status": "manual",
                               "detail": "Check Ownership: Personal = not our device | Corporate = Barry device",
                               "link": intune_devices_url()})
        else:
            steps.append({"label": "Check affected device in Intune",
                           "status": "blocked",
                           "detail": "Device not identified in Defender evidence — open incident in Defender to find device",
                           "link": ""})
        for user in users[:2]:
            domain_type, action = classify_user_domain(user)
            steps.append({"label": f"Notify user: {user}",
                           "status": "auto" if domain_type != "UNKNOWN" else "manual",
                           "detail": action,
                           "link": ""})
        steps.append({"label": "Check last scan dates in Defender/Intune",
                       "status": "manual",
                       "detail": "Look for Last Full Scan and Last Quick Scan. Trigger scan if outdated.",
                       "link": intune_devices_url()})

    elif workflow == "CREDENTIAL":
        steps.append({"label": "Incident type: Credential/Sign-in Alert",
                       "status": "auto",
                       "detail": "Matches credential workflow",
                       "link": ""})
        if users:
            for user in users[:2]:
                steps.append({"label": f"Pull sign-in logs for {user}",
                               "status": "blocked",
                               "detail": "Requires AuditLog.Read.All permission — grant in Azure AD App Registration to automate",
                               "link": signin_logs_url(user)})
                steps.append({"label": f"Check auth methods for {user}",
                               "status": "manual",
                               "detail": "Note default MFA method and registered devices",
                               "link": azure_ad_user_url(user)})
                steps.append({"label": f"Classify login attempt for {user}",
                               "status": "manual",
                               "detail": ("Same device + MFA passed = likely FP | "
                                          "Different device + wrong password = no compromise | "
                                          "Correct password + success = investigate"),
                               "link": ""})
        if ips:
            steps.append({"label": f"Suspicious IPs identified: {', '.join(ips[:3])}",
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
