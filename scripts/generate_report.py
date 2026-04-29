#!/usr/bin/env python3
"""
Barry University SOC — HTML Suppression Report Generator
Reads phase1/3/4 CSVs and produces output/suppression_report.html
"""

import os
from datetime import datetime

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUTPUT_DIR = os.path.join(BASE_DIR, "output")
REPORT_PATH = os.path.join(OUTPUT_DIR, "suppression_report.html")

# ---------------------------------------------------------------------------
# Pre-computed constants (do not recalculate)
# ---------------------------------------------------------------------------
TOTAL_SOC_EMAILS   = 4300
UNIQUE_TICKETS     = 1401
DATE_RANGE         = "Apr 2024 – Apr 2026"
TOTAL_INCIDENTS    = 7654
HIGH_SEVERITY      = 1605
ACTIVE_INCIDENTS   = 2611
MEAN_RESPONSE_H    = 18.2
MEDIAN_RESPONSE_H  = 9.0
FALSE_POSITIVE_RATE = 10.7
ANNUAL_EMAIL_VOL   = 2150
POST_SUPPRESS_VOL  = 1100
REDUCTION_PCT      = 49

# ---------------------------------------------------------------------------
# Tier color map
# ---------------------------------------------------------------------------
TIER_COLORS = {
    "SUPPRESS NOW":            {"bg": "#dc2626", "text": "#fff"},
    "SUPPRESS IF MFA PASSED":  {"bg": "#ea580c", "text": "#fff"},
    "SUPPRESS SUB-TYPE":       {"bg": "#d97706", "text": "#fff"},
    "DAILY DIGEST ONLY":       {"bg": "#2563eb", "text": "#fff"},
    "PARTIAL SUPPRESS":        {"bg": "#16a34a", "text": "#fff"},
}

# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def tier_badge(tier):
    c = TIER_COLORS.get(tier, {"bg": "#6b7280", "text": "#fff"})
    return (
        f'<span class="tier-badge" style="background:{c["bg"]};color:{c["text"]}">'
        f'{tier}</span>'
    )

def noise_bar(pct):
    color = (
        "#dc2626" if pct >= 80
        else "#ea580c" if pct >= 60
        else "#d97706" if pct >= 40
        else "#2563eb"
    )
    return (
        f'<div class="noise-bar-wrap">'
        f'<div class="noise-bar-fill" style="width:{pct}%;background:{color}"></div>'
        f'<span class="noise-bar-label">{pct}%</span>'
        f'</div>'
    )

def he(s):
    """HTML-escape a string."""
    return (str(s)
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;"))

# ---------------------------------------------------------------------------
# Suppression data (hard-coded)
# ---------------------------------------------------------------------------
SUPPRESSIONS = [
    {"rank": 1, "tier": "SUPPRESS NOW", "category": "Anomalous Token",
     "volume": 833, "noise_pct": 92.8, "fp": 16, "benign": 757, "auto": 0,
     "condition": "None — suppress unconditionally",
     "plain_english": (
         "Fires when a user logs in from a slightly different device or location "
         "than last time. In a university with students on phones, home PCs, campus "
         "labs, and VPNs, this happens constantly. John's investigation every time: "
         "'IP registered to consumer ISP, login history normal.' Zero confirmed "
         "compromises in 833 tickets."
     ),
     "john_said": (
         "This looks like a false positive. The previous known good logins show "
         "from IP registered to BIGTELECOM, showing the same location."
     ),
     "action": "Open and close ticket. No email."},

    {"rank": 2, "tier": "SUPPRESS NOW", "category": "Sign-in from Anonymous Proxy",
     "volume": 237, "noise_pct": 84.4, "fp": 0, "benign": 195, "auto": 5,
     "condition": "None — suppress unconditionally",
     "plain_english": (
         "Students and staff using commercial VPNs or ISPs that route through proxy "
         "infrastructure. Every resolution: user was on a VPN or foreign ISP. "
         "No compromise confirmed in 237 tickets."
     ),
     "john_said": "The IP is registered to Gradwell.com LTD - DSL Customer, location shows as UK.",
     "action": "Open and close ticket. No email."},

    {"rank": 3, "tier": "SUPPRESS NOW", "category": "Sign-in from Password-Spray IP",
     "volume": 19, "noise_pct": 100.0, "fp": 0, "benign": 19, "auto": 0,
     "condition": "None — 100% noise rate",
     "plain_english": (
         "The IP is flagged by threat intel feeds as 'password-spray associated' "
         "but every single login at Barry was legitimate. The alert is based on IP "
         "reputation, not on any failed login pattern here."
     ),
     "john_said": "The IP is registered to T.K Bytech Ltd... login history is not suspicious.",
     "action": "Open and close ticket. No email."},

    {"rank": 4, "tier": "SUPPRESS IF MFA PASSED", "category": "Sign-in from Anonymous IP",
     "volume": 261, "noise_pct": 74.7, "fp": 19, "benign": 171, "auto": 5,
     "condition": "Only suppress if MFA was completed successfully",
     "plain_english": (
         "75% resolve to users on state government networks, education ISPs, or "
         "consumer providers whose IP ranges carry an anonymous classification. "
         "When MFA completes, there is no risk. Only notify if MFA was bypassed "
         "or not required."
     ),
     "john_said": (
         "Christie Novius logged in from IP registered to FL Dept. of Children "
         "and Families — false positive similar to yesterday."
     ),
     "action": "Suppress when MFA passed. Email only when MFA was not completed."},

    {"rank": 5, "tier": "SUPPRESS IF MFA PASSED", "category": "Unfamiliar Sign-in Properties",
     "volume": 221, "noise_pct": 71.0, "fp": 43, "benign": 107, "auto": 2,
     "condition": "Suppress if MFA completed. Also suppress Avepoint Pool service accounts entirely.",
     "plain_english": (
         "Fires when a user logs in from a new device, different browser, or new "
         "IP subnet — all routine in a university. 43 tickets were explicitly false "
         "positives because the login FAILED (MFA not completed), meaning the alert "
         "fired on a blocked attempt. Avepoint Pool service accounts generated a "
         "cluster of these — they should be excluded from alerting entirely."
     ),
     "john_said": (
         "This is a false positive — the logins failed (user did not complete MFA) "
         "from iOS device. These incidents involving the Avepoint Pool accounts are "
         "false positives."
     ),
     "action": "Suppress when MFA passed. Exclude Avepoint Pool accounts entirely. Email only for successful sign-ins where MFA was bypassed."},

    {"rank": 6, "tier": "SUPPRESS SUB-TYPE", "category": "Defense Evasion (OneStart/PUP)",
     "volume": 11, "noise_pct": 72.7, "fp": 8, "benign": 0, "auto": 0,
     "condition": "Suppress OneStart and PUP detections specifically",
     "plain_english": (
         "Defender flags 'OneStart' browser adware as a defense evasion attempt. "
         "John's response every time: run a scan (comes back clean), remote in and "
         "remove the app. This is a nuisance software removal, not a security "
         "incident. Genuine evasion tools like Cobalt Strike or Mimikatz should "
         "still alert."
     ),
     "john_said": "Full scan returned clean. Also, I did a remote session with the user and we removed the OneStart app.",
     "action": "Suppress OneStart/PUP sub-category. Continue alerting for all other defense evasion tools."},

    {"rank": 7, "tier": "SUPPRESS SUB-TYPE", "category": "Process Injection (Gaming Clients)",
     "volume": 7, "noise_pct": 57.1, "fp": 4, "benign": 0, "auto": 0,
     "condition": "Suppress for known gaming client processes only",
     "plain_english": (
         "Defender flags Riot Games and Roblox installers as process injection "
         "because game client updaters modify running processes — that's how they "
         "work. Barry has an eSports program. This is expected behavior, not an attack."
     ),
     "john_said": "Lance Hotchkiss was updating the Riot game client — false positive. The detection is for RobloxPlayerBeta.exe — this is the actual game client.",
     "action": "Suppress for RobloxPlayerBeta.exe, Riot Games updater, Valorant. Continue all other process injection alerts."},

    {"rank": 8, "tier": "DAILY DIGEST ONLY", "category": "Password Spray Attack",
     "volume": 228, "noise_pct": 48.7, "fp": 51, "benign": 51, "auto": 9,
     "condition": "Stop per-alert emails. Send one daily digest at 8am.",
     "plain_english": (
         "About half are noise (VPN users, students abroad, IPs near spray ranges). "
         "The other half need investigation. The right cadence is not 228 individual "
         "emails — it's a daily list John reviews each morning and picks out the "
         "ones that need action."
     ),
     "john_said": "I just finished investigating this incident — it appears to be a false positive detection of password spray. The IP address does not show signs of actual spray activity at Barry.",
     "action": "No per-alert email. Include in 8am daily digest with subject, ticket number, and user."},

    {"rank": 9, "tier": "DAILY DIGEST ONLY", "category": "Malicious URL Click",
     "volume": 106, "noise_pct": 45.3, "fp": 41, "benign": 2, "auto": 5,
     "condition": "Stop per-alert emails. Send one daily digest at 8am. Suppress payment receipt URLs entirely.",
     "plain_english": (
         "39% are legitimate payment receipt emails (PayPal, vendor receipts) "
         "where a link was flagged by a URL scanner. Those can be suppressed "
         "entirely if the domain is a known payment processor. The remaining ~60% "
         "still need review but not as individual urgent emails."
     ),
     "john_said": "This is a false positive — the email was a receipt for a payment done on 7/28/24.",
     "action": "Suppress payment receipt and e-commerce URL detections. Daily digest for all others."},

    {"rank": 10, "tier": "PARTIAL SUPPRESS", "category": "Multi-stage Incident (eSports/Student Devices)",
     "volume": 102, "noise_pct": 46.1, "fp": 22, "benign": 16, "auto": 7,
     "condition": "Suppress for eSports lab device group and known student learning platforms (Genio.co)",
     "plain_english": (
         "eSports lab computers generate multi-stage detection chains because game "
         "clients make network calls that pattern-match C2 traffic. Genio.co (a "
         "student learning tool) generated multiple multi-stage detections from "
         "link-tracking behavior. These device groups are known and safe."
     ),
     "john_said": "These are also false positives — expected behavior on eSports devices. Per my investigation Genio.co is a legit site with learning tools for students.",
     "action": "Suppress for eSports lab device group and Genio.co domain. Full alerts for all other multi-stage incidents."},

    {"rank": 11, "tier": "PARTIAL SUPPRESS", "category": "Malware Detected (Auto-Quarantined)",
     "volume": 260, "noise_pct": 41.5, "fp": 55, "benign": 9, "auto": 42,
     "condition": "Suppress only the sub-set where Defender already quarantined the file",
     "plain_english": (
         "42 tickets (16%) are cases where Microsoft Defender already detected, "
         "quarantined, and resolved the malware automatically before John even saw "
         "the alert. Sending an email for something that's already fixed creates "
         "noise. The 55 FPs are over-detection by Defender on legitimate files."
     ),
     "john_said": "Defender is adding more and more items to this group of incidents... it appears to be a false positive malware detection.",
     "action": "Suppress email when Defender status is auto-quarantined/remediated. Continue alerting for pending/active malware detections."},
]

# ---------------------------------------------------------------------------
# Keep list (hard-coded)
# ---------------------------------------------------------------------------
KEEP = [
    ("Mail Forwarding / Inbox Rule",     144,  "1%",  "BEC indicator — almost always actionable"),
    ("Unusual Sign-in Location",         205,  "10%", "Active investigations, account actions taken"),
    ("Pass-the-Ticket / Kerberos",       155,  "19%", "Credential theft vector"),
    ("Sign-in from Tor / Malware C2",    191,  "18%", "High-risk, real compromise potential"),
    ("Network Reconnaissance",           173,  "6%",  "Mostly unclassified, needs review"),
    ("Sign-in Disabled Accounts",         62,  "14%", "Potential credential stuffing"),
    ("Sensitive Files / DLP",            102,  "0%",  "No benign resolutions observed"),
    ("Data Exfiltration",                 10,  "—",   "Low volume, high risk — always investigate"),
]

# ---------------------------------------------------------------------------
# HTML CSS template string
# ---------------------------------------------------------------------------
HTML_CSS = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Barry University SOC — Alert Suppression Report</title>
<script src="https://cdn.plot.ly/plotly-2.32.0.min.js"></script>
<style>
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
body {
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
  background: #0f1117; color: #e2e8f0; line-height: 1.6;
}
a { color: #60a5fa; }
.container { max-width: 1200px; margin: 0 auto; padding: 0 24px; }
.hero {
  background: linear-gradient(135deg, #1e293b 0%, #0f172a 60%, #1a1f2e 100%);
  border-bottom: 1px solid #1e293b; padding: 56px 0 48px;
}
.hero h1 { font-size: 2.4rem; font-weight: 700; color: #f8fafc; margin-bottom: 8px; }
.hero .subtitle { color: #94a3b8; font-size: 1.05rem; margin-bottom: 40px; }
.hero-stats { display: flex; flex-wrap: wrap; gap: 24px; }
.stat-card {
  background: #1e293b; border: 1px solid #334155; border-radius: 12px;
  padding: 20px 28px; min-width: 160px; flex: 1;
}
.stat-card .stat-num { font-size: 2.4rem; font-weight: 800; color: #f8fafc; line-height: 1.1; }
.stat-card .stat-num.green  { color: #34d399; }
.stat-card .stat-num.red    { color: #f87171; }
.stat-card .stat-num.blue   { color: #60a5fa; }
.stat-card .stat-num.yellow { color: #fbbf24; }
.stat-card .stat-label {
  font-size: 0.82rem; color: #94a3b8; margin-top: 4px;
  text-transform: uppercase; letter-spacing: .05em;
}
.section { padding: 48px 0 32px; }
.section h2 {
  font-size: 1.5rem; font-weight: 700; color: #f1f5f9; margin-bottom: 8px;
  border-left: 4px solid #3b82f6; padding-left: 14px;
}
.section .section-desc { color: #94a3b8; margin-bottom: 28px; font-size: 0.95rem; }
.two-col { display: grid; grid-template-columns: 1fr 1fr; gap: 24px; margin-bottom: 32px; }
@media(max-width:680px){ .two-col { grid-template-columns: 1fr; } }
.summary-box { background: #1e293b; border: 1px solid #334155; border-radius: 12px; padding: 24px; }
.summary-box h3 { font-size: 1rem; font-weight: 700; color: #f1f5f9; margin-bottom: 14px; }
.summary-row {
  display: flex; justify-content: space-between; align-items: center;
  padding: 6px 0; border-bottom: 1px solid #0f172a; font-size: 0.9rem;
}
.summary-row:last-child { border-bottom: none; }
.summary-row .val { font-weight: 700; color: #60a5fa; }
.noise-bar-wrap {
  position: relative; background: #0f172a; border-radius: 4px;
  height: 20px; width: 100%; overflow: hidden;
}
.noise-bar-fill { height: 100%; border-radius: 4px; }
.noise-bar-label {
  position: absolute; right: 6px; top: 50%; transform: translateY(-50%);
  font-size: 0.75rem; font-weight: 700; color: #fff; text-shadow: 0 0 3px #000;
}
.tier-badge {
  display: inline-block; padding: 2px 10px; border-radius: 20px;
  font-size: 0.72rem; font-weight: 700; letter-spacing: .06em;
  text-transform: uppercase; white-space: nowrap;
}
.card-grid { display: flex; flex-direction: column; gap: 20px; }
.supp-card { background: #1e293b; border: 1px solid #334155; border-radius: 12px; overflow: hidden; }
.card-header {
  display: flex; align-items: center; gap: 16px;
  padding: 18px 24px; border-bottom: 1px solid #0f172a; flex-wrap: wrap;
}
.card-rank { font-size: 1.6rem; font-weight: 800; color: #475569; min-width: 36px; text-align: center; }
.card-title { font-size: 1.05rem; font-weight: 700; color: #f1f5f9; flex: 1; }
.card-meta { display: flex; gap: 20px; align-items: center; flex-wrap: wrap; }
.card-meta .vol { font-size: 1.1rem; font-weight: 700; color: #f8fafc; }
.card-meta .vol-label { font-size: 0.75rem; color: #64748b; }
.card-body { padding: 20px 24px; display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
@media(max-width:700px){ .card-body { grid-template-columns: 1fr; } }
.card-body .field-label {
  font-size: 0.72rem; font-weight: 700; text-transform: uppercase;
  letter-spacing: .07em; color: #64748b; margin-bottom: 6px;
}
.card-body .field-val { font-size: 0.88rem; color: #cbd5e1; }
.card-body .field-val.quote {
  font-style: italic; color: #94a3b8; border-left: 3px solid #334155; padding-left: 12px;
}
.card-action {
  padding: 14px 24px; background: #0f172a; border-top: 1px solid #1e293b;
  font-size: 0.85rem; color: #e2e8f0;
}
.card-action strong { color: #60a5fa; }
.card-full { grid-column: 1 / -1; }
.chart-wrap {
  background: #1e293b; border: 1px solid #334155; border-radius: 12px;
  padding: 8px; margin-bottom: 32px;
}
.keep-table { width: 100%; border-collapse: collapse; }
.keep-table th {
  background: #0f172a; color: #64748b; font-size: 0.75rem;
  text-transform: uppercase; letter-spacing: .06em;
  padding: 10px 14px; text-align: left; border-bottom: 1px solid #1e293b;
}
.keep-table td { padding: 12px 14px; font-size: 0.9rem; border-bottom: 1px solid #1e293b; }
.keep-table tr:last-child td { border-bottom: none; }
.keep-table tr:hover td { background: #1e293b; }
.keep-table .keep-cat { font-weight: 600; color: #f1f5f9; }
.keep-table .keep-reason { color: #94a3b8; font-style: italic; }
.footer {
  padding: 32px 0; border-top: 1px solid #1e293b;
  color: #475569; font-size: 0.82rem; text-align: center;
}
</style>
</head>"""

# ---------------------------------------------------------------------------
# Main HTML builder function
# ---------------------------------------------------------------------------

def build_html():
    parts = [HTML_CSS]
    generated = datetime.now().strftime("%Y-%m-%d %H:%M")

    # ---- BODY OPEN + HERO ----
    parts.append(f"""
<body>
<!-- HERO -->
<div class="hero">
  <div class="container">
    <h1>Barry University SOC — Alert Suppression Analysis</h1>
    <p class="subtitle">
      Two years of SOC email data ({DATE_RANGE}) analyzed for noise reduction.
      Generated {generated}
    </p>
    <div class="hero-stats">
      <div class="stat-card">
        <div class="stat-num blue">{TOTAL_SOC_EMAILS:,}</div>
        <div class="stat-label">SOC Emails Received</div>
      </div>
      <div class="stat-card">
        <div class="stat-num">{UNIQUE_TICKETS:,}</div>
        <div class="stat-label">Unique Tickets ({DATE_RANGE})</div>
      </div>
      <div class="stat-card">
        <div class="stat-num red">{ANNUAL_EMAIL_VOL:,}/yr</div>
        <div class="stat-label">Current Annual Volume</div>
      </div>
      <div class="stat-card">
        <div class="stat-num green">{POST_SUPPRESS_VOL:,}/yr</div>
        <div class="stat-label">Post-Suppression Estimate</div>
      </div>
      <div class="stat-card">
        <div class="stat-num yellow">{REDUCTION_PCT}%</div>
        <div class="stat-label">Noise Reduction Possible</div>
      </div>
      <div class="stat-card">
        <div class="stat-num">{FALSE_POSITIVE_RATE}%</div>
        <div class="stat-label">Confirmed False Positive Rate</div>
      </div>
    </div>
  </div>
</div>
""")

    # ---- SECTION 1: WHAT WE RECEIVE vs WHAT NEEDS ACTION ----
    parts.append("""
<!-- SECTION 1: Summary two-col -->
<div class="section">
  <div class="container">
    <h2>Signal vs. Noise</h2>
    <p class="section-desc">
      A two-year view of what the SOC receives versus what actually requires human action.
    </p>
    <div class="two-col">
      <div class="summary-box">
        <h3>What We Receive</h3>
""")
    receive_rows = [
        ("Total SOC emails (2 years)",  f"{TOTAL_SOC_EMAILS:,}"),
        ("Unique tickets",               f"{UNIQUE_TICKETS:,}"),
        ("Date range",                   DATE_RANGE),
        ("Annual email volume",          f"~{ANNUAL_EMAIL_VOL:,}"),
        ("Total Defender incidents",     f"{TOTAL_INCIDENTS:,}"),
        ("High-severity incidents",      f"{HIGH_SEVERITY:,}"),
        ("Active / open incidents",      f"{ACTIVE_INCIDENTS:,}"),
    ]
    for label, val in receive_rows:
        parts.append(f'        <div class="summary-row"><span>{he(label)}</span><span class="val">{he(val)}</span></div>\n')
    parts.append("      </div>\n")

    parts.append('      <div class="summary-box">\n')
    parts.append('        <h3>What Actually Needs Action</h3>\n')
    action_rows = [
        ("Mean response time",              f"{MEAN_RESPONSE_H}h"),
        ("Median response time",            f"{MEDIAN_RESPONSE_H}h"),
        ("Confirmed false positive rate",   f"{FALSE_POSITIVE_RATE}%"),
        ("Suppressible alert volume",       "~49% of annual email"),
        ("Post-suppression estimate",       f"~{POST_SUPPRESS_VOL:,}/yr"),
        ("Alert categories analyzed",       str(len(SUPPRESSIONS))),
        ("Categories recommended to keep",  str(len(KEEP))),
    ]
    for label, val in action_rows:
        parts.append(f'        <div class="summary-row"><span>{he(label)}</span><span class="val">{he(val)}</span></div>\n')
    parts.append("      </div>\n")
    parts.append("    </div>\n")  # two-col
    parts.append("  </div>\n</div>\n")  # container + section

    # ---- SECTION 2: VOLUME / NOISE FUNNEL CHARTS ----
    # Build data for Plotly bar chart: alert category vs volume, colored by noise %
    cats   = [s["category"] for s in SUPPRESSIONS]
    vols   = [s["volume"]   for s in SUPPRESSIONS]
    noises = [s["noise_pct"] for s in SUPPRESSIONS]
    tiers  = [s["tier"]     for s in SUPPRESSIONS]

    bar_colors = []
    for t in tiers:
        c = TIER_COLORS.get(t, {"bg": "#6b7280"})
        bar_colors.append(c["bg"])

    # Horizontal bar chart: category vs volume, color = tier
    chart1_data = {
        "type": "bar",
        "orientation": "h",
        "x": vols,
        "y": cats,
        "marker": {"color": bar_colors},
        "text": [f"{v} alerts ({n}% noise)" for v, n in zip(vols, noises)],
        "hovertemplate": "<b>%{y}</b><br>Volume: %{x}<extra></extra>",
    }
    chart1_layout = {
        "title": {"text": "Alert Volume by Category (colored by suppression tier)", "font": {"color": "#f1f5f9", "size": 14}},
        "xaxis": {"title": "Number of Alerts", "color": "#94a3b8", "gridcolor": "#1e293b"},
        "yaxis": {"color": "#94a3b8", "automargin": True},
        "paper_bgcolor": "#1e293b",
        "plot_bgcolor":  "#0f172a",
        "font": {"color": "#94a3b8"},
        "margin": {"l": 220, "r": 30, "t": 50, "b": 50},
        "height": 420,
    }

    # Funnel chart: current volume vs suppressible vs keep
    total_suppress_vol = sum(s["volume"] for s in SUPPRESSIONS)
    total_keep_vol = sum(k[1] for k in KEEP)
    chart2_data = {
        "type": "funnel",
        "name": "Email Volume Funnel",
        "y": ["Total SOC Emails/yr", "Suppressible Alerts", "Estimated Post-Suppression"],
        "x": [ANNUAL_EMAIL_VOL, ANNUAL_EMAIL_VOL - POST_SUPPRESS_VOL, POST_SUPPRESS_VOL],
        "textinfo": "value+percent initial",
        "marker": {"color": ["#3b82f6", "#f87171", "#34d399"]},
    }
    chart2_layout = {
        "title": {"text": "Email Suppression Funnel (Annual Volume)", "font": {"color": "#f1f5f9", "size": 14}},
        "paper_bgcolor": "#1e293b",
        "plot_bgcolor":  "#0f172a",
        "font": {"color": "#94a3b8"},
        "margin": {"l": 30, "r": 30, "t": 50, "b": 30},
        "height": 340,
    }

    import json as _json
    c1d = _json.dumps([chart1_data])
    c1l = _json.dumps(chart1_layout)
    c2d = _json.dumps([chart2_data])
    c2l = _json.dumps(chart2_layout)

    parts.append(f"""
<!-- SECTION 2: Charts -->
<div class="section" style="padding-top:0">
  <div class="container">
    <h2>Volume Analysis</h2>
    <p class="section-desc">
      Suppressible alert categories ranked by volume. Bar color indicates suppression tier.
    </p>
    <div class="chart-wrap">
      <div id="chart-volume"></div>
    </div>
    <div class="chart-wrap">
      <div id="chart-funnel"></div>
    </div>
  </div>
</div>
<script>
  Plotly.newPlot('chart-volume', {c1d}, {c1l}, {{responsive:true, displayModeBar:false}});
  Plotly.newPlot('chart-funnel', {c2d}, {c2l}, {{responsive:true, displayModeBar:false}});
</script>
""")

    # ---- SECTION 3: SUPPRESSION CARDS ----
    parts.append("""
<!-- SECTION 3: Suppression Cards -->
<div class="section" style="padding-top:0">
  <div class="container">
    <h2>Suppression Recommendations</h2>
    <p class="section-desc">
      Each card shows the alert category, suppression tier, noise rate, plain-English
      explanation of why it fires, a direct quote from the analyst who investigated it,
      and the specific action to take.
    </p>
    <div class="card-grid">
""")

    for s in SUPPRESSIONS:
        badge   = tier_badge(s["tier"])
        bar     = noise_bar(s["noise_pct"])
        cat_e   = he(s["category"])
        cond_e  = he(s["condition"])
        plain_e = he(s["plain_english"])
        quote_e = he(s["john_said"])
        act_e   = he(s["action"])

        parts.append(f"""      <div class="supp-card">
        <div class="card-header">
          <div class="card-rank">#{s['rank']}</div>
          <div class="card-title">{cat_e}</div>
          <div class="card-meta">
            {badge}
            <div>
              <div class="vol">{s['volume']:,}</div>
              <div class="vol-label">alerts</div>
            </div>
          </div>
        </div>
        <div style="padding: 12px 24px 4px;">
          <div class="field-label" style="font-size:0.7rem;color:#64748b;text-transform:uppercase;letter-spacing:.06em;margin-bottom:4px;">Noise Rate</div>
          {bar}
        </div>
        <div class="card-body">
          <div>
            <div class="field-label">Why It Fires (Plain English)</div>
            <div class="field-val">{plain_e}</div>
          </div>
          <div>
            <div class="field-label">Analyst Quote</div>
            <div class="field-val quote">&ldquo;{quote_e}&rdquo;</div>
          </div>
          <div class="card-full">
            <div class="field-label">Suppression Condition</div>
            <div class="field-val">{cond_e}</div>
          </div>
        </div>
        <div class="card-action"><strong>Action:</strong> {act_e}</div>
      </div>
""")

    parts.append("    </div>\n")   # card-grid
    parts.append("  </div>\n</div>\n")  # container + section

    # ---- SECTION 4: KEEP ALERTING TABLE ----
    parts.append("""
<!-- SECTION 4: Keep Alerting -->
<div class="section" style="padding-top:0; padding-bottom: 48px;">
  <div class="container">
    <h2>Keep Alerting — Do Not Suppress</h2>
    <p class="section-desc">
      These categories should continue to generate individual, immediate emails.
      Noise rates are low and investigation outcomes confirm real risk.
    </p>
    <table class="keep-table">
      <thead>
        <tr>
          <th>Alert Category</th>
          <th>Volume (2 yrs)</th>
          <th>Benign Rate</th>
          <th>Reason to Keep</th>
        </tr>
      </thead>
      <tbody>
""")
    for (cat, vol, benign_rate, reason) in KEEP:
        parts.append(
            f'        <tr><td class="keep-cat">{he(cat)}</td>'
            f'<td>{vol:,}</td>'
            f'<td>{he(benign_rate)}</td>'
            f'<td class="keep-reason">{he(reason)}</td></tr>\n'
        )
    parts.append(f"""      </tbody>
    </table>
  </div>
</div>

<!-- FOOTER -->
<div class="footer">
  <div class="container">
    Barry University Security Operations Center &mdash; Alert Suppression Analysis<br>
    Based on SOC email data {DATE_RANGE} &middot; Generated {generated}
  </div>
</div>

</body>
</html>
""")

    return "".join(parts)


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    html = build_html()
    with open(REPORT_PATH, "w", encoding="utf-8") as fh:
        fh.write(html)
    size_kb = os.path.getsize(REPORT_PATH) / 1024
    print(f"Report written to: {REPORT_PATH}")
    print(f"File size: {size_kb:.1f} KB")


if __name__ == "__main__":
    main()
