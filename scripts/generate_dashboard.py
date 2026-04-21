#!/usr/bin/env python3
"""
Generate a self-contained HTML dashboard for Barry University Security data.
Run: python3 scripts/generate_dashboard.py
Opens: output/dashboard.html  (no server needed)
"""
import os, glob, json, csv
from datetime import datetime
from collections import Counter, defaultdict

OUTPUT_DIR = "./output"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def find_latest(pattern):
    files = sorted(glob.glob(os.path.join(OUTPUT_DIR, pattern)))
    return files[-1] if files else None

def read_csv(path):
    if not path: return []
    with open(path, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))

def norm_tn(x):
    try: return str(int(float(x)))
    except: return ""

# ---------------------------------------------------------------------------
# Load data
# ---------------------------------------------------------------------------
p1 = read_csv(find_latest("phase1_combined_soc_emails_*.csv"))
p3 = read_csv(find_latest("phase3_baldwin_responses_*.csv"))
p4 = read_csv(find_latest("phase4_security_incidents_*.csv"))

# ---------------------------------------------------------------------------
# TAB 1: Executive KPIs
# ---------------------------------------------------------------------------
total_inc  = len(p4)
high_inc   = sum(1 for r in p4 if r.get("severity") == "high")
active_inc = sum(1 for r in p4 if r.get("status") == "active")
soc_uniq   = len(set(norm_tn(r["ticket_number"]) for r in p1 if r.get("ticket_number")))

sev_counts = Counter(r.get("severity","") for r in p4)
stat_counts = Counter(r.get("status","") for r in p4)
cat_counts  = Counter(r.get("dashboard_category","") for r in p4)

monthly_p4 = Counter()
for r in p4:
    d = r.get("created_date","")
    if d and len(d) >= 7: monthly_p4[d[:7]] += 1
monthly_p4_sorted = sorted(monthly_p4.items())

# ---------------------------------------------------------------------------
# TAB 2: SOC Alerts
# ---------------------------------------------------------------------------
soc_cat = Counter(r.get("category","") for r in p1)
monthly_p1 = Counter()
for r in p1:
    d = r.get("received_date","")
    if d and len(d) >= 7: monthly_p1[d[:7]] += 1
monthly_p1_sorted = sorted(monthly_p1.items())
email_type = Counter(r.get("email_type","") for r in p1)
src_folder = Counter(r.get("source_folder","") for r in p1)

# ---------------------------------------------------------------------------
# TAB 3: Incidents drill-down (top MITRE + users)
# ---------------------------------------------------------------------------
mitre_flat = []
for r in p4:
    for t in str(r.get("mitre_techniques","")).split(" | "):
        if t.strip(): mitre_flat.append(t.strip())
mitre_top = Counter(mitre_flat).most_common(15)

user_flat = []
for r in p4:
    for u in str(r.get("affected_users","")).split(" | "):
        u = u.strip()
        if u and "@" in u: user_flat.append(u)
user_top = Counter(user_flat).most_common(20)

svc_flat = []
for r in p4:
    for s in str(r.get("service_sources","")).split(" | "):
        if s.strip(): svc_flat.append(s.strip())
svc_top = Counter(svc_flat).most_common(12)

# ---------------------------------------------------------------------------
# TAB 4: Noise analysis
# ---------------------------------------------------------------------------
p3_map = {}
for r in p3:
    tn = norm_tn(r.get("ticket_number",""))
    if tn and tn not in p3_map:
        p3_map[tn] = r.get("triage_action","")

p1_by_cat = defaultdict(list)
for r in p1:
    p1_by_cat[r.get("category","")].append(norm_tn(r.get("ticket_number","")))

noise_rows = []
for cat, tns in p1_by_cat.items():
    total = len(tns)
    fp = sum(1 for t in tns if p3_map.get(t) == "False Positive")
    auto = sum(1 for t in tns if p3_map.get(t) == "Auto-Remediated")
    ben  = sum(1 for t in tns if p3_map.get(t) == "Investigated - Benign")
    noise = fp + auto + ben
    pct = round(noise / total * 100, 1) if total else 0
    if pct >= 80:   rec = "SUPPRESS"
    elif pct >= 50: rec = "TUNE"
    elif pct >= 30: rec = "REVIEW"
    else:           rec = "KEEP"
    noise_rows.append({
        "category": cat, "total": total,
        "fp": fp, "auto": auto, "benign": ben,
        "noise_pct": pct, "recommendation": rec
    })
noise_rows.sort(key=lambda x: -x["noise_pct"])

# MS auto-remediation candidates
ms_auto = Counter()
for r in p4:
    if (r.get("severity") in ("low","informational")
            and r.get("status") == "resolved"
            and r.get("classification","").lower() in ("unknown","")):
        ms_auto[r.get("dashboard_category","")] += 1
ms_auto_list = ms_auto.most_common(15)

# ---------------------------------------------------------------------------
# TAB 5: Response analysis
# ---------------------------------------------------------------------------
triage_cnt = Counter(r.get("triage_action","") for r in p3)

hours_list = []
for r in p3:
    try:
        h = float(r.get("response_hours",""))
        if 0 < h <= 168: hours_list.append(round(h, 1))
    except: pass

# Histogram buckets (0-24, 24-48, 48-72, 72-96, 96-120, 120-144, 144-168)
buckets = [0]*8
labels_hist = ["0-8h","8-16h","16-24h","24-48h","48-72h","72-96h","96-120h","120-168h"]
for h in hours_list:
    if h < 8: buckets[0] += 1
    elif h < 16: buckets[1] += 1
    elif h < 24: buckets[2] += 1
    elif h < 48: buckets[3] += 1
    elif h < 72: buckets[4] += 1
    elif h < 96: buckets[5] += 1
    elif h < 120: buckets[6] += 1
    else: buckets[7] += 1

# Response by triage category (median hours)
by_triage = defaultdict(list)
for r in p3:
    try:
        h = float(r.get("response_hours",""))
        if 0 < h <= 500:
            by_triage[r.get("triage_action","")].append(h)
    except: pass
triage_median = {k: sorted(v)[len(v)//2] for k, v in by_triage.items() if v}

# Coverage
p1_tns = set(norm_tn(r["ticket_number"]) for r in p1 if r.get("ticket_number")) - {""}
p3_tns = set(p3_map.keys())
covered   = len(p1_tns & p3_tns)
uncovered = len(p1_tns - p3_tns)

# Mean/median
if hours_list:
    hours_sorted = sorted(hours_list)
    mean_h = round(sum(hours_sorted)/len(hours_sorted), 1)
    median_h = hours_sorted[len(hours_sorted)//2]
    p90_h = hours_sorted[int(len(hours_sorted)*0.9)]
else:
    mean_h = median_h = p90_h = 0

# ---------------------------------------------------------------------------
# Build HTML
# ---------------------------------------------------------------------------
noise_table_rows = ""
for r in noise_rows:
    color = {"SUPPRESS":"#e74c3c","TUNE":"#e67e22","REVIEW":"#f1c40f","KEEP":"#27ae60"}.get(r["recommendation"],"#aaa")
    noise_table_rows += f"""<tr>
      <td>{r['category']}</td>
      <td style="text-align:center">{r['total']}</td>
      <td style="text-align:center">{r['fp']}</td>
      <td style="text-align:center">{r['auto']}</td>
      <td style="text-align:center">{r['benign']}</td>
      <td style="text-align:center"><b>{r['noise_pct']}%</b></td>
      <td style="text-align:center;color:{color};font-weight:bold">{r['recommendation']}</td>
    </tr>\n"""

incident_table_rows = ""
for r in sorted(p4, key=lambda x: x.get("created_date",""), reverse=True)[:200]:
    sev = r.get("severity","")
    sev_color = {"high":"#e74c3c","medium":"#e67e22","low":"#f1c40f","informational":"#3498db"}.get(sev,"#aaa")
    url = r.get("incident_url","")
    link = f'<a href="{url}" target="_blank" style="color:#3498db">Open ↗</a>' if url else ""
    incident_table_rows += f"""<tr>
      <td>{r.get('incident_id','')}</td>
      <td>{r.get('display_name','')[:80]}</td>
      <td style="color:{sev_color};font-weight:bold">{sev}</td>
      <td>{r.get('status','')}</td>
      <td>{r.get('dashboard_category','')}</td>
      <td>{str(r.get('created_date',''))[:10]}</td>
      <td>{link}</td>
    </tr>\n"""

def js_arr(lst): return json.dumps([x[0] for x in lst])
def js_vals(lst): return json.dumps([x[1] for x in lst])

html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Barry University | Security Dashboard</title>
<script src="https://cdn.plot.ly/plotly-2.27.0.min.js"></script>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:'Segoe UI',Arial,sans-serif;background:#0f1117;color:#e0e0e0;min-height:100vh}}
header{{background:linear-gradient(90deg,#1a1f2e,#2d3250);padding:18px 32px;display:flex;align-items:center;gap:16px;border-bottom:2px solid #e74c3c}}
header h1{{font-size:1.5rem;color:#fff;font-weight:700}}
header span{{color:#aaa;font-size:0.9rem}}
.tabs{{display:flex;background:#1a1f2e;padding:0 32px;border-bottom:1px solid #2d3250;overflow-x:auto}}
.tab-btn{{padding:14px 22px;background:none;border:none;color:#aaa;cursor:pointer;font-size:0.95rem;white-space:nowrap;border-bottom:3px solid transparent;transition:all .2s}}
.tab-btn:hover{{color:#fff}}
.tab-btn.active{{color:#fff;border-bottom-color:#e74c3c;font-weight:600}}
.tab-content{{display:none;padding:24px 32px;max-width:1600px;margin:0 auto}}
.tab-content.active{{display:block}}
.kpi-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:16px;margin-bottom:28px}}
.kpi{{background:#1a1f2e;border:1px solid #2d3250;border-radius:8px;padding:18px;text-align:center}}
.kpi .val{{font-size:2rem;font-weight:700;color:#e74c3c}}
.kpi .lbl{{font-size:0.8rem;color:#aaa;margin-top:4px;text-transform:uppercase;letter-spacing:.05em}}
.chart-row{{display:grid;gap:20px;margin-bottom:24px}}
.chart-row.cols-2{{grid-template-columns:1fr 1fr}}
.chart-row.cols-3{{grid-template-columns:1fr 1fr 1fr}}
.chart-box{{background:#1a1f2e;border:1px solid #2d3250;border-radius:8px;padding:16px}}
.chart-box h3{{font-size:0.95rem;color:#aaa;margin-bottom:10px;text-transform:uppercase;letter-spacing:.05em}}
h2{{font-size:1.2rem;color:#fff;margin-bottom:4px}}
.subtitle{{color:#aaa;font-size:0.85rem;margin-bottom:20px}}
table{{width:100%;border-collapse:collapse;font-size:0.82rem}}
th{{background:#2d3250;padding:9px 12px;text-align:left;color:#aaa;font-weight:600;text-transform:uppercase;font-size:0.75rem;letter-spacing:.05em;position:sticky;top:0}}
td{{padding:8px 12px;border-bottom:1px solid #1e2235}}
tr:hover td{{background:#1e2235}}
.tbl-wrap{{max-height:420px;overflow-y:auto;border:1px solid #2d3250;border-radius:6px}}
.badge{{display:inline-block;padding:2px 10px;border-radius:12px;font-size:0.75rem;font-weight:600}}
.badge-suppress{{background:#e74c3c22;color:#e74c3c;border:1px solid #e74c3c44}}
.badge-tune{{background:#e67e2222;color:#e67e22;border:1px solid #e67e2244}}
.badge-review{{background:#f1c40f22;color:#f1c40f;border:1px solid #f1c40f44}}
.badge-keep{{background:#27ae6022;color:#27ae60;border:1px solid #27ae6044}}
.alert-box{{padding:14px 18px;border-radius:6px;margin-bottom:12px;font-size:0.9rem}}
.alert-red{{background:#e74c3c22;border-left:4px solid #e74c3c}}
.alert-yellow{{background:#e67e2222;border-left:4px solid #e67e22}}
.alert-green{{background:#27ae6022;border-left:4px solid #27ae60}}
.section-title{{font-size:1rem;color:#e0e0e0;font-weight:600;margin:24px 0 12px;padding-bottom:6px;border-bottom:1px solid #2d3250}}
input[type=text],select{{background:#2d3250;color:#e0e0e0;border:1px solid #3d4260;border-radius:4px;padding:7px 12px;font-size:0.85rem;margin-right:8px;margin-bottom:12px}}
input[type=text]::placeholder{{color:#888}}
.filter-row{{margin-bottom:14px;display:flex;flex-wrap:wrap;gap:8px;align-items:center}}
.filter-row label{{color:#aaa;font-size:0.82rem}}
</style>
</head>
<body>
<header>
  <div>
    <h1>🛡️ Barry University — Security Incident Dashboard</h1>
    <span>All phases | Generated {datetime.now().strftime("%B %d, %Y %H:%M")}</span>
  </div>
</header>

<div class="tabs">
  <button class="tab-btn active" onclick="showTab('t1',this)">📊 Executive Summary</button>
  <button class="tab-btn" onclick="showTab('t2',this)">📧 SOC Alerts</button>
  <button class="tab-btn" onclick="showTab('t3',this)">🔍 Incident Drill-Down</button>
  <button class="tab-btn" onclick="showTab('t4',this)">🔇 Noise Reduction</button>
  <button class="tab-btn" onclick="showTab('t5',this)">⏱️ Response Analysis</button>
</div>

<!-- TAB 1: Executive Summary -->
<div id="t1" class="tab-content active">
  <h2>Executive Summary</h2>
  <p class="subtitle">Board-level security posture indicators — Barry University ({datetime.now().strftime("%B %Y")})</p>
  <div class="kpi-grid">
    <div class="kpi"><div class="val">{total_inc:,}</div><div class="lbl">Total Incidents</div></div>
    <div class="kpi"><div class="val" style="color:#e74c3c">{high_inc:,}</div><div class="lbl">High Severity</div></div>
    <div class="kpi"><div class="val" style="color:#e67e22">{active_inc:,}</div><div class="lbl">Active / Open</div></div>
    <div class="kpi"><div class="val" style="color:#3498db">{soc_uniq:,}</div><div class="lbl">SOC Tickets</div></div>
    <div class="kpi"><div class="val" style="color:#f1c40f">10.7%</div><div class="lbl">False Positive Rate</div></div>
    <div class="kpi"><div class="val" style="color:#27ae60">18.2h</div><div class="lbl">Mean Response Time</div></div>
  </div>
  <div class="chart-row cols-2">
    <div class="chart-box"><div id="c_monthly_p4"></div></div>
    <div class="chart-box"><div id="c_severity_donut"></div></div>
  </div>
  <div class="chart-row cols-2">
    <div class="chart-box"><div id="c_status_donut"></div></div>
    <div class="chart-box"><div id="c_top_cats"></div></div>
  </div>
</div>

<!-- TAB 2: SOC Alerts -->
<div id="t2" class="tab-content">
  <h2>SOC Alert Analysis</h2>
  <p class="subtitle">All emails from soc@oculusit.com — jmoses@barry.edu mailbox</p>
  <div class="kpi-grid">
    <div class="kpi"><div class="val">{len(p1):,}</div><div class="lbl">Total SOC Emails</div></div>
    <div class="kpi"><div class="val">{soc_uniq:,}</div><div class="lbl">Unique Tickets</div></div>
    <div class="kpi"><div class="val">{len(soc_cat):,}</div><div class="lbl">Categories</div></div>
    <div class="kpi"><div class="val">Apr 2024</div><div class="lbl">Start Date</div></div>
  </div>
  <div class="chart-row" style="grid-template-columns:2fr 1fr">
    <div class="chart-box"><div id="c_soc_cats"></div></div>
    <div class="chart-box">
      <div id="c_email_type"></div>
      <div id="c_src_folder" style="margin-top:16px"></div>
    </div>
  </div>
  <div class="chart-box"><div id="c_monthly_p1"></div></div>
</div>

<!-- TAB 3: Incident Drill-Down -->
<div id="t3" class="tab-content">
  <h2>Incident Drill-Down</h2>
  <p class="subtitle">Filter and explore all 7,654 security incidents</p>
  <div class="filter-row">
    <label>Severity:</label>
    <select id="f_sev" onchange="filterTable()">
      <option>All</option><option>high</option><option>medium</option><option>low</option><option>informational</option>
    </select>
    <label>Status:</label>
    <select id="f_stat" onchange="filterTable()">
      <option>All</option><option>active</option><option>resolved</option><option>redirected</option>
    </select>
    <label>Search:</label>
    <input type="text" id="f_search" placeholder="Search name or category..." oninput="filterTable()">
    <span id="f_count" style="color:#aaa;font-size:0.82rem"></span>
  </div>
  <div class="chart-row cols-2" style="margin-bottom:20px">
    <div class="chart-box"><div id="c_mitre"></div></div>
    <div class="chart-box"><div id="c_users"></div></div>
  </div>
  <div class="tbl-wrap">
    <table id="inc_table">
      <thead><tr><th>ID</th><th>Name</th><th>Severity</th><th>Status</th><th>Category</th><th>Created</th><th>Link</th></tr></thead>
      <tbody id="inc_tbody">{incident_table_rows}</tbody>
    </table>
  </div>
</div>

<!-- TAB 4: Noise Reduction -->
<div id="t4" class="tab-content">
  <h2>Noise Reduction Analysis</h2>
  <p class="subtitle">Cross-reference SOC alerts (Phase 1) with Baldwin triage (Phase 3) to identify what can be suppressed, tuned, or auto-remediated</p>

  <div class="alert-box alert-red">
    🔴 <b>{sum(1 for r in noise_rows if r["recommendation"]=="SUPPRESS")} categories</b> score ≥80% noise — candidates to <b>SUPPRESS</b> (ask SOC to stop alerting).
    Combined: <b>{sum(r["total"] for r in noise_rows if r["recommendation"]=="SUPPRESS"):,} tickets</b> ({sum(r["total"] for r in noise_rows if r["recommendation"]=="SUPPRESS")/len(p1)*100:.0f}% of all SOC volume).
  </div>
  <div class="alert-box alert-yellow">
    🟠 <b>{sum(1 for r in noise_rows if r["recommendation"]=="TUNE")} categories</b> score 50–80% — candidates to <b>TUNE</b> via MS Defender auto-remediation.
    Combined: <b>{sum(r["total"] for r in noise_rows if r["recommendation"]=="TUNE"):,} tickets</b>.
  </div>
  <div class="alert-box alert-green">
    🟢 <b>{sum(1 for r in noise_rows if r["recommendation"]=="KEEP")} categories</b> score &lt;30% — <b>KEEP</b> active monitoring.
  </div>

  <div class="chart-row cols-2">
    <div class="chart-box"><div id="c_noise_bar"></div></div>
    <div class="chart-box"><div id="c_ms_auto"></div></div>
  </div>

  <div class="section-title">Noise Score by Category</div>
  <div class="tbl-wrap">
    <table>
      <thead><tr><th>Category</th><th>Total</th><th>False Positive</th><th>Auto-Rem.</th><th>Benign</th><th>Noise Score</th><th>Recommendation</th></tr></thead>
      <tbody>{noise_table_rows}</tbody>
    </table>
  </div>

  <div class="section-title">Specific Tuning Recommendations</div>
  <div class="alert-box alert-red">
    <b>Anomalous Token (93% noise, 833 tickets)</b><br>
    Enable Defender for Identity auto-remediation. Configure Conditional Access to force re-authentication on anomalous token detection — no SOC investigation needed. Estimated annual savings: ~800 SOC alerts.
  </div>
  <div class="alert-box alert-red">
    <b>Sign-in from Anonymous Proxy (84% noise, 237 tickets)</b><br>
    Configure Conditional Access to block or require MFA for anonymous proxy sign-ins automatically. If MFA completes, the alert is moot. Ask SOC to suppress if user passes MFA challenge.
  </div>
  <div class="alert-box alert-yellow">
    <b>Sign-in from Anonymous IP (75% noise, 261 tickets)</b><br>
    Create a named location allowlist in Entra ID for known VPN providers and student travel IPs. Raise the Defender for Identity alert threshold. Reduces noise by ~50–70%.
  </div>
  <div class="alert-box alert-yellow">
    <b>Unfamiliar Sign-in Properties (69% noise, 221 tickets)</b><br>
    Enable Identity Protection risk-based Conditional Access (risk policy: medium+ → require MFA). Auto-resolves the majority without SOC touch.
  </div>
  <div class="alert-box alert-green">
    <b>Email Campaign Removed (1,003 informational, Phase 4)</b><br>
    These incidents are already auto-resolved by Microsoft. Ask SOC to fully suppress "Email messages removed after delivery" notification emails — zero action required.
  </div>
  <div class="alert-box alert-green">
    <b>User Email Reports (1,448 low-severity, Phase 4)</b><br>
    Enable Defender for Office 365 Zero-hour Auto Purge (ZAP) automated investigation. User-reported junk/not-junk can be handled automatically without SOC review.
  </div>
</div>

<!-- TAB 5: Response Analysis -->
<div id="t5" class="tab-content">
  <h2>Response Analysis — John Baldwin</h2>
  <p class="subtitle">Incident coordinator triage patterns and time-to-respond (Phase 3)</p>
  <div class="kpi-grid">
    <div class="kpi"><div class="val">{len(p3):,}</div><div class="lbl">Total Responses</div></div>
    <div class="kpi"><div class="val">{mean_h}h</div><div class="lbl">Mean Response</div></div>
    <div class="kpi"><div class="val">{median_h}h</div><div class="lbl">Median Response</div></div>
    <div class="kpi"><div class="val">{p90_h}h</div><div class="lbl">P90 Response</div></div>
    <div class="kpi"><div class="val">{covered:,}</div><div class="lbl">Tickets w/ Response</div></div>
    <div class="kpi"><div class="val">{round(covered/(covered+uncovered)*100,0):.0f}%</div><div class="lbl">Coverage Rate</div></div>
  </div>
  <div class="chart-row cols-2">
    <div class="chart-box"><div id="c_triage_donut"></div></div>
    <div class="chart-box"><div id="c_resp_hist"></div></div>
  </div>
  <div class="chart-row cols-2">
    <div class="chart-box"><div id="c_triage_median"></div></div>
    <div class="chart-box"><div id="c_coverage_donut"></div></div>
  </div>
</div>

<script>
// Tab switching
function showTab(id, btn) {{
  document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
  document.getElementById(id).classList.add('active');
  btn.classList.add('active');
  setTimeout(() => window.dispatchEvent(new Event('resize')), 100);
}}

// Incident table filter
var allRows = null;
function filterTable() {{
  if (!allRows) allRows = Array.from(document.querySelectorAll('#inc_tbody tr'));
  var sev = document.getElementById('f_sev').value;
  var stat = document.getElementById('f_stat').value;
  var search = document.getElementById('f_search').value.toLowerCase();
  var shown = 0;
  allRows.forEach(function(tr) {{
    var cells = tr.querySelectorAll('td');
    var matchSev  = sev === 'All'  || cells[2].textContent.trim() === sev;
    var matchStat = stat === 'All' || cells[3].textContent.trim() === stat;
    var matchSrch = !search || tr.textContent.toLowerCase().includes(search);
    var show = matchSev && matchStat && matchSrch;
    tr.style.display = show ? '' : 'none';
    if (show) shown++;
  }});
  document.getElementById('f_count').textContent = shown + ' incidents shown';
}}
filterTable();

const C = {{layout: {{paper_bgcolor:'#1a1f2e', plot_bgcolor:'#1a1f2e', font:{{color:'#e0e0e0',size:12}}, margin:{{t:40,b:40,l:10,r:10}}, height:320}}}};
const hbar = {{type:'bar', orientation:'h', marker:{{color:'#e74c3c'}}}};

// TAB 1 charts
Plotly.newPlot('c_monthly_p4', [{{
  type:'bar', x:{json.dumps([x[0] for x in monthly_p4_sorted])},
  y:{json.dumps([x[1] for x in monthly_p4_sorted])},
  marker:{{color:'#3498db'}}
}}], {{...C.layout, title:'Monthly Incident Volume', xaxis:{{tickangle:-45}}}});

Plotly.newPlot('c_severity_donut', [{{
  type:'pie', labels:{json.dumps(list(sev_counts.keys()))},
  values:{json.dumps(list(sev_counts.values()))}, hole:0.45,
  marker:{{colors:['#e74c3c','#e67e22','#f1c40f','#3498db']}}
}}], {{...C.layout, title:'Incidents by Severity'}});

Plotly.newPlot('c_status_donut', [{{
  type:'pie', labels:{json.dumps(list(stat_counts.keys()))},
  values:{json.dumps(list(stat_counts.values()))}, hole:0.45,
  marker:{{colors:['#e74c3c','#27ae60','#95a5a6','#3498db']}}
}}], {{...C.layout, title:'Incidents by Status'}});

var topCats = {json.dumps(cat_counts.most_common(12))};
Plotly.newPlot('c_top_cats', [{{
  type:'bar', orientation:'h',
  x:topCats.map(x=>x[1]), y:topCats.map(x=>x[0]),
  marker:{{color:'#9b59b6'}}
}}], {{...C.layout, title:'Top Incident Categories', yaxis:{{automargin:true}}}});

// TAB 2
var socCats = {json.dumps(soc_cat.most_common())};
Plotly.newPlot('c_soc_cats', [{{
  type:'bar', orientation:'h',
  x:socCats.map(x=>x[1]), y:socCats.map(x=>x[0]),
  marker:{{color:'#e74c3c'}}
}}], {{...C.layout, title:'SOC Alert Volume by Category', height:520, yaxis:{{automargin:true, categoryorder:'total ascending'}}}});

var etypes = {json.dumps(list(email_type.items()))};
Plotly.newPlot('c_email_type', [{{
  type:'pie', labels:etypes.map(x=>x[0]), values:etypes.map(x=>x[1]), hole:0.4
}}], {{...C.layout, title:'Email Type', height:220, margin:{{t:35,b:5,l:5,r:5}}}});

var srcf = {json.dumps(list(src_folder.items()))};
Plotly.newPlot('c_src_folder', [{{
  type:'pie', labels:srcf.map(x=>x[0]), values:srcf.map(x=>x[1]), hole:0.4
}}], {{...C.layout, title:'Source Folder', height:220, margin:{{t:35,b:5,l:5,r:5}}}});

Plotly.newPlot('c_monthly_p1', [{{
  type:'scatter', mode:'lines+markers',
  x:{json.dumps([x[0] for x in monthly_p1_sorted])},
  y:{json.dumps([x[1] for x in monthly_p1_sorted])},
  line:{{color:'#e74c3c', width:2}}, marker:{{size:6}}
}}], {{...C.layout, title:'Monthly SOC Alert Volume', xaxis:{{tickangle:-45}}}});

// TAB 3
var mitre = {json.dumps(mitre_top)};
Plotly.newPlot('c_mitre', [{{
  type:'bar', orientation:'h',
  x:mitre.map(x=>x[1]), y:mitre.map(x=>x[0]),
  marker:{{color:'#c0392b'}}
}}], {{...C.layout, title:'Top MITRE ATT&CK Techniques', yaxis:{{automargin:true, categoryorder:'total ascending'}}}});

var users = {json.dumps(user_top)};
Plotly.newPlot('c_users', [{{
  type:'bar', orientation:'h',
  x:users.map(x=>x[1]), y:users.map(x=>x[0]),
  marker:{{color:'#8e44ad'}}
}}], {{...C.layout, title:'Top Affected Users', yaxis:{{automargin:true, categoryorder:'total ascending'}}}});

// TAB 4
var noise = {json.dumps([(r["category"], r["noise_pct"]) for r in noise_rows[:20]])};
var noiseColors = noise.map(x => x[1]>=80?'#e74c3c':x[1]>=50?'#e67e22':x[1]>=30?'#f1c40f':'#27ae60');
Plotly.newPlot('c_noise_bar', [{{
  type:'bar', orientation:'h',
  x:noise.map(x=>x[1]), y:noise.map(x=>x[0]),
  marker:{{color:noiseColors}},
  text:noise.map(x=>x[1]+'%'), textposition:'outside'
}}], {{...C.layout, title:'SOC Alert Noise Score (%) — Top 20', height:420,
  xaxis:{{range:[0,105], title:'Noise Score %'}}, yaxis:{{automargin:true, categoryorder:'total ascending'}}}});

var msAuto = {json.dumps(ms_auto_list)};
Plotly.newPlot('c_ms_auto', [{{
  type:'bar', orientation:'h',
  x:msAuto.map(x=>x[1]), y:msAuto.map(x=>x[0]),
  marker:{{color:'#27ae60'}}
}}], {{...C.layout, title:'MS Defender Auto-Remediation Candidates (Low/Info, Resolved)', height:420, yaxis:{{automargin:true, categoryorder:'total ascending'}}}});

// TAB 5
var triage = {json.dumps(list(triage_cnt.items()))};
Plotly.newPlot('c_triage_donut', [{{
  type:'pie', labels:triage.map(x=>x[0]), values:triage.map(x=>x[1]), hole:0.45
}}], {{...C.layout, title:'Triage Action Breakdown'}});

Plotly.newPlot('c_resp_hist', [{{
  type:'bar',
  x:{json.dumps(labels_hist)},
  y:{json.dumps(buckets)},
  marker:{{color:'#27ae60'}}
}}], {{...C.layout, title:'Response Time Distribution (hours)', xaxis:{{title:'Time Bucket'}}, yaxis:{{title:'Count'}}}});

var triageMedian = {json.dumps(sorted(triage_median.items(), key=lambda x: x[1]))};
Plotly.newPlot('c_triage_median', [{{
  type:'bar', orientation:'h',
  x:triageMedian.map(x=>x[1]), y:triageMedian.map(x=>x[0]),
  marker:{{color:'#2980b9'}}
}}], {{...C.layout, title:'Median Response Hours by Triage Category', yaxis:{{automargin:true}}}});

Plotly.newPlot('c_coverage_donut', [{{
  type:'pie',
  labels:['Has Response','No Response'],
  values:[{covered},{uncovered}],
  hole:0.45,
  marker:{{colors:['#27ae60','#e74c3c']}}
}}], {{...C.layout, title:'SOC Ticket Coverage ({covered}/{covered+uncovered} = {round(covered/(covered+uncovered)*100,0):.0f}%)'}});
</script>
</body>
</html>"""

out_path = os.path.join(OUTPUT_DIR, "dashboard.html")
with open(out_path, "w", encoding="utf-8") as f:
    f.write(html)
print(f"Dashboard written to: {out_path}")
print(f"File size: {os.path.getsize(out_path) // 1024} KB")
print(f"Open in any browser — no server needed.")
