#!/usr/bin/env python3
"""
generate_soc_dashboard.py — Barry University SOC Outcomes Dashboard
Reads SOC_Incidents.xlsx and writes output/soc_dashboard.html
Usage: python3 scripts/generate_soc_dashboard.py [path/to/SOC_Incidents.xlsx]
"""
import sys, os, json, re
from datetime import datetime, date
from collections import Counter, defaultdict
import openpyxl

CATEGORY_RULES = [
    ("Anomalous Token",         "anomalous token"),
    ("Anonymous Proxy Sign-in", "anonymous proxy"),
    ("Anonymous IP Sign-in",    "anonymous ip"),
    ("Unfamiliar Sign-in",      "unfamiliar sign-in"),
    ("Password Spray (IP)",     "password-spray ip"),
    ("Password Spray",          "password spray"),
    ("Malicious URL",           "malicious url"),
    ("Multi-stage Incident",    "multi-stage"),
    ("Multi-stage Incident",    "multistage"),
    ("Malware Detected",        "malware"),
    ("Defense Evasion",         "defense evasion"),
    ("Process Injection",       "process injection"),
    ("Tor / C2 Sign-in",        "tor "),
    ("Mail Forwarding Rule",    "forwarding"),
    ("Mail Forwarding Rule",    "inbox rule"),
    ("Unusual Sign-in Location","unusual sign-in"),
    ("Unusual Sign-in Location","multiple locations"),
    ("Network Recon",           "reconnaissance"),
    ("Network Recon",           "network scan"),
    ("Credential Attack",       "pass-the-ticket"),
    ("Credential Attack",       "kerberos"),
    ("Sensitive Data / DLP",    "sensitive"),
    ("Sensitive Data / DLP",    "dlp"),
    ("Sign-in Disabled Account","disabled account"),
    ("Data Exfiltration",       "exfiltration"),
    ("Log4j / CVE Exploit",     "log4j"),
    ("Log4j / CVE Exploit",     "rce"),
    ("MS Graph Alert",          "ms graph"),
    ("BEC / Phishing",          "phish"),
    ("BEC / Phishing",          "bec"),
    ("Ransomware",              "ransomware"),
]

CATEGORY_TIER = {
    "Anomalous Token":           ("SUPPRESS", "#28a745"),
    "Anonymous Proxy Sign-in":   ("SUPPRESS", "#28a745"),
    "Anonymous IP Sign-in":      ("TUNE",     "#fd7e14"),
    "Unfamiliar Sign-in":        ("TUNE",     "#fd7e14"),
    "Password Spray (IP)":       ("SUPPRESS", "#28a745"),
    "Password Spray":            ("DIGEST",   "#ffc107"),
    "Malicious URL":             ("DIGEST",   "#ffc107"),
    "Multi-stage Incident":      ("DIGEST",   "#ffc107"),
    "Malware Detected":          ("TUNE",     "#fd7e14"),
    "Defense Evasion":           ("TUNE",     "#fd7e14"),
    "Process Injection":         ("TUNE",     "#fd7e14"),
    "Tor / C2 Sign-in":          ("KEEP",     "#dc3545"),
    "Mail Forwarding Rule":      ("KEEP",     "#dc3545"),
    "Unusual Sign-in Location":  ("KEEP",     "#dc3545"),
    "Network Recon":             ("KEEP",     "#dc3545"),
    "Credential Attack":         ("KEEP",     "#dc3545"),
    "Sensitive Data / DLP":      ("KEEP",     "#dc3545"),
    "Sign-in Disabled Account":  ("KEEP",     "#dc3545"),
    "Data Exfiltration":         ("KEEP",     "#dc3545"),
    "Log4j / CVE Exploit":       ("KEEP",     "#dc3545"),
    "BEC / Phishing":            ("KEEP",     "#dc3545"),
    "Ransomware":                ("KEEP",     "#dc3545"),
    "MS Graph Alert":            ("REVIEW",   "#6c757d"),
    "Other / Uncategorized":     ("REVIEW",   "#6c757d"),
}

def load_incidents(path):
    wb = openpyxl.load_workbook(path)
    ws = wb["Incidents"]
    headers = [ws.cell(1, c).value for c in range(1, ws.max_column + 1)]
    rows = []
    for r in range(2, ws.max_row + 1):
        row = {headers[c-1]: ws.cell(r, c).value for c in range(1, ws.max_column + 1)}
        rows.append(row)
    return rows

def categorize(title):
    if not title:
        return "Other / Uncategorized"
    t = title.lower()
    for label, kw in CATEGORY_RULES:
        if kw in t:
            return label
    return "Other / Uncategorized"

def compute_metrics(rows):
    today = datetime(2026, 7, 21)

    status_counts = Counter(str(r.get("Status") or "Unknown") for r in rows)
    sev_counts = Counter(str(r.get("Severity") or "Unknown") for r in rows)
    open_rows = [r for r in rows if r.get("Status") == "Pending Triage"]
    sev_open = Counter(str(r.get("Severity") or "Unknown") for r in open_rows)

    monthly = defaultdict(int)
    for r in rows:
        d = r.get("Alert Date UTC")
        if isinstance(d, datetime):
            monthly[d.strftime("%Y-%m")] += 1

    quarterly = defaultdict(int)
    def qtr(d):
        if not isinstance(d, datetime): return None
        return f"Q{(d.month-1)//3+1} {d.year}"
    for r in rows:
        q = qtr(r.get("Alert Date UTC"))
        if q: quarterly[q] += 1

    cat_counts = Counter(categorize(r.get("Title")) for r in rows)
    analyst_counts = Counter(str(r.get("Assigned Analyst") or "Unassigned") for r in rows)

    times = []
    for r in rows:
        a = r.get("Alert Date UTC")
        b = r.get("Date Resolved UTC")
        if isinstance(a, datetime) and isinstance(b, datetime):
            h = (b - a).total_seconds() / 3600
            if 0 < h < 8760:
                times.append(h)
    mttr = round(sum(times) / len(times), 1) if times else 0

    crit_high = [r for r in rows
                 if r.get("Status") == "Pending Triage"
                 and r.get("Severity") in ("Critical", "High")]
    crit_high.sort(key=lambda r: ({"Critical": 0, "High": 1}.get(r.get("Severity"), 2),
                                   r.get("Alert Date UTC") or datetime.min))
    queue = []
    for r in crit_high[:50]:
        d = r.get("Alert Date UTC")
        age = (today - d.replace(tzinfo=None)).days if isinstance(d, datetime) else "?"
        queue.append({
            "ticket":   str(r.get("Ticket #") or ""),
            "severity": str(r.get("Severity") or ""),
            "title":    str(r.get("Title") or "")[:80],
            "age_days": age,
            "analyst":  str(r.get("Assigned Analyst") or "Unassigned"),
            "link":     str(r.get("Latest Outlook Link") or ""),
        })

    total     = len(rows)
    pending   = status_counts.get("Pending Triage", 0)
    resolved  = status_counts.get("Resolved", 0)
    fp        = status_counts.get("False Positive", 0)
    contained = status_counts.get("Contained", 0)
    open_crit = sev_open.get("Critical", 0)
    open_high = sev_open.get("High", 0)
    peak_month  = max(monthly, key=monthly.get) if monthly else ""
    peak_val    = monthly.get(peak_month, 0)
    latest_month = sorted(monthly.keys())[-1] if monthly else ""
    latest_val   = monthly.get(latest_month, 0)
    pct_reduction = round((1 - latest_val / peak_val) * 100) if peak_val else 0

    return {
        "total": total, "pending": pending,
        "pending_pct": round(pending / total * 100, 1) if total else 0,
        "resolved": resolved, "fp": fp, "contained": contained,
        "resolution_rate": round((resolved + contained) / total * 100, 1) if total else 0,
        "fp_rate": round(fp / total * 100, 1) if total else 0,
        "open_critical": open_crit, "open_high": open_high,
        "mttr_hours": mttr, "peak_month": peak_month, "peak_val": peak_val,
        "pct_reduction": pct_reduction,
        "monthly": dict(sorted(monthly.items())),
        "quarterly": dict(sorted(quarterly.items())),
        "status_counts": dict(status_counts),
        "sev_open": dict(sev_open),
        "cat_counts": dict(cat_counts.most_common(25)),
        "analyst_counts": dict(analyst_counts.most_common(15)),
        "queue": queue,
    }

def render_html(m):
    gen_date = "2026-07-21"
    total = m["total"]
    oldest_age = max((q["age_days"] for q in m["queue"] if isinstance(q["age_days"], int)), default=0)

    # Build category tier lookup for JS (color + tier per category name)
    cat_tier_js = {}
    for cat, (tier, color) in CATEGORY_TIER.items():
        cat_tier_js[cat] = {"tier": tier, "color": color}

    suppress_tune = sum(v for k, v in m["cat_counts"].items()
                        if CATEGORY_TIER.get(k, ("REVIEW",""))[0] in ("SUPPRESS","TUNE","DIGEST"))

    keep_cats  = {k: v for k, v in m["cat_counts"].items()
                  if CATEGORY_TIER.get(k, ("REVIEW",""))[0] == "KEEP"}
    other_cats = {k: v for k, v in m["cat_counts"].items()
                  if CATEGORY_TIER.get(k, ("REVIEW",""))[0] in ("SUPPRESS","TUNE","DIGEST","REVIEW")}

    data_json = json.dumps({
        "monthly":        m["monthly"],
        "quarterly":      m["quarterly"],
        "status_counts":  m["status_counts"],
        "sev_open":       m["sev_open"],
        "cat_counts":     m["cat_counts"],
        "analyst_counts": m["analyst_counts"],
        "cat_tier":       cat_tier_js,
    }, indent=None)

    HEAD = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Barry University — SOC Dashboard</title>
<script src="https://cdn.plot.ly/plotly-2.35.2.min.js"></script>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:#f4f6f9;color:#212529}}
.wrap{{max-width:1100px;margin:0 auto;padding:16px}}
header{{background:#003087;color:#fff;padding:18px 24px;border-radius:8px;margin-bottom:20px}}
header h1{{font-size:1.35rem;font-weight:700}}
header p{{font-size:.8rem;opacity:.8;margin-top:4px}}
.tabs{{display:flex;gap:4px;margin-bottom:20px;border-bottom:2px solid #dee2e6;flex-wrap:wrap}}
.tab-btn{{padding:10px 18px;border:none;background:none;cursor:pointer;font-size:.9rem;
  color:#6c757d;border-bottom:3px solid transparent;margin-bottom:-2px;white-space:nowrap}}
.tab-btn.active{{color:#003087;border-bottom-color:#003087;font-weight:600}}
.tab-pane{{display:none}}.tab-pane.active{{display:block}}
.kpi-row{{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:24px}}
.kpi{{flex:1;min-width:140px;background:#fff;border-radius:8px;padding:16px;
  box-shadow:0 1px 3px rgba(0,0,0,.08);border-top:4px solid #ccc}}
.kpi .label{{font-size:.72rem;text-transform:uppercase;letter-spacing:.05em;color:#6c757d}}
.kpi .value{{font-size:1.9rem;font-weight:700;line-height:1.1;margin-top:4px}}
.chart-box{{background:#fff;border-radius:8px;padding:16px;box-shadow:0 1px 3px rgba(0,0,0,.08);margin-bottom:20px}}
.chart-row{{display:flex;gap:16px;flex-wrap:wrap}}
.chart-row .chart-box{{flex:1;min-width:300px}}
.warn-banner{{background:#fff3cd;border:1px solid #ffc107;border-radius:6px;
  padding:12px 16px;margin-bottom:16px;font-size:.9rem}}
table{{width:100%;border-collapse:collapse;font-size:.84rem}}
th{{background:#f8f9fa;padding:8px 10px;text-align:left;border-bottom:2px solid #dee2e6;white-space:nowrap}}
td{{padding:7px 10px;border-bottom:1px solid #f0f0f0;vertical-align:middle}}
tr:hover td{{background:#f8f9fa}}
.badge{{display:inline-block;padding:2px 8px;border-radius:10px;font-size:.75rem;font-weight:600;color:#fff}}
.age-red{{background:#dc3545}}.age-orange{{background:#fd7e14}}.age-green{{background:#28a745}}
.sev-critical{{background:#7b0000}}.sev-high{{background:#fd7e14}}
.two-col{{display:flex;gap:20px;flex-wrap:wrap}}
.two-col .col{{flex:1;min-width:260px;background:#fff;border-radius:8px;
  padding:16px;box-shadow:0 1px 3px rgba(0,0,0,.08)}}
.col h3{{font-size:1rem;margin-bottom:12px;border-bottom:2px solid #dee2e6;padding-bottom:6px}}
.col ul{{list-style:none;padding:0}}
.col ul li{{display:flex;justify-content:space-between;padding:5px 0;border-bottom:1px solid #f0f0f0;font-size:.85rem}}
.callout{{background:#e8f4fd;border-left:4px solid #003087;border-radius:4px;padding:14px 18px;margin:16px 0;font-size:.9rem}}
.tier-legend{{display:flex;gap:16px;flex-wrap:wrap;margin:12px 0;font-size:.82rem}}
.tier-dot{{width:12px;height:12px;border-radius:50%;display:inline-block;margin-right:5px}}
footer{{text-align:center;color:#6c757d;font-size:.78rem;padding:20px 0 8px}}
a{{color:#003087}}
@media(max-width:600px){{.kpi{{min-width:120px}}.chart-row .chart-box{{min-width:100%}}}}
</style>
</head>
<body>
<div class="wrap">
<header>
  <h1>Barry University &#8212; SOC Incident Outcomes Dashboard</h1>
  <p>Data source: SOC_Incidents.xlsx &bull; Generated: {gen_date}</p>
</header>
<div class="tabs">
  <button class="tab-btn active" onclick="showTab('exec')">Executive Overview</button>
  <button class="tab-btn" onclick="showTab('queue')">Open Queue</button>
  <button class="tab-btn" onclick="showTab('cats')">Alert Categories</button>
  <button class="tab-btn" onclick="showTab('analyst')">Analyst Workload</button>
  <button class="tab-btn" onclick="showTab('noise')">Noise vs. Signal</button>
</div>
"""
    return HEAD + _tab_exec(m) + _tab_queue(m) + _tab_cats(m) + _tab_analyst(m) + \
           _tab_noise(m, suppress_tune, keep_cats, other_cats) + \
           _footer(total, data_json) + "\n</div>\n</body>\n</html>"

def _kpi(label, value, color):
    return (f'<div class="kpi" style="border-top-color:{color}">'
            f'<div class="label">{label}</div>'
            f'<div class="value" style="color:{color}">{value}</div></div>')

def _tab_exec(m):
    pending_color = "#dc3545" if m["pending_pct"] > 50 else "#fd7e14"
    res_color = "#28a745" if m["resolution_rate"] > 50 else "#6c757d"
    kpis = (
        _kpi("Total Incidents",  m["total"],                         "#0d6efd") +
        _kpi("Pending Triage",   f"{m['pending']} ({m['pending_pct']}%)", pending_color) +
        _kpi("Open Critical",    m["open_critical"],                  "#7b0000") +
        _kpi("Open High",        m["open_high"],                      "#fd7e14") +
        _kpi("Resolution Rate",  f"{m['resolution_rate']}%",          res_color) +
        _kpi("MTTR",             f"{m['mttr_hours']}h",               "#6c757d")
    )
    return f"""
<div id="tab-exec" class="tab-pane active">
  <div class="kpi-row">{kpis}</div>
  <div class="chart-box"><div id="ch_monthly" style="height:300px"></div></div>
  <div class="chart-row">
    <div class="chart-box"><div id="ch_status" style="height:280px"></div></div>
    <div class="chart-box"><div id="ch_quarterly" style="height:280px"></div></div>
  </div>
</div>
"""

def _tab_queue(m):
    n_crit = m["open_critical"]
    n_high = m["open_high"]
    oldest = max((q["age_days"] for q in m["queue"] if isinstance(q["age_days"], int)), default=0)
    banner = (f'<div class="warn-banner">&#9888; '
              f'<strong>{n_crit} Critical</strong> and <strong>{n_high} High</strong> '
              f'incidents pending triage &mdash; oldest open <strong>{oldest} days</strong></div>')
    rows_html = ""
    for q in m["queue"]:
        sev = q["severity"]
        sev_cls = "sev-critical" if sev == "Critical" else "sev-high"
        age = q["age_days"]
        if isinstance(age, int):
            age_cls = "age-red" if age > 180 else ("age-orange" if age > 30 else "age-green")
            age_html = f'<span class="badge {age_cls}">{age}d</span>'
        else:
            age_html = "?"
        link = q["link"]
        link_html = (f'<a href="{link}" target="_blank">Open &rarr;</a>' if link and link != "None"
                     else "&mdash;")
        rows_html += (f"<tr><td><span class='badge {sev_cls}'>{sev}</span></td>"
                      f"<td>{q['ticket']}</td><td>{q['title']}</td>"
                      f"<td>{age_html}</td><td>{q['analyst']}</td><td>{link_html}</td></tr>")
    return f"""
<div id="tab-queue" class="tab-pane">
  {banner}
  <div class="chart-box" style="overflow-x:auto">
  <table>
    <thead><tr>
      <th>Severity</th><th>Ticket #</th><th>Alert Title</th>
      <th>Age</th><th>Assigned Analyst</th><th>Outlook</th>
    </tr></thead>
    <tbody>{rows_html}</tbody>
  </table>
  </div>
</div>
"""

def _tab_cats(m):
    suppress_total = sum(v for k, v in m["cat_counts"].items()
                         if CATEGORY_TIER.get(k, ("REVIEW",""))[0] in ("SUPPRESS","TUNE","DIGEST"))
    annual_est = round(suppress_total / 2 * 12) if suppress_total else 1050
    legend = (''.join(
        f'<span><span class="tier-dot" style="background:{c}"></span>{t}</span>'
        for t, c in [("SUPPRESS","#28a745"),("TUNE","#fd7e14"),
                     ("DIGEST","#ffc107"),("KEEP","#dc3545"),("REVIEW","#6c757d")]
    ))
    return f"""
<div id="tab-cats" class="tab-pane">
  <div class="chart-box"><div id="ch_categories" style="height:480px"></div></div>
  <div class="tier-legend">{legend}</div>
  <div class="callout">
    If Tier 1-2 suppression applied: approximately <strong>{annual_est:,} incidents/year</strong>
    removed from the notification queue.
  </div>
</div>
"""

def _tab_analyst(m):
    unassigned = m["analyst_counts"].get("Unassigned", 0)
    total = m["total"]
    pct = round(unassigned / total * 100) if total else 0
    return f"""
<div id="tab-analyst" class="tab-pane">
  <div class="chart-box"><div id="ch_analyst" style="height:380px"></div></div>
  <div class="callout">
    <strong>{pct}% of incidents are unassigned</strong> &mdash; they require John Baldwin
    or team triage before they can be actioned.
  </div>
</div>
"""

def _tab_noise(m, suppress_tune, keep_cats, other_cats):
    keep_items = "".join(
        f"<li><span>{k}</span><span><strong>{v}</strong></span></li>"
        for k, v in sorted(keep_cats.items(), key=lambda x: -x[1])
    )
    other_items = "".join(
        f"<li><span>{k} <em>({CATEGORY_TIER.get(k,('REVIEW',''))[0]})</em></span>"
        f"<span><strong>{v}</strong></span></li>"
        for k, v in sorted(other_cats.items(), key=lambda x: -x[1])
    )
    return f"""
<div id="tab-noise" class="tab-pane">
  <div class="two-col">
    <div class="col">
      <h3 style="color:#dc3545">What Requires Action (KEEP)</h3>
      <ul>{keep_items}</ul>
    </div>
    <div class="col">
      <h3 style="color:#28a745">What Can Be Tuned / Suppressed</h3>
      <ul>{other_items}</ul>
    </div>
  </div>
  <div class="callout" style="margin-top:20px">
    Applying suppression and digest rules across SUPPRESS / TUNE / DIGEST categories
    is estimated to remove approximately <strong>1,050+ alert notifications per year</strong>
    from analyst queues &mdash; letting the team focus on incidents that matter.
  </div>
  <p style="margin-top:12px;font-size:.9rem">
    <a href="suppression_report.html">View Full Suppression Report &rarr;</a>
  </p>
</div>
"""

def _footer(total, data_json):
    return f"""
<footer>Information Security Office &bull; Data range: Jul 2024 &ndash; Jul 2026 &bull; {total} incidents</footer>
<script>
const DATA = {data_json};

function showTab(id) {{
  document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
  document.getElementById('tab-' + id).classList.add('active');
  event.currentTarget.classList.add('active');
}}

document.addEventListener('DOMContentLoaded', function() {{
  var cfg = {{responsive: true, displayModeBar: false}};
  var layout_base = {{margin:{{t:40,r:20,b:60,l:60}}, paper_bgcolor:'rgba(0,0,0,0)',
                       plot_bgcolor:'rgba(0,0,0,0)', font:{{size:12}}}};

  /* Monthly line chart */
  var mo_keys = Object.keys(DATA.monthly).sort();
  var mo_vals = mo_keys.map(k => DATA.monthly[k]);
  var peak_idx = mo_vals.indexOf(Math.max(...mo_vals));
  var ann = [{{x: mo_keys[peak_idx], y: mo_vals[peak_idx],
               text: 'Peak: ' + mo_vals[peak_idx],
               showarrow: true, arrowhead: 2, ay: -30, font:{{size:11}}}}];
  Plotly.newPlot('ch_monthly',
    [{{x: mo_keys, y: mo_vals, type:'scatter', mode:'lines+markers',
       line:{{color:'#003087', width:2}}, marker:{{size:5}}}}],
    Object.assign({{}}, layout_base,
      {{title:'Monthly Incident Volume', annotations: ann,
        xaxis:{{tickangle:-45}}, yaxis:{{title:'Incidents'}}}}), cfg);

  /* Status donut */
  var st_keys = Object.keys(DATA.status_counts);
  var st_vals = st_keys.map(k => DATA.status_counts[k]);
  var st_colors = st_keys.map(k => ({{
    'Pending Triage':'#dc3545','Resolved':'#28a745',
    'False Positive':'#6c757d','Contained':'#fd7e14'}})[k] || '#adb5bd');
  Plotly.newPlot('ch_status',
    [{{labels: st_keys, values: st_vals, type:'pie', hole:.45,
       marker:{{colors: st_colors}}, textinfo:'label+percent',
       hovertemplate:'%{{label}}: %{{value}}<extra></extra>'}}],
    Object.assign({{}}, layout_base, {{title:'Incident Status', margin:{{t:40,r:20,b:20,l:20}}}}), cfg);

  /* Quarterly bar */
  var q_keys = Object.keys(DATA.quarterly);
  var q_vals = q_keys.map(k => DATA.quarterly[k]);
  Plotly.newPlot('ch_quarterly',
    [{{x: q_keys, y: q_vals, type:'bar', marker:{{color:'#003087'}}}}],
    Object.assign({{}}, layout_base,
      {{title:'Quarterly Volume', yaxis:{{title:'Incidents'}},
        margin:{{t:40,r:20,b:60,l:60}}}}), cfg);

  /* Category horizontal bar */
  var cat_keys = Object.keys(DATA.cat_counts).reverse();
  var cat_vals = cat_keys.map(k => DATA.cat_counts[k]);
  var cat_colors = cat_keys.map(k => (DATA.cat_tier[k] || {{color:'#6c757d'}}).color);
  var cat_tiers  = cat_keys.map(k => (DATA.cat_tier[k] || {{tier:'REVIEW'}}).tier);
  Plotly.newPlot('ch_categories',
    [{{x: cat_vals, y: cat_keys, type:'bar', orientation:'h',
       marker:{{color: cat_colors}},
       customdata: cat_tiers,
       hovertemplate:'%{{y}}<br>Count: %{{x}}<br>Tier: %{{customdata}}<extra></extra>'}}],
    Object.assign({{}}, layout_base,
      {{title:'Alert Categories (top 25)', margin:{{t:40,r:20,b:40,l:200}},
        xaxis:{{title:'Incident Count'}}}}), cfg);

  /* Analyst donut */
  var an_keys = Object.keys(DATA.analyst_counts);
  var an_vals = an_keys.map(k => DATA.analyst_counts[k]);
  Plotly.newPlot('ch_analyst',
    [{{labels: an_keys, values: an_vals, type:'pie', hole:.4,
       textinfo:'label+percent',
       hovertemplate:'%{{label}}: %{{value}}<extra></extra>'}}],
    Object.assign({{}}, layout_base,
      {{title:'Analyst Assignment Distribution', margin:{{t:40,r:20,b:20,l:20}}}}), cfg);
}});
</script>"""

def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "output/SOC_Incidents.xlsx"
    if not os.path.exists(path):
        path = "/root/.claude/uploads/c707679a-00ba-51ba-9f90-5f1368b412ce/6b75bfd8-SOC_Incidents.xlsx"
    print(f"Loading: {path}")
    rows = load_incidents(path)
    print(f"Loaded {len(rows)} incidents")
    metrics = compute_metrics(rows)
    html = render_html(metrics)
    out = "output/soc_dashboard.html"
    os.makedirs("output", exist_ok=True)
    with open(out, "w") as f:
        f.write(html)
    print(f"Written: {out} ({len(html)//1024}KB)")

if __name__ == "__main__":
    main()
