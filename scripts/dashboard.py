"""
Barry University - Cybersecurity Incident Dashboard
Run: streamlit run scripts/dashboard.py
"""
import os
import glob
import warnings
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st
from collections import Counter
from datetime import datetime

warnings.filterwarnings("ignore")

st.set_page_config(
    page_title="Barry University | Security Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ---------------------------------------------------------------------------
# Theme
# ---------------------------------------------------------------------------
COLORS = {
    "high": "#e74c3c", "medium": "#e67e22", "low": "#f1c40f",
    "informational": "#3498db", "resolved": "#2ecc71", "active": "#e74c3c",
    "redirected": "#95a5a6",
}
SEV_ORDER = ["high", "medium", "low", "informational"]

# ---------------------------------------------------------------------------
# Data loading
# ---------------------------------------------------------------------------

def find_latest(pattern):
    base = "./output" if os.path.isdir("./output") else "../output"
    files = sorted(glob.glob(os.path.join(base, pattern)))
    return files[-1] if files else None

@st.cache_data(ttl=3600)
def load_phase1():
    path = find_latest("phase1_combined_soc_emails_*.csv")
    if not path:
        return pd.DataFrame(), path
    df = pd.read_csv(path, low_memory=False)
    df["received_date"] = pd.to_datetime(df["received_date"], errors="coerce")
    return df, path

@st.cache_data(ttl=3600)
def load_phase3():
    path = find_latest("phase3_baldwin_responses_*.csv")
    if not path:
        return pd.DataFrame(), path
    df = pd.read_csv(path, low_memory=False)
    return df, path

@st.cache_data(ttl=3600)
def load_phase4():
    path = find_latest("phase4_security_incidents_*.csv")
    if not path:
        return pd.DataFrame(), path
    df = pd.read_csv(path, low_memory=False)
    df["created_date"] = pd.to_datetime(df["created_date"], errors="coerce")
    return df, path

p1, p1_path = load_phase1()
p3, p3_path = load_phase3()
p4, p4_path = load_phase4()

# ---------------------------------------------------------------------------
# Sidebar
# ---------------------------------------------------------------------------
st.sidebar.image("https://upload.wikimedia.org/wikipedia/en/thumb/9/9c/Barry_University_seal.png/200px-Barry_University_seal.png", width=100) if False else None
st.sidebar.title("🛡️ Security Dashboard")
st.sidebar.markdown("**Barry University**")
st.sidebar.markdown("---")
st.sidebar.markdown("**Data Files**")
for label, path in [("Phase 1 (SOC)", p1_path), ("Phase 3 (Triage)", p3_path), ("Phase 4 (Incidents)", p4_path)]:
    if path:
        fname = os.path.basename(path)
        ts = fname.replace(".csv","").split("_")[-2] + "_" + fname.replace(".csv","").split("_")[-1]
        try:
            dt = datetime.strptime(ts, "%Y%m%d_%H%M%S").strftime("%b %d %Y %H:%M")
        except Exception:
            dt = ts
        st.sidebar.success(f"✅ {label}  \n`{dt}`")
    else:
        st.sidebar.error(f"❌ {label}: not found")

st.sidebar.markdown("---")
st.sidebar.caption("Refresh: re-run phase scripts then reload page.")

# ---------------------------------------------------------------------------
# Tabs
# ---------------------------------------------------------------------------
tabs = st.tabs(["📊 Executive Summary", "📧 SOC Alerts", "🔍 Incident Drill-Down", "🔇 Noise Reduction", "⏱️ Response Analysis"])

# ===========================================================================
# TAB 1: Executive Summary
# ===========================================================================
with tabs[0]:
    st.header("Executive Summary")
    st.caption("Board-level security posture indicators — Barry University")

    # KPI row
    c1, c2, c3, c4, c5, c6 = st.columns(6)
    total_inc = len(p4) if not p4.empty else 0
    high_inc  = int((p4["severity"] == "high").sum()) if not p4.empty else 0
    active_inc= int((p4["status"] == "active").sum()) if not p4.empty else 0
    soc_tickets = p1["ticket_number"].nunique() if not p1.empty else 0
    fp_rate = "10.7%"
    mttr = "18.2h"

    c1.metric("Total Incidents", f"{total_inc:,}")
    c2.metric("High Severity", f"{high_inc:,}", delta=None)
    c3.metric("Active / Open", f"{active_inc:,}")
    c4.metric("SOC Tickets", f"{soc_tickets:,}")
    c5.metric("False Positive Rate", fp_rate)
    c6.metric("Mean Response Time", mttr)

    st.markdown("---")
    col1, col2 = st.columns(2)

    # Monthly incident trend
    with col1:
        if not p4.empty:
            p4["month"] = p4["created_date"].dt.to_period("M").astype(str)
            monthly = p4.groupby("month").size().reset_index(name="count")
            fig = px.bar(monthly, x="month", y="count", title="Monthly Incident Volume",
                         color_discrete_sequence=["#3498db"])
            fig.update_layout(xaxis_tickangle=-45, height=350)
            st.plotly_chart(fig, use_container_width=True)

    # Severity donut
    with col2:
        if not p4.empty:
            sev = p4["severity"].value_counts().reset_index()
            sev.columns = ["severity", "count"]
            sev["severity"] = pd.Categorical(sev["severity"], categories=SEV_ORDER, ordered=True)
            sev = sev.sort_values("severity")
            fig2 = px.pie(sev, names="severity", values="count", title="Incidents by Severity",
                          hole=0.45, color="severity",
                          color_discrete_map=COLORS)
            fig2.update_layout(height=350)
            st.plotly_chart(fig2, use_container_width=True)

    col3, col4 = st.columns(2)

    # Status breakdown
    with col3:
        if not p4.empty:
            stat = p4["status"].value_counts().reset_index()
            stat.columns = ["status", "count"]
            fig3 = px.pie(stat, names="status", values="count", title="Incidents by Status",
                          hole=0.45, color="status",
                          color_discrete_map=COLORS)
            fig3.update_layout(height=350)
            st.plotly_chart(fig3, use_container_width=True)

    # Top categories
    with col4:
        if not p4.empty:
            cats = p4["dashboard_category"].value_counts().head(12).reset_index()
            cats.columns = ["category", "count"]
            fig4 = px.bar(cats, x="count", y="category", orientation="h",
                          title="Top Incident Categories",
                          color_discrete_sequence=["#9b59b6"])
            fig4.update_layout(yaxis={"categoryorder": "total ascending"}, height=350)
            st.plotly_chart(fig4, use_container_width=True)

# ===========================================================================
# TAB 2: SOC Alerts
# ===========================================================================
with tabs[1]:
    st.header("SOC Alert Analysis (Phase 1)")
    st.caption("All emails from soc@oculusit.com — Barry University mailbox")

    if p1.empty:
        st.warning("Phase 1 data not found.")
    else:
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Total SOC Emails", f"{len(p1):,}")
        c2.metric("Unique Tickets", f"{p1['ticket_number'].nunique():,}")
        c3.metric("Date Range", f"{p1['received_date'].min().strftime('%b %Y')} – {p1['received_date'].max().strftime('%b %Y')}" if not p1['received_date'].isna().all() else "N/A")
        c4.metric("Categories", str(p1['category'].nunique()))

        st.markdown("---")
        col1, col2 = st.columns([2, 1])

        with col1:
            cat_cnt = p1["category"].value_counts().reset_index()
            cat_cnt.columns = ["category", "count"]
            fig = px.bar(cat_cnt, x="count", y="category", orientation="h",
                         title="SOC Alert Volume by Category",
                         color_discrete_sequence=["#e74c3c"])
            fig.update_layout(yaxis={"categoryorder": "total ascending"}, height=600)
            st.plotly_chart(fig, use_container_width=True)

        with col2:
            type_cnt = p1["email_type"].value_counts().reset_index()
            type_cnt.columns = ["type", "count"]
            fig2 = px.pie(type_cnt, names="type", values="count", title="Email Type", hole=0.4)
            fig2.update_layout(height=280)
            st.plotly_chart(fig2, use_container_width=True)

            if "source_folder" in p1.columns:
                src_cnt = p1["source_folder"].value_counts().reset_index()
                src_cnt.columns = ["folder", "count"]
                fig3 = px.pie(src_cnt, names="folder", values="count", title="Source Folder", hole=0.4)
                fig3.update_layout(height=280)
                st.plotly_chart(fig3, use_container_width=True)

        # Monthly trend
        p1["month"] = p1["received_date"].dt.to_period("M").astype(str)
        monthly = p1.groupby("month").size().reset_index(name="count")
        fig4 = px.line(monthly, x="month", y="count", title="Monthly SOC Alert Volume",
                       markers=True, color_discrete_sequence=["#e74c3c"])
        fig4.update_layout(xaxis_tickangle=-45, height=300)
        st.plotly_chart(fig4, use_container_width=True)

# ===========================================================================
# TAB 3: Incident Drill-Down
# ===========================================================================
with tabs[2]:
    st.header("Incident Drill-Down (Phase 4)")
    if p4.empty:
        st.warning("Phase 4 data not found.")
    else:
        fc1, fc2, fc3 = st.columns(3)
        sel_sev  = fc1.selectbox("Severity",  ["All"] + sorted(p4["severity"].dropna().unique().tolist()))
        sel_stat = fc2.selectbox("Status",    ["All"] + sorted(p4["status"].dropna().unique().tolist()))
        sel_cat  = fc3.selectbox("Category",  ["All"] + sorted(p4["dashboard_category"].dropna().unique().tolist()))

        dfi = p4.copy()
        if sel_sev  != "All": dfi = dfi[dfi["severity"] == sel_sev]
        if sel_stat != "All": dfi = dfi[dfi["status"]   == sel_stat]
        if sel_cat  != "All": dfi = dfi[dfi["dashboard_category"] == sel_cat]
        st.caption(f"Showing {len(dfi):,} of {len(p4):,} incidents")

        col1, col2 = st.columns(2)
        with col1:
            mitre_flat = [t.strip() for row in dfi["mitre_techniques"].dropna()
                          for t in str(row).split(" | ") if t.strip()]
            if mitre_flat:
                mc = pd.DataFrame(Counter(mitre_flat).most_common(15), columns=["technique", "count"])
                fig = px.bar(mc, x="count", y="technique", orientation="h",
                             title="Top MITRE ATT&CK Techniques",
                             color_discrete_sequence=["#c0392b"])
                fig.update_layout(yaxis={"categoryorder": "total ascending"}, height=400)
                st.plotly_chart(fig, use_container_width=True)
        with col2:
            user_flat = [u.strip() for row in dfi["affected_users"].dropna()
                         for u in str(row).split(" | ") if u.strip() and "@" in u]
            if user_flat:
                uc = pd.DataFrame(Counter(user_flat).most_common(20), columns=["user", "count"])
                fig2 = px.bar(uc, x="count", y="user", orientation="h",
                              title="Top Affected Users",
                              color_discrete_sequence=["#8e44ad"])
                fig2.update_layout(yaxis={"categoryorder": "total ascending"}, height=400)
                st.plotly_chart(fig2, use_container_width=True)

        dcols = ["incident_id", "display_name", "severity", "status", "dashboard_category", "created_date", "assigned_to"]
        show_df = dfi[[c for c in dcols if c in dfi.columns]].copy()
        show_df["created_date"] = show_df["created_date"].astype(str).str[:10]
        st.markdown("#### Incidents Table")
        st.dataframe(show_df.head(500), use_container_width=True, height=350)

# ===========================================================================
# TAB 4: Noise Reduction
# ===========================================================================
with tabs[3]:
    st.header("Noise Reduction Analysis")
    st.caption("Identify which SOC alert categories can be suppressed, tuned, or auto-remediated.")

    if p1.empty or p3.empty:
        st.warning("Phase 1 and/or Phase 3 data not found.")
    else:
        # Build noise table
        def norm_tn(x):
            try: return str(int(float(x)))
            except: return ""

        p3_clean = p3.dropna(subset=["ticket_number"]).copy()
        p3_clean["ticket_number"] = p3_clean["ticket_number"].apply(norm_tn)
        p3_map = p3_clean[p3_clean["ticket_number"] != ""].drop_duplicates("ticket_number").set_index("ticket_number")["triage_action"].to_dict()

        p1_work = p1.copy()
        p1_work["tn_norm"] = p1_work["ticket_number"].apply(norm_tn)

        rows = []
        for cat, grp in p1_work.groupby("category"):
            total = len(grp)
            fp = ben = auto = 0
            for _, r in grp.iterrows():
                tn = r.get("tn_norm", "")
                ta = p3_map.get(tn, "No Response")
                if ta == "False Positive":    fp += 1
                elif ta == "Auto-Remediated": auto += 1
                elif ta == "Investigated - Benign": ben += 1
            noise = fp + auto + ben
            noise_pct = noise / total * 100 if total else 0
            fp_pct   = fp   / total * 100 if total else 0
            auto_pct = auto / total * 100 if total else 0
            ben_pct  = ben  / total * 100 if total else 0

            if noise_pct >= 80:
                rec = "🔴 SUPPRESS — Ask SOC to stop alerting"
            elif noise_pct >= 50:
                rec = "🟠 TUNE — Enable MS Defender auto-remediation"
            elif noise_pct >= 30:
                rec = "🟡 REVIEW — Batch review instead of per-alert"
            else:
                rec = "🟢 KEEP — Active monitoring required"

            rows.append({"Category": cat, "Total": total, "FP%": round(fp_pct,1),
                         "Auto%": round(auto_pct,1), "Benign%": round(ben_pct,1),
                         "Noise Score": round(noise_pct,1), "Recommendation": rec})

        noise_df = pd.DataFrame(rows).sort_values("Noise Score", ascending=False)

        # Noise bar chart
        fig_n = px.bar(noise_df.head(20), x="Noise Score", y="Category", orientation="h",
                       title="SOC Alert Noise Score by Category (Higher = More Tunable)",
                       color="Noise Score", color_continuous_scale="RdYlGn_r",
                       range_color=[0, 100])
        fig_n.update_layout(yaxis={"categoryorder": "total ascending"}, height=550)
        st.plotly_chart(fig_n, use_container_width=True)

        # Suppression candidates callout
        suppress = noise_df[noise_df["Noise Score"] >= 80]
        tune     = noise_df[(noise_df["Noise Score"] >= 50) & (noise_df["Noise Score"] < 80)]
        if not suppress.empty:
            total_suppressible = int(p1_work[p1_work["category"].isin(suppress["Category"])]["tn_norm"].nunique())
            st.error(f"**{len(suppress)} categories** ({total_suppressible:,} unique tickets) score ≥80% noise — strong candidates to **suppress or stop alerting entirely**.")
        if not tune.empty:
            total_tunable = int(p1_work[p1_work["category"].isin(tune["Category"])]["tn_norm"].nunique())
            st.warning(f"**{len(tune)} categories** ({total_tunable:,} unique tickets) score 50–80% — candidates for **MS Defender auto-remediation or raised thresholds**.")

        st.markdown("#### Noise Reduction Table")
        st.dataframe(noise_df, use_container_width=True, height=400)

        # Phase 4 auto-remediation candidates
        st.markdown("---")
        st.subheader("Microsoft Defender Auto-Remediation Candidates (Phase 4)")
        st.caption("Incidents that are informational/low severity, resolved, with unknown classification — safe to auto-remediate.")
        if not p4.empty:
            auto_cands = p4[(p4["severity"].isin(["low","informational"])) &
                            (p4["status"] == "resolved") &
                            (p4["classification"] == "unknown")]
            ac_cnt = auto_cands["dashboard_category"].value_counts().reset_index()
            ac_cnt.columns = ["category", "count"]
            ac_cnt["pct_of_category"] = ac_cnt.apply(
                lambda r: round(r["count"] / len(p4[p4["dashboard_category"]==r["category"]]) * 100, 1), axis=1)
            fig_ac = px.bar(ac_cnt.head(15), x="count", y="category", orientation="h",
                            title="Top Auto-Remediation Candidates by Category",
                            color="pct_of_category", color_continuous_scale="Greens")
            fig_ac.update_layout(yaxis={"categoryorder": "total ascending"}, height=400)
            st.plotly_chart(fig_ac, use_container_width=True)
            st.dataframe(ac_cnt, use_container_width=True)

        # Specific recommendations
        st.markdown("---")
        st.subheader("Specific Tuning Recommendations")
        recs = [
            ("Anomalous Token (93% noise)", "Enable **Defender for Identity** auto-remediation for anomalous token alerts. Require re-authentication via Conditional Access instead of SOC investigation."),
            ("Sign-in from Anonymous Proxy (84% noise)", "Configure Conditional Access policy to **block or require MFA** for anonymous proxy sign-ins automatically. SOC alert unnecessary if policy enforces it."),
            ("Investigated - Benign Sign-ins (>65% across sign-in categories)", "Create a **named location allowlist** in Entra ID for known VPN providers and student travel patterns. Reduce signal-to-noise ratio by 50-70%."),
            ("User Email Reports (1,448 incidents, all low severity)", "Enable **Defender for Office 365 automated investigation** to handle user-reported junk/not-junk automatically. No SOC involvement needed."),
            ("Email Campaign Removed (1,003 informational)", "These are **auto-resolved by Microsoft**. Ask SOC to suppress all 'Email messages removed after delivery' notifications — Microsoft already handled them."),
            ("Admin Action (138 informational, all resolved)", "Suppress — these are **generated by your own admins** performing manual investigations. Not a threat."),
        ]
        for title, detail in recs:
            with st.expander(f"📋 {title}"):
                st.markdown(detail)

# ===========================================================================
# TAB 5: Response Analysis
# ===========================================================================
with tabs[4]:
    st.header("Response Analysis — John Baldwin (Phase 3)")
    st.caption("Triage response patterns and time-to-respond for SOC incident coordinator.")

    if p3.empty:
        st.warning("Phase 3 data not found.")
    else:
        c1, c2, c3, c4 = st.columns(4)
        hrs = pd.to_numeric(p3["response_hours"], errors="coerce").dropna()
        c1.metric("Total Responses", f"{len(p3):,}")
        c2.metric("Mean Response Time", f"{hrs.mean():.1f}h" if len(hrs) else "N/A")
        c3.metric("Median Response Time", f"{hrs.median():.1f}h" if len(hrs) else "N/A")
        c4.metric("P90 Response Time", f"{hrs.quantile(0.9):.1f}h" if len(hrs) else "N/A")

        st.markdown("---")
        col1, col2 = st.columns(2)

        with col1:
            ta_cnt = p3["triage_action"].value_counts().reset_index()
            ta_cnt.columns = ["action", "count"]
            fig = px.pie(ta_cnt, names="action", values="count",
                         title="Triage Action Breakdown", hole=0.4)
            fig.update_layout(height=400)
            st.plotly_chart(fig, use_container_width=True)

        with col2:
            # Response time histogram capped at 168h
            hrs_cap = hrs[hrs <= 168]
            fig2 = px.histogram(hrs_cap, x=hrs_cap, nbins=40,
                                title="Response Time Distribution (capped at 168h)",
                                labels={"x": "Hours"}, color_discrete_sequence=["#27ae60"])
            fig2.update_layout(height=400)
            st.plotly_chart(fig2, use_container_width=True)

        # Response time by triage category
        p3_hrs = p3.copy()
        p3_hrs["response_hours"] = pd.to_numeric(p3_hrs["response_hours"], errors="coerce")
        p3_hrs = p3_hrs[p3_hrs["response_hours"].notna() & (p3_hrs["response_hours"] <= 168)]
        if not p3_hrs.empty:
            fig3 = px.box(p3_hrs, x="triage_action", y="response_hours",
                          title="Response Time by Triage Category",
                          color_discrete_sequence=["#2980b9"])
            fig3.update_layout(xaxis_tickangle=-30, height=400)
            st.plotly_chart(fig3, use_container_width=True)

        # Coverage
        if not p1.empty:
            st.markdown("---")
            st.subheader("Coverage Analysis")
            def norm_tn2(x):
                try: return str(int(float(x)))
                except: return ""
            all_tickets = set(p1["ticket_number"].dropna().apply(norm_tn2)) - {""}
            responded   = set(p3["ticket_number"].dropna().apply(norm_tn2)) - {""}
            covered = len(all_tickets & responded)
            uncovered = len(all_tickets - responded)
            cov_df = pd.DataFrame({"Status": ["Response Found", "No Response"],
                                   "Count": [covered, uncovered]})
            fig4 = px.pie(cov_df, names="Status", values="Count",
                          title=f"SOC Ticket Coverage ({covered}/{len(all_tickets)} tickets)",
                          hole=0.45, color_discrete_sequence=["#27ae60","#e74c3c"])
            fig4.update_layout(height=300)
            st.plotly_chart(fig4, use_container_width=True)
