import networkx as nx
import matplotlib.pyplot as plt
import streamlit as st
import pandas as pd
import json
import requests
import plotly.express as px
from sklearn.ensemble import IsolationForest
import numpy as np
import subprocess
from streamlit_autorefresh import st_autorefresh
from fpdf import FPDF

# ---------------------------------------------------
# PAGE CONFIG
# ---------------------------------------------------
st.set_page_config(page_title="Advanced Intrusion Dashboard", layout="wide")
st_autorefresh(interval=3000, key="refresh")

st.markdown("""
<style>

/* Main background */
.stApp {
    background: linear-gradient(135deg, #0b1220, #111827);
    color: white;
}

/* Metric cards */
div[data-testid="metric-container"] {
    background: rgba(255,255,255,0.04);
    border: 1px solid rgba(255,255,255,0.08);
    padding: 15px;
    border-radius: 14px;
    box-shadow: 0 4px 18px rgba(0,0,0,0.35);
}

/* Headers */
h1, h2, h3 {
    color: #f8fafc;
}

/* Buttons */
.stButton > button {
    background: linear-gradient(90deg,#2563eb,#1d4ed8);
    color: white;
    border: none;
    border-radius: 10px;
    padding: 0.55rem 1rem;
    font-weight: 600;
}

/* Dataframes */
section[data-testid="stDataFrame"] {
    border-radius: 12px;
    overflow: hidden;
}

/* Sidebar */
section[data-testid="stSidebar"] {
    background: #0f172a;
}

/* Alerts */
div[role="alert"] {
    border-radius: 12px;
}

</style>
""", unsafe_allow_html=True)

# ---------------------------------------------------
# LOAD LOGS
# ---------------------------------------------------
logfile = "var/log/cowrie/cowrie.json"

data = []

try:
    with open(logfile, "r") as f:
        for line in f:
            entry = json.loads(line)

            data.append({
                "IP": entry.get("src_ip"),
                "Command": entry.get("input"),
                "Event": entry.get("eventid"),
                "Time": entry.get("timestamp")
            })
except:
    st.error("Cowrie log file not found.")

df = pd.DataFrame(data)

if not df.empty:
    df["Time"] = pd.to_datetime(df["Time"], errors="coerce")

# ---------------------------------------------------
# HELPERS
# ---------------------------------------------------
def classify_ip(ip):
    if str(ip) == "127.0.0.1":
        return "Internal Host"
    elif str(ip).startswith("192.168."):
        return "Lab Attacker"
    else:
        return "Unknown"


def risk_level(cmd):
    if pd.isna(cmd):
        return "Low"

    cmd = cmd.lower()

    if any(x in cmd for x in ["wget", "curl", "chmod", "rm", "bash"]):
        return "High"

    if any(x in cmd for x in ["uname", "passwd", "ps", "netstat"]):
        return "Medium"

    return "Low"


def nlp_intent(cmd):
    if pd.isna(cmd):
        return "Unknown"

    cmd = cmd.lower()

    if any(x in cmd for x in ["ls", "pwd", "whoami", "uname"]):
        return "Reconnaissance"

    if any(x in cmd for x in ["cat /etc/passwd", "ps", "netstat"]):
        return "Enumeration"

    if any(x in cmd for x in ["wget", "curl"]):
        return "Payload Download"

    if any(x in cmd for x in ["chmod", "bash", "python"]):
        return "Execution"

    if any(x in cmd for x in ["rm", "history -c"]):
        return "Anti-Forensics"

    return "General Activity"



def mitre_map(cmd):
    if pd.isna(cmd):
        return "None"

    cmd = cmd.lower()

    if "whoami" in cmd or "uname" in cmd or "ls" in cmd:
        return "Discovery"

    if "wget" in cmd or "curl" in cmd:
        return "Ingress Tool Transfer"

    if "chmod" in cmd or "bash" in cmd:
        return "Execution"

    if "rm" in cmd:
        return "Defense Evasion"

    return "General Activity"


# ---------------------------------------------------
# ENRICH DATA
# ---------------------------------------------------
if not df.empty:
    df["Risk"] = df["Command"].apply(risk_level)
    df["Source"] = df["IP"].apply(classify_ip)
    df["MITRE"] = df["Command"].apply(mitre_map)
    df["Intent"] = df["Command"].apply(nlp_intent)
# ---------------------------------------------------
# TITLE
# ---------------------------------------------------
st.markdown("""
<div style='padding:18px;border-radius:16px;
background:linear-gradient(90deg,#111827,#1e293b);
border:1px solid rgba(255,255,255,0.08);'>

<h1 style='margin-bottom:0;color:white;'>🛡 Intrusion Intelligence Center</h1>

<p style='color:#94a3b8; margin-top:6px; font-size:17px;'>
Real-Time Honeypot Monitoring • AI Detection • Threat Analytics
</p>

</div>
""", unsafe_allow_html=True)

tab1, tab2, tab3, tab4 = st.tabs(
    ["📊 Overview", "🧠 AI Analytics", "🛡 Threat Intel", "📄 Reports"]
)

st.sidebar.title("⚙ Control Panel")
st.sidebar.success("System Status: Live")
st.sidebar.info("Cowrie Honeypot Active")
st.sidebar.caption("Updated every 3 seconds")

# ---------------------------------------------------
# ALERT
# ---------------------------------------------------
high = df[df["Risk"] == "High"]

if len(high) > 0:
    st.error("🚨 High Risk Activity Detected")

# ---------------------------------------------------
# THREAT SCORE
# ---------------------------------------------------
st.markdown("---")
score = min(len(high) * 10, 100)

st.subheader("🎯 Threat Score")
st.progress(score)
st.write(f"{score}/100")

# ---------------------------------------------------
# METRICS
# ---------------------------------------------------
st.markdown("---")
if not df.empty:
    c1, c2, c3, c4 = st.columns(4)

    c1.metric("Total Events", len(df))
    c2.metric("Unique IPs", df["IP"].nunique())
    c3.metric("High Risk Events", len(high))
    c4.metric("MITRE Tactics", df["MITRE"].nunique())

# ---------------------------------------------------
# TOP IPS
# ---------------------------------------------------
st.subheader("🌐 Top Attacker IPs")

ip_counts = df["IP"].value_counts().reset_index()
ip_counts.columns = ["IP", "Count"]

fig1 = px.bar(ip_counts, x="IP", y="Count", color="Count", text="Count")
st.plotly_chart(fig1, use_container_width=True)

# ---------------------------------------------------
# ATTACK TIMELINE
# ---------------------------------------------------
st.subheader("📈 Attack Timeline")

timeline = df.groupby(df["Time"].dt.strftime("%H:%M:%S")).size().reset_index()
timeline.columns = ["Time", "Events"]

fig2 = px.area(timeline, x="Time", y="Events")
st.plotly_chart(fig2, use_container_width=True)

# ---------------------------------------------------
# TOP COMMANDS
# ---------------------------------------------------
st.subheader("💻 Top Commands")

cmds = df[df["Event"] == "cowrie.command.input"]

if not cmds.empty:
    top_cmd = cmds["Command"].value_counts().head(10).reset_index()
    top_cmd.columns = ["Command", "Count"]

    fig3 = px.bar(top_cmd, x="Command", y="Count", color="Count", text="Count")
    st.plotly_chart(fig3, use_container_width=True)

# ---------------------------------------------------
# MITRE ATT&CK MAPPING
# ---------------------------------------------------
st.markdown("---")
st.subheader("🛡 MITRE ATT&CK Mapping")

mitre = df["MITRE"].value_counts().reset_index()
mitre.columns = ["Tactic", "Count"]

fig4 = px.pie(mitre, names="Tactic", values="Count", hole=0.45)
st.plotly_chart(fig4, use_container_width=True)

# ---------------------------------------------------
# VULNERABILITY SCANNER
# ---------------------------------------------------
st.markdown("---")
st.subheader("🔎 Vulnerability Scan (Nmap)")

target = st.text_input("Target IP", "192.168.56.101")

if st.button("Run Scan"):
    try:
        result = subprocess.check_output(
            ["nmap", "-sV", target],
            text=True
        )
        st.code(result)
    except:
        st.error("Nmap scan failed.")

# ---------------------------------------------------
# CORRELATION
# ---------------------------------------------------
st.subheader("🔗 Attack-Vulnerability Correlation")

st.write("• SSH Port exposure may enable brute-force attempts.")
st.write("• wget / curl indicates payload download behavior.")
st.write("• chmod +x suggests execution preparation.")
st.write("• rm indicates cleanup / defense evasion.")

# ---------------------------------------------------
# ADVANCED PDF INCIDENT REPORT
# ---------------------------------------------------
st.markdown("---")
st.subheader("📄 Generate Professional Incident Report")

if st.button("Generate PDF Report"):

    pdf = FPDF()
    pdf.add_page()
    pdf.set_auto_page_break(auto=True, margin=15)

    pdf.set_font("Arial", "B", 16)
    pdf.cell(200, 10, "Intrusion Intelligence Report", ln=True)

    pdf.set_font("Arial", "", 11)
    pdf.cell(200, 10, f"Generated: {pd.Timestamp.now()}", ln=True)

    pdf.ln(5)

    # Summary
    pdf.set_font("Arial", "B", 13)
    pdf.cell(200, 10, "Executive Summary", ln=True)

    pdf.set_font("Arial", "", 11)
    pdf.cell(200, 8, f"Total Events: {len(df)}", ln=True)
    pdf.cell(200, 8, f"Unique IPs: {df['IP'].nunique()}", ln=True)
    pdf.cell(200, 8, f"High Risk Events: {len(df[df['Risk']=='High'])}", ln=True)

    pdf.ln(5)

    # Top IPs
    pdf.set_font("Arial", "B", 13)
    pdf.cell(200, 10, "Top Attacker IPs", ln=True)

    pdf.set_font("Arial", "", 11)
    for ip, count in df["IP"].value_counts().head(5).items():
        pdf.cell(200, 8, f"{ip}  --> {count} events", ln=True)

    pdf.ln(5)

    # MITRE
    pdf.set_font("Arial", "B", 13)
    pdf.cell(200, 10, "MITRE ATT&CK Tactics Detected", ln=True)

    pdf.set_font("Arial", "", 11)
    for tactic, count in df["MITRE"].value_counts().items():
        pdf.cell(200, 8, f"{tactic}: {count}", ln=True)

    pdf.ln(5)

    # Recommendations
    pdf.set_font("Arial", "B", 13)
    pdf.cell(200, 10, "Recommendations", ln=True)

    pdf.set_font("Arial", "", 11)
    pdf.multi_cell(0, 8,
        "- Restrict SSH exposure.\n"
        "- Monitor downloader commands (wget/curl).\n"
        "- Apply stronger authentication.\n"
        "- Investigate anomalous sessions.\n"
        "- Continue continuous log monitoring."
    )

    filename = "advanced_incident_report.pdf"
    pdf.output(filename)

    with open(filename, "rb") as file:
        st.download_button(
            label="⬇ Download PDF Report",
            data=file,
            file_name=filename,
            mime="application/pdf"
        )

# ---------------------------------------------------
# RAW EVENTS
# ---------------------------------------------------
# ---------------------------------------------------
# ANALYST FILTERS + CSV EXPORT
# ---------------------------------------------------
st.subheader("🔎 Analyst Investigation Panel")

col1, col2, col3 = st.columns(3)

with col1:
    ip_filter = st.text_input("Search IP", "")

with col2:
    cmd_filter = st.text_input("Search Command", "")

with col3:
    risk_filter = st.selectbox(
        "Risk Level",
        ["All", "Low", "Medium", "High"]
    )

filtered_df = df.copy()

if ip_filter:
    filtered_df = filtered_df[
        filtered_df["IP"].astype(str).str.contains(ip_filter, case=False, na=False)
    ]

if cmd_filter:
    filtered_df = filtered_df[
        filtered_df["Command"].astype(str).str.contains(cmd_filter, case=False, na=False)
    ]

if risk_filter != "All":
    filtered_df = filtered_df[
        filtered_df["Risk"] == risk_filter
    ]

csv = filtered_df.to_csv(index=False).encode("utf-8")

st.download_button(
    "⬇ Export Filtered CSV",
    csv,
    "filtered_attack_logs.csv",
    "text/csv"
)

st.subheader("📄 Latest Events")
st.dataframe(filtered_df.tail(20), use_container_width=True)
# ---------------------------------------------------
# NLP ATTACK INTENT ANALYSIS
# ---------------------------------------------------
st.markdown("---")
st.subheader("🧠 NLP Attack Intent Analysis")

intent_counts = df["Intent"].value_counts().reset_index()
intent_counts.columns = ["Intent", "Count"]

fig = px.pie(
    intent_counts,
    names="Intent",
    values="Count",
    hole=0.45
)

st.plotly_chart(fig, use_container_width=True)

# ---------------------------------------------------
# ML ANOMALY DETECTION
# ---------------------------------------------------
st.subheader("🤖 ML Anomaly Detection")

features = pd.DataFrame({
    "risk_num": df["Risk"].map({"Low":1, "Medium":2, "High":3}),
    "cmd_len": df["Command"].fillna("").apply(len)
})

model = IsolationForest(
    contamination=0.15,
    random_state=42
)

df["Anomaly"] = model.fit_predict(features)

anomalies = df[df["Anomaly"] == -1]

st.metric("Detected Anomalies", len(anomalies))

st.dataframe(
    anomalies[["IP", "Command", "Risk", "Time"]].tail(10),
    use_container_width=True
)

# ---------------------------------------------------
# AI SUMMARY
# ---------------------------------------------------
st.subheader("📝 AI Threat Summary")

top_intent = df["Intent"].value_counts().idxmax()

st.info(
    f"Most common attacker behavior: {top_intent}. "
    f"{len(anomalies)} anomalous events detected."
)

# ---------------------------------------------------
# LIVE ATTACK TOPOLOGY MAP
# ---------------------------------------------------
st.subheader("🕸 Live Attack Network Map")

G = nx.DiGraph()

honeypot = "Ubuntu Honeypot\n192.168.56.101"
G.add_node(honeypot)

top_ips = df["IP"].value_counts().head(8).index

for ip in top_ips:
    G.add_node(ip)
    G.add_edge(ip, honeypot)

fig, ax = plt.subplots(figsize=(12,7))

pos = nx.spring_layout(G, seed=42)

nx.draw_networkx_nodes(
    G, pos,
    node_size=2500,
    ax=ax
)

nx.draw_networkx_edges(
    G, pos,
    arrows=True,
    arrowstyle="->",
    arrowsize=20,
    width=2,
    ax=ax
)

nx.draw_networkx_labels(
    G, pos,
    font_size=9,
    ax=ax
)

ax.set_axis_off()

st.pyplot(fig)

# ---------------------------------------------------
# LIVE SESSION REPLAY TERMINAL
# ---------------------------------------------------
st.subheader("🖥 Live Session Replay")

cmd_logs = df[
    (df["Event"] == "cowrie.command.input") &
    (df["Command"].notna())
]["Command"].tail(12).tolist()

terminal_output = ""

for cmd in cmd_logs:
    terminal_output += f"root@svr04:~# {cmd}\n"

st.code(terminal_output, language="bash")

# ---------------------------------------------------
# VULNERABILITY CORRELATION HEATMAP
# ---------------------------------------------------
st.subheader("🔥 Vulnerability Correlation Heatmap")

heatmap_data = pd.DataFrame(
    {
        "Recon": [9, 8, 5],
        "Payload": [4, 3, 8],
        "Execution": [7, 5, 6],
        "Evasion": [2, 2, 7]
    },
    index=[
        "SSH Exposure",
        "Weak Authentication",
        "File Permissions"
    ]
)

fig = px.imshow(
    heatmap_data,
    text_auto=True,
    aspect="auto",
    labels=dict(x="Attack Stage", y="Weakness", color="Risk")
)

fig.update_layout(height=500)

st.plotly_chart(fig, use_container_width=True)

# ---------------------------------------------------
# NEXT ATTACK COMMAND PREDICTION
# ---------------------------------------------------
st.subheader("🔮 Predict Next Attack Step")

recent_cmds = df[
    (df["Event"] == "cowrie.command.input") &
    (df["Command"].notna())
]["Command"].tail(15).str.lower().tolist()

prediction = "General Reconnaissance"
confidence = "Low"

if any("wget" in c or "curl" in c for c in recent_cmds):
    prediction = "chmod +x payload.sh / Execute Downloaded File"
    confidence = "High"

elif any("whoami" in c or "uname" in c or "ls" in c for c in recent_cmds):
    prediction = "cat /etc/passwd or Further Enumeration"
    confidence = "Medium"

elif any("chmod" in c for c in recent_cmds):
    prediction = "bash payload.sh / Execution Attempt"
    confidence = "High"

elif any("rm" in c for c in recent_cmds):
    prediction = "history -c / Cleanup Activity"
    confidence = "Medium"

st.metric("Likely Next Action", prediction)
st.write(f"Confidence: {confidence}")

# ---------------------------------------------------
# FOOTER
# ---------------------------------------------------
st.markdown("---")
st.markdown("🔐 Cowrie Honeypot | Advanced Cyber Threat Monitoring Platform")
