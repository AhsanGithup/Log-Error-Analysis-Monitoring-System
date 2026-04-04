import streamlit as st
import pandas as pd
import plotly.express as px
from utils import clean_file
from fpdf import FPDF
import paramiko
from streamlit_autorefresh import st_autorefresh
import io
import os
import time 
from email.mime.text import MIMEText
from collections import Counter
import smtplib
df = None

st.set_page_config(
    layout="wide",
    page_title="Log Error Analysis System",
    initial_sidebar_state="expanded"
)

# Custom CSS for transparent selectbox backgrounds and dark theme
st.markdown("""
<style>
/* Hide default Streamlit header & footer */
header {visibility: hidden;}
footer {visibility: hidden;}
#MainMenu {visibility: hidden;}

/* Remove extra top spacing */
.block-container {
    padding-top: 1rem;
}

/* Main App Background */
.stApp {
    background-color: #0e1117 !important;
    color: #ffffff !important;
}

/* Sidebar */
section[data-testid="stSidebar"] {
    background-color: #111827 !important;
}

/* Text visibility fix */
h1, h2, h3, h4, h5, h6, p, span, label, div {
    color: #ffffff !important;
}

/* Buttons */
.stButton>button, .stDownloadButton>button {
    background-color: #1f2937;
    color: white;
    border-radius: 8px;
    border: 1px solid #374151;
}
.stButton>button:hover, .stDownloadButton>button:hover {
    background-color: #374151;
}

/* Input fields */
.stTextInput>div>div>input,
.stSelectbox>div>div,
.stTextArea textarea {
    background-color: #1f2937 !important;
    color: white !important;
}

/* Dataframe fix */
[data-testid="stDataFrame"] {
    background-color: #1e1e1e !important;
}

/* Hide DataFrame top toolbar */
[data-testid="stDataFrame"] div.css-1adrfps { 
    display: none !important;
}

/* DataFrame toolbar icons color change to black */
[data-testid="stDataFrame"] svg {
    fill: #000000 !important;
}

/* Upload box */
[data-testid="stFileUploader"] {
    background-color: #1f2937 !important;
}

/* Radio buttons */
div[role="radiogroup"] label {
    color: white !important;
}

/* File uploader outer box */
.stFileUploader > div {
    background-color: #ffffff !important;  /* White background */
    border: 1px solid #374151 !important;
    border-radius: 8px !important;
    padding: 10px !important;
}

/* Choose File button */
.stFileUploader > div > label {
    background-color: #ffffff !important;  /* White button background */
    color: #000000 !important;             /* Black text */
    border-radius: 8px !important;
    border: 1px solid #374151 !important;
    padding: 6px 12px !important;
    font-weight: bold;
}

/* Hover effect for button */
.stFileUploader > div > label:hover {
    background-color: #e5e5e5 !important;  /* Slight gray hover */
}

/* Drag & Drop instructions */
.stFileUploader > div > label + div p {
    color: #000000 !important;             /* Black text */
    background-color: #ffffff !important;  /* White background */
    padding: 4px 8px;
    border-radius: 5px;
    font-weight: bold;
}

/* File name: "No file chosen" */
.stFileUploader span {
    color: #000000 !important;             /* Black text */
}

/* Upload icon / SVG logo */
.stFileUploader svg {
    fill: #000000 !important;              /* Black icon */
}
/* Force upload icon black (backup selector) */
div[data-testid="stFileUploader"] svg {
    fill: #000000 !important;
} 
             
/* Force Drag & Drop text black (Strong Override) */
div[data-testid="stFileUploader"] section div {
    color: #000000 !important;
}

div[data-testid="stFileUploader"] section div * {
    color: #000000 !important;
}      

/* ===== FORCE FIX SELECTBOX DROPDOWN ===== */

/* Selected value box */
div[data-testid="stSelectbox"] > div > div {
    background-color: #1f2937 !important;
    color: white !important;
}

/* Dropdown panel */
ul[role="listbox"] {
    background-color: #1f2937 !important;
    color: white !important;
}

/* Each option */
li[role="option"] {
    background-color: #1f2937 !important;
    color: white !important;
}

/* Hover effect */
li[role="option"]:hover {
    background-color: #374151 !important;
    color: white !important;
}

/* Selected option */
li[aria-selected="true"] {
    background-color: #2563eb !important;
    color: white !important;
}
            
</style>
""", unsafe_allow_html=True)

# Initialize session state variables
if "data" not in st.session_state:
    st.session_state["data"] = None
if "filtered_data" not in st.session_state:
    st.session_state["filtered_data"] = None
if "sender_email" not in st.session_state:
    st.session_state["sender_email"] = ""
if "sender_pass" not in st.session_state:
    st.session_state["sender_pass"] = ""
# Main title
st.title("📊 Log Error Analysis System")

# ===== Sidebar Header =====
st.sidebar.markdown("""
<div style="text-align:center; font-size:25px; line-height:1.1;">
    🔥<br>
    <strong>Apache Log Error</strong>
</div>
""", unsafe_allow_html=True)
st.sidebar.markdown("<div style='margin-bottom:40px;'></div>", unsafe_allow_html=True)

# ===== Sidebar Menu =====
menu = st.sidebar.radio(
    "", ["Home","Live Error", "View CSV", "Data Filter", "Data Visualization", "Dashboard", "Report","Alert"],
    label_visibility="collapsed"
)

# Reset / New File Button
if st.sidebar.button("♻️ New File / Reset Page", key="reset_button"):
    st.session_state.clear()
    st.rerun()

# ===== GLOBAL FILTERS =====
df_filtered = None
if st.session_state["data"] is not None:
    df = st.session_state["data"]
    
    st.sidebar.markdown("---")
    st.sidebar.markdown('<p class="sidebar-section-header">🔎 Global Filters</p>', unsafe_allow_html=True)
    
    # IP Filter with transparent background
    st.sidebar.markdown('<p class="filter-label">IP Filter</p>', unsafe_allow_html=True)
    search_ip = st.sidebar.text_input("", key="search_ip", placeholder="Enter IP address...")
    
    # Log Level Filter with transparent background
    level_options = ["All"] + sorted(df["level"].dropna().unique().tolist())
    st.sidebar.markdown('<p class="filter-label">Log Level</p>', unsafe_allow_html=True)
    search_level = st.sidebar.selectbox("", level_options, key="search_level")
    
    # Month Filter with transparent background
    month_options = ["All"] + sorted(df["datetime"].dt.month.dropna().unique().tolist())
    st.sidebar.markdown('<p class="filter-label">Month</p>', unsafe_allow_html=True)
    search_month = st.sidebar.selectbox("", month_options, key="search_month")
    
    # Hour Filter with transparent background
    hour_options = ["All"] + sorted(df["datetime"].dt.hour.dropna().unique().tolist())
    st.sidebar.markdown('<p class="filter-label">Hour</p>', unsafe_allow_html=True)
    search_hour = st.sidebar.selectbox("", hour_options, key="search_hour")
    
    # ===== Apply Global Filters =====
    df_filtered = df.copy()
    
    if search_ip:
        df_filtered = df_filtered[df_filtered["ip"].str.contains(search_ip, na=False)]
    
    if search_level != "All":
        df_filtered = df_filtered[df_filtered["level"] == search_level]
    
    if search_month != "All":
        df_filtered = df_filtered[df_filtered["datetime"].dt.month == int(search_month)]
    
    if search_hour != "All":
        df_filtered = df_filtered[df_filtered["datetime"].dt.hour == int(search_hour)]
    
    st.session_state["filtered_data"] = df_filtered

# ===== Reset / Delete Button =====
if st.session_state["data"] is not None:
    st.sidebar.markdown("---")
    if st.sidebar.button("🗑️ Clear All Data & Reset App", key="delete_all_data"):
        st.session_state.clear()
        st.rerun()


# ================== ALERT SETTINGS ==================
def send_alert_email(receiver, ip, hits, limit):
    sender = st.session_state.get("sender_email")
    password = st.session_state.get("sender_pass")

    if not sender or not password:
        st.warning("⚠️ Please enter Gmail & App Password first")
        return

    message = f"""Subject: 🚨 Traffic Alert

High Traffic Detected!
IP: {ip}
Hits: {hits}
Limit: {limit}
"""
    try:
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(sender, password)
        server.sendmail(sender, receiver, message)
        server.quit()
        st.success(f"📧 Email sent to {receiver}")
    except Exception as e:
        st.error(f"Email Error: {e}")



# ================= HOME =================
if menu == "Home":
    st.markdown("<h2 style='text-align:center;'>📁 Upload Log File</h2>", unsafe_allow_html=True)
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        uploaded_file = st.file_uploader("Choose File", type=["txt", "log", "dat"])
        if uploaded_file:
            df = clean_file(uploaded_file)
            if "datetime" in df.columns:
                df["datetime"] = pd.to_datetime(df["datetime"], errors="coerce")
                df["hour"] = df["datetime"].dt.hour
            st.session_state["data"] = df
            st.success("✅ File Converted Successfully")
            st.dataframe(df.head(50))


elif menu == "Alert":
    st.header("🚨 Alert System")
    if st.session_state["data"] is None:
        st.warning("⚠️ Please upload a file from Home first")
    else:
        df = st.session_state["data"]

        st.session_state["sender_email"] = st.text_input("Your Gmail", value=st.session_state["sender_email"])
        st.session_state["sender_pass"] = st.text_input("Gmail App Password", type="password", value=st.session_state["sender_pass"])
        email_alert = st.text_input("Receive Alerts On (Email)")

        alert_limit = st.number_input("Set IP Hit Limit (Per Minute)", min_value=1, value=50)

        # Per IP per minute calculation
        df["datetime"] = pd.to_datetime(df["datetime"], errors="coerce")
        traffic = df.set_index("datetime").groupby("ip").resample("1T").size().reset_index(name="hits")
        exceeded = traffic[traffic["hits"] >= alert_limit]

        if not exceeded.empty:
            st.error("🚨 High Traffic Detected!")
            for _, row in exceeded.iterrows():
                ip = row["ip"]
                hits = row["hits"]
                minute = row["datetime"]
                st.warning(f"⚠️ {ip} → {hits} hits at {minute}")
                if email_alert:
                    send_alert_email(email_alert, ip, hits, alert_limit)
        else:
            st.success("✅ No IP crossed limit")



# ================= VIEW CSV =================
elif menu == "View CSV":
    st.header("📄 CSV Viewer")
    if df_filtered is not None:
        st.subheader("📋 Filtered CSV Data")
        st.dataframe(df_filtered)
        st.download_button(
            "⬇️ Download CSV",
            df_filtered.to_csv(index=False).encode("utf-8"),
            "filtered_data.csv",
            "text/csv"
        )
    else:
        st.warning("⚠️ Please upload a file from the Home section first")

# ================= DATA FILTER =================
elif menu == "Data Filter":
    st.header("🔍 Data Filter & Analysis")
    if df_filtered is not None:
        df = df_filtered
        
        # ===== Level Count =====
        if "level" in df.columns:
            st.subheader("Log Level Count")
            st.dataframe(df["level"].value_counts())
        
        # ===== Top Values =====
        def top_values(col):
            return df[col].value_counts().head(10)
        
        st.subheader("Top Column Values")
        cols = ["hour", "ip", "code", "port", "pid", "module"]
        for col in cols:
            if col in df.columns:
                st.write(f"📌 {col.upper()}")
                st.dataframe(top_values(col))
        
        # ===== Traffic =====
        if "datetime" in df.columns and "ip" in df.columns:
            st.subheader("High Traffic IP (Per Minute)")
            traffic = df.set_index("datetime").groupby("ip").resample("1T").size().sort_values(ascending=False).head(10)
            st.dataframe(traffic)
        
        # ===== Relations =====
        st.subheader("Column Relations")
        def analyze(c1, c2):
            return df.groupby(c1)[c2].value_counts().head(10)
        
        relations = [
            ("ip", "hour"), ("ip", "port"), ("ip", "code"), ("ip", "pid"), ("ip", "level"),
            ("level", "ip"), ("level", "hour"), ("level", "port"), ("level", "code"), ("level", "pid")
        ]
        for a, b in relations:
            if a in df.columns and b in df.columns:
                st.write(f"{a.upper()} vs {b.upper()}")
                st.dataframe(analyze(a, b))
        
        # ===== Message Analysis =====
        if "message" in df.columns:
            st.subheader("Message Analysis")
            st.write("Common Paths")
            st.dataframe(df["message"].str.extract(r"(/[\w/\.\-]+)").value_counts().head(10))
            st.write("Error Keywords")
            st.dataframe(df["message"].str.extract(r"(denied|script|php|cgi|permission|not found|error|warning)", expand=False).value_counts())
        
        # ===== Path Analysis =====
        if "path" in df.columns:
            st.subheader("Path Analysis")
            st.write("Directories")
            st.dataframe(df["path"].str.extract(r"(/[^/]+/)").value_counts().head(10))
            st.write("Extensions")
            st.dataframe(df["path"].str.extract(r"(\.\w+)$").value_counts())
    else:
        st.warning("⚠️ Please upload a file from the Home section first")

# ================= DATA VISUALIZATION =================
elif menu == "Data Visualization":
    st.header("📈 Advanced Data Visualization & Storytelling")
    if df_filtered is not None:
        df = df_filtered
        
        if "datetime" in df.columns:
            df["datetime"] = pd.to_datetime(df["datetime"], errors="coerce")
            df["hour"] = df["datetime"].dt.hour
        
        # ===== Log Level Distribution =====
        if "level" in df.columns:
            st.markdown("### 🔹 Log Level Distribution")
            fig = px.pie(df, names="level", title="Log Level Distribution", hole=0.4)
            st.plotly_chart(fig, use_container_width=True)
            st.write("Insight: Most frequent log levels indicate common system events or errors.")
        
        # ===== Top 10 IPs =====
        if "ip" in df.columns:
            st.markdown("### 🔹 Top 10 IPs")
            top_ip = df["ip"].value_counts().head(10).reset_index()
            top_ip.columns = ["IP", "Count"]
            fig = px.bar(top_ip, x="IP", y="Count", color="Count", text="Count", title="Top 10 IPs Generating Logs")
            st.plotly_chart(fig, use_container_width=True)
            st.write("Insight: Monitor these IPs for unusual activity or high log volume.")
        
        # ===== Top Values for Key Columns =====
        cols = ["code", "port", "pid", "module"]
        for col in cols:
            if col in df.columns:
                st.markdown(f"### 🔹 Top 10 {col.upper()} Values")
                top_vals = df[col].value_counts().head(10).reset_index()
                top_vals.columns = [col, "Count"]
                fig = px.bar(top_vals, x=col, y="Count", color="Count", text="Count", title=f"Top 10 {col.upper()} Values")
                st.plotly_chart(fig, use_container_width=True)
                st.write(f"Insight: Shows common identifiers or modules generating logs.")
        
        # ===== Traffic Analysis per Hour =====
        if "datetime" in df.columns and "ip" in df.columns:
            st.markdown("### 🔹 Traffic Analysis (High Traffic IPs per Hour)")
            traffic_time = df.set_index("datetime").groupby("ip").resample("1H").size().reset_index(name="count")
            fig = px.line(traffic_time, x="datetime", y="count", color="ip", title="Traffic Trend per IP")
            st.plotly_chart(fig, use_container_width=True)
            st.write("Insight: Identify peak activity hours and potential bottlenecks.")
        
        # ===== Column Relations =====
        st.markdown("### 🔹 Column Relations")
        relations = [("ip", "hour"), ("ip", "port"), ("ip", "code"), ("ip", "pid"), ("ip", "level")]
        for a, b in relations:
            if a in df.columns and b in df.columns:
                rel_data = df.groupby([a, b]).size().reset_index(name="count")
                fig = px.bar(rel_data, x=a, y="count", color=b, text="count", title=f"{a.upper()} vs {b.upper()}")
                st.plotly_chart(fig, use_container_width=True)
                st.write(f"Insight: Relation between {a.upper()} and {b.upper()} shows patterns in logs.")
        
        # ===== Message Analysis =====
        if "message" in df.columns:
            st.markdown("### 🔹 Message Analysis")
            paths = df["message"].str.extract(r"(/[\w/\.\-]+)").value_counts().head(10).reset_index()
            paths.columns = ["Path", "Count"]
            fig = px.bar(paths, x="Path", y="Count", color="Count", text="Count", title="Top Paths in Messages")
            st.plotly_chart(fig, use_container_width=True)
            st.write("Insight: Frequently accessed paths generating logs.")
            
            errors = df["message"].str.extract(r"(denied|script|php|cgi|permission|not found|error|warning)", expand=False)
            err_count = errors.value_counts().head(10).reset_index()
            err_count.columns = ["Keyword", "Count"]
            fig = px.bar(err_count, x="Keyword", y="Count", color="Count", text="Count", title="Top Error Keywords")
            st.plotly_chart(fig, use_container_width=True)
            st.write("Insight: Most common errors to prioritize for fixes or monitoring.")
        
        # ===== Path Analysis =====
        if "path" in df.columns:
            st.markdown("### 🔹 Path Analysis")
            dirs = df["path"].str.extract(r"(/[^/]+/)").value_counts().head(10).reset_index()
            dirs.columns = ["Directory", "Count"]
            fig = px.bar(dirs, x="Directory", y="Count", color="Count", text="Count", title="Top Directories")
            st.plotly_chart(fig, use_container_width=True)
            st.write("Insight: Directories most frequently accessed or causing errors.")
            
            exts = df["path"].str.extract(r"(\.\w+)$").value_counts().reset_index()
            exts.columns = ["Extension", "Count"]
            fig = px.bar(exts, x="Extension", y="Count", color="Count", text="Count", title="Top File Extensions")
            st.plotly_chart(fig, use_container_width=True)
            st.write("Insight: Shows most common file types triggering logs or errors.")
    
    else:
        st.warning("⚠️ Please upload a file from the Home section first")




elif menu == "Dashboard":

    st.markdown("""
        <style>
        .kpi-card {
            background-color: #111827;
            padding: 12px;
            border-radius: 8px;
            text-align: center;
            color: white;
        }
        .kpi-title {
            font-size: 12px;
            color: #9CA3AF;
        }
        .kpi-value {
            font-size: 18px;
            font-weight: bold;
        }
        </style>
    """, unsafe_allow_html=True)

    st.header("📊 Log Analysis Dashboard")

    if df is not None and not df.empty:

        # ===== SMALL KPI ROW =====
        col1, col2, col3, col4 = st.columns(4)

        total_logs = len(df)
        unique_ips = df["ip"].nunique() if "ip" in df.columns else 0
        top_level = df["level"].value_counts().idxmax() if "level" in df.columns else "N/A"
        peak_hour = df["hour"].value_counts().idxmax() if "hour" in df.columns else "N/A"

        for col, title, value in zip(
            [col1, col2, col3, col4],
            ["Total Logs", "Unique IPs", "Top Level", "Peak Hour"],
            [total_logs, unique_ips, top_level, peak_hour]
        ):
            col.markdown(f"""
                <div class="kpi-card">
                    <div class="kpi-title">{title}</div>
                    <div class="kpi-value">{value}</div>
                </div>
            """, unsafe_allow_html=True)

        st.markdown("---")

        # ===== ALL CHARTS IN ONE SCREEN =====
        c1, c2, c3 = st.columns(3)

        # 1️⃣ Pie
        with c1:
            if "level" in df.columns:
                fig = px.pie(
                    df,
                    names="level",
                    hole=0.6,
                    height=250
                )
                fig.update_layout(
                    margin=dict(l=0, r=0, t=30, b=0)
                )
                st.plotly_chart(fig, use_container_width=True)

        # 2️⃣ Top IP
        with c2:
            if "ip" in df.columns:
                top_ip = df["ip"].value_counts().head(5).reset_index()
                top_ip.columns = ["IP", "Count"]

                fig = px.bar(
                    top_ip,
                    x="IP",
                    y="Count",
                    height=250
                )
                fig.update_layout(
                    margin=dict(l=0, r=0, t=30, b=0)
                )
                st.plotly_chart(fig, use_container_width=True)

        # 3️⃣ Status Code
        with c3:
            if "code" in df.columns:
                top_code = df["code"].value_counts().head(5).reset_index()
                top_code.columns = ["Code", "Count"]

                fig = px.bar(
                    top_code,
                    x="Code",
                    y="Count",
                    height=250
                )
                fig.update_layout(
                    margin=dict(l=0, r=0, t=30, b=0)
                )
                st.plotly_chart(fig, use_container_width=True)

        # ===== SECOND SMALL ROW =====
        c4, c5 = st.columns(2)

        with c4:
            if "datetime" in df.columns:
                trend = df.set_index("datetime").resample("1H").size().reset_index(name="count")
                fig = px.line(
                    trend,
                    x="datetime",
                    y="count",
                    height=250
                )
                fig.update_layout(
                    margin=dict(l=0, r=0, t=30, b=0)
                )
                st.plotly_chart(fig, use_container_width=True)

        with c5:
            if "path" in df.columns:
                exts = df["path"].str.extract(r"(\.\w+)$").value_counts().reset_index()
                exts.columns = ["Extension","Count"]

                fig = px.bar(
                    exts.head(5),
                    x="Extension",
                    y="Count",
                    height=250
                )
                fig.update_layout(
                    margin=dict(l=0, r=0, t=30, b=0)
                )
                st.plotly_chart(fig, use_container_width=True)

    else:
        st.warning("⚠️ Upload log file first.")
        
# ================= REPORT =================
elif menu == "Report":
    st.header("📑 Automatic Report Generation")
    if df_filtered is not None:
        df = df_filtered

        if "datetime" in df.columns:
            df["datetime"] = pd.to_datetime(df["datetime"], errors="coerce")
            df["hour"] = df["datetime"].dt.hour

        total_logs = len(df)
        unique_ips = df["ip"].nunique() if "ip" in df.columns else 0
        top_ip = df["ip"].value_counts().idxmax() if "ip" in df.columns else "N/A"
        top_level = df["level"].value_counts().idxmax() if "level" in df.columns else "N/A"
        peak_hour = df["hour"].value_counts().idxmax() if "hour" in df.columns else "N/A"

        top_errors = df["message"].str.extract(
            r"(denied|script|php|cgi|permission|not found|error|warning)", expand=False
        ).value_counts().head(5) if "message" in df.columns else pd.Series([])

        report_text = f"""
LOG ERROR ANALYSIS REPORT
=========================

Total Logs: {total_logs}
Unique IPs: {unique_ips}
Most Active IP: {top_ip}
Most Frequent Log Level: {top_level}
Peak Log Hour: {peak_hour}

Top 5 Error Keywords:
{top_errors.to_string()}

Insights & Recommendations:
- Monitor top IPs for unusual activity.
- Investigate frequent error types and permissions issues.
- Review peak hours to optimize system monitoring.
"""
        st.text(report_text)

        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Arial","B",12)
        for line in report_text.split("\n"):
            pdf.multi_cell(180, 7, line)
        pdf_bytes = pdf.output(dest='S').encode('latin-1')
        st.download_button(
            "⬇️ Download Report as PDF",
            pdf_bytes,
            "Log_Report.pdf",
            "application/pdf"
        )
    else:
        st.warning("⚠️ Please upload a file from the Home section first")



elif menu == "Live Error":

    st.header("🔴 Live Server Error Monitor")

    server_ip = st.text_input("Server IP")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    log_path = st.text_input("Log File Path", "/var/log/apache2/error.log")

    start_live = st.button("Start Live Monitoring")

    if start_live:
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(server_ip, username=username, password=password)

            # 🔴 REAL TIME COMMAND
            command = f"tail -f {log_path}"
            stdin, stdout, stderr = ssh.exec_command(command)

            st.success("✅ Live Monitoring Started")

            log_box = st.empty()   # UI box
            logs = ""

            # 🔁 Live Reading
            while True:
                line = stdout.readline()

                if not line:
                    break

                logs += line
                log_box.text(logs)

        except Exception as e:
            st.error(f"Connection Failed: {e}")

        