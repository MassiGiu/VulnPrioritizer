import streamlit as st
import pandas as pd
import plotly.express as px
from config import FOLDER, FINAL_FILE

CSV_PATH = FOLDER / FINAL_FILE
# === Page configuration ===
st.set_page_config(page_title="CVE Prioritizer", layout="wide", initial_sidebar_state="expanded")

# === Load CSV data ===
@st.cache_data
def load_data():
    return pd.read_csv(CSV_PATH)

df = load_data()

# === Sidebar: Filters ===
st.sidebar.title("Filters")

min_score = st.sidebar.slider("🎯 Minimum Score", 0.0, 1.0, 0.5, 0.01)
only_kev = st.sidebar.checkbox("🧨 Show only KEV vulnerabilities", value=False)
sort_by_score = st.sidebar.radio("↕️ Sort by", ["Descending Score", "Ascending Score"])

# === Apply filters ===
filtered = df[df["priority_score"] >= min_score]
if only_kev:
    filtered = filtered[df["kev"].str.upper() == "YES"]

sort_ascending = sort_by_score == "Ascending Score"
filtered = filtered.sort_values("priority_score", ascending=sort_ascending)

# === Header ===
st.markdown("""
    <h1 style='text-align: center;'>🔐 Vulnerability Prioritization Dashboard</h1>
    <p style='text-align: center; color: gray;'>CVE Analysis Project, with EPSS, KEV, CVSS, NVD and CAPEC</p>
    <hr>
""", unsafe_allow_html=True)

# === KPI boxes ===
col1, col2, col3 = st.columns(3)
col1.metric("🔎 Total CVEs", len(df))
col2.metric("📉 Filtered CVEs", len(filtered))
col3.metric("🧨 CVEs with KEV", (df["kev"].str.upper() == "YES").sum())

# === Table ===
st.markdown("### 📋 Prioritized Vulnerabilities")
st.dataframe(
    filtered.style.background_gradient(cmap='Oranges', subset=['priority_score']),
    use_container_width=True,
    height=500
)

# === Plot (score > 0.5) ===
st.markdown("### 📊 CVE Scores (score > 0.5)")
plot_data = filtered[filtered["priority_score"] > 0.5].sort_values("priority_score", ascending=False)

if not plot_data.empty:
    fig = px.bar(
        plot_data,
        x="cve",
        y="priority_score",
        color="priority_score",
        color_continuous_scale="Oranges",
        title="CVEs Ordered by Score",
        labels={"priority_score": "Score", "cve": "CVE ID"},
        height=400
    )
    st.plotly_chart(fig, use_container_width=True)
else:
    st.info("No CVEs with score greater than 0.5 found in the filtered results.")

# === Export filtered CSV ===
st.markdown("### 📥 Export Results")
st.download_button(
    label="Download Filtered Results (CSV)",
    data=filtered.to_csv(index=False),
    file_name="filtered_vulnerabilities.csv",
    mime="text/csv"
)
