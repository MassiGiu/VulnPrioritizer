import streamlit as st
import pandas as pd
import plotly.express as px
from pathlib import Path
from config.config import FOLDER, FINAL_FILE

CSV_PATH = FOLDER / FINAL_FILE

# ---------------------------------------------------------------------------
# Page config
# ---------------------------------------------------------------------------

st.set_page_config(
    page_title="CVE Prioritizer",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def classify_severity(score: float) -> str:
    if score >= 0.75:
        return "CRITICAL"
    elif score >= 0.5:
        return "HIGH"
    elif score >= 0.25:
        return "MEDIUM"
    return "LOW"

# ---------------------------------------------------------------------------
# Load data
# ---------------------------------------------------------------------------

@st.cache_data
def load_data():
    if not Path(CSV_PATH).exists():
        st.error(f"File non trovato: {CSV_PATH}")
        return pd.DataFrame()

    df = pd.read_csv(CSV_PATH)

    # Normalizzazione colonne
    df["priority_score"] = pd.to_numeric(df["priority_score"], errors="coerce").fillna(0)
    df["kev"] = df["kev"].fillna("").astype(str)

    # Severity
    df["severity"] = df["priority_score"].apply(classify_severity)

    return df

df = load_data()

if df.empty:
    st.stop()

# ---------------------------------------------------------------------------
# Sidebar
# ---------------------------------------------------------------------------

st.sidebar.title("Filters")

min_score = st.sidebar.slider("🎯 Minimum Score", 0.0, 1.0, 0.5, 0.01)
only_kev = st.sidebar.checkbox("🧨 Only KEV", value=False)
severity_filter = st.sidebar.multiselect(
    "🚨 Severity",
    ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
    default=["CRITICAL", "HIGH", "MEDIUM", "LOW"]
)

sort_by_score = st.sidebar.radio(
    "↕️ Sort by",
    ["Descending Score", "Ascending Score"]
)

# ---------------------------------------------------------------------------
# Filtering
# ---------------------------------------------------------------------------

filtered = df[df["priority_score"] >= min_score]

if only_kev:
    filtered = filtered[filtered["kev"].str.upper() == "YES"]

filtered = filtered[filtered["severity"].isin(severity_filter)]

ascending = sort_by_score == "Ascending Score"
filtered = filtered.sort_values("priority_score", ascending=ascending)

# ---------------------------------------------------------------------------
# Header
# ---------------------------------------------------------------------------

st.markdown("""
    <h1 style='text-align: center;'>🔐 Vulnerability Prioritization Dashboard</h1>
    <p style='text-align: center; color: gray;'>EPSS + KEV + CVSS + NVD + CAPEC</p>
    <hr>
""", unsafe_allow_html=True)

# ---------------------------------------------------------------------------
# KPI
# ---------------------------------------------------------------------------

col1, col2, col3, col4 = st.columns(4)

col1.metric("🔎 Total CVEs", len(df))
col2.metric("📉 Filtered CVEs", len(filtered))
col3.metric("🧨 KEV CVEs", (df["kev"].str.upper() == "YES").sum())
col4.metric("🔥 Critical", (df["severity"] == "CRITICAL").sum())

# ---------------------------------------------------------------------------
# Table
# ---------------------------------------------------------------------------

st.markdown("### 📋 Prioritized Vulnerabilities")

st.dataframe(
    filtered.style.background_gradient(
        cmap="Oranges",
        subset=["priority_score"]
    ),
    use_container_width=True,
    height=500
)

# ---------------------------------------------------------------------------
# Plot
# ---------------------------------------------------------------------------

st.markdown("### 📊 CVE Scores")

plot_data = filtered.head(20)

if not plot_data.empty:
    fig = px.bar(
        plot_data,
        x="cve",
        y="priority_score",
        color="severity",
        title="Top Vulnerabilities",
        hover_data=["cvss", "epss", "kev", "published_date"],
        height=450
    )

    st.plotly_chart(fig, use_container_width=True)
else:
    st.info("Nessun dato da visualizzare.")

# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------

st.markdown("### 📥 Export Results")

st.download_button(
    label="Download CSV",
    data=filtered.to_csv(index=False),
    file_name="filtered_vulnerabilities.csv",
    mime="text/csv"
)