import streamlit as st
import pandas as pd
import plotly.express as px

st.set_page_config(page_title="🛡️ CVE Prioritizer", layout="wide", initial_sidebar_state="expanded")

# === Carica dati CSV ===
@st.cache_data
def load_data():
    return pd.read_csv("vulnerabilities_scored.csv")

df = load_data()

# === Sidebar: Filtri ===
st.sidebar.title("🎛️ Filtri")

min_score = st.sidebar.slider("🎯 Score minimo", 0.0, 1.0, 0.5, 0.01)
only_kev = st.sidebar.checkbox("🧨 Solo vulnerabilità con KEV", value=False)
sort_by_score = st.sidebar.radio("↕️ Ordinamento", ["Score decrescente", "Score crescente"])

# === Applica filtri ===
filtered = df[df["priority_score"] >= min_score]
if only_kev:
    filtered = filtered[filtered["in_kev"].str.upper() == "YES"]

sort_ascending = sort_by_score == "Score crescente"
filtered = filtered.sort_values("priority_score", ascending=sort_ascending)

# === Header ===
st.markdown("""
    <h1 style='text-align: center;'>🔐 Vulnerability Prioritization Dashboard</h1>
    <p style='text-align: center; color: gray;'>Progetto di Analisi CVE, con EPSS, KEV, CVSS, NVD e CAPEC</p>
    <hr>
""", unsafe_allow_html=True)

# === KPI boxes ===
col1, col2, col3 = st.columns(3)
col1.metric("🔎 CVE Totali", len(df))
col2.metric("📉 CVE Filtrate", len(filtered))
col3.metric("🧨 CVE con KEV", (df["in_kev"].str.upper() == "YES").sum())

# === Tabella ===
st.markdown("### 📋 Vulnerabilità Prioritarie")
st.dataframe(
    filtered.style.background_gradient(cmap='Oranges', subset=['priority_score']),
    use_container_width=True,
    height=500
)

# === Grafico (score > 0.5) ===
st.markdown("### 📊 Score delle CVE (score > 0.5)")
plot_data = filtered[filtered["priority_score"] > 0.5].sort_values("priority_score", ascending=False)

if not plot_data.empty:
    fig = px.bar(
        plot_data,
        x="cve",
        y="priority_score",
        color="priority_score",
        color_continuous_scale="Oranges",
        title="CVE ordinate per score",
        labels={"priority_score": "Score", "cve": "CVE ID"},
        height=400
    )
    st.plotly_chart(fig, use_container_width=True)
else:
    st.info("Nessuna CVE con score superiore a 0.5 nei risultati filtrati.")

# === Download CSV filtrato ===
st.markdown("### 📥 Esporta i risultati")
st.download_button(
    label="Scarica risultati filtrati (CSV)",
    data=filtered.to_csv(index=False),
    file_name="filtered_vulnerabilities.csv",
    mime="text/csv"
)
