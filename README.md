# VulnPrioritizer Tool
**VulnPrioritizer Tool** is a modular software system designed to automatically detect, enrich, and prioritize software vulnerabilities (CVEs) by leveraging data from Nmap and external threat intelligence sources such as CVSS, EPSS, KEV, CWE, CAPEC, and NVD.  
The project is intended to support activities such as penetration testing, system hardening, and patch management.


## Main Features

- **Automated Vulnerability Detection**  
  Performs an Nmap scan using the NSE script (`vulners.nse`) to identify active CVEs on discovered services.

- **Data Enrichment**  
  Each CVE is enriched with information from:  
  - CVSS (technical severity)  
  - EPSS (real-world exploit probability)  
  - CISA KEV (known actively exploited vulnerabilities)  
  - NVD (publication date, CWE)  
  - CAPEC (attack pattern classification)

- **Priority Scoring System**  
  Vulnerabilities are ranked based on a custom score that considers severity, risk, active exploitation, and recency.

- **Streamlit Dashboard**  
  A web-based interactive interface to visualize, filter, and analyze results.


## Installation Instructions

1. Clone the repository:
   ```bash
   git clone <repository_url>
   cd vulnPrioritizer
   ```

2. Create and activate a virtual environment:
   ```bash
   python3 -m venv venv
   source venv/bin/activate   # Linux/macOS
   venv\Scripts\activate      # Windows
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt

## Usage
#### Step 1: Scan the target with Nmap
   ```bash
   sudo nmap -sV --script vulners -oX output.xml <IP_TARGET>
   ```
#### Step 2: Run the main
   ```bash
   python main.py
   ```
  This will generate the final file vulnerabilities_scored.csv.

#### Step 3: Launch the interactive dashboard
   ```bash
   streamlit run app.py
   ```
