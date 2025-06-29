import csv
import requests
import time
from config import FOLDER, KEV_FILE, NVD_FILE
from dotenv import load_dotenv
import os

load_dotenv()
NVD_API_KEY = os.getenv("NVD_API_KEY")

def get_nvd_data(cve_id):
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    headers = {'apiKey': NVD_API_KEY}
    
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        data = response.json()

        vulnerabilities = data.get("vulnerabilities", [])
        if not vulnerabilities:
            return "N/A", "N/A"

        cve_data = vulnerabilities[0]['cve']

        # === Data pubblicazione ===
        published = cve_data.get("published", "N/A").split("T")[0]

        # === CWE ID ===
        weaknesses = cve_data.get("weaknesses", [])
        if weaknesses and weaknesses[0]["description"]:
            cwe_id = weaknesses[0]["description"][0]["value"]
        else:
            cwe_id = "N/A"

        return published, cwe_id

    except Exception as e:
        print(f"[!] Errore per {cve_id}: {e}")
        return "N/A", "N/A"

def enrich_with_nvd(input_file, output_file):
    enriched = []

    with open(input_file, 'r') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            cve_id = row['cve'].strip()
            print(f"[NVD] Recupero dati per {cve_id}...")
            published_date, cwe_id = get_nvd_data(cve_id)
            time.sleep(6)  # Rispetta rate limit NVD

            row['published_date'] = published_date
            row['cwe_id'] = cwe_id
            enriched.append(row)

    with open(output_file, 'w', newline='') as csvfile:
        fieldnames = list(enriched[0].keys())
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for row in enriched:
            writer.writerow(row)

    print(f"\nEnrichment NVD completato. File salvato come: {NVD_FILE}")

# Esecuzione
if __name__ == "__main__":
    input_file = FOLDER / KEV_FILE
    output_file = FOLDER / NVD_FILE
    enrich_with_nvd(input_file, output_file)
