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

        published = cve_data.get("published", "N/A").split("T")[0]

        weaknesses = cve_data.get("weaknesses", [])
        if weaknesses and weaknesses[0]["description"]:
            cwe_id = weaknesses[0]["description"][0]["value"]
        else:
            cwe_id = "N/A"

        return published, cwe_id

    except Exception as e:
        print(f"Errore per {cve_id}: {e}")
        return "N/A", "N/A"

def enrich_with_nvd(input_file, output_file):
    # Carica i CVE già processati (se presenti)
    processed_cves = set()
    try:
        with open(output_file, 'r') as f_out:
            reader = csv.DictReader(f_out)
            for row in reader:
                if row.get('published_date') and row.get('published_date') != "N/A":
                    processed_cves.add(row['cve'])
        print(f"[ℹ️] Ripreso da {len(processed_cves)} CVE già processati.")
    except FileNotFoundError:
        print("[ℹ️] Nessun file di output trovato. Inizio da zero.")

    # Carica output esistente (se presente)
    enriched = []
    if processed_cves:
        with open(output_file, 'r') as f_out:
            reader = csv.DictReader(f_out)
            enriched = list(reader)

    # Legge l'input e arricchisce solo i nuovi
    with open(input_file, 'r') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            cve_id = row['cve'].strip()
            if cve_id in processed_cves:
                continue

            print(f"[NVD] Recupero dati per {cve_id}...")
            published_date, cwe_id = get_nvd_data(cve_id)
            time.sleep(6)  # Rate limit consigliato da NVD

            row['published_date'] = published_date
            row['cwe_id'] = cwe_id
            enriched.append(row)

            # Salva il file dopo ogni CVE
            with open(output_file, 'w', newline='') as f_out:
                fieldnames = list(row.keys())
                writer = csv.DictWriter(f_out, fieldnames=fieldnames)
                writer.writeheader()
                for r in enriched:
                    writer.writerow(r)

    print(f"\n✅ Enrichment NVD completato. File salvato come: {NVD_FILE}")

if __name__ == "__main__":
    input_file = FOLDER / KEV_FILE
    output_file = FOLDER / NVD_FILE
    enrich_with_nvd(input_file, output_file)
