import csv
import requests 
import time
from config import FOLDER, RAW_FILE, EPSS_FILE

def get_epss_score(cve_id):
    url = f"https://api.first.org/data/v1/epss?cve={cve_id}"
    try:
        response = requests.get(url)
        data = response.json()
        if data["data"]:
            return float(data["data"][0]["epss"])
        else:
            return None
    except Exception as e:
        print(f"[!] Errore con {cve_id}: {e}")
        return None

def enrich_with_epss(input_file, output_file):
    enriched = []

    with open(input_file, 'r') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            cve_id = row['cve']
            print(f"[EPSS] Recupero score per {cve_id}...")
            epss_score = get_epss_score(cve_id)
            time.sleep(1)  # rispetto per l'API
            row['epss'] = epss_score if epss_score is not None else "N/A"
            enriched.append(row)

    # Scrivi file arricchito
    with open(output_file, 'w', newline='') as csvfile:
        fieldnames = list(enriched[0].keys())
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for row in enriched:
            writer.writerow(row)

    print(f"\n✅ EPSS enrichment completato. File salvato come: {output_file}")

# === Esecuzione ===
if __name__ == "__main__":
    input_file = FOLDER / RAW_FILE
    output_file = FOLDER / EPSS_FILE
    enrich_with_epss(input_file, output_file)
