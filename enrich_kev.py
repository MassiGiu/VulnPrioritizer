import csv
import requests
from config import FOLDER, EPSS_FILE, KEV_FILE

def download_kev_csv(destination_path):
    url = "https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv"
    print("[↓] Downloading latest KEV catalog from CISA...")
    response = requests.get(url)
    response.raise_for_status()

    with open(destination_path, 'wb') as f:
        f.write(response.content)

    print(f"[✔] KEV file salvato in: {destination_path}")

def load_kev_catalog(kev_file):
    kev_set = set()
    with open(kev_file, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            kev_set.add(row['cveID'].strip())
    return kev_set

def enrich_with_kev(input_file, kev_file, output_file):
    kev_set = load_kev_catalog(kev_file)
    enriched = []

    with open(input_file, 'r') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            cve = row['cve'].strip()
            row['in_kev'] = "YES" if cve in kev_set else "NO"
            enriched.append(row)

    with open(output_file, 'w', newline='') as csvfile:
        fieldnames = list(enriched[0].keys())
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for row in enriched:
            writer.writerow(row)

    print(f"[✔] KEV enrichment completato. File salvato come: {output_file}")

# === Esecuzione ===
if __name__ == "__main__":
    kev_csv_path = FOLDER / "known_exploited_vulnerabilities.csv"
    download_kev_csv(kev_csv_path)

    input_file = FOLDER / EPSS_FILE
    output_file = FOLDER / KEV_FILE

    enrich_with_kev(input_file, kev_csv_path, output_file)
