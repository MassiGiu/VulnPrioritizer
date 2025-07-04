import csv
import requests
from config import FOLDER, EPSS_FILE, KEV_FILE

def download_kev_csv(destination_path):
    url = "https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv"
    print("...Downloading latest KEV catalog from CISA...")
    response = requests.get(url)
    response.raise_for_status()

    with open(destination_path, 'wb') as f:
        f.write(response.content)

    print(f"KEV file salvato in: {destination_path}")

def load_kev_catalog(kev_file):
    kev_set = set()
    with open(kev_file, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            kev_set.add(row['cveID'].strip())
    print(f"Catalogo KEV caricato. CVE totali: {len(kev_set)}")
    return kev_set

def enrich_with_kev(input_file, kev_file, output_file):
    kev_set = load_kev_catalog(kev_file)

    # Se già presente un file output, recupera i CVE già processati
    processed_cves = set()
    try:
        with open(output_file, 'r') as f_out:
            reader = csv.DictReader(f_out)
            for row in reader:
                processed_cves.add(row['cve'])
        print(f"[ℹ️] Ripreso da {len(processed_cves)} CVE già processati.")
    except FileNotFoundError:
        print("[ℹ️] Nessun file di output trovato. Inizio da zero.")

    # Leggi il file di input e arricchisci solo i CVE non ancora processati
    with open(input_file, 'r') as infile:
        reader = csv.DictReader(infile)
        rows_to_process = [row for row in reader if row['cve'] not in processed_cves]

    if not rows_to_process:
        print("✅ Nessun nuovo CVE da elaborare.")
        return

    # Leggi l'output esistente (se presente)
    enriched = []
    if processed_cves:
        with open(output_file, 'r') as f_out:
            reader = csv.DictReader(f_out)
            enriched = list(reader)

    # Aggiunge KEV e salva progressivamente
    for row in rows_to_process:
        cve = row['cve'].strip()
        row['kev'] = "YES" if cve in kev_set else "NO"
        enriched.append(row)

        # Salva dopo ogni riga
        with open(output_file, 'w', newline='') as f_out:
            fieldnames = list(row.keys())
            writer = csv.DictWriter(f_out, fieldnames=fieldnames)
            writer.writeheader()
            for r in enriched:
                writer.writerow(r)

    print(f"✅ KEV enrichment completato. File salvato come: {output_file}")

if __name__ == "__main__":
    kev_csv_path = FOLDER / "known_exploited_vulnerabilities.csv"
    download_kev_csv(kev_csv_path)

    input_file = FOLDER / EPSS_FILE
    output_file = FOLDER / KEV_FILE

    enrich_with_kev(input_file, kev_csv_path, output_file)
