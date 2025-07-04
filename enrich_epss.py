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
    # === Leggi i CVE già elaborati (se il file esiste) ===
    processed_cves = set()
    try:
        with open(output_file, 'r') as f_out:
            reader = csv.DictReader(f_out)
            for row in reader:
                if row.get('epss') and row['epss'] != "N/A":
                    processed_cves.add(row['cve'])
        print(f"[ℹ️] Ripreso da {len(processed_cves)} CVE già processati.")
    except FileNotFoundError:
        print("[ℹ️] Nessun file di output trovato. Inizio da zero.")

    enriched = []
    # Se riprendi, carichi il file esistente per non perdere i progressi
    if processed_cves:
        with open(output_file, 'r') as f_out:
            reader = csv.DictReader(f_out)
            enriched = list(reader)

    # === Leggi l’input e arricchisci solo i nuovi ===
    with open(input_file, 'r') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            cve_id = row['cve']
            if cve_id in processed_cves:
                continue

            print(f"[EPSS] Recupero score per {cve_id}...")
            epss_score = get_epss_score(cve_id)
            time.sleep(1)  # Rispetta i limiti API
            row['epss'] = epss_score if epss_score is not None else "N/A"
            enriched.append(row)

            # Salva progressivamente dopo ogni CVE
            with open(output_file, 'w', newline='') as f_out:
                fieldnames = list(row.keys())
                writer = csv.DictWriter(f_out, fieldnames=fieldnames)
                writer.writeheader()
                for r in enriched:
                    writer.writerow(r)

    print(f"\n✅ EPSS enrichment completato. File salvato come: {output_file}")

if __name__ == "__main__":
    input_file = FOLDER / RAW_FILE
    output_file = FOLDER / EPSS_FILE
    enrich_with_epss(input_file, output_file)
