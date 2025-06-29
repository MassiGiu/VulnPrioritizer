import csv
from config import FOLDER, EPSS_FILE, KEV_FILE, KEV_FILE_CSV

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

    print(f"KEV enrichment completato. File salvato come: {KEV_FILE}")

# Esegui
if __name__ == "__main__":
    input_file = FOLDER / EPSS_FILE
    output_file = FOLDER / KEV_FILE
    kev_file= KEV_FILE_CSV

    enrich_with_kev(input_file, kev_file, output_file)
