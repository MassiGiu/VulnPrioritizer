import csv
from config import FOLDER, NVD_FILE, CAPEC_NAMED_FILE, FINAL_FILE

def load_capec_mapping(filename):
    capec_map = {}
    with open(filename, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            cwe = row['cwe_id'].strip()
            if cwe not in capec_map:
                capec_map[cwe] = {
                    'capec_id': row['capec_id'].strip(),
                    'capec_name': row['capec_name'].strip()
                }
    return capec_map

def enrich_with_capec(input_file, capec_map, output_file):
    enriched = []
    with open(input_file, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            cwe = row.get('cwe_id', '').strip()
            capec = capec_map.get(cwe, {'capec_id': 'N/A', 'capec_name': 'N/A'})
            row['capec_id'] = capec['capec_id']
            row['capec_name'] = capec['capec_name']
            enriched.append(row)

    with open(output_file, 'w', newline='') as f:
        fieldnames = list(enriched[0].keys())
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in enriched:
            writer.writerow(row)

    print(f"Enrichment completato. File creato: {output_file}")

if __name__ == "__main__":
    input_file = FOLDER / NVD_FILE
    output_file = FOLDER / FINAL_FILE
    capec_map = load_capec_mapping(CAPEC_NAMED_FILE)
    enrich_with_capec(input_file, capec_map, output_file)
