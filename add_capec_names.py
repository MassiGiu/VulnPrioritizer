import xml.etree.ElementTree as ET
import csv
from config import CWETOCAPEC_FILE, CAPEC_FILE, CAPEC_NAMED_FILE

# === Namespace usato nel file CAPEC XML ===
NS = {'capec': 'http://capec.mitre.org/capec-3'}

def load_capec_names(xml_file):
    print("[🔍] Estrazione CAPEC_ID → CAPEC_NAME dal file XML...")
    capec_map = {}
    tree = ET.parse(xml_file)
    root = tree.getroot()

    for pattern in root.findall(".//capec:Attack_Pattern", NS):
        capec_id = pattern.attrib.get("ID")
        capec_name = pattern.attrib.get("Name", "").strip()
        if capec_id and capec_name:
            capec_map[f"CAPEC-{capec_id}"] = capec_name
    print(f"[✅] Trovati {len(capec_map)} CAPEC con nome.")
    return capec_map

def enrich_csv_with_names(input_csv, capec_dict, output_csv):
    print("[🛠️] Enrichment del file CSV con i nomi CAPEC...")
    enriched = []

    with open(input_csv, 'r') as infile:
        reader = csv.DictReader(infile)
        for row in reader:
            capec_id = row['capec_id']
            capec_name = capec_dict.get(capec_id, "N/A")
            row['capec_name'] = capec_name
            enriched.append(row)

    with open(output_csv, 'w', newline='') as outfile:
        fieldnames = ['cwe_id', 'capec_id', 'capec_name']
        writer = csv.DictWriter(outfile, fieldnames=fieldnames)
        writer.writeheader()
        for row in enriched:
            writer.writerow(row)

    print(f"File generato: {output_csv}")

if __name__ == "__main__":
    input_file = CWETOCAPEC_FILE
    output_file = CAPEC_NAMED_FILE
    capec_dict = load_capec_names(CAPEC_FILE)
    enrich_csv_with_names(input_file, capec_dict, output_file)
