import xml.etree.ElementTree as ET
import csv
import requests
import os
from config import FOLDER, CWETOCAPEC_FILE, CAPEC_NAMED_FILE

# === Namespace CAPEC ===
NS = {'capec': 'http://capec.mitre.org/capec-3'}

# === Download CAPEC ===
def download_latest_capec(destination_folder=FOLDER, filename="capec_latest.xml"):
    url = "https://capec.mitre.org/data/xml/capec_latest.xml"
    destination_folder.mkdir(parents=True, exist_ok=True)

    output_path = destination_folder / filename

    print("...Downloading latest CAPEC XML from MITRE...")
    try:
        response = requests.get(url)
        response.raise_for_status()
        with open(output_path, "wb") as f_out:
            f_out.write(response.content)
        print(f"File CAPEC salvato in: {output_path}")
        return output_path
    except requests.RequestException as e:
        print(f"Errore durante il download di CAPEC: {e}")
        return None

# === Load CAPEC Names ===
def load_capec_names(xml_file):
    print("...Estrazione CAPEC_ID → CAPEC_NAME dal file XML...")
    capec_map = {}
    tree = ET.parse(xml_file)
    root = tree.getroot()

    for pattern in root.findall(".//capec:Attack_Pattern", NS):
        capec_id = pattern.attrib.get("ID")
        capec_name = pattern.attrib.get("Name", "").strip()
        if capec_id and capec_name:
            capec_map[f"CAPEC-{capec_id}"] = capec_name
    print(f"Trovati {len(capec_map)} CAPEC con nome.")
    return capec_map

# === Enrich CSV ===
def enrich_csv_with_names(input_csv, capec_dict, output_csv):
    print("Enrichment del file CSV con i nomi CAPEC...")
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
    capec_file = download_latest_capec()

    if capec_file:
        input_file = FOLDER / CWETOCAPEC_FILE
        output_file = FOLDER / CAPEC_NAMED_FILE
        
        capec_dict = load_capec_names(capec_file)
        enrich_csv_with_names(input_file, capec_dict, output_file)

        # === Cancella il file di input ===
        if os.path.exists(input_file):
            os.remove(input_file)
        
    else:
        print("Errore: CAPEC XML non disponibile, enrichment interrotto.")
