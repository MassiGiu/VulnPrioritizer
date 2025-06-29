import xml.etree.ElementTree as ET
import csv
import requests
import zipfile
import io
import os
from config import FOLDER, CWETOCAPEC_FILE

# === Namespace CWE ===
NS = {'cwe': 'http://cwe.mitre.org/cwe-7'}

# === Scarica ultima versione CWE ===
def download_latest_cwe(destination_folder=FOLDER, filename="cwec_latest.xml"):
    url = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
    destination_folder.mkdir(parents=True, exist_ok=True)  # Usa Path.mkdir()

    print("[↓] Downloading latest CWE XML from MITRE...")
    response = requests.get(url)
    response.raise_for_status()

    with zipfile.ZipFile(io.BytesIO(response.content)) as zip_file:
        for file in zip_file.namelist():
            if file.endswith(".xml"):
                output_path = destination_folder / filename  # Usa Path
                with zip_file.open(file) as xml_file, open(output_path, "wb") as f_out:
                    f_out.write(xml_file.read())
                print(f"[✔] File salvato in: {output_path}")
                return output_path
    print("[!] Nessun file XML trovato nello ZIP.")
    return None

# === Parsing XML CWE → CAPEC ===
def parse_cwe_to_capec(xml_file):
    print(f"[📂] Parsing del file XML con namespace: {xml_file}")
    cwe_to_capec = []
    tree = ET.parse(xml_file)
    root = tree.getroot()

    for weakness in root.findall(".//cwe:Weakness", namespaces=NS):
        cwe_id = weakness.attrib.get("ID", "").strip()
        related_patterns = weakness.find("cwe:Related_Attack_Patterns", namespaces=NS)
        if related_patterns:
            for pattern in related_patterns.findall("cwe:Related_Attack_Pattern", namespaces=NS):
                capec_id = pattern.attrib.get("CAPEC_ID", "").strip()
                capec_name = pattern.attrib.get("Name", "").strip()
                cwe_to_capec.append({
                    "cwe_id": f"CWE-{cwe_id}",
                    "capec_id": f"CAPEC-{capec_id}",
                    "capec_name": capec_name
                })
    return cwe_to_capec

# === Salvataggio CSV ===
def save_to_csv(mapping, output_file):
    print(f"[💾] Scrittura file CSV: {output_file}")
    with open(output_file, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=["cwe_id", "capec_id", "capec_name"])
        writer.writeheader()
        for row in mapping:
            writer.writerow(row)
    print("File generato con successo!")

# === Esecuzione principale ===
if __name__ == "__main__":
    xml_file_path = download_latest_cwe()
    if xml_file_path:
        mapping = parse_cwe_to_capec(xml_file_path)
        save_to_csv(mapping, CWETOCAPEC_FILE)
