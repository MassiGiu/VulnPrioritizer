import xml.etree.ElementTree as ET
import csv
from config import CWEC_FILE, CWETOCAPEC_FILE

# === Namespace CWE ===
NS = {'cwe': 'http://cwe.mitre.org/cwe-7'}

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

def save_to_csv(mapping, output_file):
    print(f"[💾] Scrittura file CSV: {output_file}")
    with open(output_file, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=["cwe_id", "capec_id", "capec_name"])
        writer.writeheader()
        for row in mapping:
            writer.writerow(row)
    print("File generato con successo!")

if __name__ == "__main__": 
    output_file = CWETOCAPEC_FILE
    mapping = parse_cwe_to_capec(CWEC_FILE)
    save_to_csv(mapping, output_file)
