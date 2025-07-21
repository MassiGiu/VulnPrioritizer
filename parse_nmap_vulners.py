import xml.etree.ElementTree as ET
import re
import csv
import shutil
from config import FOLDER, RAW_FILE, SCAN_FILE
from pathlib import Path

FOLDER.mkdir(parents=True, exist_ok=True)

# === File input/output ===
OUTPUT_FILE = FOLDER / RAW_FILE
SCAN_PATH = Path(SCAN_FILE)  # Assicura che SCAN_FILE sia un Path

# === STEP 2: Carica il file XML ===
tree = ET.parse(SCAN_PATH)
root = tree.getroot()

results = []

# === STEP 3: Scansiona ogni host e porta ===
for host in root.findall('host'):
    for port in host.find('ports').findall('port'):
        port_id = port.attrib.get('portid')
        service_info = port.find('service')

        if service_info is None:
            continue

        # Costruisci il nome del servizio
        product = service_info.attrib.get('product', '')
        version = service_info.attrib.get('version', '')
        service_name = f"{product} {version}".strip()

        # Trova lo script NSE (vulners)
        script = port.find("script[@id='vulners']")
        if script is None:
            continue

        output_text = script.attrib.get("output", "")

        # === STEP 4: Estrai CVE, CVSS e URL con regex ===
        pattern = r"(CVE-\d{4}-\d{4,7})\s+([\d.]+)\s+(https?://\S+)"
        for match in re.findall(pattern, output_text):
            cve_id, cvss_score, url = match
            results.append({
                "port": port_id,
                "service": service_name,
                "cve": cve_id,
                "cvss": float(cvss_score),
                "url": url
            })

# === STEP 5: Scrivi i risultati in CSV ===
with open(OUTPUT_FILE, 'w', newline='') as csvfile:
    fieldnames = ['port', 'service', 'cve', 'cvss', 'url']
    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

    writer.writeheader()
    for row in results:
        writer.writerow(row)

print(f"\n✅ Parsing completato. Dati salvati in: '{OUTPUT_FILE}'")

# === STEP 6: Sposta lo scan file nella cartella di output ===
new_scan_path = FOLDER / SCAN_PATH.name
try:
    shutil.move(str(SCAN_PATH), str(new_scan_path))
except Exception as e:
    print(f"Errore durante lo spostamento del file XML: {e}")
