import xml.etree.ElementTree as ET
import re
import csv
import shutil
from pathlib import Path
from config.config import FOLDER, RAW_FILE, SCAN_FILE

# Compila regex una sola volta
CVE_PATTERN = re.compile(r"(CVE-\d{4}-\d{4,7})\s+([\d.]+)\s+(https?://\S+)")

def parse_nmap_xml(scan_path: Path):
    if not scan_path.exists():
        raise FileNotFoundError(f"File XML non trovato: {scan_path}")

    tree = ET.parse(scan_path)
    root = tree.getroot()

    for host in root.findall('host'):
        ports = host.find('ports')
        if ports is None:
            continue

        for port in ports.findall('port'):
            port_id = port.attrib.get('portid')

            service_info = port.find('service')
            if service_info is None:
                continue

            product = service_info.attrib.get('product', '')
            version = service_info.attrib.get('version', '')
            service_name = f"{product} {version}".strip()

            script = port.find("script[@id='vulners']")
            if script is None:
                continue

            output_text = script.attrib.get("output", "")

            for cve_id, cvss_score, url in CVE_PATTERN.findall(output_text):
                try:
                    cvss = float(cvss_score)
                except ValueError:
                    cvss = 0.0

                yield {
                    "port": port_id,
                    "service": service_name,
                    "cve": cve_id,
                    "cvss": cvss,
                    "url": url
                }

def write_csv(output_file: Path, rows):
    with open(output_file, 'w', newline='') as csvfile:
        fieldnames = ['port', 'service', 'cve', 'cvss', 'url']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        for row in rows:
            writer.writerow(row)

def move_scan_file(scan_path: Path, destination_folder: Path):
    new_path = destination_folder / scan_path.name
    try:
        shutil.move(str(scan_path), str(new_path))
    except Exception as e:
        print(f"[!] Errore durante lo spostamento: {e}")

def main():
    FOLDER.mkdir(parents=True, exist_ok=True)

    scan_path = Path(SCAN_FILE)
    output_file = FOLDER / RAW_FILE

    print("[*] Parsing Nmap XML...")

    rows = parse_nmap_xml(scan_path)
    write_csv(output_file, rows)

    print(f"✅ Parsing completato: {output_file}")

    move_scan_file(scan_path, FOLDER)

if __name__ == "__main__":
    main()