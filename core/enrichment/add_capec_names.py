import csv
import logging
from pathlib import Path

import requests
import xml.etree.ElementTree as ET

from config.config import CAPEC_NAMED_FILE, CWETOCAPEC_FILE, FOLDER

# ---------------------------------------------------------------------------
# Configurazione
# ---------------------------------------------------------------------------

CAPEC_XML_URL = "https://capec.mitre.org/data/xml/capec_latest.xml"
CAPEC_XML_FILENAME = "capec_latest.xml"
NS = {"capec": "http://capec.mitre.org/capec-3"}

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Download
# ---------------------------------------------------------------------------

def download_latest_capec(
    destination_folder: Path = FOLDER,
    filename: str = CAPEC_XML_FILENAME,
    force: bool = False,
) -> Path | None:
    """
    Scarica il file XML CAPEC da MITRE in streaming.
    Salta il download se il file esiste già (a meno che force=True).
    """
    destination_folder.mkdir(parents=True, exist_ok=True)
    output_path = destination_folder / filename

    if output_path.exists() and not force:
        log.info("File CAPEC già presente, skip download: %s", output_path)
        return output_path

    log.info("Download CAPEC XML da MITRE…")

    try:
        tmp_path = output_path.with_suffix(".tmp")

        with requests.get(CAPEC_XML_URL, stream=True, timeout=60) as response:
            response.raise_for_status()
            with open(tmp_path, "wb") as f:
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)

        tmp_path.replace(output_path)
        log.info("File CAPEC salvato: %s", output_path)
        return output_path

    except requests.RequestException as e:
        log.error("Errore durante il download di CAPEC: %s", e)
        if tmp_path.exists():
            tmp_path.unlink()
        return None


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

def load_capec_names(xml_file: Path) -> dict[str, str]:
    """Estrae la mappa CAPEC_ID → CAPEC_NAME dal file XML MITRE."""
    log.info("Parsing CAPEC XML: %s", xml_file)

    capec_map: dict[str, str] = {}
    tree = ET.parse(xml_file)
    root = tree.getroot()

    for pattern in root.findall(".//capec:Attack_Pattern", NS):
        capec_id = pattern.attrib.get("ID", "").strip()
        capec_name = pattern.attrib.get("Name", "").strip()
        if capec_id and capec_name:
            capec_map[f"CAPEC-{capec_id}"] = capec_name

    log.info("CAPEC con nome trovati: %d", len(capec_map))
    return capec_map


# ---------------------------------------------------------------------------
# Enrichment
# ---------------------------------------------------------------------------

def enrich_csv_with_names(
    input_csv: Path,
    capec_map: dict[str, str],
    output_csv: Path,
) -> None:
    """Arricchisce il CSV CWE→CAPEC con i nomi dei CAPEC."""
    if not input_csv.exists():
        raise FileNotFoundError(f"File input non trovato: {input_csv}")

    enriched: list[dict[str, str]] = []

    with open(input_csv, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            capec_id = row.get("capec_id", "").strip()
            row["capec_name"] = capec_map.get(capec_id, "N/A")
            enriched.append(row)

    if not enriched:
        log.warning("Nessuna riga da arricchire.")
        return

    # Scrittura atomica
    fieldnames = ["cwe_id", "capec_id", "capec_name"]
    tmp = output_csv.with_suffix(".tmp")

    with open(tmp, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(enriched)

    tmp.replace(output_csv)
    log.info("CSV arricchito salvato: %s (%d righe)", output_csv, len(enriched))


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    FOLDER.mkdir(parents=True, exist_ok=True)

    capec_xml = download_latest_capec()

    if not capec_xml:
        log.error("CAPEC XML non disponibile, enrichment interrotto.")
        raise SystemExit(1)

    capec_map = load_capec_names(capec_xml)
    enrich_csv_with_names(
        input_csv=FOLDER / CWETOCAPEC_FILE,
        capec_map=capec_map,
        output_csv=FOLDER / CAPEC_NAMED_FILE,
    )

    # Rimozione file intermedio SOLO dopo salvataggio confermato
    intermediate = FOLDER / CWETOCAPEC_FILE
    if intermediate.exists():
        intermediate.unlink()
        log.info("File intermedio rimosso: %s", intermediate)