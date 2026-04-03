import csv
import io
import logging
import zipfile
import requests
import xml.etree.ElementTree as ET
import argparse

from pathlib import Path
from xml.etree.ElementTree import Element
from config.config import CWETOCAPEC_FILE

# ---------------------------------------------------------------------------
# Configurazione
# ---------------------------------------------------------------------------

CWE_ZIP_URL = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
CWE_XML_FILENAME = "cwec_latest.xml"
NS = {"cwe": "http://cwe.mitre.org/cwe-7"}

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Download
# ---------------------------------------------------------------------------

def download_latest_cwe(
    destination_folder: Path,
    filename: str = CWE_XML_FILENAME,
    force: bool = False,
) -> Path | None:
    """
    Scarica e decomprime il file XML CWE da MITRE.
    Salta il download se il file esiste già (a meno che force=True).
    """
    destination_folder.mkdir(parents=True, exist_ok=True)
    output_path = destination_folder / filename

    if output_path.exists() and not force:
        log.info("File CWE già presente, skip download: %s", output_path)
        return output_path

    log.info("Download CWE XML da MITRE…")

    with requests.get(CWE_ZIP_URL, stream=True, timeout=60) as response:
        response.raise_for_status()
        zip_bytes = io.BytesIO(response.content)

    with zipfile.ZipFile(zip_bytes) as zf:
        xml_names = [name for name in zf.namelist() if name.endswith(".xml")]

        if not xml_names:
            log.error("Nessun file XML trovato nello ZIP.")
            return None

        # Scrittura atomica: tmp → rename
        tmp_path = output_path.with_suffix(".tmp")
        with zf.open(xml_names[0]) as xml_file:
            tmp_path.write_bytes(xml_file.read())

        tmp_path.replace(output_path)

    log.info("File CWE salvato: %s", output_path)
    return output_path


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

def _get_capec_name(root: Element, capec_id: str) -> str:
    """
    Cerca il nome del CAPEC direttamente nel catalogo CWE
    tramite Category o Attack_Pattern_Catalog se disponibile.
    Restituisce stringa vuota se non trovato.
    """
    # Il nome CAPEC non è un attributo inline di Related_Attack_Pattern —
    # lasciamo il campo vuoto piuttosto che inventare dati.
    return ""


def parse_cwe_to_capec(xml_file: Path) -> list[dict[str, str]]:
    """
    Estrae la mappatura CWE → CAPEC dal file XML MITRE.

    Nota: l'attributo 'Name' non è presente in Related_Attack_Pattern
    nel formato standard CWE; capec_name viene lasciato vuoto.
    """
    log.info("Parsing XML CWE: %s", xml_file)

    tree = ET.parse(xml_file)
    root = tree.getroot()
    mapping: list[dict[str, str]] = []

    for weakness in root.findall(".//cwe:Weakness", namespaces=NS):
        cwe_id = weakness.attrib.get("ID", "").strip()
        if not cwe_id:
            continue

        related_patterns = weakness.find("cwe:Related_Attack_Patterns", namespaces=NS)
        if related_patterns is None:
            continue

        for pattern in related_patterns.findall("cwe:Related_Attack_Pattern", namespaces=NS):
            capec_id = pattern.attrib.get("CAPEC_ID", "").strip()
            if not capec_id:
                continue

            mapping.append({
                "cwe_id": f"CWE-{cwe_id}",
                "capec_id": f"CAPEC-{capec_id}",
                "capec_name": "",  # non disponibile nel formato XML CWE
            })

    log.info("Mappature CWE→CAPEC estratte: %d", len(mapping))
    return mapping


# ---------------------------------------------------------------------------
# Salvataggio
# ---------------------------------------------------------------------------

def save_to_csv(mapping: list[dict[str, str]], output_file: Path) -> None:
    """Salva la mappatura in CSV con scrittura atomica."""
    if not mapping:
        log.warning("Nessuna mappatura da salvare.")
        return

    tmp = output_file.with_suffix(".tmp")
    fieldnames = ["cwe_id", "capec_id", "capec_name"]

    with open(tmp, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(mapping)

    tmp.replace(output_file)
    log.info("CSV salvato: %s (%d righe)", output_file, len(mapping))


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate CWE to CAPEC mapping")
    parser.add_argument("--output", required=True, help="CSV output")
    parser.add_argument("--workdir", required=True, help="Directory dove salvare l'XML CWE")
    parser.add_argument("--force-download", action="store_true")
    args = parser.parse_args()

    workdir = Path(args.workdir)
    workdir.mkdir(parents=True, exist_ok=True)

    xml_path = download_latest_cwe(
        destination_folder=workdir,
        force=args.force_download,
    )

    if xml_path:
        mapping = parse_cwe_to_capec(xml_path)
        save_to_csv(mapping, Path(args.output))