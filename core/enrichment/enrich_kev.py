import csv
import logging
from pathlib import Path
from typing import Tuple, List, Dict, Set

import requests

from config.config import EPSS_FILE, FOLDER, KEV_FILE

# ---------------------------------------------------------------------------
# Configurazione
# ---------------------------------------------------------------------------

KEV_URL = "https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv"
CHUNK_SIZE = 8192

KEV_TRUE = "YES"
KEV_FALSE = "NO"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Download KEV
# ---------------------------------------------------------------------------

def download_kev_csv(destination: Path, timeout: int = 30) -> None:
    """Scarica il catalogo KEV in streaming."""
    log.info("Download catalogo KEV da CISA…")

    with requests.get(KEV_URL, stream=True, timeout=timeout) as response:
        response.raise_for_status()
        with open(destination, "wb") as f:
            for chunk in response.iter_content(chunk_size=CHUNK_SIZE):
                if chunk:  # evita keep-alive vuoti
                    f.write(chunk)

    log.info("KEV salvato in: %s", destination)


# ---------------------------------------------------------------------------
# Caricamento KEV
# ---------------------------------------------------------------------------

def load_kev_catalog(kev_file: Path) -> Set[str]:
    """Carica il catalogo KEV come set di CVE."""
    kev_set: Set[str] = set()

    with open(kev_file, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            cve_id = row.get("cveID")
            if not cve_id:
                continue
            kev_set.add(cve_id.strip())

    log.info("Catalogo KEV caricato: %d CVE.", len(kev_set))
    return kev_set


# ---------------------------------------------------------------------------
# I/O helpers
# ---------------------------------------------------------------------------

def _load_existing_output(output_file: Path) -> Tuple[Set[str], List[Dict], List[str]]:
    """
    Legge output esistente.

    Returns:
        processed_cves
        existing_rows
        fieldnames
    """
    if not output_file.exists():
        log.info("Nessun file di output trovato. Inizio da zero.")
        return set(), [], []

    processed: Set[str] = set()
    rows: List[Dict] = []
    fieldnames: List[str] = []

    with open(output_file, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        fieldnames = list(reader.fieldnames or [])

        for row in reader:
            cve = row.get("cve")
            if cve:
                processed.add(cve.strip())
            rows.append(row)

    log.info("Ripresi %d CVE già processati.", len(processed))
    return processed, rows, fieldnames


def _save_atomic(output_file: Path, rows: List[Dict], fieldnames: List[str]) -> None:
    """Scrittura atomica."""
    if not rows:
        log.warning("Nessuna riga da salvare.")
        return

    tmp_file = output_file.with_suffix(".tmp")

    with open(tmp_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    tmp_file.replace(output_file)
    log.info("File salvato (atomico): %s", output_file)


# ---------------------------------------------------------------------------
# Enrichment KEV
# ---------------------------------------------------------------------------

def enrich_with_kev(input_file: Path, kev_file: Path, output_file: Path) -> None:
    kev_set = load_kev_catalog(kev_file)
    processed_cves, output_rows, out_fieldnames = _load_existing_output(output_file)

    with open(input_file, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        in_fieldnames = list(reader.fieldnames or [])

        if not in_fieldnames:
            raise ValueError("Input CSV senza header.")

        # Definizione fieldnames output
        if not out_fieldnames:
            out_fieldnames = (
                in_fieldnames if "kev" in in_fieldnames else in_fieldnames + ["kev"]
            )

        new_count = 0

        for row in reader:
            cve_id = row.get("cve")

            if not cve_id:
                log.warning("Riga senza CVE: %s", row)
                continue

            cve_id = cve_id.strip()

            if cve_id in processed_cves:
                continue

            row["kev"] = KEV_TRUE if cve_id in kev_set else KEV_FALSE
            output_rows.append(row)
            new_count += 1

    if new_count == 0:
        log.info("Nessun nuovo CVE da elaborare.")
        return

    log.info("%d nuovi CVE arricchiti con KEV.", new_count)

    _save_atomic(output_file, output_rows, out_fieldnames)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    FOLDER.mkdir(parents=True, exist_ok=True)

    kev_csv_path = FOLDER / "known_exploited_vulnerabilities.csv"

    # Scarica solo se necessario
    if not kev_csv_path.exists():
        download_kev_csv(kev_csv_path)
    else:
        log.info("File KEV già presente, skip download.")

    enrich_with_kev(
        input_file=FOLDER / EPSS_FILE,
        kev_file=kev_csv_path,
        output_file=FOLDER / KEV_FILE,
    )