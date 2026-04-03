import csv
import logging
import os
import time
from pathlib import Path
from typing import Any

import requests
from dotenv import load_dotenv

from config.config import FOLDER, KEV_FILE, NVD_FILE

# ---------------------------------------------------------------------------
# Configurazione
# ---------------------------------------------------------------------------

load_dotenv()

NVD_API_KEY = os.getenv("NVD_API_KEY")
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# NVD raccomanda circa:
# - ~6 secondi senza API key
# - ~0.6 secondi con API key
REQUEST_DELAY = 0.6 if NVD_API_KEY else 6.0
MAX_RETRIES = 3
SAVE_EVERY = 5  # salvataggio atomico ogni N CVE processati

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Validazione configurazione
# ---------------------------------------------------------------------------

def _get_headers() -> dict[str, str]:
    """Restituisce gli header HTTP per NVD."""
    if not NVD_API_KEY:
        raise EnvironmentError(
            "NVD_API_KEY non trovata nel file .env. "
            "Registrati su https://nvd.nist.gov/developers/request-an-api-key"
        )
    return {"apiKey": NVD_API_KEY}


# ---------------------------------------------------------------------------
# Helpers parsing NVD
# ---------------------------------------------------------------------------

def _extract_cwe_id(cve_data: dict[str, Any]) -> str:
    """Estrae il primo CWE disponibile in modo robusto."""
    weaknesses = cve_data.get("weaknesses", [])
    for weakness in weaknesses:
        descriptions = weakness.get("description", [])
        for desc in descriptions:
            value = desc.get("value", "").strip()
            if value:
                return value
    return "N/A"


def _extract_published_date(cve_data: dict[str, Any]) -> str:
    """Estrae la published date in formato YYYY-MM-DD."""
    published = cve_data.get("published", "")
    if not published:
        return "N/A"
    return published.split("T")[0]


# ---------------------------------------------------------------------------
# API NVD
# ---------------------------------------------------------------------------

def get_nvd_data(session: requests.Session, cve_id: str) -> tuple[str, str]:
    """
    Recupera published_date e cwe_id da NVD per un singolo CVE.
    Gestisce rate limit (429), retry su errori transitori e backoff progressivo.
    """
    headers = _get_headers()

    for attempt in range(1, MAX_RETRIES + 1):
        try:
            response = session.get(
                NVD_API_URL,
                params={"cveId": cve_id},
                headers=headers,
                timeout=15,
            )

            if response.status_code == 429:
                wait_time = 10 * attempt
                log.warning(
                    "Rate limit NVD per %s. Attendo %ds (tentativo %d/%d)...",
                    cve_id,
                    wait_time,
                    attempt,
                    MAX_RETRIES,
                )
                time.sleep(wait_time)
                continue

            if 500 <= response.status_code < 600:
                wait_time = 2 * attempt
                log.warning(
                    "Errore server NVD %s per %s. Retry tra %ds (tentativo %d/%d)...",
                    response.status_code,
                    cve_id,
                    wait_time,
                    attempt,
                    MAX_RETRIES,
                )
                time.sleep(wait_time)
                continue

            response.raise_for_status()
            data = response.json()

            vulnerabilities = data.get("vulnerabilities", [])
            if not vulnerabilities:
                log.warning("Nessun dato NVD trovato per %s.", cve_id)
                return "N/A", "N/A"

            cve_data = vulnerabilities[0].get("cve", {})
            published_date = _extract_published_date(cve_data)
            cwe_id = _extract_cwe_id(cve_data)

            return published_date, cwe_id

        except requests.HTTPError as e:
            log.error(
                "HTTP error per %s (tentativo %d/%d): %s",
                cve_id,
                attempt,
                MAX_RETRIES,
                e,
            )
            if attempt < MAX_RETRIES:
                time.sleep(2 * attempt)
                continue

        except requests.RequestException as e:
            log.error(
                "Errore di rete per %s (tentativo %d/%d): %s",
                cve_id,
                attempt,
                MAX_RETRIES,
                e,
            )
            if attempt < MAX_RETRIES:
                time.sleep(2 * attempt)
                continue

        except ValueError as e:
            log.error("JSON non valido per %s: %s", cve_id, e)
            break

    return "N/A", "N/A"


# ---------------------------------------------------------------------------
# I/O helpers
# ---------------------------------------------------------------------------

def _load_existing_output(output_file: Path) -> tuple[dict[str, dict[str, str]], list[str]]:
    """
    Carica l'output esistente e restituisce:
    - una mappa {cve: row}
    - i fieldnames dell'output
    """
    if not output_file.exists():
        log.info("Nessun file di output trovato. Inizio da zero.")
        return {}, []

    rows_map: dict[str, dict[str, str]] = {}

    with open(output_file, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        fieldnames = list(reader.fieldnames or [])

        for row in reader:
            cve_id = row.get("cve", "").strip()
            if cve_id:
                rows_map[cve_id] = row

    processed = sum(
        1
        for row in rows_map.values()
        if row.get("published_date", "").strip()
        and row.get("published_date") != "N/A"
    )

    log.info("Ripresi %d CVE già processati.", processed)
    return rows_map, fieldnames


def _save_atomic(output_file: Path, rows_map: dict[str, dict[str, str]], fieldnames: list[str]) -> None:
    """Scrittura atomica tramite file temporaneo + rename."""
    if not rows_map:
        log.warning("Nessuna riga da salvare.")
        return

    tmp_file = output_file.with_suffix(".tmp")
    ordered_rows = list(rows_map.values())

    with open(tmp_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(ordered_rows)

    tmp_file.replace(output_file)


# ---------------------------------------------------------------------------
# Enrichment NVD
# ---------------------------------------------------------------------------

def enrich_with_nvd(input_file: Path, output_file: Path) -> None:
    if not input_file.exists():
        raise FileNotFoundError(f"File input non trovato: {input_file}")

    rows_map, out_fieldnames = _load_existing_output(output_file)

    with open(input_file, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        in_fieldnames = list(reader.fieldnames or [])

        if not in_fieldnames:
            raise ValueError("Input CSV senza header.")

        if "cve" not in in_fieldnames:
            raise ValueError("Il CSV di input deve contenere la colonna 'cve'.")

        if not out_fieldnames:
            extra_columns = [col for col in ("published_date", "cwe_id") if col not in in_fieldnames]
            out_fieldnames = in_fieldnames + extra_columns

        pending: list[dict[str, str]] = []
        for row in reader:
            cve_id = row.get("cve", "").strip()
            if not cve_id:
                log.warning("Riga senza CVE trovata, salto.")
                continue

            existing = rows_map.get(cve_id)
            already_processed = (
                existing is not None
                and existing.get("published_date", "").strip()
                and existing.get("published_date") != "N/A"
            )

            if not already_processed:
                pending.append(row)

    if not pending:
        log.info("Nessun nuovo CVE da elaborare.")
        return

    log.info("%d CVE da arricchire con NVD.", len(pending))

    with requests.Session() as session:
        for i, row in enumerate(pending, start=1):
            cve_id = row["cve"].strip()
            log.info("[%d/%d] NVD → %s", i, len(pending), cve_id)

            published_date, cwe_id = get_nvd_data(session, cve_id)
            row["published_date"] = published_date
            row["cwe_id"] = cwe_id

            # aggiorna/sostituisce sempre la riga relativa a quel CVE
            rows_map[cve_id] = row

            if i % SAVE_EVERY == 0:
                _save_atomic(output_file, rows_map, out_fieldnames)
                log.info("Salvataggio intermedio completato (%d CVE processati).", i)

            time.sleep(REQUEST_DELAY)

    # salvataggio finale
    _save_atomic(output_file, rows_map, out_fieldnames)
    log.info("NVD enrichment completato: %s", output_file)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    FOLDER.mkdir(parents=True, exist_ok=True)

    enrich_with_nvd(
        input_file=FOLDER / KEV_FILE,
        output_file=FOLDER / NVD_FILE,
    )