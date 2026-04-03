import csv
import logging
import time
import argparse
import requests

from pathlib import Path

# --- Configurazione ---
API_URL = "https://api.first.org/data/v1/epss"
REQUEST_DELAY = 0.5
MAX_RETRIES = 3
BATCH_SIZE = 100

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# API
# ---------------------------------------------------------------------------

def get_epss_scores_batch(session: requests.Session, cve_ids: list[str]) -> dict[str, float]:
    """Recupera gli score EPSS per un batch di CVE in una sola chiamata."""
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            response = session.get(
                API_URL,
                params={"cve": ",".join(cve_ids)},
                timeout=15,
            )

            if response.status_code == 429:
                wait = 5 * attempt
                log.warning("Rate limit raggiunto. Attendo %ds (tentativo %d/%d)…", wait, attempt, MAX_RETRIES)
                time.sleep(wait)
                continue

            response.raise_for_status()
            data = response.json()
            return {
                item["cve"]: float(item["epss"])
                for item in data.get("data", [])
            }

        except requests.RequestException as e:
            log.error("Errore HTTP (tentativo %d/%d): %s", attempt, MAX_RETRIES, e)
            if attempt < MAX_RETRIES:
                time.sleep(2 * attempt)

    log.error("Tutti i tentativi falliti per il batch: %s", cve_ids)
    return {}


# ---------------------------------------------------------------------------
# I/O
# ---------------------------------------------------------------------------

def load_processed_cves(output_file: Path) -> tuple[set[str], list[dict], list[str]]:
    """
    Legge l'output già esistente.

    Returns:
        processed  – CVE già arricchiti con uno score valido
        rows       – righe già salvate
        fieldnames – ordine colonne originale (o lista vuota)
    """
    processed: set[str] = set()
    rows: list[dict] = []
    fieldnames: list[str] = []

    if output_file.exists():
        with open(output_file, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            fieldnames = reader.fieldnames or []
            for row in reader:
                rows.append(row)
                if row.get("epss") and row["epss"] != "N/A":
                    processed.add(row["cve"])

        log.info("Ripresi %d CVE già processati.", len(processed))

    return processed, rows, list(fieldnames)


def save_to_file(output_file: Path, rows: list[dict], fieldnames: list[str]) -> None:
    """Scrittura atomica: scrive su un file temporaneo poi lo rinomina."""
    if not rows:
        log.warning("Nessuna riga da salvare.")
        return

    tmp = output_file.with_suffix(".tmp")
    with open(tmp, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    tmp.replace(output_file)


# ---------------------------------------------------------------------------
# Logica principale
# ---------------------------------------------------------------------------

def enrich_with_epss(input_file: Path, output_file: Path) -> None:
    processed_cves, enriched, fieldnames = load_processed_cves(output_file)

    # Legge tutto l'input e filtra solo le CVE da processare
    with open(input_file, newline="", encoding="utf-8") as f_in:
        reader = csv.DictReader(f_in)
        input_fieldnames = reader.fieldnames or []
        pending: list[dict] = [
            row for row in reader if row["cve"] not in processed_cves
        ]

    if not pending:
        log.info("Nessuna nuova CVE da processare.")
        return

    # Determina i fieldnames finali (aggiunge "epss" se mancante)
    if not fieldnames:
        fieldnames = input_fieldnames
    if "epss" not in fieldnames:
        fieldnames = list(fieldnames) + ["epss"]

    log.info("%d CVE da arricchire, batch size=%d.", len(pending), BATCH_SIZE)

    with requests.Session() as session:
        # Processa le CVE in batch
        for i in range(0, len(pending), BATCH_SIZE):
            batch_rows = pending[i : i + BATCH_SIZE]
            batch_ids = [row["cve"] for row in batch_rows]

            log.info("Batch %d-%d / %d…", i + 1, i + len(batch_rows), len(pending))
            scores = get_epss_scores_batch(session, batch_ids)

            for row in batch_rows:
                cve_id = row["cve"]
                row["epss"] = scores.get(cve_id, "N/A")
                enriched.append(row)

            # Salvataggio atomico dopo ogni batch
            save_to_file(output_file, enriched, fieldnames)
            time.sleep(REQUEST_DELAY)

    log.info("✅ EPSS enrichment completato: %s", output_file)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Enrich vulnerabilities with EPSS")
    parser.add_argument("--input", required=True, help="CSV input")
    parser.add_argument("--output", required=True, help="CSV output")
    args = parser.parse_args()

    enrich_with_epss(
        input_file=Path(args.input),
        output_file=Path(args.output),
    )

    