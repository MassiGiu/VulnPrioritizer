import csv
import logging
import argparse

from pathlib import Path

# ---------------------------------------------------------------------------
# Configurazione logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# CAPEC mapping
# ---------------------------------------------------------------------------

def load_capec_mapping(filename: Path) -> dict[str, dict[str, str]]:
    """Carica la mappatura CWE → CAPEC."""
    if not filename.exists():
        raise FileNotFoundError(f"File CAPEC non trovato: {filename}")

    capec_map: dict[str, dict[str, str]] = {}

    with open(filename, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)

        if not reader.fieldnames:
            raise ValueError("File CAPEC senza header.")

        required = {"cwe_id", "capec_id", "capec_name"}
        if not required.issubset(reader.fieldnames):
            raise ValueError(f"Il file CAPEC deve contenere le colonne: {required}")

        for row in reader:
            cwe = row.get("cwe_id", "").strip()
            if not cwe:
                continue

            # Mantieni solo il primo mapping (evita override)
            if cwe not in capec_map:
                capec_map[cwe] = {
                    "capec_id": row.get("capec_id", "N/A").strip(),
                    "capec_name": row.get("capec_name", "N/A").strip(),
                }

    log.info("Caricate %d associazioni CWE → CAPEC.", len(capec_map))
    return capec_map


# ---------------------------------------------------------------------------
# I/O helpers
# ---------------------------------------------------------------------------

def _save_atomic(output_file: Path, rows: list[dict], fieldnames: list[str]) -> None:
    """Scrittura atomica per evitare file corrotti."""
    if not rows:
        log.warning("Nessuna riga da salvare.")
        return

    tmp_file = output_file.with_suffix(".tmp")

    with open(tmp_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    tmp_file.replace(output_file)


# ---------------------------------------------------------------------------
# Enrichment CAPEC
# ---------------------------------------------------------------------------

def enrich_with_capec(input_file: Path, capec_map: dict[str, dict[str, str]], output_file: Path) -> None:
    """Arricchisce i dati con CAPEC partendo da CWE."""
    if not input_file.exists():
        raise FileNotFoundError(f"File input non trovato: {input_file}")

    enriched: list[dict] = []

    with open(input_file, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)

        fieldnames = list(reader.fieldnames or [])
        if not fieldnames:
            raise ValueError("Input CSV senza header.")

        if "cwe_id" not in fieldnames:
            raise ValueError("Il CSV di input deve contenere la colonna 'cwe_id'.")

        # Aggiungi colonne CAPEC se non presenti
        extra_columns = [c for c in ("capec_id", "capec_name") if c not in fieldnames]
        out_fieldnames = fieldnames + extra_columns

        for row in reader:
            cwe = row.get("cwe_id", "").strip()

            capec = capec_map.get(
                cwe,
                {"capec_id": "N/A", "capec_name": "N/A"},
            )

            row["capec_id"] = capec["capec_id"]
            row["capec_name"] = capec["capec_name"]

            enriched.append(row)

    if not enriched:
        log.warning("Nessun dato da arricchire.")
        return

    _save_atomic(output_file, enriched, out_fieldnames)

    log.info("CAPEC enrichment completato: %s (%d righe)", output_file, len(enriched))


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Enrich vulnerabilities with CAPEC data")
    parser.add_argument("--input", required=True, help="CSV input")
    parser.add_argument("--capec-file", required=True, help="CSV mapping CWE->CAPEC")
    parser.add_argument("--output", required=True, help="CSV output")
    args = parser.parse_args()

    capec_map = load_capec_mapping(Path(args.capec_file))

    enrich_with_capec(
        input_file=Path(args.input),
        capec_map=capec_map,
        output_file=Path(args.output),
    )