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
# Helpers
# ---------------------------------------------------------------------------

def safe_float(value) -> float:
    """Conversione sicura a float."""
    try:
        return float(value)
    except (ValueError, TypeError):
        return 0.0


def _save_atomic(output_file: Path, rows: list[dict], fieldnames: list[str]) -> None:
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


# ---------------------------------------------------------------------------
# Sorting
# ---------------------------------------------------------------------------

def sort_by_priority(input_file: Path, output_file: Path) -> None:
    if not input_file.exists():
        raise FileNotFoundError(f"File input non trovato: {input_file}")

    with open(input_file, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)

        fieldnames = list(reader.fieldnames or [])
        if not fieldnames:
            raise ValueError("CSV senza header.")

        if "priority_score" not in fieldnames:
            raise ValueError("Colonna 'priority_score' non trovata.")

        rows = list(reader)

    if not rows:
        log.warning("Nessun dato da ordinare.")
        return

    # ordinamento robusto
    rows_sorted = sorted(
        rows,
        key=lambda x: safe_float(x.get("priority_score")),
        reverse=True,
    )

    _save_atomic(output_file, rows_sorted, fieldnames)

    log.info("File ordinato salvato: %s (%d righe)", output_file, len(rows_sorted))


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Sort vulnerabilities by priority score")
    parser.add_argument("--input", required=True, help="CSV input")
    parser.add_argument("--output", required=True, help="CSV output")
    args = parser.parse_args()

    sort_by_priority(
        input_file=Path(args.input),
        output_file=Path(args.output),
    )