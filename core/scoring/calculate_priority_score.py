import csv
import logging
import math
import argparse

from datetime import datetime
from pathlib import Path
from tabulate import tabulate

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

def safe_float(value: str) -> float:
    """Converte in float in modo sicuro."""
    try:
        return float(value)
    except (ValueError, TypeError):
        return 0.0


def compute_recency_score(pub_date_str: str) -> float:
    """
    Calcola uno score continuo basato sulla recency.
    Decadimento esponenziale.
    """
    try:
        pub_date = datetime.strptime(pub_date_str, "%Y-%m-%d")
        days = (datetime.today() - pub_date).days
        return math.exp(-days / 365)  # decay annuale
    except Exception:
        return 0.0


def compute_priority_score(cvss: float, epss: float, kev: float, recency: float) -> float:
    """
    Formula utilizzata:
    - meno peso al CVSS (teorico)
    - più peso a KEV (exploit reale)
    - aggiunta interazione EPSS*KEV
    """
    score = (
        (cvss / 10) * 0.25 +
        epss * 0.35 +
        kev * 0.25 +
        recency * 0.10 +
        (epss * kev) * 0.05
    )
    return round(score, 4)


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
# Scoring principale
# ---------------------------------------------------------------------------

def calculate_score(input_file: Path, output_file: Path) -> None:
    if not input_file.exists():
        raise FileNotFoundError(f"File input non trovato: {input_file}")

    enriched: list[dict] = []

    with open(input_file, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)

        fieldnames = list(reader.fieldnames or [])
        if not fieldnames:
            raise ValueError("Input CSV senza header.")

        required = {"cvss", "epss", "kev", "published_date", "cve"}
        if not required.issubset(fieldnames):
            raise ValueError(f"Mancano colonne richieste: {required}")

        # aggiungi colonna score se non presente
        if "priority_score" not in fieldnames:
            out_fieldnames = fieldnames + ["priority_score"]
        else:
            out_fieldnames = fieldnames

        for row in reader:
            try:
                cvss = safe_float(row.get("cvss"))
                epss = safe_float(row.get("epss"))
                kev = 1.0 if row.get("kev", "").strip().upper() == "YES" else 0.0
                recency = compute_recency_score(row.get("published_date", ""))

                score = compute_priority_score(cvss, epss, kev, recency)
                row["priority_score"] = score

            except Exception as e:
                log.error("Errore su %s: %s", row.get("cve", "N/A"), e)
                row["priority_score"] = 0.0

            enriched.append(row)

    if not enriched:
        log.warning("Nessun dato elaborato.")
        return

    # -----------------------------------------------------------------------
    # Salvataggio file
    # -----------------------------------------------------------------------

    _save_atomic(output_file, enriched, out_fieldnames)
    log.info("File salvato: %s (%d righe)", output_file, len(enriched))

    # -----------------------------------------------------------------------
    # Raggruppamento per CVE
    # -----------------------------------------------------------------------

    grouped = {}

    for row in enriched:
        cve = row.get("cve", "").strip()
        if not cve:
            continue

        if cve not in grouped:
            grouped[cve] = {
                "cvss": row.get("cvss"),
                "epss": row.get("epss"),
                "kev": row.get("kev"),
                "published_date": row.get("published_date"),
                "priority_score": float(row.get("priority_score", 0)),
                "ports": set([row.get("port", "")]),
            }
        else:
            grouped[cve]["ports"].add(row.get("port", ""))

    # -----------------------------------------------------------------------
    # Top 10
    # -----------------------------------------------------------------------

    top_sorted = sorted(
        grouped.items(),
        key=lambda x: x[1]["priority_score"],
        reverse=True,
    )

    table_data = [
        [
            ",".join(sorted(filter(None, info["ports"]))),
            cve,
            info["cvss"],
            info["epss"],
            info["kev"],
            info["published_date"],
            round(info["priority_score"], 4),
        ]
        for cve, info in top_sorted[:10]
    ]

    headers = ["Ports", "CVE", "CVSS", "EPSS", "KEV", "Published", "Score"]

    print("\n- Top 10 vulnerabilità prioritarie:")
    print(tabulate(table_data, headers=headers, tablefmt="fancy_grid"))


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Calculate vulnerability priority score")
    parser.add_argument("--input", required=True, help="CSV input")
    parser.add_argument("--output", required=True, help="CSV output")
    args = parser.parse_args()

    calculate_score(
        input_file=Path(args.input),
        output_file=Path(args.output),
    )