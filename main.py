import sys
import subprocess
import logging
from pathlib import Path

from config.config import (
    FOLDER,
    RAW_FILE,
    CWETOCAPEC_FILE,
    CAPEC_NAMED_FILE,
)

# ---------------------------------------------------------------------------
# Config logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def run_module(module_name: str) -> None:
    """Esegue un modulo Python in modo sicuro (usa il venv corrente)."""
    log.info("▶️ Avvio: %s", module_name)

    result = subprocess.run(
        [sys.executable, "-m", module_name],
    )

    if result.returncode != 0:
        log.error("❌ Errore durante l'esecuzione di %s", module_name)
        sys.exit(1)

    log.info("✅ Completato: %s", module_name)


def file_exists(path: Path) -> bool:
    return path.exists()


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------

def main():
    log.info("▶️ Avvio pipeline di prioritizzazione vulnerabilità")

    # 1. Parsing Nmap
    if not file_exists(FOLDER / RAW_FILE):
        run_module("core.parsing.parse_nmap_vulners")
    else:
        log.info("- vulnerabilities.csv già presente")

    # 2. EPSS
    run_module("core.enrichment.enrich_epss")

    # 3. KEV
    run_module("core.enrichment.enrich_kev")

    # 4. NVD
    run_module("core.enrichment.enrich_nvd")

    # 5. CWE → CAPEC mapping
    if not file_exists(FOLDER / CWETOCAPEC_FILE):
        run_module("core.enrichment.generate_cwe_to_capec")
    else:
        log.info("- cwe_to_capec.csv già presente")

    if not file_exists(FOLDER / CAPEC_NAMED_FILE):
        run_module("core.enrichment.add_capec_names")
    else:
        log.info("- cwe_to_capec_named.csv già presente")

    # 6. CAPEC enrichment
    run_module("core.enrichment.enrich_capec")

    # 7. Scoring
    run_module("core.scoring.calculate_priority_score")

    # 8. Sorting
    run_module("core.sorting.sort_by_priority")

    log.info("Pipeline completata. Output in: %s", FOLDER)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    FOLDER.mkdir(parents=True, exist_ok=True)
    main()