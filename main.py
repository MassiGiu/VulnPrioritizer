import sys
import subprocess
import logging
import argparse

from pathlib import Path
from config.config import (
    RAW_FILE,
    EPSS_FILE,
    KEV_FILE,
    NVD_FILE,
    CWETOCAPEC_FILE,
    CAPEC_NAMED_FILE,
    FULL_ENRICHED_FILE,
    FINAL_FILE,
    SORTED_FILE,
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

def run_module(module_name: str, args: list[str] | None = None) -> None:
    log.info("▶️ Avvio: %s", module_name)

    cmd = [sys.executable, "-m", module_name]
    if args:
        cmd.extend(args)

    result = subprocess.run(cmd)

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
    parser = argparse.ArgumentParser(description="Pipeline di prioritizzazione vulnerabilità")
    parser.add_argument("--scan-file", required=True, help="Path file XML Nmap")
    parser.add_argument("--workdir", required=True, help="Directory di lavoro/output")
    args = parser.parse_args()

    scan_file = Path(args.scan_file)
    workdir = Path(args.workdir)
    workdir.mkdir(parents=True, exist_ok=True)

    raw_file = workdir / RAW_FILE
    epss_file = workdir / EPSS_FILE
    kev_file = workdir / KEV_FILE
    nvd_file = workdir / NVD_FILE
    cwe_to_capec_file = workdir / CWETOCAPEC_FILE
    capec_named_file = workdir / CAPEC_NAMED_FILE
    full_enriched_file = workdir / FULL_ENRICHED_FILE
    final_file = workdir / FINAL_FILE
    sorted_file = workdir / SORTED_FILE
    kev_catalog_file = workdir / "known_exploited_vulnerabilities.csv"

    log.info("▶️ Avvio pipeline di prioritizzazione vulnerabilità")

    # 1. Parsing Nmap
    if not file_exists(raw_file):
        run_module(
            "core.parsing.parse_nmap_vulners",
            ["--scan-file", str(scan_file), "--output-dir", str(workdir)],
        )
    else:
        log.info("- vulnerabilities.csv già presente")

    # 2. EPSS
    run_module(
        "core.enrichment.enrich_epss",
        ["--input", str(raw_file), "--output", str(epss_file)],
    )

    # 3. KEV
    run_module(
        "core.enrichment.enrich_kev",
        [
            "--input", str(epss_file),
            "--output", str(kev_file),
            "--kev-file", str(kev_catalog_file),
            "--download-kev",
        ],
    )

    # 4. NVD
    run_module(
        "core.enrichment.enrich_nvd",
        ["--input", str(kev_file), "--output", str(nvd_file)],
    )

    # 5. CWE → CAPEC mapping
    if not file_exists(cwe_to_capec_file):
        run_module(
            "core.enrichment.generate_cwe_to_capec",
            ["--output", str(cwe_to_capec_file), "--workdir", str(workdir)],
        )
    else:
        log.info("- cwe_to_capec.csv già presente")

    if not file_exists(capec_named_file):
        run_module(
            "core.enrichment.add_capec_names",
            [
                "--input", str(cwe_to_capec_file),
                "--output", str(capec_named_file),
                "--workdir", str(workdir),
                "--delete-input-after",
            ],
        )
    else:
        log.info("- cwe_to_capec_named.csv già presente")

    # 6. CAPEC enrichment
    run_module(
        "core.enrichment.enrich_capec",
        [
            "--input", str(nvd_file),
            "--capec-file", str(capec_named_file),
            "--output", str(full_enriched_file),
        ],
    )

    # 7. Scoring
    run_module(
        "core.scoring.calculate_priority_score",
        ["--input", str(full_enriched_file), "--output", str(final_file)],
    )

    # 8. Sorting
    run_module(
        "core.sorting.sort_by_priority",
        ["--input", str(final_file), "--output", str(sorted_file)],
    )

    log.info("Pipeline completata. Output in: %s", workdir)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    main()