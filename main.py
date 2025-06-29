import os
import subprocess
from config import FOLDER, RAW_FILE, EPSS_FILE, KEV_FILE, NVD_FILE, CWETOCAPEC_FILE, CAPEC_NAMED_FILE, FINAL_FILE, SCORED_FILE

def run_script(script_name):
    print(f"\n🚀 Avvio: {script_name}")
    result = subprocess.run(["python", script_name])
    if result.returncode == 0:
        print(f"✅ Completato: {script_name}")
    else:
        print(f"❌ Errore durante l'esecuzione di {script_name}")
        exit(1)

def file_exists(file_name):
    return os.path.exists(file_name)

if __name__ == "__main__":
    print("Inizio processo di prioritizzazione automatica delle vulnerabilità")

    # 1. Parsing output.xml → vulnerabilities.csv
    if not file_exists(FOLDER / RAW_FILE):
        run_script("parse_nmap_vulners.py")
    else:
        print("- vulnerabilities.csv già presente.")

    # 2. Enrichment con EPSS
    if not file_exists(FOLDER / EPSS_FILE):
        run_script("enrich_epss.py")
    else:
        print("- vulnerabilities_with_epss.csv già presente.")

    # 3. Enrichment con KEV
    if not file_exists(FOLDER / KEV_FILE):
        run_script("enrich_kev.py")
    else:
        print("- vulnerabilities_with_epss_kev.csv già presente.")

    # 4. Enrichment con NVD (published_date, cwe_id)
    if not file_exists(FOLDER / NVD_FILE):
        run_script("enrich_nvd.py")
    else:
        print("- vulnerabilities_with_nvd.csv già presente.")

    # 5. Genera mappa CWE → CAPEC (se non presente)
    if not file_exists(CWETOCAPEC_FILE):
        run_script("generate_cwe_to_capec.py")
    else:
        print("- cwe_to_capec.csv già presente.")

    if not file_exists(CAPEC_NAMED_FILE):
        run_script("add_capec_names.py")
    else:
        print("- cwe_to_capec_named.csv già presente.")

    # 6. Enrichment con CAPEC
    if not file_exists(FOLDER / FINAL_FILE):
        run_script("enrich_capec.py")
    else:
        print("- vulnerabilities_final.csv già presente.")

    # 7. Calcolo dello score finale
    if not file_exists(FOLDER / SCORED_FILE):
        run_script("calculate_priority_score.py")
    else:
        print("- vulnerabilities_scored.csv già presente.")

    print(f"\nPipeline completata! Trovi il risultato nella cartella: {FOLDER}")
