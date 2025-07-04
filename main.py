import os
import subprocess
from config import FOLDER, RAW_FILE, EPSS_FILE, KEV_FILE, NVD_FILE, CWETOCAPEC_FILE, CAPEC_NAMED_FILE, FINAL_FILE, SCORED_FILE

def run_script(script_name):
    print(f"\n▶️ Avvio: {script_name}")
    result = subprocess.run(["python", script_name])
    if result.returncode == 0:
        print(f"✅ Completato: {script_name}")
    else:
        print(f"❌ Errore durante l'esecuzione di {script_name}")
        exit(1)

def file_exists(file_name):
    return os.path.exists(file_name)

if __name__ == "__main__":
    print("🚀 Inizio processo di prioritizzazione automatica delle vulnerabilità")

    # 1. Parsing output.xml → vulnerabilities.csv
    if not file_exists(FOLDER / RAW_FILE):
        run_script("parse_nmap_vulners.py")
    else:
        print("- vulnerabilities.csv già presente.")

    # 2. Enrichment con EPSS (sempre eseguito: gestisce la ripresa internamente)
    run_script("enrich_epss.py")

    # 3. Enrichment con KEV (può essere gestito nello stesso modo se serve)
    run_script("enrich_kev.py")

    # 4. Enrichment con NVD
    run_script("enrich_nvd.py")

    # 5. Genera mappa CWE → CAPEC (solo se non esiste)
    if not file_exists(CWETOCAPEC_FILE):
        run_script("generate_cwe_to_capec.py")
    else:
        print("- cwe_to_capec.csv già presente.")

    if not file_exists(CAPEC_NAMED_FILE):
        run_script("add_capec_names.py")
    else:
        print("- cwe_to_capec_named.csv già presente.")

    # 6. Enrichment con CAPEC
    run_script("enrich_capec.py")

    # 7. Calcolo dello score finale
    run_script("calculate_priority_score.py")

    print(f"\n✅ Esecuzione completata. Il risultato finale è nella cartella: {FOLDER}")
