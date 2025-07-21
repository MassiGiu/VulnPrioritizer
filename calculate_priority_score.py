import csv
from datetime import datetime
from tabulate import tabulate 
from config import FOLDER, FULL_ENRICHED_FILE, FINAL_FILE


# === Funzione per calcolare il punteggio in base alla data ===
def compute_recency_score(pub_date_str):
    try:
        pub_date = datetime.strptime(pub_date_str, "%Y-%m-%d")
        delta_days = (datetime.today() - pub_date).days

        if delta_days <= 90:
            return 1.0
        elif delta_days <= 365:
            return 0.5
        else:
            return 0.2
    except:
        return 0.0  # se data mancante o errore

# === Funzione principale ===
def calculate_score(input_file, output_file):
    enriched = []

    with open(input_file, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            try:
                # Parsing campi
                cvss = float(row['cvss']) if row['cvss'] else 0.0
                epss = float(row['epss']) if row['epss'] else 0.0
                kev = 1.0 if row['kev'].strip().upper() == "YES" else 0.0
                recency = compute_recency_score(row['published_date'])

                # Calcolo score
                score = (cvss / 10) * 0.4 + epss * 0.4 + kev * 0.15 + recency * 0.05
                row['priority_score'] = round(score, 4)
            except Exception as e:
                print(f"[!] Errore su {row.get('cve', 'N/A')}: {e}")
                row['priority_score'] = 0.0

            enriched.append(row)

    # Scrittura file output
    with open(output_file, 'w', newline='') as f:
        fieldnames = list(enriched[0].keys())
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in enriched:
            writer.writerow(row)

    print(f"\n✅ File salvato nella cartella: {output_file}")

       # === Raggruppa per CVE ===
    grouped = {}
    for row in enriched:
        cve = row['cve']
        if cve not in grouped:
            grouped[cve] = {
                "cvss": row['cvss'],
                "epss": row['epss'],
                "kev": row['kev'],
                "published_date": row['published_date'],
                "priority_score": row['priority_score'],
                "ports": set([row['port']])
            }
        else:
            grouped[cve]["ports"].add(row['port'])

    # Ordina per score decrescente
    top_sorted = sorted(grouped.items(), key=lambda x: float(x[1]['priority_score']), reverse=True)

    # Seleziona le Top 10
    table_data = [
        [",".join(sorted(info["ports"])), cve, info["cvss"], info["epss"], info["kev"], info["published_date"], info["priority_score"]]
        for cve, info in top_sorted[:10]
    ]

    # Stampa tabella
    headers = ["Ports", "CVE", "CVSS", "EPSS", "KEV", "Published", "Score"]
    print("\n📊 Top 10 vulnerabilità prioritarie:")
    print(tabulate(table_data, headers=headers, tablefmt="fancy_grid"))


# === Esecuzione ===
if __name__ == "__main__":
    
    input_file = FOLDER / FULL_ENRICHED_FILE
    output_file = FOLDER / FINAL_FILE
    calculate_score(input_file, output_file)
