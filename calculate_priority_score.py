import csv
from datetime import datetime
from tabulate import tabulate 
from config import FOLDER, FINAL_FILE, SCORED_FILE


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
                kev = 1.0 if row['in_kev'].strip().upper() == "YES" else 0.0
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

    print(f"\n✅ File salvato con punteggio: {output_file}")

    # === Stampa tabella riassuntiva (Top 10 score) ===
    enriched_sorted = sorted(enriched, key=lambda x: x['priority_score'], reverse=True)
    table_data = [
        [row['cve'], row['cvss'], row['epss'], row['in_kev'], row['published_date'], row['priority_score']]
        for row in enriched_sorted[:10]
    ]
    headers = ["CVE", "CVSS", "EPSS", "KEV", "Published", "Score"]
    print("\n📊 Top 10 vulnerabilità prioritarie:")
    print(tabulate(table_data, headers=headers, tablefmt="fancy_grid"))

# === Esecuzione ===
if __name__ == "__main__":
    
    input_file = FOLDER / FINAL_FILE
    output_file = FOLDER / SCORED_FILE
    calculate_score(input_file, output_file)
