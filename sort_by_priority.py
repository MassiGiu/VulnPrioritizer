import csv
from config import FOLDER, FINAL_FILE, SORTED_FILE

def sort_by_priority(input_file, output_file):
    # === Leggi il file CSV e ordina in base al priority score ===
    with open(input_file, 'r') as f:
        reader = csv.DictReader(f)
        rows = sorted(reader, key=lambda x: float(x['priority_score']), reverse=True)

    # === Scrivi il file ordinato ===
    with open(output_file, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)

    print(f"[✅] File ordinato in base al priority score salvato come: {output_file}")

# === Esecuzione ===
if __name__ == "__main__":
    input_file = FOLDER / FINAL_FILE
    output_file = FOLDER / SORTED_FILE
    sort_by_priority(input_file, output_file)
