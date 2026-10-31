import csv
import os
import json
from collections import Counter

csv_path = os.path.join("data", "cti_binary_dataset.csv")

total_rows = 0
class_dist = Counter()
malicious_dist = Counter()
original_label_dist = Counter()
missing_counts = Counter()
web_nonzero = Counter()

web_cols = [
    "web_http_status", "web_is_live", "web_ext_ratio", "web_unique_domains",
    "web_favicon", "web_csp", "web_xframe", "web_hsts", "web_xcontent",
    "web_security_score", "web_forms_count", "web_password_fields",
    "web_hidden_inputs", "web_has_login", "web_ssl_valid"
]

print("Starting streaming analysis of dataset...")

with open(csv_path, "r", encoding="utf-8", errors="ignore") as f:
    reader = csv.DictReader(f)
    columns = reader.fieldnames
    for row in reader:
        total_rows += 1
        class_dist[row.get("class_label", "MISSING")] += 1
        malicious_dist[row.get("is_malicious", "MISSING")] += 1
        original_label_dist[row.get("original_label", "MISSING")] += 1
        
        for k, v in row.items():
            if v is None or v == "" or v == "NA" or v == "NaN":
                missing_counts[k] += 1
                
        for col in web_cols:
            val = row.get(col, "0")
            try:
                fval = float(val)
                if fval != 0.0:
                    web_nonzero[col] += 1
            except:
                pass
                
        if total_rows % 100000 == 0:
            print(f"Processed {total_rows} rows...")

summary = {
    "total_rows": total_rows,
    "total_columns": len(columns),
    "class_label_distribution": dict(class_dist),
    "is_malicious_distribution": dict(malicious_dist),
    "original_label_distribution": dict(original_label_dist),
    "missing_values_summary": {k: v for k, v in missing_counts.items() if v > 0},
    "web_nonzero_counts": dict(web_nonzero)
}

os.makedirs("artifacts", exist_ok=True)
with open("artifacts/dataset_profile.json", "w") as out:
    json.dump(summary, out, indent=2)

print("\n--- DATASET PROFILE SUMMARY ---")
print(f"Total rows: {total_rows}")
print(f"Total columns: {len(columns)}")
print("Class label distribution:", dict(class_dist))
print("is_malicious distribution:", dict(malicious_dist))
print("Missing values in columns:", {k: v for k, v in missing_counts.items() if v > 0})
print("Web columns non-zero counts:", dict(web_nonzero))

