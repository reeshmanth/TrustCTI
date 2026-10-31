import csv

csv_path = "data/cti_binary_dataset.csv"

excluded = {
    "url_normalized", "url_hash", "host", "class_label", "original_label", "is_malicious",
    "web_http_status", "web_is_live", "web_ext_ratio", "web_unique_domains",
    "web_favicon", "web_csp", "web_xframe", "web_hsts", "web_xcontent",
    "web_security_score", "web_forms_count", "web_password_fields",
    "web_hidden_inputs", "web_has_login", "web_ssl_valid"
}

with open(csv_path, "r", encoding="utf-8", errors="ignore") as f:
    reader = csv.DictReader(f)
    fieldnames = reader.fieldnames
    features = [col for col in fieldnames if col not in excluded]
    print(f"Total features: {len(features)}")
    
    first_row = next(reader)
    non_numeric = []
    for col in features:
        val = first_row[col]
        try:
            float(val)
        except ValueError:
            if val in ["True", "False", "true", "false"]:
                pass
            else:
                non_numeric.append((col, val))
                
    print("Non numeric features:", non_numeric)
    print("\nFeature list:")
    for i, f in enumerate(features):
        print(f"  {i+1}: {f}")

