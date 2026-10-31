import pandas as pd

df = pd.read_csv("data/cti_binary_dataset.csv", nrows=50000)

excluded = {
    "url_normalized", "url_hash", "host", "class_label", "original_label", "is_malicious",
    "web_http_status", "web_is_live", "web_ext_ratio", "web_unique_domains",
    "web_favicon", "web_csp", "web_xframe", "web_hsts", "web_xcontent",
    "web_security_score", "web_forms_count", "web_password_fields",
    "web_hidden_inputs", "web_has_login", "web_ssl_valid"
}

feature_cols = [c for c in df.columns if c not in excluded]

corrs = {}
for col in feature_cols:
    try:
        c = df[col].astype(float).corr(df["is_malicious"].astype(float))
        corrs[col] = c
    except:
        pass

sorted_corrs = sorted(corrs.items(), key=lambda x: abs(x[1]), reverse=True)
print("Top 20 highest absolute correlation with is_malicious:")
for col, val in sorted_corrs[:20]:
    print(f"  {col}: {val:.4f}")

