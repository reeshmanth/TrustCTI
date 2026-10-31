import pandas as pd

df = pd.read_csv("data/cti_binary_dataset.csv", nrows=100)
benign = df[df["is_malicious"] == 0]
print("Benign URLs in dataset:")
for _, r in benign.head(10).iterrows():
    print(f"URL: {r['url_normalized']} | domain_len: {r['domain_len']} | path_len: {r['path_len']} | is_https: {r['is_https']} | https: {r['https']}")

