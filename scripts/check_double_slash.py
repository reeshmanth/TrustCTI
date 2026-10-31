import pandas as pd

df = pd.read_csv("data/cti_binary_dataset.csv", usecols=["url_normalized", "//", "is_malicious"], nrows=20)
for _, r in df.iterrows():
    print(f"{r['//']} | mal={r['is_malicious']} | {r['url_normalized']}")

