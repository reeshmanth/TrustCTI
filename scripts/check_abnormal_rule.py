import pandas as pd

df = pd.read_csv("data/cti_binary_dataset.csv", usecols=["url_normalized", "host", "abnormal_url", "is_malicious"], nrows=50)

print("Rows with abnormal_url == 0:")
for _, row in df[df["abnormal_url"] == 0].head(10).iterrows():
    print(f"  {row['url_normalized']} (host: {row['host']}, mal: {row['is_malicious']})")

print("\nRows with abnormal_url == 1:")
for _, row in df[df["abnormal_url"] == 1].head(10).iterrows():
    print(f"  {row['url_normalized']} (host: {row['host']}, mal: {row['is_malicious']})")

