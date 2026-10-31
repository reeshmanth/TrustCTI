import pandas as pd

df = pd.read_csv("data/cti_binary_dataset.csv", nrows=100)

for idx, row in df.iterrows():
    if row["abnormal_url"] == 0 and row["is_malicious"] == 0:
        print(f"abnormal 0, benign: {row['url_normalized']}")
    elif row["abnormal_url"] == 1 and row["is_malicious"] == 1:
        print(f"abnormal 1, malicious: {row['url_normalized']}")

