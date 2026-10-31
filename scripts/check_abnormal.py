import pandas as pd

df = pd.read_csv("data/cti_binary_dataset.csv", usecols=["url_normalized", "class_label", "is_malicious", "abnormal_url", "https", "url_len", "phish_adv_exact_brand_match"], nrows=10000)

print(df.groupby(["is_malicious", "abnormal_url"]).size())
print("\nBenign sample with abnormal_url:")
print(df[df["is_malicious"] == 0][["url_normalized", "abnormal_url", "https", "url_len"]].head(10))

print("\nMalicious sample with abnormal_url:")
print(df[df["is_malicious"] == 1][["url_normalized", "abnormal_url", "https", "url_len"]].head(10))

