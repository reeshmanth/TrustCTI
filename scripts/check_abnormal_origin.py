import pandas as pd
from urllib.parse import urlparse
import re

df = pd.read_csv("data/cti_binary_dataset.csv", nrows=1000)

correlations = {}
for i, row in df.iterrows():
    url = row["url_normalized"]
    ab = row["abnormal_url"]
    parsed = urlparse(url)
    h = parsed.netloc or ""
    # let's test possible functions:
    f1 = 1 if h in parsed.path else 0
    f2 = 1 if h in url else 0
    f3 = 1 if re.search(re.escape(h), url) else 0
    # What about WHOIS or response check?
    
print("abnormal_url values in first 1000 rows:")
print(df["abnormal_url"].value_counts())
print("\nIs abnormal_url correlated with whois or web features?")
print(df[["abnormal_url", "is_malicious"]].corr())

