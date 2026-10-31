import pandas as pd
from urllib.parse import urlparse

df = pd.read_csv("data/cti_binary_dataset.csv", nrows=10)
for _, r in df.iterrows():
    u = r["url_normalized"]
    p = urlparse(u).path
    print(f"Dataset path_len: {r['path_len']}, url: {u}, parsed path: '{p}', len(path): {len(p)}")

