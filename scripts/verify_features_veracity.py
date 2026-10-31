import pandas as pd
import numpy as np
import re
import math
from collections import Counter
from urllib.parse import urlparse

df = pd.read_csv("data/cti_binary_dataset.csv", nrows=1000)

def shannon_entropy(text):
    if not text:
        return 0.0
    counts = Counter(text)
    total = len(text)
    return float(round(-sum((c / total) * math.log2(c / total) for c in counts.values()), 4))

# Let's test standard lexical features:
results = {}

# 1. url_len_v2 vs len(url)
exact_match_len_v2 = (df["url_len_v2"] == df["url_normalized"].apply(len)).mean()
results["url_len_v2"] = exact_match_len_v2

# 2. host entropy
def compute_host_ent(u):
    h = urlparse(u).netloc.split(":")[0]
    return shannon_entropy(h)
ent_host_match = np.isclose(df["host_entropy"], df["url_normalized"].apply(compute_host_ent), atol=0.01).mean()
results["host_entropy"] = ent_host_match

# 3. url entropy
def compute_url_ent(u):
    return shannon_entropy(u)
ent_url_match = np.isclose(df["url_entropy"], df["url_normalized"].apply(compute_url_ent), atol=0.01).mean()
results["url_entropy"] = ent_url_match

# 4. digit_count_v2
digit_v2_match = (df["digit_count_v2"] == df["url_normalized"].apply(lambda u: sum(c.isdigit() for c in u))).mean()
results["digit_count_v2"] = digit_v2_match

# 5. letter_count_v2
letter_v2_match = (df["letter_count_v2"] == df["url_normalized"].apply(lambda u: sum(c.isalpha() for c in u))).mean()
results["letter_count_v2"] = letter_v2_match

# 6. special_count_v2
def spec_cnt(u):
    return len(u) - sum(c.isalnum() for c in u)
results["special_count_v2"] = (df["special_count_v2"] == df["url_normalized"].apply(spec_cnt)).mean()

# 7. char counts: '-', '.', '=', '?', '@'
for ch in ["-", ".", "=", "?", "@"]:
    results[f"char_{ch}"] = (df[ch] == df["url_normalized"].apply(lambda u: u.count(ch))).mean()

# 8. domain_len
results["domain_len"] = (df["domain_len"] == df["url_normalized"].apply(lambda u: len(urlparse(u).netloc.split(":")[0]))).mean()

# 9. path_len
results["path_len"] = (df["path_len"] == df["url_normalized"].apply(lambda u: len(urlparse(u).path.lstrip("/")))).mean()

# 10. query_len
results["query_len"] = (df["query_len"] == df["url_normalized"].apply(lambda u: len(urlparse(u).query))).mean()

# 11. abnormal_url
# Can abnormal_url be computed?
results["abnormal_url_match"] = "UNREPRODUCIBLE LEAKAGE"
results["//_match"] = (df["//"] == df["url_normalized"].apply(lambda u: u.count("//"))).mean()

for k, v in results.items():
    print(f"  {k}: {v}")

