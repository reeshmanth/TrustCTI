import csv
import math
from collections import Counter

csv_path = "data/cti_binary_dataset.csv"

def calc_entropy(text):
    if not text:
        return 0.0
    counts = Counter(text)
    total = len(text)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())

with open(csv_path, "r", encoding="utf-8", errors="ignore") as f:
    reader = csv.DictReader(f)
    samples = []
    for i, row in enumerate(reader):
        if i < 5:
            samples.append(row)
        else:
            break

for idx, sample in enumerate(samples):
    url = sample["url_normalized"]
    host = sample["host"]
    print(f"\n--- Sample {idx + 1}: {url} ---")
    print(f"Dataset host: {host}")
    print(f"Dataset url_len: {sample['url_len']}, url_len_v2: {sample['url_len_v2']}, domain_len: {sample['domain_len']}, path_len: {sample['path_len']}")
    print(f"Dataset entropy: url={sample['url_entropy']}, host={sample['host_entropy']}")
    print(f"Computed entropy: url={calc_entropy(url):.4f}, host={calc_entropy(host):.4f}")
    print(f"Dataset tokens: count={sample['token_count']}, max={sample['max_token_len']}, avg={sample['avg_token_len']}")
    print(f"Dataset char counts: digits_v2={sample['digit_count_v2']}, letters_v2={sample['letter_count_v2']}, special_v2={sample['special_count_v2']}")
    print(f"Dataset digits={sample['digits']}, letters={sample['letters']}")

