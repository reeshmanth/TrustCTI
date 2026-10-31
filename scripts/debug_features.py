from ml.features import extract_features
import pandas as pd

feat_google = extract_features("https://google.com")
print("Google features:")
for k, v in feat_google.items():
    if v != 0:
        print(f"  {k}: {v}")

feat_row0 = extract_features("http://br-icloud.com.br")
print("\nbr-icloud features:")
for k, v in feat_row0.items():
    if v != 0:
        print(f"  {k}: {v}")

