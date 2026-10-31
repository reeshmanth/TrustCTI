import csv
import sys
import os

csv_path = os.path.join("data", "cti_binary_dataset.csv")

if not os.path.exists(csv_path):
    print(f"Error: {csv_path} does not exist")
    sys.exit(1)

file_size_mb = os.path.getsize(csv_path) / (1024 * 1024)
print(f"File size: {file_size_mb:.2f} MB")

with open(csv_path, "r", encoding="utf-8", errors="ignore") as f:
    reader = csv.reader(f)
    header = next(reader)
    print(f"Total columns: {len(header)}")
    print("Columns:")
    for i, col in enumerate(header):
        print(f"  {i}: {col}")
    
    first_rows = []
    for _ in range(3):
        try:
            row = next(reader)
            first_rows.append(row)
        except StopIteration:
            break

print("\nFirst row sample:")
for col, val in zip(header, first_rows[0]):
    print(f"  {col}: {val}")

