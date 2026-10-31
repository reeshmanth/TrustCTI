import os
import csv
import pytest

DATASET_PATH = os.path.join("data", "cti_binary_dataset.csv")

def test_dataset_exists_and_not_empty():
    assert os.path.exists(DATASET_PATH), f"Dataset {DATASET_PATH} missing"
    assert os.path.getsize(DATASET_PATH) > 100 * 1024 * 1024, "Dataset file size should exceed 100MB"

def test_dataset_headers_and_target_columns():
    with open(DATASET_PATH, "r", encoding="utf-8", errors="ignore") as f:
        reader = csv.reader(f)
        header = next(reader)
        assert len(header) == 89, f"Expected 89 columns, got {len(header)}"
        assert "is_malicious" in header
        assert "class_label" in header
        assert "url_normalized" in header
        assert "url_hash" in header
        assert "host" in header

def test_dataset_row_validity():
    with open(DATASET_PATH, "r", encoding="utf-8", errors="ignore") as f:
        reader = csv.DictReader(f)
        for i, row in enumerate(reader):
            if i >= 100:
                break
            assert row["is_malicious"] in ["0", "1"]
            assert row["class_label"] in ["benign", "defacement", "phishing", "malware"]

