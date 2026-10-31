import pytest
from backend.canonical import (
    serialize_canonical_json, calculate_sha256_hash, compute_record_integrity
)

def test_deterministic_key_sorting():
    dict1 = {"id": "1", "url_normalized": "http://test.com", "classification": "Malicious", "threat_risk_score": 80}
    dict2 = {"threat_risk_score": 80, "classification": "Malicious", "url_normalized": "http://test.com", "id": "1"}

    json1 = serialize_canonical_json(dict1)
    json2 = serialize_canonical_json(dict2)

    assert json1 == json2, "Canonical JSON must sort keys identically regardless of insertion order"
    assert calculate_sha256_hash(json1) == calculate_sha256_hash(json2)

def test_hash_sensitivity_to_tampering():
    original = {"id": "rec-123", "classification": "Malicious", "threat_risk_score": 90}
    tampered = {"id": "rec-123", "classification": "Benign", "threat_risk_score": 90}

    _, hash_orig = compute_record_integrity(original)
    _, hash_tamp = compute_record_integrity(tampered)

    assert hash_orig != hash_tamp, "Any modification in record data must alter SHA-256 hash"
    assert len(hash_orig) == 64
    assert len(hash_tamp) == 64

