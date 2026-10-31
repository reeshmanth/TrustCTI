import pytest
from ml.features import extract_features, FEATURE_COLUMNS, shannon_entropy

def test_shannon_entropy_calculation():
    # Empty string entropy is 0.0
    assert shannon_entropy("") == 0.0
    # Homogeneous string entropy is 0.0
    assert shannon_entropy("aaaaaa") == 0.0
    # Randomized string has positive entropy
    ent = shannon_entropy("abcdefghijklmnopqrstuvwxyz")
    assert ent > 4.0

def test_feature_extraction_column_count():
    feats = extract_features("https://secure.example.com/login?token=abc")
    assert len(feats) == len(FEATURE_COLUMNS)
    for col in FEATURE_COLUMNS:
        assert col in feats, f"Missing feature {col}"

def test_ip_host_detection():
    feats_ip = extract_features("http://192.168.1.100/admin/index.php")
    assert feats_ip["is_ip_host"] == 1
    assert feats_ip["having_ip_address"] == 1

    feats_domain = extract_features("https://www.google.com")
    assert feats_domain["is_ip_host"] == 0

def test_brand_and_security_keyword_heuristics():
    url = "http://verify-account-apple-support.xyz/login.php?user=urgent"
    feats = extract_features(url)
    assert feats["phish_brand_mentions"] >= 1
    assert feats["phish_security_words"] >= 1
    assert feats["phish_urgency_words"] >= 1
    assert feats["phish_suspicious_tld"] == 1

