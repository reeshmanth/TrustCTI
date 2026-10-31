import pytest
from backend.scoring import calculate_threat_risk, calculate_cti_trust

def test_threat_risk_score_bounds():
    # Clean benign features
    features_clean = {"is_ip_host": 0, "phish_suspicious_tld": 0, "url_entropy": 2.5}
    risk_clean, cat_clean, _ = calculate_threat_risk(features_clean, malicious_prob=0.01)
    assert 0 <= risk_clean <= 20
    assert cat_clean == "CLEAN"

    # Critical malicious features
    features_mal = {
        "is_ip_host": 1,
        "phish_suspicious_tld": 1,
        "phish_brand_hijack": 1,
        "path_has_hacked_terms": 1,
        "url_entropy": 5.2
    }
    risk_mal, cat_mal, indicators = calculate_threat_risk(features_mal, malicious_prob=0.99)
    assert risk_mal >= 85
    assert cat_mal in ["HIGH", "CRITICAL"]
    assert len(indicators) >= 4

def test_cti_trust_score_factors():
    # High confidence, reputable org, verified on blockchain
    trust_high, cat_high, breakdown = calculate_cti_trust(
        prediction_confidence=0.99,
        source_reputation=95,
        blockchain_status="VERIFIED",
        feature_completeness=1.0
    )
    assert trust_high >= 85
    assert cat_high == "HIGHLY_TRUSTED"

    # Tampered blockchain record drops trust significantly
    trust_tampered, cat_tampered, _ = calculate_cti_trust(
        prediction_confidence=0.99,
        source_reputation=95,
        blockchain_status="TAMPERED",
        feature_completeness=1.0
    )
    assert trust_tampered < 75
    assert cat_tampered != "HIGHLY_TRUSTED"

