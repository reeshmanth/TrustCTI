from typing import Dict, Any, List, Tuple

def calculate_threat_risk(features: Dict[str, Any], malicious_prob: float) -> Tuple[int, str, List[Dict[str, Any]]]:
    """
    Computes Threat Risk Score (0-100).
    Represents HOW DANGEROUS the analyzed URL appears to be.
    
    Formula:
      BaseRisk = malicious_prob * 60 (derived from XGBoost model probability)
      HeuristicAdditions = Sum of weighted risk indicators (max 40 pts)
      Total = min(100, max(0, round(BaseRisk + HeuristicAdditions)))
    """
    indicators = []
    heuristic_points = 0
    
    # 1. IP address in host (Evasion & Direct Access)
    if features.get("is_ip_host", 0) == 1 or features.get("having_ip_address", 0) == 1:
        score = 10
        heuristic_points += score
        indicators.append({
            "indicator": "Direct IP Host",
            "score_impact": score,
            "severity": "CRITICAL",
            "description": "URL bypasses domain name resolution using a raw IPv4/IPv6 host, commonly associated with malicious C2 or phishing kits."
        })
        
    # 2. Suspicious TLD
    if features.get("phish_suspicious_tld", 0) == 1 or features.get("phish_adv_suspicious_tld", 0) == 1:
        score = 8
        heuristic_points += score
        indicators.append({
            "indicator": "Suspicious Top-Level Domain",
            "score_impact": score,
            "severity": "HIGH",
            "description": "Host registered under a TLD known for high abuse and malicious activity (e.g. .xyz, .top, .work, .tk)."
        })
        
    # 3. Brand Hijack / Typosquatting
    if features.get("phish_brand_hijack", 0) == 1 or features.get("phish_adv_brand_in_subdomain", 0) == 1:
        score = 8
        heuristic_points += score
        indicators.append({
            "indicator": "Brand Spoofing / Hijacking",
            "score_impact": score,
            "severity": "HIGH",
            "description": "Well-known enterprise or financial brand keyword detected in subdomain or path on an untrusted parent domain."
        })
        
    # 4. Hacked terms or dangerous file extensions
    if features.get("path_has_hacked_terms", 0) == 1 or features.get("suspicious_extension", 0) == 1:
        score = 7
        heuristic_points += score
        indicators.append({
            "indicator": "Malicious Payload / Shell Indicator",
            "score_impact": score,
            "severity": "HIGH",
            "description": "URL points to an executable, script extension (.exe, .sh, .apk) or webshell/administrative backdoor keyword."
        })
        
    # 5. Phishing urgency / credential harvesting keywords
    urgency_cnt = features.get("phish_urgency_words", 0)
    security_cnt = features.get("phish_security_words", 0)
    if urgency_cnt > 0 or security_cnt > 0:
        score = min(5, (urgency_cnt + security_cnt) * 2)
        heuristic_points += score
        indicators.append({
            "indicator": "Social Engineering Keywords",
            "score_impact": score,
            "severity": "MEDIUM",
            "description": f"URL contains {urgency_cnt + security_cnt} credential harvesting, urgency, or account-action keywords."
        })
        
    # 6. High Shannon Entropy (Randomized host/path)
    url_entropy = features.get("url_entropy", 0.0)
    if url_entropy > 4.5:
        score = 4
        heuristic_points += score
        indicators.append({
            "indicator": "High Character Entropy",
            "score_impact": score,
            "severity": "MEDIUM",
            "description": f"Abnormally high entropy ({url_entropy:.2f}) indicates potential algorithmically generated or obfuscated URL tokens."
        })
        
    # 7. Shortener Service
    if features.get("is_shortener", 0) == 1:
        score = 3
        heuristic_points += score
        indicators.append({
            "indicator": "URL Shortener Redirection",
            "score_impact": score,
            "severity": "LOW",
            "description": "Shortening service obscures destination domain and payload path."
        })
        
    # 8. Benign mitigating factors
    if features.get("is_gov_edu", 0) == 1:
        heuristic_points -= 10
        indicators.append({
            "indicator": "Government / Academic Domain",
            "score_impact": -10,
            "severity": "INFO",
            "description": "Legitimate institutional .gov or .edu domain structure."
        })

    # Base ML contribution (0 to 60)
    base_ml_risk = malicious_prob * 60.0
    
    # Cap total heuristic additions to 40
    capped_heuristics = min(40, max(-15, heuristic_points))
    
    total_raw_risk = base_ml_risk + capped_heuristics
    
    # If ML prediction is very benign (< 0.10) and no critical indicators, clamp low
    if malicious_prob < 0.10 and not any(ind["severity"] in ["CRITICAL", "HIGH"] for ind in indicators):
        total_raw_risk = min(18.0, total_raw_risk)
        
    risk_score = int(round(min(100.0, max(0.0, total_raw_risk))))
    
    if risk_score >= 90:
        category = "CRITICAL"
    elif risk_score >= 70:
        category = "HIGH"
    elif risk_score >= 40:
        category = "MEDIUM"
    elif risk_score >= 20:
        category = "LOW"
    else:
        category = "CLEAN"
        
    return risk_score, category, indicators


def calculate_cti_trust(
    prediction_confidence: float,
    source_reputation: int = 90,
    blockchain_status: str = "REGISTERED", # REGISTERED, PENDING, TAMPERED, UNAVAILABLE
    feature_completeness: float = 1.0
) -> Tuple[int, str, List[Dict[str, Any]]]:
    """
    Computes CTI Trust Score (0-100).
    Represents HOW RELIABLE AND VERIFIABLE this threat intelligence record is.
    
    Weights:
      w1 = 0.35 : Model Prediction Confidence (distance from uncertainty 0.5)
      w2 = 0.25 : Source Organization Reliability / Reputation (0-100)
      w3 = 0.25 : Blockchain Integrity & Verification Status (0, 60, or 100)
      w4 = 0.15 : Indicator Completeness & Reproducibility (0-100)
    """
    # 1. Prediction Confidence factor (0 to 100)
    # prediction_confidence is expected in [0.5, 1.0] -> normalize (conf - 0.5) * 2 * 100
    conf_norm = min(100.0, max(0.0, (prediction_confidence - 0.5) * 200.0))
    w1_contrib = 0.35 * conf_norm
    
    # 2. Source Organization Reputation (0 to 100)
    rep_norm = min(100.0, max(0.0, float(source_reputation)))
    w2_contrib = 0.25 * rep_norm
    
    # 3. Blockchain Status (0 to 100)
    if blockchain_status == "REGISTERED" or blockchain_status == "VERIFIED":
        bc_score = 100.0
        bc_desc = "Cryptographic integrity proven via immutable Ethereum smart contract."
    elif blockchain_status == "PENDING":
        bc_score = 60.0
        bc_desc = "Local record generated; blockchain registration pending or on dev network."
    elif blockchain_status == "TAMPERED":
        bc_score = 0.0
        bc_desc = "CRITICAL: Hash mismatch detected against on-chain ledger."
    else: # UNAVAILABLE
        bc_score = 40.0
        bc_desc = "Blockchain node unreachable or network timeout during verification."
    w3_contrib = 0.25 * bc_score
    
    # 4. Feature Completeness (0 to 100)
    feat_score = min(100.0, max(0.0, feature_completeness * 100.0))
    w4_contrib = 0.15 * feat_score
    
    total_trust = int(round(w1_contrib + w2_contrib + w3_contrib + w4_contrib))
    total_trust = min(100, max(0, total_trust))
    
    if total_trust >= 85:
        category = "HIGHLY_TRUSTED"
    elif total_trust >= 70:
        category = "TRUSTED"
    elif total_trust >= 50:
        category = "MODERATE"
    else:
        category = "LOW_TRUST"
        
    breakdown = [
        {
            "component": "Model Prediction Confidence",
            "weight": 0.35,
            "raw_score": round(conf_norm, 1),
            "weighted_score": round(w1_contrib, 1),
            "description": f"XGBoost certainty: {prediction_confidence * 100:.1f}% confidence."
        },
        {
            "component": "Source Organization Reputation",
            "weight": 0.25,
            "raw_score": round(rep_norm, 1),
            "weighted_score": round(w2_contrib, 1),
            "description": f"Submitting organization reputation baseline: {source_reputation}/100."
        },
        {
            "component": "Blockchain Ledger Integrity",
            "weight": 0.25,
            "raw_score": round(bc_score, 1),
            "weighted_score": round(w3_contrib, 1),
            "description": bc_desc
        },
        {
            "component": "Feature Pipeline Reproducibility",
            "weight": 0.15,
            "raw_score": round(feat_score, 1),
            "weighted_score": round(w4_contrib, 1),
            "description": "Purely lexical URL extraction with 0 external network dependencies."
        }
    ]
    
    return total_trust, category, breakdown

