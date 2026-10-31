import os
import json
import joblib
import numpy as np
import pandas as pd
from urllib.parse import urlparse
from typing import Dict, Any, List

from ml.features import extract_features, FEATURE_COLUMNS
from backend.scoring import calculate_threat_risk, calculate_cti_trust

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ARTIFACTS_DIR = os.path.join(BASE_DIR, "artifacts")

INV_CLASS_MAP = {
    0: "Benign",
    1: "Defacement",
    2: "Phishing",
    3: "Malware"
}

class URLPredictor:
    _instance = None

    def __init__(self):
        self.binary_model = None
        self.multiclass_model = None
        self.explainer = None
        self.background_samples = None
        self.global_importance = []
        self._load_models()

    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = URLPredictor()
        return cls._instance

    def _load_models(self):
        binary_path = os.path.join(ARTIFACTS_DIR, "xgb_binary_model.joblib")
        multi_path = os.path.join(ARTIFACTS_DIR, "xgb_multiclass_model.joblib")
        explainer_path = os.path.join(ARTIFACTS_DIR, "shap_explainer.joblib")
        bg_path = os.path.join(ARTIFACTS_DIR, "shap_background.joblib")
        global_imp_path = os.path.join(ARTIFACTS_DIR, "global_feature_importance.json")

        if os.path.exists(binary_path):
            self.binary_model = joblib.load(binary_path)
        if os.path.exists(multi_path):
            self.multiclass_model = joblib.load(multi_path)
        if os.path.exists(explainer_path):
            try:
                self.explainer = joblib.load(explainer_path)
            except Exception:
                if self.binary_model is not None:
                    import shap
                    self.explainer = shap.TreeExplainer(self.binary_model)
        elif self.binary_model is not None:
            import shap
            self.explainer = shap.TreeExplainer(self.binary_model)

        if os.path.exists(bg_path):
            try:
                self.background_samples = joblib.load(bg_path)
            except Exception:
                self.background_samples = None
        if os.path.exists(global_imp_path):
            with open(global_imp_path, "r") as f:
                self.global_importance = json.load(f)

    def analyze_url(self, raw_url: str, organization_reputation: int = 90) -> Dict[str, Any]:
        """
        Full CTI analysis for a URL:
          Feature Extraction -> XGBoost Prediction -> Confidence ->
          Threat Risk -> SHAP Explanation -> CTI Trust Score
        """
        # 1. Feature extraction
        features = extract_features(raw_url)
        df_feat = pd.DataFrame([features])[FEATURE_COLUMNS].astype(np.float32)

        # 2. Binary Prediction
        if self.binary_model is None:
            raise RuntimeError("XGBoost binary model not loaded.")
        
        binary_probs = self.binary_model.predict_proba(df_feat)[0]
        prob_benign = float(binary_probs[0])
        prob_malicious = float(binary_probs[1])
        
        is_malicious = prob_malicious >= 0.5
        classification = "Malicious" if is_malicious else "Benign"
        confidence = float(prob_malicious if is_malicious else prob_benign)

        # 3. Multi-Class Attribution
        if self.multiclass_model is not None:
            multi_probs = self.multiclass_model.predict_proba(df_feat)[0]
            if not is_malicious:
                threat_type = "Benign"
            else:
                # Find argmax among malicious classes 1 (defacement), 2 (phishing), 3 (malware)
                mal_indices = [1, 2, 3]
                best_idx = mal_indices[int(np.argmax([multi_probs[i] for i in mal_indices]))]
                threat_type = INV_CLASS_MAP.get(best_idx, "Malicious")
            threat_distribution = {
                INV_CLASS_MAP[i]: round(float(multi_probs[i]), 4)
                for i in range(len(multi_probs))
            }
        else:
            threat_type = "Malicious" if is_malicious else "Benign"
            threat_distribution = {classification: confidence}

        # 4. Threat Risk Score
        threat_risk_score, threat_risk_category, risk_indicators = calculate_threat_risk(
            features, prob_malicious
        )

        # 5. SHAP Explanation
        shap_details = self._explain_prediction(df_feat, features)

        # 6. CTI Trust Score
        cti_trust_score, cti_trust_category, trust_indicators = calculate_cti_trust(
            prediction_confidence=confidence,
            source_reputation=organization_reputation,
            blockchain_status="PENDING",
            feature_completeness=1.0
        )

        normalized_url = raw_url.strip()
        if not (normalized_url.startswith("http://") or normalized_url.startswith("https://")):
            normalized_url = "http://" + normalized_url
        parsed_norm = urlparse(normalized_url)
        if parsed_norm.netloc and not parsed_norm.path:
            normalized_url += "/"

        return {
            "url": raw_url.strip(),
            "url_normalized": normalized_url,
            "classification": classification,
            "threat_type": threat_type,
            "confidence": round(confidence, 4),
            "probabilities": {
                "benign": round(prob_benign, 4),
                "malicious": round(prob_malicious, 4)
            },
            "threat_distribution": threat_distribution,
            "threat_risk_score": threat_risk_score,
            "threat_risk_category": threat_risk_category,
            "cti_trust_score": cti_trust_score,
            "cti_trust_category": cti_trust_category,
            "risk_indicators": risk_indicators,
            "trust_indicators": trust_indicators,
            "shap_summary": shap_details,
            "features_snapshot": features
        }

    def _explain_prediction(self, df_feat: pd.DataFrame, features: Dict[str, Any]) -> Dict[str, Any]:
        """
        Computes local SHAP explanation for the single prediction.
        Identifies exact features contributing toward malicious (+) or benign (-).
        """
        try:
            if self.explainer is not None:
                shap_vals = self.explainer.shap_values(df_feat)[0]
                base_value = float(getattr(self.explainer, "expected_value", 0.0))
            else:
                # Fallback if explainer object not available
                shap_vals = [0.0] * len(FEATURE_COLUMNS)
                base_value = 0.0

            contributions = []
            for feat_name, s_val in zip(FEATURE_COLUMNS, shap_vals):
                val = features.get(feat_name, 0)
                contributions.append({
                    "feature": feat_name,
                    "value": val,
                    "shap_value": round(float(s_val), 4),
                    "impact": "Malicious" if s_val > 0 else "Benign"
                })

            # Sort by absolute SHAP value
            contributions.sort(key=lambda x: abs(x["shap_value"]), reverse=True)
            top_positive = [c for c in contributions if c["shap_value"] > 0][:5]
            top_negative = [c for c in contributions if c["shap_value"] < 0][:5]

            return {
                "base_value": round(base_value, 4),
                "top_features": contributions[:10],
                "top_positive": top_positive,
                "top_negative": top_negative,
                "all_contributions": contributions
            }
        except Exception as e:
            return {
                "error": str(e),
                "top_features": [],
                "top_positive": [],
                "top_negative": []
            }

