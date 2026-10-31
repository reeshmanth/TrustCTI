import pytest
from ml.predictor import URLPredictor

@pytest.fixture(scope="module")
def predictor():
    return URLPredictor.get_instance()

def test_model_loaded(predictor):
    assert predictor.binary_model is not None, "XGBoost binary model must be loaded"
    assert predictor.multiclass_model is not None, "XGBoost multiclass model must be loaded"
    assert predictor.explainer is not None, "SHAP explainer must be loaded"

def test_prediction_output_structure(predictor):
    url = "http://br-icloud.com.br"
    result = predictor.analyze_url(url)
    
    assert "classification" in result
    assert result["classification"] in ["Benign", "Malicious"]
    assert "confidence" in result
    assert 0.5 <= result["confidence"] <= 1.0
    assert "threat_risk_score" in result
    assert 0 <= result["threat_risk_score"] <= 100
    assert "cti_trust_score" in result
    assert 0 <= result["cti_trust_score"] <= 100
    assert "shap_summary" in result
    assert "top_features" in result["shap_summary"]
    assert len(result["shap_summary"]["top_features"]) > 0

def test_shap_values_real_numbers(predictor):
    url = "http://br-icloud.com.br"
    result = predictor.analyze_url(url)
    shap_feats = result["shap_summary"]["top_features"]
    
    for f in shap_feats:
        assert isinstance(f["shap_value"], float)
        assert f["impact"] in ["Malicious", "Benign"]

