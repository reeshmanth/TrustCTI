import pytest
import uuid
from fastapi.testclient import TestClient
from backend.main import app

client = TestClient(app)

@pytest.fixture(scope="module")
def auth_headers():
    # Login as seeded user
    res = client.post("/api/auth/login", json={
        "username": "cert_admin",
        "password": "TrustCTI@2026!"
    })
    assert res.status_code == 200, f"Login failed: {res.text}"
    token = res.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}

def test_health_check():
    res = client.get("/api/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "healthy"
    assert data["ml_engine"]["loaded"] is True

def test_url_scan_api(auth_headers):
    res = client.post("/api/scan", headers=auth_headers, json={
        "url": "http://br-icloud.com.br"
    })
    assert res.status_code == 200
    data = res.json()
    assert data["classification"] == "Malicious"
    assert data["threat_type"] == "Phishing"
    assert "shap_summary" in data
    assert "threat_risk_score" in data
    assert "cti_trust_score" in data

def test_cti_record_creation_and_blockchain_registration(auth_headers):
    # 1. Scan URL
    scan_res = client.post("/api/scan", headers=auth_headers, json={
        "url": "http://192.168.1.50/admin/webshell.php?cmd=id"
    })
    assert scan_res.status_code == 200
    scan_data = scan_res.json()

    # 2. Save as official CTI Record with blockchain registration
    payload = {
        "url": scan_data["url"],
        "classification": scan_data["classification"],
        "threat_type": scan_data["threat_type"],
        "confidence": scan_data["confidence"],
        "threat_risk_score": scan_data["threat_risk_score"],
        "threat_risk_category": scan_data["threat_risk_category"],
        "cti_trust_score": scan_data["cti_trust_score"],
        "cti_trust_category": scan_data["cti_trust_category"],
        "features_snapshot": scan_data["features_snapshot"],
        "shap_summary": scan_data["shap_summary"],
        "risk_indicators": scan_data["risk_indicators"],
        "trust_indicators": scan_data["trust_indicators"],
        "register_on_blockchain": True
    }
    rec_res = client.post("/api/records", headers=auth_headers, json=payload)
    assert rec_res.status_code == 200
    rec_data = rec_res.json()
    record_id = rec_data["id"]

    assert rec_data["record_hash"] is not None
    assert len(rec_data["record_hash"]) == 64

    # 3. Verify Blockchain Integrity
    verify_res = client.post("/api/verify", headers=auth_headers, json={
        "cti_record_id": record_id
    })
    assert verify_res.status_code == 200
    v_data = verify_res.json()
    assert v_data["result"] in ["VERIFIED", "UNAVAILABLE"]

    # 4. Test Tamper Detection
    tampered_json = rec_data["canonical_json"].replace("Malicious", "Benign")
    tamper_res = client.post("/api/verify", headers=auth_headers, json={
        "cti_record_id": record_id,
        "custom_canonical_json": tampered_json
    })
    assert tamper_res.status_code == 200
    t_data = tamper_res.json()
    if v_data["result"] == "VERIFIED":
        assert t_data["result"] == "TAMPERED", "Tampered canonical JSON must result in TAMPERED"

def test_cti_sharing_workflow(auth_headers):
    # 1. Fetch available records
    recs_res = client.get("/api/records", headers=auth_headers)
    assert recs_res.status_code == 200
    records = recs_res.json()
    assert len(records) > 0
    rec_id = records[0]["id"]

    # 2. Share with FinSOC (org-fin-soc)
    share_res = client.post("/api/share", headers=auth_headers, json={
        "cti_record_id": rec_id,
        "target_organization_ids": ["org-fin-soc"],
        "notes": "Urgent alert: active targeted malicious campaign."
    })
    assert share_res.status_code == 200
    assert share_res.json()["success"] is True

    # 3. Login as FinSOC analyst and check received feed
    login_fin = client.post("/api/auth/login", json={
        "username": "fin_analyst",
        "password": "TrustCTI@2026!"
    })
    assert login_fin.status_code == 200
    fin_headers = {"Authorization": f"Bearer {login_fin.json()['access_token']}"}

    recv_res = client.get("/api/shared/received", headers=fin_headers)
    assert recv_res.status_code == 200
    recv_list = recv_res.json()
    assert any(item["id"] == rec_id for item in recv_list)

