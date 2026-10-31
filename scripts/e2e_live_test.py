import httpx
import sys

BASE_URL = "http://127.0.0.1:8000"

def run_e2e_test():
    print("==================================================")
    print("TrustCTI Live End-to-End Workflow Verification")
    print("==================================================")
    
    client = httpx.Client(base_url=BASE_URL, timeout=20.0)

    # 1. Health & Node Status Check
    print("\n[Step 1] Checking System Health & Blockchain Status...")
    h_res = client.get("/api/health")
    assert h_res.status_code == 200, f"Health check failed: {h_res.text}"
    health = h_res.json()
    print(f"  System Status:    {health['status']}")
    print(f"  ML Engine Loaded: {health['ml_engine']['loaded']} ({health['ml_engine']['features_count']} features)")
    print(f"  Blockchain RPC:   {health['blockchain']['rpc_url']} (Block #{health['blockchain']['latest_block']})")
    assert health['blockchain']['connected'] is True, "Blockchain node must be connected"

    # 2. Authenticate as US-CERT
    print("\n[Step 2] Authenticating as US-CERT Analyst (cert_admin)...")
    login_res = client.post("/api/auth/login", json={
        "username": "cert_admin",
        "password": "TrustCTI@2026!"
    })
    assert login_res.status_code == 200, f"Login failed: {login_res.text}"
    cert_token = login_res.json()["access_token"]
    cert_headers = {"Authorization": f"Bearer {cert_token}"}
    print("  Authenticated. Organization: US-CERT Defense Network")

    # 3. URL Submission & Feature Extraction & Inference
    test_url = "http://financial-login-verification-portal.xyz/account/login.php?action=urgent"
    print(f"\n[Step 3] Submitting suspicious target URL:\n  {test_url}")
    scan_res = client.post("/api/scan", headers=cert_headers, json={"url": test_url})
    assert scan_res.status_code == 200, f"Scan failed: {scan_res.text}"
    scan_data = scan_res.json()

    print(f"  Classification:    {scan_data['classification']} ({scan_data['threat_type']})")
    print(f"  Certainty:         {scan_data['confidence']*100:.2f}%")
    print(f"  Threat Risk Score: {scan_data['threat_risk_score']}/100 [{scan_data['threat_risk_category']}]")
    print(f"  CTI Trust Score:   {scan_data['cti_trust_score']}/100 [{scan_data['cti_trust_category']}]")
    print(f"  Triggered Risks:   {[i['indicator'] for i in scan_data['risk_indicators']]}")

    # 4. Save CTI Record & Anchor on Blockchain
    print("\n[Step 4] Creating CTI Record & Registering on Ethereum Blockchain...")
    create_payload = {
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
    rec_res = client.post("/api/records", headers=cert_headers, json=create_payload)
    assert rec_res.status_code == 200, f"Record creation failed: {rec_res.text}"
    rec_data = rec_res.json()
    record_id = rec_data["id"]

    print(f"  CTI Record ID:     {record_id}")
    print(f"  SHA-256 Hash:      {rec_data['record_hash']}")
    print(f"  On-Chain Anchored: {rec_data['blockchain_registered']}")
    print(f"  Transaction Hash:  {rec_data['blockchain_tx_hash']}")
    print(f"  Mined in Block:    #{rec_data['blockchain_block_number']}")
    assert rec_data["blockchain_registered"] is True, "Record must be registered on-chain"

    # 5. Share CTI with FinSOC
    print("\n[Step 5] Transmitting CTI record to FinSOC Global Intelligence...")
    share_res = client.post("/api/share", headers=cert_headers, json={
        "cti_record_id": record_id,
        "target_organization_ids": ["org-fin-soc"],
        "notes": "Urgent alert: active targeted financial credential phishing domain."
    })
    assert share_res.status_code == 200
    print(f"  Dissemination confirmed: {share_res.json()['message']}")

    # 6. FinSOC Analyst Logs In & Receives Intelligence
    print("\n[Step 6] Authenticating as FinSOC Analyst (fin_analyst)...")
    fin_login = client.post("/api/auth/login", json={
        "username": "fin_analyst",
        "password": "TrustCTI@2026!"
    })
    assert fin_login.status_code == 200
    fin_token = fin_login.json()["access_token"]
    fin_headers = {"Authorization": f"Bearer {fin_token}"}
    print("  Authenticated. Organization: FinSOC Global Intelligence")

    recv_res = client.get("/api/shared/received", headers=fin_headers)
    assert recv_res.status_code == 200
    received_list = recv_res.json()
    matched = next((item for item in received_list if item["id"] == record_id), None)
    assert matched is not None, "FinSOC must have received the shared CTI record"
    print(f"  Record found in FinSOC feed! Transmitted from: {matched['share_metadata']['source_organization_name']}")

    # 7. Blockchain Integrity Verification (Valid Case)
    print("\n[Step 7] Executing Cryptographic Integrity Verification against Smart Contract...")
    verify_res = client.post("/api/verify", headers=fin_headers, json={
        "cti_record_id": record_id
    })
    assert verify_res.status_code == 200
    v_data = verify_res.json()
    print(f"  Verification Result: {v_data['result']}")
    print(f"  Local Computed Hash: {v_data['computed_hash']}")
    print(f"  Blockchain Hash:     {v_data['blockchain_hash']}")
    print(f"  Audit Proof:         {v_data['message']}")
    assert v_data["result"] == "VERIFIED", f"Expected VERIFIED, got {v_data['result']}"

    # 8. Blockchain Tamper Simulation Test
    print("\n[Step 8] Simulating Database Tampering (Attacker modifies classification to 'Benign')...")
    tampered_json = rec_data["canonical_json"].replace("Malicious", "Benign")
    tamper_res = client.post("/api/verify", headers=fin_headers, json={
        "cti_record_id": record_id,
        "custom_canonical_json": tampered_json
    })
    assert tamper_res.status_code == 200
    t_data = tamper_res.json()
    print(f"  Tamper Test Result:  {t_data['result']}")
    print(f"  Tampered Hash:       {t_data['computed_hash']}")
    print(f"  Blockchain Hash:     {t_data['blockchain_hash']}")
    print(f"  Alert Message:       {t_data['message']}")
    assert t_data["result"] == "TAMPERED", f"Expected TAMPERED, got {t_data['result']}"

    # 9. Post-Tamper Re-Verification: Proving Original DB Record & Blockchain Unchanged
    print("\n[Step 9] Re-verifying Original Record After Tamper Simulation...")
    recheck_res = client.post("/api/verify", headers=fin_headers, json={
        "cti_record_id": record_id
    })
    assert recheck_res.status_code == 200
    r_data = recheck_res.json()
    print(f"  Re-Check Result:     {r_data['result']}")
    print(f"  Re-Check Hash:       {r_data['computed_hash']}")
    assert r_data["result"] == "VERIFIED", f"Expected VERIFIED on re-verification, got {r_data['result']}"
    assert r_data["computed_hash"] == v_data["computed_hash"], "Hash must match original"
    print("  Proof Confirmed: Tamper simulation operated exclusively in-memory without mutating DB or chain state.")

    print("\n==================================================")
    print("SUCCESS: Complete TrustCTI End-to-End Workflow 100% Operational!")
    print("==================================================")

if __name__ == "__main__":
    run_e2e_test()

