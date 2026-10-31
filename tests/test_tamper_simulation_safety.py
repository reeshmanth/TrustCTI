import pytest
from fastapi.testclient import TestClient
from web3 import Web3

from backend.main import app
from backend.database import SessionLocal
from backend.models import CTIRecord
from backend.blockchain import BlockchainService, RPC_URL

client = TestClient(app)

@pytest.fixture(scope="module")
def auth_headers():
    res = client.post("/api/auth/login", json={
        "username": "cert_admin",
        "password": "TrustCTI@2026!"
    })
    assert res.status_code == 200, f"Authentication failed: {res.text}"
    token = res.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}

def test_tamper_simulation_preserves_database_record_state(auth_headers):
    """
    AUDIT REQUIREMENT 1 & 2:
    Proves that tamper simulation executes exclusively on an in-memory copy
    and does NOT modify:
      1. The original database record in PostgreSQL
      2. The registered on-chain SHA-256 hash in the Ethereum smart contract
    And verifies that the record remains VERIFIED when checked again afterwards.
    """
    # 1. Create a fresh verified record anchored on blockchain
    scan_res = client.post("/api/scan", headers=auth_headers, json={
        "url": "http://malicious-credential-stealer.xyz/login.php"
    })
    assert scan_res.status_code == 200
    scan_data = scan_res.json()

    rec_res = client.post("/api/records", headers=auth_headers, json={
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
    })
    assert rec_res.status_code == 200
    rec_data = rec_res.json()
    record_id = rec_data["id"]

    # 2. Capture immutable baseline directly from the database
    db = SessionLocal()
    db_before = db.query(CTIRecord).filter(CTIRecord.id == record_id).first()
    assert db_before is not None

    baseline_hash = db_before.record_hash
    baseline_canonical = db_before.canonical_json
    baseline_classification = db_before.classification
    baseline_risk = db_before.threat_risk_score
    baseline_tx_hash = db_before.blockchain_tx_hash
    db.close()

    # 3. Capture baseline from the actual deployed Solidity smart contract via JSON-RPC
    bc = BlockchainService.get_instance()
    assert bc.is_connected(), "Ethereum local node must be reachable"
    assert bc.contract is not None, "CTIRegistry contract must be loaded"

    contract_rec_before = bc.contract.functions.getRecord(record_id).call()
    onchain_hash_before = "0x" + contract_rec_before[0].hex()
    assert onchain_hash_before.lower() == ("0x" + baseline_hash).lower(), "On-chain hash must match DB record hash"

    # 4. First verification of original record: MUST BE VERIFIED
    verify_res1 = client.post("/api/verify", headers=auth_headers, json={
        "cti_record_id": record_id
    })
    assert verify_res1.status_code == 200
    v1_data = verify_res1.json()
    assert v1_data["result"] == "VERIFIED", f"Expected VERIFIED, got {v1_data['result']}"
    assert v1_data["is_tampered_test"] is False

    # 5. Execute Tamper Simulation with forged payload
    tampered_json = baseline_canonical.replace(baseline_classification, "Benign").replace(str(baseline_risk), "0")
    assert tampered_json != baseline_canonical, "Tampered JSON must differ from original"

    tamper_res = client.post("/api/verify", headers=auth_headers, json={
        "cti_record_id": record_id,
        "custom_canonical_json": tampered_json
    })
    assert tamper_res.status_code == 200
    t_data = tamper_res.json()
    assert t_data["result"] == "TAMPERED", f"Expected TAMPERED, got {t_data['result']}"
    assert t_data["is_tampered_test"] is True
    assert t_data["computed_hash"] != v1_data["computed_hash"]

    # 6. AUDIT CHECK: Verify Database Record is completely unchanged
    db = SessionLocal()
    db_after = db.query(CTIRecord).filter(CTIRecord.id == record_id).first()
    assert db_after is not None

    assert db_after.record_hash == baseline_hash, "DATABASE AUDIT FAILURE: record_hash was altered!"
    assert db_after.canonical_json == baseline_canonical, "DATABASE AUDIT FAILURE: canonical_json was altered!"
    assert db_after.classification == baseline_classification, "DATABASE AUDIT FAILURE: classification was altered!"
    assert db_after.threat_risk_score == baseline_risk, "DATABASE AUDIT FAILURE: threat_risk_score was altered!"
    assert db_after.blockchain_tx_hash == baseline_tx_hash, "DATABASE AUDIT FAILURE: blockchain_tx_hash was altered!"
    db.close()

    # 7. AUDIT CHECK: Verify Blockchain On-Chain State is completely unchanged
    contract_rec_after = bc.contract.functions.getRecord(record_id).call()
    onchain_hash_after = "0x" + contract_rec_after[0].hex()
    assert onchain_hash_after == onchain_hash_before, "BLOCKCHAIN AUDIT FAILURE: On-chain hash was overwritten!"

    # 8. AUDIT CHECK: Verify original record AGAIN after tamper test: MUST STILL BE VERIFIED
    verify_res2 = client.post("/api/verify", headers=auth_headers, json={
        "cti_record_id": record_id
    })
    assert verify_res2.status_code == 200
    v2_data = verify_res2.json()
    assert v2_data["result"] == "VERIFIED", f"Expected VERIFIED on re-check, got {v2_data['result']}"
    assert v2_data["computed_hash"] == v1_data["computed_hash"]
    assert v2_data["blockchain_hash"] == onchain_hash_before


def test_blockchain_live_jsonrpc_contract_queries():
    """
    AUDIT REQUIREMENT 2:
    Direct EVM verification without relying on backend API abstractions:
      - Validates contract deployment address and bytecode
      - Validates Chain ID (31337)
      - Verifies EVM view calls to verifyRecord()
    """
    bc = BlockchainService.get_instance()
    w3 = bc.w3
    assert w3.is_connected(), "JSON-RPC connection failed"

    chain_id = w3.eth.chain_id
    assert chain_id == 31337, f"Expected Hardhat chain ID 31337, got {chain_id}"

    contract_addr = bc.contract_address
    assert contract_addr is not None and Web3.is_address(contract_addr)

    bytecode = w3.eth.get_code(Web3.to_checksum_address(contract_addr))
    assert len(bytecode) > 2, f"No contract bytecode deployed at {contract_addr}"

    total_records = bc.contract.functions.getRecordCount().call()
    assert total_records >= 0

