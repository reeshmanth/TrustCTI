import os
import uuid
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend.models import Base, Organization, User, CTIRecord, CTIShare, VerificationHistory, BlockchainTransaction
from backend.auth import get_password_hash, verify_password, create_access_token
from backend.canonical import compute_record_integrity, serialize_canonical_json, calculate_sha256_hash
from ml.features import extract_features, FEATURE_COLUMNS
from ml.predictor import URLPredictor
from backend.scoring import calculate_threat_risk, calculate_cti_trust
from backend.blockchain import BlockchainService

BASE_PG_URL = os.getenv("DATABASE_URL", "postgresql+psycopg://postgres:password@127.0.0.1:5432/trustcti")
if "trustcti" in BASE_PG_URL and not BASE_PG_URL.endswith("trustcti_test"):
    CLEAN_DB_URL = BASE_PG_URL.rsplit("/", 1)[0] + "/trustcti_test"
else:
    CLEAN_DB_URL = BASE_PG_URL

@pytest.fixture(scope="module")
def clean_db_session():
    # 1. Initialize fresh isolated PostgreSQL test database
    engine = create_engine(CLEAN_DB_URL, pool_pre_ping=True)
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    session = Session()

    # 2. Seed minimal test entities
    org_src = Organization(
        id="org-clean-cert",
        name="Clean Test CERT",
        code="CLEAN-CERT",
        description="Isolated CERT for clean environment audit.",
        reputation_score=95
    )
    org_dst = Organization(
        id="org-clean-isac",
        name="Clean Test ISAC",
        code="CLEAN-ISAC",
        description="Isolated ISAC for clean environment audit.",
        reputation_score=90
    )
    session.add_all([org_src, org_dst])
    session.commit()

    user_src = User(
        id="user-clean-admin",
        organization_id=org_src.id,
        username="clean_admin",
        email="clean_admin@test.gov",
        hashed_password=get_password_hash("CleanPass@2026!"),
        role="admin"
    )
    user_dst = User(
        id="user-clean-analyst",
        organization_id=org_dst.id,
        username="clean_analyst",
        email="clean_analyst@test.org",
        hashed_password=get_password_hash("CleanPass@2026!"),
        role="analyst"
    )
    session.add_all([user_src, user_dst])
    session.commit()

    yield {
        "session": session,
        "engine": engine,
        "org_src": org_src,
        "org_dst": org_dst,
        "user_src": user_src,
        "user_dst": user_dst
    }

    # Teardown
    session.close()
    Base.metadata.drop_all(bind=engine)
    engine.dispose()


def test_clean_environment_schema_and_auth(clean_db_session):
    """Verifies fresh database table creation and direct Bcrypt authentication in isolation."""
    session = clean_db_session["session"]
    user = session.query(User).filter(User.username == "clean_admin").first()
    assert user is not None
    assert verify_password("CleanPass@2026!", user.hashed_password)
    assert not verify_password("WrongPassword!", user.hashed_password)

    token = create_access_token({"sub": user.id, "org_id": user.organization_id})
    assert len(token) > 20


def test_clean_environment_ml_and_shap_inference():
    """Verifies that ML model and SHAP explainer load and execute in clean environment without network."""
    predictor = URLPredictor.get_instance()
    assert predictor.binary_model is not None
    assert predictor.multiclass_model is not None
    assert predictor.explainer is not None

    url = "http://phish-secure-banking-verification.com/login.php"
    features = extract_features(url)
    assert len(features) == len(FEATURE_COLUMNS)

    analysis = predictor.analyze_url(url, organization_reputation=95)
    assert analysis["classification"] == "Malicious"
    assert analysis["threat_type"] == "Phishing"
    assert analysis["confidence"] >= 0.5
    assert "shap_summary" in analysis
    assert len(analysis["shap_summary"]["top_features"]) > 0


def test_clean_environment_e2e_workflow(clean_db_session):
    """
    Executes the entire end-to-end lifecycle in a fresh isolated database:
    URL -> Features -> ML -> SHAP -> Scores -> Canonical Hash -> DB Record
    -> Blockchain -> Sharing -> Integrity Verification -> Tamper Simulation -> Re-Verification
    """
    session = clean_db_session["session"]
    user_src = clean_db_session["user_src"]
    org_src = clean_db_session["org_src"]
    org_dst = clean_db_session["org_dst"]

    # 1. URL Analysis
    predictor = URLPredictor.get_instance()
    url = "http://192.168.1.200/wp-content/plugins/revslider/temp/update_extract/revslider/shell.php"
    analysis = predictor.analyze_url(url, organization_reputation=org_src.reputation_score)

    rec_id = f"cti-{uuid.uuid4()}"
    record_dict = {
        "id": rec_id,
        "url_normalized": analysis["url_normalized"],
        "organization_id": org_src.id,
        "classification": analysis["classification"],
        "threat_type": analysis["threat_type"],
        "confidence": analysis["confidence"],
        "threat_risk_score": analysis["threat_risk_score"],
        "threat_risk_category": analysis["threat_risk_category"],
        "cti_trust_score": analysis["cti_trust_score"],
        "version": "1.0",
        "created_at": "2026-10-31T00:00:00Z"
    }

    # 2. Canonical serialization and hashing
    canonical_json, rec_hash = compute_record_integrity(record_dict)
    assert len(rec_hash) == 64

    # 3. Store record in clean isolated database
    record = CTIRecord(
        id=rec_id,
        url=url,
        url_normalized=analysis["url_normalized"],
        organization_id=org_src.id,
        created_by_user_id=user_src.id,
        classification=analysis["classification"],
        threat_type=analysis["threat_type"],
        confidence=analysis["confidence"],
        threat_risk_score=analysis["threat_risk_score"],
        threat_risk_category=analysis["threat_risk_category"],
        cti_trust_score=analysis["cti_trust_score"],
        cti_trust_category=analysis["cti_trust_category"],
        features_snapshot=analysis["features_snapshot"],
        shap_summary=analysis["shap_summary"],
        risk_indicators=analysis["risk_indicators"],
        trust_indicators=analysis["trust_indicators"],
        canonical_json=canonical_json,
        record_hash=rec_hash,
        blockchain_registered=False
    )
    session.add(record)
    session.commit()

    # 4. Register on blockchain
    bc = BlockchainService.get_instance()
    assert bc.is_connected(), "Blockchain node must be running"
    reg = bc.register_record(
        record_id=rec_id,
        record_hash_hex=rec_hash,
        organization_id=org_src.code,
        threat_type=analysis["threat_type"],
        risk_score=analysis["threat_risk_score"]
    )
    assert reg["success"] is True
    record.blockchain_registered = True
    record.blockchain_tx_hash = reg["tx_hash"]
    record.blockchain_block_number = reg["block_number"]
    session.commit()

    # 5. Share with receiving organization (CLEAN-ISAC)
    share = CTIShare(
        id=f"share-{uuid.uuid4()}",
        cti_record_id=rec_id,
        source_organization_id=org_src.id,
        target_organization_id=org_dst.id,
        shared_by_user_id=user_src.id,
        status="ACTIVE"
    )
    session.add(share)
    session.commit()

    # Verify receiver can see the share
    recv_shares = session.query(CTIShare).filter(
        CTIShare.target_organization_id == org_dst.id,
        CTIShare.status == "ACTIVE"
    ).all()
    assert any(s.cti_record_id == rec_id for s in recv_shares)

    # 6. Verify Blockchain Integrity: MUST BE VERIFIED
    verify_result = bc.verify_record(rec_id, rec_hash)
    assert verify_result["verified"] is True
    assert verify_result["result"] == "VERIFIED"

    # 7. Tamper Simulation on in-memory copy
    tampered_json = canonical_json.replace(analysis["classification"], "Benign")
    tampered_hash = calculate_sha256_hash(tampered_json)
    tamper_result = bc.verify_record(rec_id, tampered_hash)
    assert tamper_result["verified"] is False
    assert tamper_result["result"] == "TAMPERED"

    # 8. Assert DB Record is completely unaltered
    session.refresh(record)
    assert record.classification == analysis["classification"]
    assert record.record_hash == rec_hash
    assert record.canonical_json == canonical_json

    # 9. Assert original record is still VERIFIED
    recheck_result = bc.verify_record(rec_id, rec_hash)
    assert recheck_result["verified"] is True
    assert recheck_result["result"] == "VERIFIED"

