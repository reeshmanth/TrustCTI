import uuid
import datetime
from sqlalchemy.orm import Session
from backend.database import engine, Base, SessionLocal
from backend.models import Organization, User, CTIRecord, CTIShare, VerificationHistory, BlockchainTransaction
from backend.auth import get_password_hash
from backend.canonical import compute_record_integrity
from ml.predictor import URLPredictor

def seed_database():
    print("Initializing database schema...")
    Base.metadata.create_all(bind=engine)
    
    db: Session = SessionLocal()
    try:
        # Check if already seeded
        if db.query(Organization).first() and db.query(CTIRecord).first():
            print("Database already contains organizations and records. Skipping seeding.")
            return

        org1 = db.query(Organization).filter_by(id="org-us-cert").first()
        org2 = db.query(Organization).filter_by(id="org-fin-soc").first()
        org3 = db.query(Organization).filter_by(id="org-ci-isac").first()

        if not org1:
            print("Seeding organizations...")
            org1 = Organization(
                id="org-us-cert",
                name="US-CERT Defense Network",
                code="US-CERT",
                description="National cyber incident response and threat sharing team.",
                eth_address="0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266", # Hardhat default account 0
                reputation_score=98
            )
            org2 = Organization(
                id="org-fin-soc",
                name="Global Financial Threat Alliance (FinSOC)",
                code="FIN-SOC",
                description="International banking and financial institution threat sharing consortium.",
                eth_address="0x70997970C51812dc3A010C7d01b50e0d17dc79C8", # Hardhat default account 1
                reputation_score=95
            )
            org3 = Organization(
                id="org-ci-isac",
                name="Critical Infrastructure ISAC",
                code="CI-ISAC",
                description="Energy, healthcare, and water sector threat defense.",
                eth_address="0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC", # Hardhat default account 2
                reputation_score=92
            )
            db.add_all([org1, org2, org3])
            db.commit()

        user1 = db.query(User).filter_by(id="user-cert-admin").first()
        user2 = db.query(User).filter_by(id="user-finsoc-analyst").first()
        user3 = db.query(User).filter_by(id="user-isac-viewer").first()

        if not user1:
            print("Seeding users...")
            pwd_hash = get_password_hash("TrustCTI@2026!")
            user1 = User(
                id="user-cert-admin",
                organization_id=org1.id,
                username="cert_admin",
                email="admin@us-cert.gov",
                hashed_password=pwd_hash,
                full_name="Sarah Vance (Chief Threat Analyst)",
                role="admin"
            )
            user2 = User(
                id="user-finsoc-analyst",
                organization_id=org2.id,
                username="fin_analyst",
                email="analyst@finsoc.org",
                hashed_password=pwd_hash,
                full_name="David Chen (Senior SecOps Analyst)",
                role="analyst"
            )
            user3 = User(
                id="user-isac-viewer",
                organization_id=org3.id,
                username="isac_member",
                email="intel@ci-isac.net",
                hashed_password=pwd_hash,
                full_name="Elena Rostova (SOC Lead)",
                role="analyst"
            )
            db.add_all([user1, user2, user3])
            db.commit()

        print("Seeding initial authentic CTI records from dataset...")
        predictor = URLPredictor.get_instance()
        
        sample_urls = [
            ("http://br-icloud.com.br", user1, org1, "Initial high-severity phishing kit impersonating Apple iCloud credentials."),
            ("http://mp3raid.com/music/krizz_kaliko.html", user1, org1, "Clean legacy web music indexing portal, benign classification."),
            ("http://signin.eby.de.zukruygxctzmmqi.civpro.co.za", user2, org2, "Targeted phishing kit targeting German banking and eBay users.")
        ]

        created_records = []
        for url_str, user, org, notes in sample_urls:
            analysis = predictor.analyze_url(url_str, organization_reputation=org.reputation_score)
            rec_id = str(uuid.uuid4())
            
            record_dict_for_hash = {
                "id": rec_id,
                "url_normalized": analysis["url_normalized"],
                "organization_id": org.id,
                "classification": analysis["classification"],
                "threat_type": analysis["threat_type"],
                "confidence": analysis["confidence"],
                "threat_risk_score": analysis["threat_risk_score"],
                "threat_risk_category": analysis["threat_risk_category"],
                "cti_trust_score": analysis["cti_trust_score"],
                "version": "1.0",
                "created_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            }
            canonical_str, rec_hash = compute_record_integrity(record_dict_for_hash)

            record = CTIRecord(
                id=rec_id,
                url=url_str,
                url_normalized=analysis["url_normalized"],
                organization_id=org.id,
                created_by_user_id=user.id,
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
                canonical_json=canonical_str,
                record_hash=rec_hash,
                blockchain_registered=False
            )
            db.add(record)
            created_records.append((record, user, org, notes))
            
        db.commit()

        # Seed initial share between org1 and org2
        if len(created_records) >= 2:
            share = CTIShare(
                id=str(uuid.uuid4()),
                cti_record_id=created_records[0][0].id,
                source_organization_id=org1.id,
                target_organization_id=org2.id,
                shared_by_user_id=user1.id,
                notes="Cross-sector alert: Active credential harvester domain targeting enterprise users."
            )
            db.add(share)
            db.commit()

        print("Database successfully seeded with organizations, users, and baseline records.")
    finally:
        db.close()

if __name__ == "__main__":
    seed_database()

