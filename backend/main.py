import os
import uuid
import json
import datetime
from typing import List, Optional, Dict, Any

from fastapi import FastAPI, Depends, HTTPException, Query, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from sqlalchemy.orm import Session
from sqlalchemy import desc, or_

from backend.database import get_db, engine, Base
from backend.models import Organization, User, CTIRecord, CTIShare, VerificationHistory, BlockchainTransaction
from backend.schemas import (
    UserRegisterRequest, UserLoginRequest, TokenResponse,
    URLScanRequest, URLScanResponse, CTIRecordCreateRequest,
    CTIRecordResponse, CTIShareRequest, VerifyRequest, VerifyResponse
)
from backend.auth import (
    verify_password, get_password_hash, create_access_token,
    get_current_user
)
from backend.canonical import compute_record_integrity, serialize_canonical_json, calculate_sha256_hash
from backend.scoring import calculate_threat_risk, calculate_cti_trust
from backend.blockchain import BlockchainService
from ml.predictor import URLPredictor

app = FastAPI(
    title="TrustCTI API",
    description="Explainable AI and Blockchain-Based Trustworthy Cyber Threat Intelligence Sharing Platform",
    version="1.0.0"
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize tables
Base.metadata.create_all(bind=engine)

def format_canonical_timestamp(dt: Any) -> str:
    """Standardizes datetime to ISO UTC format without microsecond drift."""
    if isinstance(dt, datetime.datetime):
        if dt.tzinfo is not None:
            dt = dt.astimezone(datetime.timezone.utc).replace(tzinfo=None)
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    s = str(dt).strip().replace(" ", "T")
    if "." in s:
        s = s.split(".")[0]
    if not s.endswith("Z"):
        s += "Z"
    return s

def get_current_utc() -> datetime.datetime:
    """Returns current UTC datetime without timezone object for PostgreSQL compatibility."""
    return datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)

# ==========================================
# 1. SYSTEM & HEALTH ENDPOINTS
# ==========================================
@app.get("/api/health")
def health_check(db: Session = Depends(get_db)):
    bc = BlockchainService.get_instance()
    bc_status = bc.get_status()
    predictor = URLPredictor.get_instance()
    
    dialect_name = engine.dialect.name
    return {
        "status": "healthy",
        "service": "TrustCTI Core Engine",
        "timestamp": format_canonical_timestamp(datetime.datetime.now(datetime.timezone.utc)),
        "database": "connected",
        "database_info": {
            "status": "connected",
            "dialect": dialect_name,
            "display_name": "PostgreSQL (Production)",
            "storage_mode": "Dedicated PostgreSQL database server",
            "active_tables": ["organizations", "users", "cti_records", "verification_history", "cti_shares", "blockchain_transactions"]
        },
        "ml_engine": {
            "loaded": predictor.binary_model is not None,
            "features_count": len(predictor.global_importance) or 65
        },
        "blockchain": bc_status
    }

# ==========================================
# 2. AUTHENTICATION & USERS
# ==========================================
@app.post("/api/auth/register", response_model=TokenResponse)
def register(req: UserRegisterRequest, db: Session = Depends(get_db)):
    if db.query(User).filter(or_(User.username == req.username, User.email == req.email)).first():
        raise HTTPException(status_code=400, detail="Username or email already registered")

    org = db.query(Organization).filter(Organization.code == req.organization_code.upper()).first()
    if not org:
        org = Organization(
            id=f"org-{uuid.uuid4().hex[:8]}",
            name=req.organization_name,
            code=req.organization_code.upper(),
            description=f"Registered organization: {req.organization_name}",
            reputation_score=85
        )
        db.add(org)
        db.commit()
        db.refresh(org)

    new_user = User(
        id=f"user-{uuid.uuid4().hex[:8]}",
        organization_id=org.id,
        username=req.username,
        email=req.email,
        full_name=req.full_name or req.username,
        hashed_password=get_password_hash(req.password),
        role="analyst"
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    token = create_access_token({"sub": new_user.id, "org_id": org.id})
    return {
        "access_token": token,
        "token_type": "bearer",
        "user": {
            "id": new_user.id,
            "username": new_user.username,
            "email": new_user.email,
            "full_name": new_user.full_name,
            "role": new_user.role,
            "organization": {
                "id": org.id,
                "name": org.name,
                "code": org.code,
                "reputation_score": org.reputation_score
            }
        }
    }

@app.post("/api/auth/login", response_model=TokenResponse)
def login(req: UserLoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == req.username).first()
    if not user or not verify_password(req.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid username or password")

    org = user.organization
    token = create_access_token({"sub": user.id, "org_id": org.id if org else None})
    return {
        "access_token": token,
        "token_type": "bearer",
        "user": {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "full_name": user.full_name,
            "role": user.role,
            "organization": {
                "id": org.id,
                "name": org.name,
                "code": org.code,
                "reputation_score": org.reputation_score
            } if org else None
        }
    }

@app.get("/api/auth/me")
def get_me(user: User = Depends(get_current_user)):
    org = user.organization
    return {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "full_name": user.full_name,
        "role": user.role,
        "organization": {
            "id": org.id,
            "name": org.name,
            "code": org.code,
            "description": org.description,
            "reputation_score": org.reputation_score,
            "eth_address": org.eth_address
        } if org else None
    }

# ==========================================
# 3. REAL-TIME URL SCANNER & INFERENCE
# ==========================================
@app.post("/api/scan", response_model=URLScanResponse)
def scan_url(req: URLScanRequest, user: User = Depends(get_current_user)):
    if not req.url or len(req.url.strip()) < 3:
        raise HTTPException(status_code=400, detail="Invalid URL submitted.")
    
    predictor = URLPredictor.get_instance()
    rep = user.organization.reputation_score if user.organization else 90
    analysis = predictor.analyze_url(req.url, organization_reputation=rep)
    return analysis

# ==========================================
# 4. CTI RECORD GENERATION & STORAGE
# ==========================================
@app.post("/api/records", response_model=CTIRecordResponse)
def create_cti_record(
    req: CTIRecordCreateRequest,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    rec_id = str(uuid.uuid4())
    now_dt = get_current_utc()
    created_at_canonical = format_canonical_timestamp(now_dt)
    
    url_norm = req.url.strip()
    if not (url_norm.startswith("http://") or url_norm.startswith("https://")):
        url_norm = "http://" + url_norm

    # 1. Deterministic canonical representation
    record_dict_for_hash = {
        "id": rec_id,
        "url_normalized": url_norm,
        "organization_id": user.organization_id,
        "classification": req.classification,
        "threat_type": req.threat_type,
        "confidence": req.confidence,
        "threat_risk_score": req.threat_risk_score,
        "threat_risk_category": req.threat_risk_category,
        "cti_trust_score": req.cti_trust_score,
        "version": "1.0",
        "created_at": created_at_canonical
    }
    canonical_str, rec_hash = compute_record_integrity(record_dict_for_hash)

    # 2. Blockchain registration (if requested)
    blockchain_registered = False
    tx_hash = None
    block_num = None
    registered_at_dt = None

    if req.register_on_blockchain:
        bc = BlockchainService.get_instance()
        reg_result = bc.register_record(
            record_id=rec_id,
            record_hash_hex=rec_hash,
            organization_id=user.organization.code if user.organization else "ORG",
            threat_type=req.threat_type,
            risk_score=req.threat_risk_score
        )
        if reg_result.get("success"):
            blockchain_registered = True
            tx_hash = reg_result.get("tx_hash")
            block_num = reg_result.get("block_number")
            registered_at_dt = get_current_utc()

    # 3. Store in PostgreSQL (Add parent record first to satisfy foreign key constraints)
    new_record = CTIRecord(
        id=rec_id,
        url=req.url.strip(),
        url_normalized=url_norm,
        organization_id=user.organization_id,
        created_by_user_id=user.id,
        classification=req.classification,
        threat_type=req.threat_type,
        confidence=req.confidence,
        threat_risk_score=req.threat_risk_score,
        threat_risk_category=req.threat_risk_category,
        cti_trust_score=req.cti_trust_score,
        cti_trust_category=req.cti_trust_category,
        features_snapshot=req.features_snapshot,
        shap_summary=req.shap_summary,
        risk_indicators=req.risk_indicators,
        trust_indicators=req.trust_indicators,
        canonical_json=canonical_str,
        record_hash=rec_hash,
        blockchain_registered=blockchain_registered,
        blockchain_tx_hash=tx_hash,
        blockchain_block_number=block_num,
        blockchain_registered_at=registered_at_dt,
        created_at=now_dt
    )
    db.add(new_record)
    db.flush()

    # 4. Record on-chain transaction log referencing parent record
    if blockchain_registered and tx_hash:
        tx_log = BlockchainTransaction(
            id=str(uuid.uuid4()),
            cti_record_id=rec_id,
            tx_hash=tx_hash,
            block_number=block_num,
            block_hash=reg_result.get("block_hash"),
            gas_used=reg_result.get("gas_used"),
            sender_address=reg_result.get("sender"),
            contract_address=reg_result.get("contract_address")
        )
        db.add(tx_log)

    db.commit()
    db.refresh(new_record)

    return _format_cti_record(new_record)

@app.get("/api/records")
def list_cti_records(
    q: Optional[str] = None,
    classification: Optional[str] = None,
    sort_by: str = "created_at",
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    query = db.query(CTIRecord).filter(CTIRecord.organization_id == user.organization_id)
    if q:
        query = query.filter(or_(CTIRecord.url.ilike(f"%{q}%"), CTIRecord.id.ilike(f"%{q}%")))
    if classification and classification != "ALL":
        query = query.filter(CTIRecord.classification == classification)

    if sort_by == "risk":
        query = query.order_by(desc(CTIRecord.threat_risk_score))
    elif sort_by == "trust":
        query = query.order_by(desc(CTIRecord.cti_trust_score))
    else:
        query = query.order_by(desc(CTIRecord.created_at))

    records = query.all()
    return [_format_cti_record(r) for r in records]

@app.get("/api/records/{record_id}", response_model=CTIRecordResponse)
def get_cti_record(record_id: str, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    rec = db.query(CTIRecord).filter(CTIRecord.id == record_id).first()
    if not rec:
        raise HTTPException(status_code=404, detail="CTI Record not found")
    
    is_owner = rec.organization_id == user.organization_id
    is_shared = db.query(CTIShare).filter(
        CTIShare.cti_record_id == record_id,
        CTIShare.target_organization_id == user.organization_id,
        CTIShare.status == "ACTIVE"
    ).first() is not None

    if not (is_owner or is_shared):
        raise HTTPException(status_code=403, detail="Unauthorized access to this CTI Record.")

    return _format_cti_record(rec)

# ==========================================
# 5. BLOCKCHAIN REGISTRATION & INTEGRITY VERIFICATION
# ==========================================
@app.post("/api/records/{record_id}/register-blockchain")
def register_on_blockchain(
    record_id: str,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    rec = db.query(CTIRecord).filter(CTIRecord.id == record_id).first()
    if not rec:
        raise HTTPException(status_code=404, detail="CTI Record not found")
    if rec.organization_id != user.organization_id:
        raise HTTPException(status_code=403, detail="Only the creating organization can register on blockchain.")

    if rec.blockchain_registered:
        return {
            "success": True,
            "status": "ALREADY_REGISTERED",
            "message": "Record is already registered on blockchain.",
            "tx_hash": rec.blockchain_tx_hash
        }

    bc = BlockchainService.get_instance()
    reg_result = bc.register_record(
        record_id=rec.id,
        record_hash_hex=rec.record_hash,
        organization_id=user.organization.code if user.organization else "ORG",
        threat_type=rec.threat_type,
        risk_score=rec.threat_risk_score
    )

    if reg_result.get("success"):
        rec.blockchain_registered = True
        rec.blockchain_tx_hash = reg_result.get("tx_hash")
        rec.blockchain_block_number = reg_result.get("block_number")
        rec.blockchain_registered_at = get_current_utc()
        
        tx_log = BlockchainTransaction(
            id=str(uuid.uuid4()),
            cti_record_id=rec.id,
            tx_hash=rec.blockchain_tx_hash,
            block_number=rec.blockchain_block_number,
            block_hash=reg_result.get("block_hash"),
            gas_used=reg_result.get("gas_used"),
            sender_address=reg_result.get("sender"),
            contract_address=reg_result.get("contract_address")
        )
        db.add(tx_log)
        db.commit()
        return reg_result
    else:
        return reg_result

@app.post("/api/verify", response_model=VerifyResponse)
def verify_integrity(
    req: VerifyRequest,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    rec = db.query(CTIRecord).filter(CTIRecord.id == req.cti_record_id).first()
    if not rec:
        raise HTTPException(status_code=404, detail="CTI Record not found")

    is_tampered_test = False
    if req.custom_canonical_json:
        is_tampered_test = True
        computed_hash = calculate_sha256_hash(req.custom_canonical_json)
    else:
        # Recreate deterministic canonical JSON using stored attributes
        # Use existing canonical_json if stored, or reconstruct
        if rec.canonical_json:
            computed_hash = calculate_sha256_hash(rec.canonical_json)
        else:
            record_dict = {
                "id": rec.id,
                "url_normalized": rec.url_normalized,
                "organization_id": rec.organization_id,
                "classification": rec.classification,
                "threat_type": rec.threat_type,
                "confidence": rec.confidence,
                "threat_risk_score": rec.threat_risk_score,
                "threat_risk_category": rec.threat_risk_category,
                "cti_trust_score": rec.cti_trust_score,
                "version": rec.version or "1.0",
                "created_at": format_canonical_timestamp(rec.created_at)
            }
            recomputed_json = serialize_canonical_json(record_dict)
            computed_hash = calculate_sha256_hash(recomputed_json)

    # Query blockchain registry
    bc = BlockchainService.get_instance()
    verify_result = bc.verify_record(rec.id, computed_hash)

    # Log to verification history
    v_history = VerificationHistory(
        id=str(uuid.uuid4()),
        cti_record_id=rec.id,
        verified_by_user_id=user.id,
        verified_by_org_id=user.organization_id,
        computed_hash=computed_hash,
        blockchain_hash=verify_result.get("onchain_hash") or "N/A",
        result=verify_result.get("result", "UNAVAILABLE"),
        details=verify_result
    )
    db.add(v_history)
    db.commit()

    return {
        "record_id": rec.id,
        "computed_hash": computed_hash,
        "blockchain_hash": verify_result.get("onchain_hash"),
        "result": verify_result.get("result", "UNAVAILABLE"),
        "message": verify_result.get("message", ""),
        "organization_id": verify_result.get("organization_id"),
        "verified_at": format_canonical_timestamp(get_current_utc()),
        "on_chain_timestamp": verify_result.get("registered_at_timestamp"),
        "is_tampered_test": is_tampered_test
    }

@app.get("/api/blockchain/status")
def blockchain_status():
    bc = BlockchainService.get_instance()
    return bc.get_status()

@app.get("/api/blockchain/transactions")
def list_transactions(db: Session = Depends(get_db)):
    txs = db.query(BlockchainTransaction).order_by(desc(BlockchainTransaction.created_at)).limit(50).all()
    return [
        {
            "id": tx.id,
            "cti_record_id": tx.cti_record_id,
            "tx_hash": tx.tx_hash,
            "block_number": tx.block_number,
            "gas_used": tx.gas_used,
            "status": tx.status,
            "sender_address": tx.sender_address,
            "contract_address": tx.contract_address,
            "created_at": tx.created_at.isoformat()
        }
        for tx in txs
    ]

# ==========================================
# 6. CTI SHARING BETWEEN ORGANIZATIONS
# ==========================================
@app.post("/api/share")
def share_cti_record(
    req: CTIShareRequest,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    rec = db.query(CTIRecord).filter(CTIRecord.id == req.cti_record_id).first()
    if not rec:
        raise HTTPException(status_code=404, detail="CTI Record not found")
    if rec.organization_id != user.organization_id:
        raise HTTPException(status_code=403, detail="You can only share records owned by your organization.")

    shared_count = 0
    for target_org_id in req.target_organization_ids:
        if target_org_id == user.organization_id:
            continue
        target_org = db.query(Organization).filter(Organization.id == target_org_id).first()
        if not target_org:
            continue

        existing = db.query(CTIShare).filter(
            CTIShare.cti_record_id == rec.id,
            CTIShare.target_organization_id == target_org_id
        ).first()

        if not existing:
            share = CTIShare(
                id=str(uuid.uuid4()),
                cti_record_id=rec.id,
                source_organization_id=user.organization_id,
                target_organization_id=target_org_id,
                shared_by_user_id=user.id,
                notes=req.notes or "Threat Intelligence Shared via TrustCTI."
            )
            db.add(share)
            shared_count += 1

    db.commit()
    return {
        "success": True,
        "shared_count": shared_count,
        "message": f"Successfully shared CTI record with {shared_count} organizations."
    }

@app.get("/api/shared/received")
def get_received_shares(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    shares = db.query(CTIShare).filter(
        CTIShare.target_organization_id == user.organization_id,
        CTIShare.status == "ACTIVE"
    ).order_by(desc(CTIShare.shared_at)).all()

    results = []
    for s in shares:
        rec = s.cti_record
        if rec:
            rec_formatted = _format_cti_record(rec)
            rec_formatted["share_metadata"] = {
                "share_id": s.id,
                "shared_at": s.shared_at.isoformat(),
                "notes": s.notes,
                "source_organization_name": s.source_organization.name if s.source_organization else "Unknown",
                "source_organization_code": s.source_organization.code if s.source_organization else "UNK"
            }
            results.append(rec_formatted)
    return results

@app.get("/api/shared/sent")
def get_sent_shares(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    shares = db.query(CTIShare).filter(
        CTIShare.source_organization_id == user.organization_id
    ).order_by(desc(CTIShare.shared_at)).all()

    return [
        {
            "share_id": s.id,
            "record_id": s.cti_record_id,
            "url": s.cti_record.url if s.cti_record else "",
            "classification": s.cti_record.classification if s.cti_record else "",
            "target_organization_name": s.target_organization.name if s.target_organization else "",
            "target_organization_code": s.target_organization.code if s.target_organization else "",
            "notes": s.notes,
            "shared_at": s.shared_at.isoformat()
        }
        for s in shares
    ]

# ==========================================
# 7. ORGANIZATIONS & ML METRICS
# ==========================================
@app.get("/api/organizations")
def list_organizations(db: Session = Depends(get_db)):
    orgs = db.query(Organization).all()
    return [
        {
            "id": o.id,
            "name": o.name,
            "code": o.code,
            "description": o.description,
            "reputation_score": o.reputation_score,
            "eth_address": o.eth_address
        }
        for o in orgs
    ]

@app.get("/api/ml/metrics")
def get_ml_metrics():
    path = os.path.join("artifacts", "metrics.json")
    if os.path.exists(path):
        with open(path, "r") as f:
            return json.load(f)
    return {"message": "Metrics not yet available."}

@app.get("/api/ml/global-importance")
def get_global_importance():
    path = os.path.join("artifacts", "global_feature_importance.json")
    if os.path.exists(path):
        with open(path, "r") as f:
            return json.load(f)
    return []

# Helper
def _format_cti_record(rec: CTIRecord) -> Dict[str, Any]:
    return {
        "id": rec.id,
        "url": rec.url,
        "url_normalized": rec.url_normalized,
        "organization_id": rec.organization_id,
        "organization_name": rec.organization.name if rec.organization else None,
        "organization_code": rec.organization.code if rec.organization else None,
        "classification": rec.classification,
        "threat_type": rec.threat_type,
        "confidence": rec.confidence,
        "threat_risk_score": rec.threat_risk_score,
        "threat_risk_category": rec.threat_risk_category,
        "cti_trust_score": rec.cti_trust_score,
        "cti_trust_category": rec.cti_trust_category,
        "record_hash": rec.record_hash,
        "canonical_json": rec.canonical_json,
        "blockchain_registered": rec.blockchain_registered,
        "blockchain_tx_hash": rec.blockchain_tx_hash,
        "blockchain_block_number": rec.blockchain_block_number,
        "blockchain_registered_at": rec.blockchain_registered_at.isoformat() if rec.blockchain_registered_at else None,
        "created_at": format_canonical_timestamp(rec.created_at),
        "features_snapshot": rec.features_snapshot,
        "shap_summary": rec.shap_summary,
        "risk_indicators": rec.risk_indicators,
        "trust_indicators": rec.trust_indicators
    }

# ==========================================
# 8. FRONTEND STATIC FILE SERVING
# ==========================================
FRONTEND_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "frontend")
if os.path.exists(FRONTEND_DIR):
    app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")

@app.get("/")
def serve_index():
    index_path = os.path.join(FRONTEND_DIR, "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path)
    return {"message": "TrustCTI API Active. Frontend not built yet."}
