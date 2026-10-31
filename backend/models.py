import datetime
from sqlalchemy import (
    Column, String, Integer, Float, Boolean, DateTime,
    ForeignKey, Text, JSON
)
from sqlalchemy.orm import relationship
from backend.database import Base

def get_utc_now():
    return datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)

class Organization(Base):
    __tablename__ = "organizations"

    id = Column(String(64), primary_key=True, index=True)
    name = Column(String(128), nullable=False)
    code = Column(String(32), unique=True, index=True, nullable=False)
    description = Column(Text, nullable=True)
    eth_address = Column(String(64), nullable=True)
    reputation_score = Column(Integer, default=90) # Baseline reputation 0-100
    created_at = Column(DateTime, default=get_utc_now)

    users = relationship("User", back_populates="organization")
    records = relationship("CTIRecord", back_populates="organization")
    shared_out = relationship("CTIShare", foreign_keys="CTIShare.source_organization_id", back_populates="source_organization")
    shared_in = relationship("CTIShare", foreign_keys="CTIShare.target_organization_id", back_populates="target_organization")


class User(Base):
    __tablename__ = "users"

    id = Column(String(64), primary_key=True, index=True)
    organization_id = Column(String(64), ForeignKey("organizations.id"), nullable=False)
    username = Column(String(64), unique=True, index=True, nullable=False)
    email = Column(String(128), unique=True, index=True, nullable=False)
    hashed_password = Column(String(256), nullable=False)
    full_name = Column(String(128), nullable=True)
    role = Column(String(32), default="analyst") # admin, analyst, viewer
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=get_utc_now)

    organization = relationship("Organization", back_populates="users")
    records = relationship("CTIRecord", back_populates="creator")


class CTIRecord(Base):
    __tablename__ = "cti_records"

    id = Column(String(64), primary_key=True, index=True) # UUID
    url = Column(Text, nullable=False)
    url_normalized = Column(Text, nullable=False)
    organization_id = Column(String(64), ForeignKey("organizations.id"), nullable=False)
    created_by_user_id = Column(String(64), ForeignKey("users.id"), nullable=False)
    
    classification = Column(String(32), nullable=False) # Malicious vs Benign
    threat_type = Column(String(32), nullable=False)    # Phishing, Malware, Defacement, Benign
    confidence = Column(Float, nullable=False)          # Model confidence (0.0 to 1.0)
    
    threat_risk_score = Column(Integer, nullable=False) # 0 to 100
    threat_risk_category = Column(String(32), nullable=False) # CRITICAL, HIGH, MEDIUM, LOW, CLEAN
    
    cti_trust_score = Column(Integer, nullable=False)   # 0 to 100
    cti_trust_category = Column(String(32), nullable=False) # HIGHLY_TRUSTED, TRUSTED, MODERATE, LOW_TRUST
    
    features_snapshot = Column(JSON, nullable=False)
    shap_summary = Column(JSON, nullable=False)
    risk_indicators = Column(JSON, nullable=False)
    trust_indicators = Column(JSON, nullable=False)
    
    canonical_json = Column(Text, nullable=False)       # Exact deterministic serialization
    record_hash = Column(String(128), nullable=False, index=True) # SHA-256 hash in hex
    
    blockchain_registered = Column(Boolean, default=False)
    blockchain_tx_hash = Column(String(128), nullable=True, index=True)
    blockchain_block_number = Column(Integer, nullable=True)
    blockchain_registered_at = Column(DateTime, nullable=True)
    
    version = Column(String(16), default="1.0")
    created_at = Column(DateTime, default=get_utc_now)
    updated_at = Column(DateTime, default=get_utc_now, onupdate=get_utc_now)

    organization = relationship("Organization", back_populates="records")
    creator = relationship("User", back_populates="records")
    shares = relationship("CTIShare", back_populates="cti_record", cascade="all, delete-orphan")
    verifications = relationship("VerificationHistory", back_populates="cti_record", cascade="all, delete-orphan")


class CTIShare(Base):
    __tablename__ = "cti_shares"

    id = Column(String(64), primary_key=True, index=True)
    cti_record_id = Column(String(64), ForeignKey("cti_records.id"), nullable=False)
    source_organization_id = Column(String(64), ForeignKey("organizations.id"), nullable=False)
    target_organization_id = Column(String(64), ForeignKey("organizations.id"), nullable=False)
    shared_by_user_id = Column(String(64), ForeignKey("users.id"), nullable=False)
    
    notes = Column(Text, nullable=True)
    status = Column(String(32), default="ACTIVE") # ACTIVE, REVOKED
    shared_at = Column(DateTime, default=get_utc_now)

    cti_record = relationship("CTIRecord", back_populates="shares")
    source_organization = relationship("Organization", foreign_keys=[source_organization_id], back_populates="shared_out")
    target_organization = relationship("Organization", foreign_keys=[target_organization_id], back_populates="shared_in")


class VerificationHistory(Base):
    __tablename__ = "verification_history"

    id = Column(String(64), primary_key=True, index=True)
    cti_record_id = Column(String(64), ForeignKey("cti_records.id"), nullable=False)
    verified_by_user_id = Column(String(64), ForeignKey("users.id"), nullable=False)
    verified_by_org_id = Column(String(64), ForeignKey("organizations.id"), nullable=False)
    
    computed_hash = Column(String(128), nullable=False)
    blockchain_hash = Column(String(128), nullable=False)
    result = Column(String(32), nullable=False) # VERIFIED, TAMPERED, UNAVAILABLE
    details = Column(JSON, nullable=True)
    verified_at = Column(DateTime, default=get_utc_now)

    cti_record = relationship("CTIRecord", back_populates="verifications")


class BlockchainTransaction(Base):
    __tablename__ = "blockchain_transactions"

    id = Column(String(64), primary_key=True, index=True)
    cti_record_id = Column(String(64), ForeignKey("cti_records.id"), nullable=False)
    tx_hash = Column(String(128), unique=True, index=True, nullable=False)
    block_number = Column(Integer, nullable=True)
    block_hash = Column(String(128), nullable=True)
    gas_used = Column(Integer, nullable=True)
    status = Column(String(32), default="CONFIRMED") # CONFIRMED, FAILED
    sender_address = Column(String(128), nullable=False)
    contract_address = Column(String(128), nullable=False)
    event_emitted = Column(String(64), default="RecordRegistered")
    created_at = Column(DateTime, default=get_utc_now)
