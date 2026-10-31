from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field

class UserRegisterRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    email: str = Field(..., min_length=5)
    password: str = Field(..., min_length=6)
    full_name: Optional[str] = None
    organization_name: str = Field(..., min_length=2)
    organization_code: str = Field(..., min_length=2, max_length=20)

class UserLoginRequest(BaseModel):
    username: str
    password: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: Dict[str, Any]

class OrganizationResponse(BaseModel):
    id: str
    name: str
    code: str
    description: Optional[str] = None
    reputation_score: int
    eth_address: Optional[str] = None

class URLScanRequest(BaseModel):
    url: str

class URLScanResponse(BaseModel):
    url: str
    url_normalized: str
    classification: str
    threat_type: str
    confidence: float
    probabilities: Dict[str, float]
    threat_distribution: Dict[str, float]
    threat_risk_score: int
    threat_risk_category: str
    cti_trust_score: int
    cti_trust_category: str
    risk_indicators: List[Dict[str, Any]]
    trust_indicators: List[Dict[str, Any]]
    shap_summary: Dict[str, Any]
    features_snapshot: Dict[str, Any]

class CTIRecordCreateRequest(BaseModel):
    url: str
    classification: str
    threat_type: str
    confidence: float
    threat_risk_score: int
    threat_risk_category: str
    cti_trust_score: int
    cti_trust_category: str
    features_snapshot: Dict[str, Any]
    shap_summary: Dict[str, Any]
    risk_indicators: List[Dict[str, Any]]
    trust_indicators: List[Dict[str, Any]]
    register_on_blockchain: bool = False

class CTIRecordResponse(BaseModel):
    id: str
    url: str
    url_normalized: str
    organization_id: str
    organization_name: Optional[str] = None
    organization_code: Optional[str] = None
    classification: str
    threat_type: str
    confidence: float
    threat_risk_score: int
    threat_risk_category: str
    cti_trust_score: int
    cti_trust_category: str
    record_hash: str
    canonical_json: str
    blockchain_registered: bool
    blockchain_tx_hash: Optional[str] = None
    blockchain_block_number: Optional[int] = None
    blockchain_registered_at: Optional[str] = None
    created_at: str
    features_snapshot: Optional[Dict[str, Any]] = None
    shap_summary: Optional[Dict[str, Any]] = None
    risk_indicators: Optional[List[Dict[str, Any]]] = None
    trust_indicators: Optional[List[Dict[str, Any]]] = None

class CTIShareRequest(BaseModel):
    cti_record_id: str
    target_organization_ids: List[str]
    notes: Optional[str] = None

class VerifyRequest(BaseModel):
    cti_record_id: str
    custom_canonical_json: Optional[str] = None # For testing tampering

class VerifyResponse(BaseModel):
    record_id: str
    computed_hash: str
    blockchain_hash: Optional[str] = None
    result: str # VERIFIED, TAMPERED, UNAVAILABLE
    message: str
    organization_id: Optional[str] = None
    verified_at: str
    on_chain_timestamp: Optional[int] = None
    is_tampered_test: bool = False
