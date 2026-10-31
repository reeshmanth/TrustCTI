import json
import hashlib
from typing import Dict, Any

CANONICAL_FIELDS = [
    "id",
    "url_normalized",
    "organization_id",
    "classification",
    "threat_type",
    "confidence",
    "threat_risk_score",
    "threat_risk_category",
    "cti_trust_score",
    "version",
    "created_at"
]

def build_canonical_payload(record_dict: Dict[str, Any]) -> Dict[str, Any]:
    """
    Constructs a deterministic dictionary containing only the canonical fields.
    Standardizes numbers and timestamps.
    """
    canonical_dict = {}
    for field in CANONICAL_FIELDS:
        val = record_dict.get(field)
        if isinstance(val, float):
            canonical_dict[field] = round(val, 4)
        elif isinstance(val, (int, str, bool)):
            canonical_dict[field] = val
        elif val is None:
            canonical_dict[field] = None
        else:
            canonical_dict[field] = str(val)
    return canonical_dict

def serialize_canonical_json(record_dict: Dict[str, Any]) -> str:
    """
    Produces deterministic, sort-keyed, compact JSON string without arbitrary whitespace.
    """
    payload = build_canonical_payload(record_dict)
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))

def calculate_sha256_hash(canonical_json_str: str) -> str:
    """
    Computes standard SHA-256 hex digest of the canonical string.
    """
    return hashlib.sha256(canonical_json_str.encode("utf-8")).hexdigest()

def compute_record_integrity(record_dict: Dict[str, Any]) -> tuple[str, str]:
    """
    Returns (canonical_json_string, sha256_hash_hex)
    """
    canonical_str = serialize_canonical_json(record_dict)
    record_hash = calculate_sha256_hash(canonical_str)
    return canonical_str, record_hash

