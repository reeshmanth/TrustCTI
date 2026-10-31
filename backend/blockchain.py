import os
import json
from typing import Dict, Any, Optional
from web3 import Web3

RPC_URL = os.getenv("BLOCKCHAIN_RPC_URL", "http://127.0.0.1:8545")
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEPLOYMENT_PATH = os.path.join(BASE_DIR, "blockchain", "deployments", "deployment.json")
BACKEND_DEPLOYMENT_PATH = os.path.join(BASE_DIR, "backend", "config", "contract_address.json")
ABI_PATH = os.path.join(BASE_DIR, "blockchain", "artifacts", "contracts", "CTIRegistry.sol", "CTIRegistry.json")

class BlockchainService:
    _instance = None

    def __init__(self):
        self.w3 = Web3(Web3.HTTPProvider(RPC_URL))
        self.contract_address: Optional[str] = None
        self.contract_abi: Optional[list] = None
        self.contract = None
        self._load_contract_info()

    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = BlockchainService()
        return cls._instance

    def _load_contract_info(self):
        # Try loading contract address
        address = os.getenv("CONTRACT_ADDRESS")
        if not address:
            for p in [DEPLOYMENT_PATH, BACKEND_DEPLOYMENT_PATH]:
                if os.path.exists(p):
                    try:
                        with open(p, "r") as f:
                            data = json.load(f)
                            address = data.get("contractAddress")
                            if address:
                                break
                    except Exception:
                        pass
        self.contract_address = address

        # Try loading ABI
        if os.path.exists(ABI_PATH):
            try:
                with open(ABI_PATH, "r") as f:
                    data = json.load(f)
                    self.contract_abi = data.get("abi")
            except Exception:
                pass

        if self.is_connected() and self.contract_address and self.contract_abi:
            try:
                self.contract = self.w3.eth.contract(
                    address=Web3.to_checksum_address(self.contract_address),
                    abi=self.contract_abi
                )
            except Exception:
                self.contract = None

    def is_connected(self) -> bool:
        try:
            return bool(self.w3.is_connected())
        except Exception:
            return False

    def get_status(self) -> Dict[str, Any]:
        connected = self.is_connected()
        status = {
            "connected": connected,
            "rpc_url": RPC_URL,
            "contract_address": self.contract_address,
            "contract_loaded": self.contract is not None,
            "latest_block": None,
            "network_id": None,
            "accounts_available": 0,
            "default_account": None
        }

        if connected:
            try:
                status["latest_block"] = self.w3.eth.block_number
                status["network_id"] = self.w3.eth.chain_id
                accounts = self.w3.eth.accounts
                status["accounts_available"] = len(accounts)
                if accounts:
                    status["default_account"] = accounts[0]
                    bal = self.w3.eth.get_balance(accounts[0])
                    status["account_balance_eth"] = float(self.w3.from_wei(bal, "ether"))
            except Exception as e:
                status["error"] = str(e)

        return status

    def register_record(
        self,
        record_id: str,
        record_hash_hex: str,
        organization_id: str,
        threat_type: str,
        risk_score: int
    ) -> Dict[str, Any]:
        """
        Registers CTI hash on-chain by calling CTIRegistry.registerRecord().
        """
        if not self.is_connected():
            return {
                "success": False,
                "status": "UNAVAILABLE",
                "message": "Blockchain RPC is unreachable. Ensure local Hardhat node is running at " + RPC_URL
            }

        if not self.contract:
            self._load_contract_info()
            if not self.contract:
                return {
                    "success": False,
                    "status": "UNAVAILABLE",
                    "message": "CTIRegistry contract not deployed or ABI not loaded."
                }

        try:
            clean_hash = record_hash_hex.lower().replace("0x", "")
            if len(clean_hash) != 64:
                return {
                    "success": False,
                    "status": "ERROR",
                    "message": f"Invalid SHA-256 hash length: expected 64 hex chars, got {len(clean_hash)}"
                }
            bytes32_hash = bytes.fromhex(clean_hash)

            # Use local funded test account
            sender = self.w3.eth.accounts[0]
            
            # Send transaction
            tx_fn = self.contract.functions.registerRecord(
                record_id,
                bytes32_hash,
                organization_id,
                threat_type,
                int(risk_score)
            )

            tx_hash = tx_fn.transact({"from": sender, "gas": 300000})
            receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash, timeout=15)

            tx_hash_hex = receipt.transactionHash.hex()
            if not tx_hash_hex.startswith("0x"):
                tx_hash_hex = "0x" + tx_hash_hex

            return {
                "success": bool(receipt.status == 1),
                "status": "CONFIRMED" if receipt.status == 1 else "REVERTED",
                "tx_hash": tx_hash_hex,
                "block_number": receipt.blockNumber,
                "block_hash": receipt.blockHash.hex(),
                "gas_used": receipt.gasUsed,
                "sender": sender,
                "contract_address": self.contract_address,
                "record_id": record_id,
                "record_hash": record_hash_hex
            }
        except Exception as e:
            return {
                "success": False,
                "status": "ERROR",
                "message": str(e)
            }

    def verify_record(self, record_id: str, computed_hash_hex: str) -> Dict[str, Any]:
        """
        Queries on-chain registry and compares local hash with registered hash.
        """
        if not self.is_connected():
            return {
                "verified": False,
                "result": "UNAVAILABLE",
                "message": "Cannot reach blockchain node to verify integrity."
            }

        if not self.contract:
            self._load_contract_info()
            if not self.contract:
                return {
                    "verified": False,
                    "result": "UNAVAILABLE",
                    "message": "CTIRegistry contract not deployed or ABI missing."
                }

        try:
            clean_hash = computed_hash_hex.lower().replace("0x", "")
            bytes32_hash = bytes.fromhex(clean_hash)

            # Call view function
            is_valid, registered_at, org_id = self.contract.functions.verifyRecord(
                record_id,
                bytes32_hash
            ).call()

            # Also fetch actual on-chain hash for full transparency
            onchain_hash_hex = None
            if self.contract.functions.recordExists(record_id).call():
                rec = self.contract.functions.getRecord(record_id).call()
                onchain_hash_bytes = rec[0]
                onchain_hash_hex = onchain_hash_bytes.hex()
                if not onchain_hash_hex.startswith("0x"):
                    onchain_hash_hex = "0x" + onchain_hash_hex

            computed_with_prefix = "0x" + clean_hash
            result = "VERIFIED" if is_valid else ("TAMPERED" if onchain_hash_hex else "NOT_FOUND")

            return {
                "verified": is_valid,
                "result": result,
                "record_id": record_id,
                "computed_hash": computed_with_prefix,
                "onchain_hash": onchain_hash_hex,
                "organization_id": org_id,
                "registered_at_timestamp": registered_at,
                "message": "Hashes match perfectly. CTI record integrity confirmed on Ethereum blockchain."
                if is_valid else (
                    "CRITICAL: Record hash does NOT match on-chain registered hash! Record has been modified or tampered."
                    if onchain_hash_hex else "Record ID not registered on blockchain."
                )
            }
        except Exception as e:
            return {
                "verified": False,
                "result": "ERROR",
                "message": str(e)
            }

