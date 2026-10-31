// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title CTIRegistry
 * @notice Decentralized, tamper-evident registry for Cyber Threat Intelligence (CTI) records.
 * Stores canonical SHA-256 integrity hashes and verification metadata on-chain without exposing sensitive intelligence data.
 */
contract CTIRegistry {
    struct CTIRecordEntry {
        bytes32 recordHash;         // SHA-256 hash of canonical CTI JSON record
        string organizationId;      // Submitting organization identifier
        string threatClassification;// Benign, Malware, Phishing, Defacement, etc.
        uint8 riskScore;            // 0-100 threat risk score
        uint256 registeredAt;       // On-chain block timestamp
        address submitter;          // Submitting Ethereum address
        bool exists;                // Existence guard
    }

    // Mapping from CTI unique recordId to on-chain record entry
    mapping(string => CTIRecordEntry) private _records;
    
    // Ordered list of registered record IDs for auditability
    string[] private _recordIds;

    // Contract owner / admin
    address public owner;

    // Events
    event RecordRegistered(
        string indexed recordId,
        bytes32 indexed recordHash,
        address indexed submitter,
        string organizationId,
        string threatClassification,
        uint8 riskScore,
        uint256 timestamp
    );

    modifier onlyOwner() {
        require(msg.sender == owner, "CTIRegistry: caller is not the owner");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    /**
     * @notice Register a new CTI record hash on-chain
     * @param recordId Unique CTI record identifier (e.g. UUID)
     * @param recordHash Canonical SHA-256 hash of the full CTI JSON record
     * @param organizationId Organization code or ID registering this intelligence
     * @param threatClassification Classified threat type
     * @param riskScore Threat risk score (0-100)
     */
    function registerRecord(
        string calldata recordId,
        bytes32 recordHash,
        string calldata organizationId,
        string calldata threatClassification,
        uint8 riskScore
    ) external {
        require(bytes(recordId).length > 0, "CTIRegistry: recordId cannot be empty");
        require(recordHash != bytes32(0), "CTIRegistry: recordHash cannot be zero");
        require(!_records[recordId].exists, "CTIRegistry: recordId already registered");
        require(riskScore <= 100, "CTIRegistry: riskScore out of range (0-100)");

        _records[recordId] = CTIRecordEntry({
            recordHash: recordHash,
            organizationId: organizationId,
            threatClassification: threatClassification,
            riskScore: riskScore,
            registeredAt: block.timestamp,
            submitter: msg.sender,
            exists: true
        });

        _recordIds.push(recordId);

        emit RecordRegistered(
            recordId,
            recordHash,
            msg.sender,
            organizationId,
            threatClassification,
            riskScore,
            block.timestamp
        );
    }

    /**
     * @notice Retrieve on-chain CTI record details
     */
    function getRecord(string calldata recordId)
        external
        view
        returns (
            bytes32 recordHash,
            string memory organizationId,
            string memory threatClassification,
            uint8 riskScore,
            uint256 registeredAt,
            address submitter
        )
    {
        require(_records[recordId].exists, "CTIRegistry: record not found");
        CTIRecordEntry storage entry = _records[recordId];
        return (
            entry.recordHash,
            entry.organizationId,
            entry.threatClassification,
            entry.riskScore,
            entry.registeredAt,
            entry.submitter
        );
    }

    /**
     * @notice Verify whether a provided SHA-256 hash matches the on-chain registered hash
     * @param recordId CTI identifier to verify
     * @param computedHash SHA-256 hash computed from local canonical record
     * @return isValid True if match, false otherwise
     * @return registeredAt Block timestamp of registration
     * @return organizationId Submitting organization
     */
    function verifyRecord(string calldata recordId, bytes32 computedHash)
        external
        view
        returns (
            bool isValid,
            uint256 registeredAt,
            string memory organizationId
        )
    {
        if (!_records[recordId].exists) {
            return (false, 0, "");
        }
        CTIRecordEntry storage entry = _records[recordId];
        bool matches = (entry.recordHash == computedHash);
        return (matches, entry.registeredAt, entry.organizationId);
    }

    /**
     * @notice Check if a record ID exists in registry
     */
    function recordExists(string calldata recordId) external view returns (bool) {
        return _records[recordId].exists;
    }

    /**
     * @notice Get total count of registered records
     */
    function getRecordCount() external view returns (uint256) {
        return _recordIds.length;
    }

    /**
     * @notice Get record ID at a given index
     */
    function getRecordIdAtIndex(uint256 index) external view returns (string memory) {
        require(index < _recordIds.length, "CTIRegistry: index out of bounds");
        return _recordIds[index];
    }
}

