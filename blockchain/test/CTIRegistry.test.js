const { expect } = require("chai");
const { ethers } = require("hardhat");

describe("CTIRegistry Smart Contract", function () {
  let CTIRegistry;
  let registry;
  let owner;
  let org1;
  let org2;

  beforeEach(async function () {
    [owner, org1, org2] = await ethers.getSigners();
    CTIRegistry = await ethers.getContractFactory("CTIRegistry");
    registry = await CTIRegistry.deploy();
    await registry.waitForDeployment();
  });

  it("Should set the correct deployer as owner", async function () {
    expect(await registry.owner()).to.equal(owner.address);
  });

  it("Should register a CTI record and retrieve its details", async function () {
    const recordId = "cti-rec-001";
    // Canonical SHA-256 hash (bytes32 format)
    const testHash = ethers.keccak256(ethers.toUtf8Bytes("canonical-cti-data-test"));
    const orgId = "ORG-CERT-01";
    const classification = "Phishing";
    const riskScore = 88;

    const tx = await registry.connect(org1).registerRecord(
      recordId,
      testHash,
      orgId,
      classification,
      riskScore
    );
    await tx.wait();

    // Check existence
    expect(await registry.recordExists(recordId)).to.be.true;
    expect(await registry.getRecordCount()).to.equal(1);

    // Fetch record
    const record = await registry.getRecord(recordId);
    expect(record[0]).to.equal(testHash);
    expect(record[1]).to.equal(orgId);
    expect(record[2]).to.equal(classification);
    expect(record[3]).to.equal(riskScore);
    expect(record[5]).to.equal(org1.address);
  });

  it("Should verify valid and invalid hashes accurately", async function () {
    const recordId = "cti-rec-002";
    const validHash = ethers.keccak256(ethers.toUtf8Bytes("authentic-record"));
    const tamperedHash = ethers.keccak256(ethers.toUtf8Bytes("tampered-record"));

    await registry.connect(org1).registerRecord(
      recordId,
      validHash,
      "CYBER-SOC",
      "Malware",
      95
    );

    // Verify matching hash
    const [isValidMatch, timestamp, orgId] = await registry.verifyRecord(recordId, validHash);
    expect(isValidMatch).to.be.true;
    expect(orgId).to.equal("CYBER-SOC");

    // Verify tampered hash
    const [isTamperedMatch] = await registry.verifyRecord(recordId, tamperedHash);
    expect(isTamperedMatch).to.be.false;

    // Verify non-existent record
    const [nonExistentMatch] = await registry.verifyRecord("non-existent", validHash);
    expect(nonExistentMatch).to.be.false;
  });

  it("Should prevent duplicate record registration", async function () {
    const recordId = "cti-rec-duplicate";
    const hash1 = ethers.keccak256(ethers.toUtf8Bytes("original"));
    const hash2 = ethers.keccak256(ethers.toUtf8Bytes("duplicate"));

    await registry.registerRecord(recordId, hash1, "ORG-A", "Benign", 5);

    await expect(
      registry.registerRecord(recordId, hash2, "ORG-B", "Malware", 90)
    ).to.be.revertedWith("CTIRegistry: recordId already registered");
  });

  it("Should reject risk score greater than 100", async function () {
    const recordId = "cti-rec-invalid-risk";
    const hash1 = ethers.keccak256(ethers.toUtf8Bytes("test"));

    await expect(
      registry.registerRecord(recordId, hash1, "ORG-A", "Malware", 101)
    ).to.be.revertedWith("CTIRegistry: riskScore out of range (0-100)");
  });
});

