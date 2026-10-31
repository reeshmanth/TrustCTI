const hre = require("hardhat");
const fs = require("fs");
const path = require("path");

async function main() {
  console.log("Deploying CTIRegistry contract to network:", hre.network.name);

  const [deployer] = await hre.ethers.getSigners();
  console.log("Deploying contract with account:", deployer.address);
  
  const balance = await hre.ethers.provider.getBalance(deployer.address);
  console.log("Account balance:", hre.ethers.formatEther(balance), "ETH");

  const CTIRegistry = await hre.ethers.getContractFactory("CTIRegistry");
  const registry = await CTIRegistry.deploy();

  await registry.waitForDeployment();
  const contractAddress = await registry.getAddress();
  console.log("CTIRegistry deployed successfully at:", contractAddress);

  // Write deployment info to a shared JSON file for backend consumption
  const deploymentInfo = {
    contractAddress: contractAddress,
    deployerAddress: deployer.address,
    network: hre.network.name,
    chainId: (await hre.ethers.provider.getNetwork()).chainId.toString(),
    deployedAt: new Date().toISOString()
  };

  const outputDir = path.join(__dirname, "..", "deployments");
  if (!fs.existsSync(outputDir)) {
    fs.mkdirSync(outputDir, { recursive: true });
  }

  const outputPath = path.join(outputDir, "deployment.json");
  fs.writeFileSync(outputPath, JSON.stringify(deploymentInfo, null, 2));
  console.log("Deployment info written to:", outputPath);

  // Also write into backend/config for direct access
  const backendConfigDir = path.join(__dirname, "..", "..", "backend", "config");
  if (!fs.existsSync(backendConfigDir)) {
    fs.mkdirSync(backendConfigDir, { recursive: true });
  }
  fs.writeFileSync(path.join(backendConfigDir, "contract_address.json"), JSON.stringify(deploymentInfo, null, 2));
  console.log("Deployment info copied to backend config.");
}

main().catch((error) => {
  console.error("Deployment failed:", error);
  process.exitCode = 1;
});

