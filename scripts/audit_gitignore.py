import os
import pathspec

def run_audit():
    with open('.gitignore', 'r', encoding='utf-8') as f:
        spec = pathspec.PathSpec.from_lines('gitwildmatch', f)

    all_files = []
    ignored_files = []
    included_files = []

    for root, dirs, files in os.walk('.'):
        for file in files:
            rel_path = os.path.relpath(os.path.join(root, file), '.').replace('\\', '/')
            all_files.append(rel_path)
            if spec.match_file(rel_path):
                ignored_files.append(rel_path)
            else:
                included_files.append(rel_path)

    print(f"=== GITIGNORE AUDIT RESULTS ===")
    print(f"Total files on disk: {len(all_files)}")
    print(f"Total files EXCLUDED by .gitignore: {len(ignored_files)}")
    print(f"Total files INCLUDED for distribution: {len(included_files)}")

    print("\n[Audit: Sensitive Files Exclusion Check]")
    must_exclude = [
        ".env",
        "trustcti.db",
        "test_isolated_audit.db",
        "blockchain/cache/solidity-files-cache.json",
        "blockchain/artifacts/build-info/17945e13c8cee85f8699391fc60d325.json",
        "backend/__pycache__/main.cpython-313.pyc",
        ".pytest_cache/v/cache/nodeids"
    ]
    for target in must_exclude:
        actual_files = [f for f in all_files if f.startswith(target) or f == target]
        if actual_files:
            for f in actual_files:
                is_ignored = spec.match_file(f)
                status = "SECURE (EXCLUDED)" if is_ignored else "VULNERABILITY (INCLUDED!)"
                print(f"  - {f:<60} -> {status}")
        else:
            is_ignored = spec.match_file(target)
            status = "RULE ACTIVE (EXCLUDED)" if is_ignored else "NOT MATCHED"
            print(f"  - {target:<60} -> {status} (Rule Verified)")

    print("\n[Audit: Essential Files Inclusion Check]")
    must_include = [
        ".env.example",
        "requirements.txt",
        "package.json",
        "pytest.ini",
        "README.md",
        "FINAL_AUDIT_REPORT.md",
        "docker-compose.yml",
        "backend/main.py",
        "backend/auth.py",
        "backend/database.py",
        "backend/models.py",
        "backend/schemas.py",
        "backend/scoring.py",
        "backend/canonical.py",
        "backend/blockchain.py",
        "backend/seed.py",
        "backend/config/contract_address.json",
        "ml/features.py",
        "ml/predictor.py",
        "ml/train.py",
        "frontend/index.html",
        "frontend/js/app.js",
        "frontend/css/styles.css",
        "blockchain/package.json",
        "blockchain/package-lock.json",
        "blockchain/hardhat.config.js",
        "blockchain/contracts/CTIRegistry.sol",
        "blockchain/scripts/deploy.js",
        "blockchain/test/CTIRegistry.test.js",
        "blockchain/deployments/deployment.json",
        "blockchain/artifacts/contracts/CTIRegistry.sol/CTIRegistry.json",
        "artifacts/xgb_binary_model.joblib",
        "artifacts/xgb_multiclass_model.joblib",
        "artifacts/shap_explainer.joblib",
        "artifacts/shap_background.joblib",
        "artifacts/dataset_profile.json",
        "artifacts/feature_names.json",
        "artifacts/global_feature_importance.json",
        "artifacts/metrics.json",
        "data/cti_binary_dataset.csv"
    ]
    all_passed = True
    for target in must_include:
        is_ignored = spec.match_file(target)
        status = "PASSED (INCLUDED)" if not is_ignored else "ERROR (ACCIDENTALLY EXCLUDED!)"
        if is_ignored:
            all_passed = False
        print(f"  - {target:<60} -> {status}")

    print(f"\nAll essential files included: {all_passed}")

if __name__ == "__main__":
    run_audit()

