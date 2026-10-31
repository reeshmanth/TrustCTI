import os
import re

PATTERNS = {
    "Postgres URI with password": r"postgres(?:ql)?(?:\+[a-z]+)?://[^:\s]+:[^@\s]+@[^\s/]+",
    "Ethereum Private Key (64 hex)": r"(?<![a-zA-Z0-9])0x[a-fA-F0-9]{64}(?![a-zA-Z0-9])",
    "JWT Token": r"eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}",
    "Secret / API Key Assignment": r"(?:api[_-]?key|secret[_-]?key|private[_-]?key)\s*=\s*[\"'][^\"']{8,}[\"']"
}

EXCLUDED_DIRS = {'.git', 'node_modules', '.pytest_cache', '__pycache__', 'artifacts', 'data'}
findings = []

for root, dirs, files in os.walk('.'):
    dirs[:] = [d for d in dirs if d not in EXCLUDED_DIRS]
    for file in files:
        if file == 'scan_secrets.py':
            continue
        filepath = os.path.join(root, file)
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                for name, pat in PATTERNS.items():
                    for m in re.finditer(pat, content, re.IGNORECASE):
                        val = m.group(0)
                        masked = val[:8] + "..." + val[-4:] if len(val) > 12 else "***"
                        findings.append({
                            "file": filepath,
                            "line": content[:m.start()].count('\n') + 1,
                            "type": name,
                            "masked": masked
                        })
        except Exception:
            pass

print(f"Total potential secret matches found: {len(findings)}")
for f in findings:
    print(f"- {f['file']}:{f['line']} [{f['type']}] -> {f['masked']}")

