"""
ci_scanner.py - Autonomous CI/CD Shift-Left Security Linter & Pipeline Gate
Can be executed in GitHub Actions, GitLab CI, or pre-commit hooks to block pull requests
introducing high/critical vulnerabilities, hardcoded secrets, or raw SQL queries.
"""

import os
import sys
import ast
import re
import json
import argparse
from typing import Dict, Any, List

class CIScanner:
    """
    Scans project source files for security flaws during build/CI pipeline.
    """

    SECRET_PATTERNS = [
        ("AWS_SECRET_KEY", re.compile(r"""(?i)(?:aws_secret_access_key|aws_key)\s*=\s*['"][A-Za-z0-9/+=]{40}['"]""")),
        ("GENERIC_API_KEY", re.compile(r"""(?i)(?:api_key|secret_key|private_key)\s*=\s*['"][A-Za-z0-9_\-]{24,}['"]""")),
        ("SLACK_WEBHOOK", re.compile(r"""https://hooks\.slack\.com/services/T[0-9A-Z]{8}/B[0-9A-Z]{8}/[0-9A-Za-z]{24}""")),
    ]

    def scan_directory(self, target_dir: str) -> Dict[str, Any]:
        """Performs static code and secret analysis across python and config files."""
        findings = []
        files_scanned = 0

        for root, _, files in os.walk(target_dir):
            if any(p in root for p in (".git", "__pycache__", "venv", ".venv", "node_modules")):
                continue

            for fname in files:
                if not fname.endswith((".py", ".env", ".json", ".yml", ".yaml")):
                    continue

                fpath = os.path.join(root, fname)
                files_scanned += 1

                try:
                    with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()

                    # 1. Secret Scanning
                    for stype, rx in self.SECRET_PATTERNS:
                        for match in rx.finditer(content):
                            findings.append({
                                "file": os.path.relpath(fpath, target_dir),
                                "type": stype,
                                "severity": "CRITICAL",
                                "message": f"Clé secrète codée en dur ({stype}) détectée."
                            })

                    # 2. Python AST Analysis
                    if fname.endswith(".py"):
                        try:
                            tree = ast.parse(content, filename=fname)
                            for node in ast.walk(tree):
                                # Check for raw SQL f-strings: f"SELECT ... {var}"
                                if isinstance(node, ast.JoinedStr):
                                    # Inspect raw text parts
                                    text_parts = "".join(p.value for p in node.values if isinstance(p, ast.Constant))
                                    if re.search(r"\b(SELECT|INSERT|UPDATE|DELETE)\b.*?\b(FROM|INTO|SET|WHERE)\b", text_parts, re.I):
                                        findings.append({
                                            "file": os.path.relpath(fpath, target_dir),
                                            "line": node.lineno,
                                            "type": "SQL_INJECTION_RISK",
                                            "severity": "HIGH",
                                            "message": "Requête SQL construite par f-string (risque d'injection SQL critique). Utilisez des paramètres préparés."
                                        })
                                # Check for eval()
                                if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "eval":
                                    findings.append({
                                        "file": os.path.relpath(fpath, target_dir),
                                        "line": node.lineno,
                                        "type": "DANGEROUS_EVAL",
                                        "severity": "HIGH",
                                        "message": "Utilisation de eval() dangereux détectée."
                                    })
                        except Exception:
                            pass
                except Exception:
                    pass

        return {
            "files_scanned": files_scanned,
            "findings_count": len(findings),
            "findings": findings,
            "passed": len([f for f in findings if f["severity"] in ("CRITICAL", "HIGH")]) == 0
        }

def main():
    parser = argparse.ArgumentParser(description="Ultron CI/CD Security Gate")
    parser.add_argument("--dir", default=".", help="Directory to audit")
    parser.add_argument("--fail-on", default="HIGH", choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"])
    args = parser.parse_args()

    scanner = CIScanner()
    res = scanner.scan_directory(args.dir)
    print(json.dumps(res, indent=2))

    if not res["passed"]:
        print(f"\n[ÉCHEC CI/CD] {res['findings_count']} vulnérabilités détectées. Pipeline bloquée.")
        sys.exit(1)
    else:
        print("\n[SUCCÈS CI/CD] Aucun problème critique détecté. Déploiement autorisé.")
        sys.exit(0)

if __name__ == "__main__":
    main()
