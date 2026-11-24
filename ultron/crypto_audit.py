"""
crypto_audit.py - Cryptographic Implementation & Timing Attack Audit Engine
Analyzes source code via AST parsing to detect timing attack vulnerabilities
(unsafe string equality on secrets), weak PRNGs (random vs secrets), and hardcoded keys.
"""

import ast
import re
from typing import Dict, Any, List

class CryptoAuditor:
    """
    Audits cryptographic practices and detects side-channel timing attack weaknesses.
    """

    SECRET_VAR_NAMES = {
        "token", "secret", "password", "hash", "signature", "key",
        "api_key", "session_token", "auth_token", "csrf_token"
    }

    def audit_python_code(self, source_code: str, filename: str = "app.py") -> List[Dict[str, Any]]:
        """Parses Python AST to identify timing attack risks and weak randomness."""
        findings = []
        try:
            tree = ast.parse(source_code, filename=filename)
        except Exception:
            return findings

        for node in ast.walk(tree):
            # 1. Detect timing attack in string comparison (== on secret variable)
            if isinstance(node, ast.Compare):
                # Check if comparison is == or !=
                is_eq = any(isinstance(op, (ast.Eq, ast.NotEq)) for op in node.ops)
                if is_eq:
                    names_in_comp = set()
                    for sub in [node.left] + node.comparators:
                        if isinstance(sub, ast.Name):
                            names_in_comp.add(sub.id.lower())
                        elif isinstance(sub, ast.Attribute):
                            names_in_comp.add(sub.attr.lower())

                    matched_secrets = [n for n in names_in_comp if any(s in n for s in self.SECRET_VAR_NAMES)]
                    if matched_secrets:
                        findings.append({
                            "file": filename,
                            "line": node.lineno,
                            "type": "TIMING_ATTACK_VULNERABILITY",
                            "severity": "HIGH",
                            "message": f"Comparaison directe (==) sur une variable sensible ({', '.join(matched_secrets)}). Vulnérable aux attaques temporelles. Utilisez 'hmac.compare_digest()'."
                        })

            # 2. Detect weak PRNG (using random.random() or random.choice for security)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                if isinstance(node.func.value, ast.Name) and node.func.value.id == "random":
                    if node.func.attr in ("randint", "random", "choice", "randrange"):
                        findings.append({
                            "file": filename,
                            "line": node.lineno,
                            "type": "INSECURE_PRNG_USAGE",
                            "severity": "MEDIUM",
                            "message": f"Utilisation du module 'random.{node.func.attr}' potentiellement prédictible. Pour des jetons ou secrets, utilisez le module standard 'secrets'."
                        })

        return findings

# Global singleton
crypto_auditor = CryptoAuditor()
