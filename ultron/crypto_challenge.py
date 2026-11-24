"""
crypto_challenge.py - Autonomous Cryptographic Proof-of-Work (PoW) Challenge
Serves an invisible, zero-friction browser security check (equivalent to Cloudflare Turnstile
and "Under Attack Mode") to instantly weed out automated scrapers, headless bots, and DDoS scripts.
"""

import hmac
import hashlib
import time
import uuid
from typing import Dict, Any, Tuple, Optional

# Secret key for signing clearance cookies
CHALLENGE_SECRET = "ultron_stealth_pow_secret_key_2026"

class CryptoChallengeEngine:
    """
    Issues and verifies fast client-side SHA-256 Proof-of-Work puzzles.
    """

    def generate_challenge(self, ip_str: str) -> Dict[str, Any]:
        """Generates a challenge puzzle with difficulty 4 (leading '0000')."""
        challenge_id = uuid.uuid4().hex[:12]
        timestamp = int(time.time())
        # Signed token ensuring the challenge originated from Ultron
        sig = hmac.new(CHALLENGE_SECRET.encode(), f"{challenge_id}:{timestamp}:{ip_str}".encode(), hashlib.sha256).hexdigest()[:16]

        return {
            "challenge_id": challenge_id,
            "timestamp": timestamp,
            "ip": ip_str,
            "difficulty": "0000",
            "token": f"{challenge_id}.{timestamp}.{sig}"
        }

    def verify_solution(self, token: str, nonce: str, ip_str: str) -> bool:
        """Verifies if the submitted nonce solves the SHA-256 PoW puzzle."""
        try:
            parts = token.split(".")
            if len(parts) != 3:
                return False
            challenge_id, ts_str, sig = parts
            ts = int(ts_str)

            # Check expiration (max 2 minutes to solve)
            if time.time() - ts > 120:
                return False

            # Verify signature
            expected_sig = hmac.new(CHALLENGE_SECRET.encode(), f"{challenge_id}:{ts}:{ip_str}".encode(), hashlib.sha256).hexdigest()[:16]
            if not hmac.compare_digest(sig, expected_sig):
                return False

            # Verify Proof-of-Work
            test_str = f"{challenge_id}:{nonce}".encode()
            digest = hashlib.sha256(test_str).hexdigest()
            if digest.startswith("0000"):
                return True
            return False
        except Exception:
            return False

    def issue_clearance_token(self, ip_str: str) -> str:
        """Issues an authenticated clearance token valid for 24h."""
        exp = int(time.time()) + 86400
        sig = hmac.new(CHALLENGE_SECRET.encode(), f"clearance:{ip_str}:{exp}".encode(), hashlib.sha256).hexdigest()
        return f"{exp}.{sig}"

    def verify_clearance_token(self, clearance_token: str, ip_str: str) -> bool:
        """Verifies if visitor holds a valid clearance token."""
        try:
            exp_str, sig = clearance_token.split(".", 1)
            exp = int(exp_str)
            if time.time() > exp:
                return False
            expected_sig = hmac.new(CHALLENGE_SECRET.encode(), f"clearance:{ip_str}:{exp}".encode(), hashlib.sha256).hexdigest()
            return hmac.compare_digest(sig, expected_sig)
        except Exception:
            return False

    def render_challenge_html(self, challenge: Dict[str, Any], redirect_target: str = "/") -> str:
        """Renders the sleek, automated 'Checking your browser' waiting room page."""
        return f"""<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vérification de sécurité - Ultron Sentinel</title>
    <style>
        body {{
            background: #0d1117; color: #c9d1d9; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
            display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0;
        }}
        .card {{
            background: #161b22; border: 1px solid #30363d; border-radius: 12px; padding: 32px; max-width: 440px; text-align: center;
            box-shadow: 0 8px 24px rgba(0,0,0,0.5);
        }}
        .spinner {{
            width: 44px; height: 44px; border: 3px solid rgba(56, 189, 248, 0.2); border-top-color: #38bdf8;
            border-radius: 50%; animation: spin 1s infinite linear; margin: 0 auto 20px;
        }}
        @keyframes spin {{ 0% {{ transform: rotate(0deg); }} 100% {{ transform: rotate(360deg); }} }}
        h2 {{ font-size: 20px; margin: 0 0 10px; color: #f0f6fc; font-weight: 600; }}
        p {{ font-size: 14px; color: #8b949e; line-height: 1.5; margin: 0 0 16px; }}
        .badge {{ display: inline-block; font-size: 11px; padding: 4px 10px; background: rgba(56, 189, 248, 0.1); color: #38bdf8; border-radius: 20px; border: 1px solid rgba(56, 189, 248, 0.3); }}
    </style>
</head>
<body>
    <div class="card">
        <div class="spinner"></div>
        <h2>Vérification de sécurité en cours...</h2>
        <p>Ultron Sentinel valide l'intégrité de votre navigateur avant de vous autoriser l'accès. Cette étape prend moins d'une seconde.</p>
        <span class="badge">Bouclier Cryptographique Actif</span>
    </div>

    <script>
        (async function solveChallenge() {{
            const challengeId = "{challenge['challenge_id']}";
            const token = "{challenge['token']}";
            const target = "{redirect_target}";

            let nonce = 0;
            const prefix = "0000";

            async function sha256(message) {{
                const msgBuffer = new TextEncoder().encode(message);
                const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
                const hashArray = Array.from(new Uint8Array(hashBuffer));
                return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
            }}

            while (true) {{
                const hash = await sha256(challengeId + ":" + nonce);
                if (hash.startsWith(prefix)) {{
                    // Solved! Send response
                    const resp = await fetch("/__sc/security/api/sentinel/challenge/verify", {{
                        method: "POST",
                        headers: {{ "Content-Type": "application/json" }},
                        body: JSON.stringify({{ token: token, nonce: nonce.toString() }})
                    }});
                    if (resp.ok) {{
                        window.location.href = target;
                    }} else {{
                        document.querySelector("p").innerText = "Échec de validation. Veuillez rafraîchir la page.";
                    }}
                    break;
                }}
                nonce++;
            }}
        }})();
    </script>
</body>
</html>"""

# Global singleton
crypto_challenge = CryptoChallengeEngine()
