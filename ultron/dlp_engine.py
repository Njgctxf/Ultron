"""
dlp_engine.py - Outbound Data Loss Prevention (DLP) & Response Sanitizer
Inspects outgoing HTTP responses to detect and redact sensitive data (Credit Cards,
API keys, Private Keys, Social Security numbers, Database dumps) before they reach clients.
"""

import re
import logging
from typing import Dict, Any, List, Tuple
from .database import log_event

logger = logging.getLogger("sentinel.dlp")

class DLPEngine:
    """
    Scans outgoing response content and masks sensitive data leaks in real-time.
    """

    # Credit Card pattern (Visa, Mastercard, Amex, Discover)
    CC_REGEX = re.compile(r"""\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b""")

    # Private Keys & SSH certificates
    KEY_REGEX = re.compile(r"-----BEGIN\s+(?:RSA|OPENSSH|DSA|EC)?\s*PRIVATE\s+KEY-----[\s\S]*?-----END", re.IGNORECASE)

    # Cloud Secrets & Tokens
    AWS_KEY_REGEX = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
    JWT_SECRET_REGEX = re.compile(r"\beyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*\b")

    # Sensitive DB & Stack Trace indicators
    DB_TRACE_REGEX = re.compile(r"(?:OperationalError|ProgrammingError|sqlite3\.OperationalError|SQLSTATE\[\w+\]|Traceback \(most recent call last\):)", re.IGNORECASE)

    def _luhn_checksum(self, card_number: str) -> bool:
        """Validates Luhn algorithm for authentic credit card identification."""
        digits = [int(c) for c in card_number if c.isdigit()]
        if len(digits) < 13:
            return False
        checksum = 0
        reverse_digits = digits[::-1]
        for i, digit in enumerate(reverse_digits):
            if i % 2 == 1:
                doubled = digit * 2
                checksum += doubled - 9 if doubled > 9 else doubled
            else:
                checksum += digit
        return checksum % 10 == 0

    def sanitize_response(self, content_str: str, content_type: str = "") -> Tuple[str, List[Dict[str, Any]]]:
        """Inspects response content, redacts identified leaks, and returns redacted text + leak metadata."""
        if not content_str or not isinstance(content_str, str):
            return content_str, []

        # Only inspect text, JSON, or HTML responses
        ct = (content_type or "").lower()
        if ct and not any(t in ct for t in ("text", "json", "html", "javascript", "xml")):
            return content_str, []

        leaks_found = []
        redacted = content_str

        # 1. Mask AWS Access Keys
        for match in self.AWS_KEY_REGEX.finditer(redacted):
            key = match.group(0)
            redacted = redacted.replace(key, f"AKIA{key[4:8]}****REDACTED")
            leaks_found.append({"type": "AWS_ACCESS_KEY", "severity": "CRITICAL", "action": "REDACTED"})

        # 2. Mask Private Keys
        for match in self.KEY_REGEX.finditer(redacted):
            redacted = self.KEY_REGEX.sub("[REDACTED_PRIVATE_KEY_BY_ULTRON_DLP]", redacted)
            leaks_found.append({"type": "PRIVATE_KEY_LEAK", "severity": "CRITICAL", "action": "REDACTED"})

        # 3. Check & Mask Credit Cards with Luhn validation
        for match in self.CC_REGEX.finditer(redacted):
            card = match.group(0)
            if self._luhn_checksum(card):
                masked = f"{card[:4]}-****-****-{card[-4:]}"
                redacted = redacted.replace(card, masked)
                leaks_found.append({"type": "CREDIT_CARD_LEAK", "severity": "CRITICAL", "action": "REDACTED"})

        # 4. Mask Stack Traces
        if self.DB_TRACE_REGEX.search(redacted):
            redacted = self.DB_TRACE_REGEX.sub("[ERREUR_SYSTEME_MASQUEE_PAR_ULTRON_DLP]", redacted)
            leaks_found.append({"type": "DATABASE_ERROR_DISCLOSURE", "severity": "HIGH", "action": "REDACTED"})

        if leaks_found:
            log_event("DLP_LEAK_PREVENTED", "CRITICAL", "DLP_ENGINE",
                      f"{len(leaks_found)} fuite(s) de données sensibles interceptée(s) et masquée(s) dans la réponse sortante.")

        return redacted, leaks_found

# Global singleton
dlp_engine = DLPEngine()
