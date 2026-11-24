"""
deserialization_guard.py - Insecure Deserialization & Gadget Chain Neutralizer
Inspects inbound requests for malicious serialized binary/text objects:
Java serialization magic bytes, Python pickle opcodes, PHP unserialize, and unsafe YAML tags.
"""

import re
import base64
import logging
from typing import Dict, Any, List, Optional
from .database import log_event

logger = logging.getLogger("ultron.deserialization")

class DeserializationGuard:
    """
    Detects and neutralizes insecure object deserialization attacks.
    """

    PATTERNS = [
        # Java Serialization (Magic bytes 0xAC 0xED 0x00 0x05 or Base64 rO0AB)
        ("JAVA_SERIALIZATION_STREAM", re.compile(r"(?:rO0AB[A-Za-z0-9+/=]{4,}|\xac\xed\x00\x05)")),
        # Python Pickle Opcodes (cos\nsystem, cposix\nsystem, c__builtin__)
        ("PYTHON_PICKLE_OPCODE", re.compile(r"""(?:\bc(?:posix|os|subprocess|__builtin__)\b[\s\S]{1,40}\b(?:system|popen|call|check_output|exec)\b|cbuiltins\b)""")),
        # PHP Serialized Object Injection (e.g. O:8:"Exploit":...)
        ("PHP_SERIALIZED_OBJECT", re.compile(r"""\bO:[0-9]+:"[A-Za-z0-9_\\-]+":[0-9]+:\{""")),
        # YAML Unsafe Object Tags (!!python/object, !!javax.script)
        ("YAML_UNSAFE_OBJECT_TAG", re.compile(r"""(?:\!\!python\/object(?:\/apply)?|\!\!javax\.script\.ScriptEngineManager)""")),
        # .NET BinaryFormatter / TypeObject
        ("DOTNET_TYPENAME_INJECTION", re.compile(r"""(?:\$type\s*:\s*['"][^'"]*System\.Diagnostics\.Process)"""))
    ]

    def inspect_payload(self, text: str) -> Optional[Dict[str, Any]]:
        """Scans raw body, headers, or query parameters for serialized attack payloads."""
        if not text or len(text) < 6:
            return None

        # 1. Direct Pattern Matching
        for name, rx in self.PATTERNS:
            if rx.search(text):
                log_event("DESERIALIZATION_ATTACK_BLOCKED", "CRITICAL", "DESERIALIZATION_GUARD",
                          f"Payload de désérialisation non sécurisé détecté ({name}).")
                return {
                    "blocked": True,
                    "category": "insecure_deserialization",
                    "severity": "CRITICAL",
                    "type": name,
                    "reason": f"Objet sérialisé non sécurisé détecté ({name}) - Risque d'exécution de code à distance (RCE)"
                }

        # 2. Base64 decoded check (many deserialization payloads are base64-encoded)
        if len(text) > 20 and re.match(r"^[A-Za-z0-9+/=\s]+$", text.strip()):
            try:
                decoded = base64.b64decode(text.strip()[:2000]).decode("latin-1", errors="ignore")
                for name, rx in self.PATTERNS:
                    if rx.search(decoded):
                        return {
                            "blocked": True,
                            "category": "insecure_deserialization",
                            "severity": "CRITICAL",
                            "type": f"{name}_BASE64",
                            "reason": f"Payload de désérialisation dissimulé en Base64 détecté ({name})"
                        }
            except Exception:
                pass

        return None

# Global singleton
deserialization_guard = DeserializationGuard()
