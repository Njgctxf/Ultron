"""
prompt_guard.py - Indirect Prompt Injection & LLM Jailbreak Neutralizer
Protects autonomous AI security agents (PentAGI, Sentinel Agent) from adversarial
prompt injections hidden inside audited web pages, HTML comments, or user reviews.
"""

import re
import unicodedata
import logging
from typing import Dict, Any, List, Tuple
from .database import log_event

logger = logging.getLogger("ultron.prompt_guard")

class PromptGuard:
    """
    Sanitizes external untrusted text before it is consumed by AI language models.
    """

    INJECTION_PATTERNS = [
        re.compile(r"""(?i)\b(?:ignore|disregard|forget)\s+(?:all\s+)?(?:previous|prior|above)\s+(?:instructions|prompts|rules|directives)\b"""),
        re.compile(r"""(?i)\b(?:you\s+are\s+now|act\s+as|pretend\s+to\s+be)\s+(?:DAN|jailbreak|unfiltered|an\s+AI\s+without\s+rules)\b"""),
        re.compile(r"""(?i)\b(?:system\s*prompt|system\s*instruction|assistant\s*rule)\s*:\s*"""),
        re.compile(r"""(?i)\b(?:override|bypass)\s+security\s+(?:checks|rules|filters|scanning)\b"""),
        re.compile(r"""(?i)\b(?:do\s+not\s+report|classify\s+as\s+safe|mark\s+as\s+secure|hide\s+vulnerabilities)\b"""),
        re.compile(r"""(?i)\[\s*system\s*\][\s\S]{1,40}\[\s*\/\s*system\s*\]"""),
    ]

    ZERO_WIDTH_CHARS = re.compile(r"[\u200B-\u200D\uFEFF\u202A-\u202E]")

    def inspect_and_sanitize(self, untrusted_text: str) -> Tuple[str, List[Dict[str, Any]]]:
        """
        Sanitizes untrusted content, removes zero-width hidden characters,
        and defangs any adversarial prompt injection attempts.
        """
        if not untrusted_text or not isinstance(untrusted_text, str):
            return "", []

        # 1. Normalize unicode and strip zero-width stealth characters
        clean = unicodedata.normalize("NFKD", untrusted_text)
        clean = self.ZERO_WIDTH_CHARS.sub("", clean)

        findings = []
        sanitized = clean

        # 2. Match & Defang Prompt Injections
        for rx in self.INJECTION_PATTERNS:
            for match in rx.finditer(clean):
                val = match.group(0)
                findings.append({
                    "type": "INDIRECT_PROMPT_INJECTION",
                    "severity": "CRITICAL",
                    "pattern": val[:60],
                    "action": "DEFANGED"
                })
                # Defang by enclosing in quotes and prepending warning
                sanitized = sanitized.replace(val, f"[TEXTE_SUSPECT_NEUTRALISE_PAR_ULTRON: '{val[:40]}...']")

        if findings:
            log_event("PROMPT_INJECTION_DEFANGED", "CRITICAL", "PROMPT_GUARD",
                      f"{len(findings)} tentative(s) d'injection de prompt indirecte neutralisée(s) avant traitement par l'IA.")
            return sanitized, findings

        return untrusted_text, []

# Global singleton
prompt_guard = PromptGuard()
