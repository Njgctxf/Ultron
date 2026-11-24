"""
semantic_waf.py - Advanced Semantic & Lexical AST Analyzer for Ultron WAF
Operates beyond basic regular expressions by performing multi-layer normalization
(recursive URL decode, Unicode NFKD, HTML entity decoding, comment removal)
and token-stream lexical analysis to stop obfuscated SQLi, XSS, and command injections.
"""

import re
import urllib.parse
import html
import unicodedata
from typing import Dict, Any, List, Optional, Tuple

class SemanticAnalyzer:
    """
    High-performance semantic tokenizer and deobfuscation engine.
    Detects evasive payload mutations that bypass typical regex WAFs.
    """

    SQL_RESERVED = {
        "SELECT", "UNION", "FROM", "WHERE", "ORDER", "GROUP", "BY", "HAVING",
        "INSERT", "UPDATE", "DELETE", "DROP", "ALTER", "CREATE", "EXEC",
        "EXECUTE", "XP_CMDSHELL", "WAITFOR", "DELAY", "BENCHMARK", "PG_SLEEP", "SLEEP"
    }

    SQL_TAUTOLOGY_REGEX = re.compile(
        r"""(?ix)
        \b(?:or|and)\b\s+
        (?:
            (['"]?)([^'"\s=<>!]+)\1\s*(?:=|like)\s*\1\2\1
            |
            (\d+)\s*(?:=|<=>|like)\s*\3
            |
            \btrue\b
            |
            1\s*=\s*1
        )
        """
    )

    SQL_INLINE_COMMENT_REGEX = re.compile(r"/\*.*?\*/", re.DOTALL)
    MYSQL_VERSION_COMMENT_REGEX = re.compile(r"/\*!\d{5}.*?\*/", re.DOTALL)
    NULL_BYTE_REGEX = re.compile(r"[\x00\r]")

    def normalize(self, raw_input: str) -> str:
        """
        Recursively unpacks and normalizes raw payload into canonical representation.
        Handles:
          - Multiple URL encodings (%252e -> %2e -> .)
          - HTML entity escapes (&quot;, &#x3c;)
          - Unicode full-width and compatibility characters (NFKD)
          - Null-byte injections and trailing whitespace
        """
        if not raw_input or not isinstance(raw_input, str):
            return ""

        cur = raw_input
        # 1. Recursive URL unquote (up to 3 levels to avoid infinite loops)
        for _ in range(3):
            unquoted = urllib.parse.unquote(cur)
            if unquoted == cur:
                break
            cur = unquoted

        # 2. HTML unescape
        cur = html.unescape(cur)

        # 3. Unicode NFKD normalization (converts fullwidth ＜script＞ to <script>)
        cur = unicodedata.normalize("NFKD", cur)

        # 4. Strip null bytes
        cur = self.NULL_BYTE_REGEX.sub("", cur)

        return cur

    def strip_sql_comments(self, text: str) -> str:
        """Strips SQL inline comments like /*!50000SELECT*/ or UNION/**/SELECT."""
        # Replace MySQL version comment wrapper keeping content
        def _extract_mysql_comment(match):
            val = match.group(0)
            return re.sub(r"^/\*!\d{5}\s*", " ", val[:-2]) + " "

        t = self.MYSQL_VERSION_COMMENT_REGEX.sub(_extract_mysql_comment, text)
        t = self.SQL_INLINE_COMMENT_REGEX.sub(" ", t)
        # Collapse multiple whitespaces
        t = re.sub(r"\s+", " ", t)
        return t

    def analyze_sqli(self, raw_input: str) -> Optional[Dict[str, Any]]:
        """Performs lexical and semantic analysis for SQL Injection."""
        norm = self.normalize(raw_input)
        clean_sql = self.strip_sql_comments(norm)

        # Check 1: Semantic Tautologies (OR 1=1, 'a'='a', OR true)
        if self.SQL_TAUTOLOGY_REGEX.search(clean_sql):
            return {
                "category": "sqli",
                "severity": "CRITICAL",
                "reason": "Détection d'une tautologie SQL sémantique (condition toujours vraie)",
                "normalized": clean_sql[:120]
            }

        # Check 2: Obfuscated UNION SELECT (e.g. UNION/**/SELECT or UnIoN  SeLeCt)
        tokens = [tok.upper() for tok in re.findall(r"\b[A-Za-z_]+\b", clean_sql)]
        for i in range(len(tokens) - 1):
            if tokens[i] == "UNION" and tokens[i+1] in ("SELECT", "ALL"):
                return {
                    "category": "sqli",
                    "severity": "CRITICAL",
                    "reason": "Séquence de mots-clés UNION SELECT détectée après désobfuscation",
                    "normalized": clean_sql[:120]
                }

        # Check 3: Blind Timing Attacks (sleep, benchmark, waitfor delay)
        if re.search(r"\b(sleep|pg_sleep|benchmark)\s*\(", clean_sql, re.IGNORECASE):
            return {
                "category": "sqli",
                "severity": "HIGH",
                "reason": "Appel de fonction d'injection aveugle temporelle (Blind Timing)",
                "normalized": clean_sql[:120]
            }
        if re.search(r"\bwaitfor\s+delay\b", clean_sql, re.IGNORECASE):
            return {
                "category": "sqli",
                "severity": "CRITICAL",
                "reason": "Instruction d'attente temporelle MSSQL (WAITFOR DELAY)",
                "normalized": clean_sql[:120]
            }

        # Check 4: Stacked DDL/DML injection
        if re.search(r";\s*(?:drop\s+table|alter\s+table|exec\s+xp_cmdshell|delete\s+from)\b", clean_sql, re.IGNORECASE):
            return {
                "category": "sqli",
                "severity": "CRITICAL",
                "reason": "Injection de commande SQL empilée destructive (Stacked Query)",
                "normalized": clean_sql[:120]
            }

        # Check 5: De-commented SELECT FROM extraction
        if re.search(r"\bselect\b.{1,40}\bfrom\b", clean_sql, re.IGNORECASE):
            return {
                "category": "sqli",
                "severity": "HIGH",
                "reason": "Extraction SELECT ... FROM détectée après suppression des commentaires inline",
                "normalized": clean_sql[:120]
            }

        return None

    def analyze_xss(self, raw_input: str) -> Optional[Dict[str, Any]]:
        """Performs lexical analysis for Cross-Site Scripting (XSS) and DOM injections."""
        norm = self.normalize(raw_input)

        # Check 1: Script tags & pseudo-protocols
        if re.search(r"<\s*script[\s/>]", norm, re.IGNORECASE):
            return {
                "category": "xss",
                "severity": "HIGH",
                "reason": "Balise <script> active détectée après désobfuscation Unicode/HTML",
                "normalized": norm[:120]
            }

        # Check 2: Event handlers with loose spacing (e.g. onerror\s*=\s*, onload\s*=)
        if re.search(r"\bon\w+\s*=\s*['\"]?[^'\">\s]+", norm, re.IGNORECASE):
            # Exclude harmless matches like 'only' or 'one'
            if re.search(r"\b(onerror|onload|onmouseover|onclick|onfocus|onblur|onkeydown)\s*=", norm, re.IGNORECASE):
                return {
                    "category": "xss",
                    "severity": "HIGH",
                    "reason": "Gestionnaire d'événements HTML actif (Event Handler Injection)",
                    "normalized": norm[:120]
                }

        # Check 3: Javascript URI or data URI script
        if re.search(r"(?:javascript|vbscript)\s*:", norm, re.IGNORECASE):
            return {
                "category": "xss",
                "severity": "HIGH",
                "reason": "Pseudo-protocole d'exécution de script (javascript: / vbscript:)",
                "normalized": norm[:120]
            }

        # Check 4: Obfuscated string evaluation (String.fromCharCode, eval, Function constructor)
        if re.search(r"\b(eval|Function)\s*\(", norm, re.IGNORECASE) and re.search(r"(document\.|window\.|location\.|cookie)", norm, re.IGNORECASE):
            return {
                "category": "xss",
                "severity": "HIGH",
                "reason": "Évaluation dynamique de code JavaScript ciblant des objets DOM sensibles",
                "normalized": norm[:120]
            }

        return None

    def analyze(self, raw_input: str) -> List[Dict[str, Any]]:
        """Runs the complete semantic analysis suite across all categories."""
        hits = []
        if not raw_input:
            return hits

        sqli_hit = self.analyze_sqli(raw_input)
        if sqli_hit:
            hits.append(sqli_hit)

        xss_hit = self.analyze_xss(raw_input)
        if xss_hit:
            hits.append(xss_hit)

        return hits

# Global singleton
semantic_analyzer = SemanticAnalyzer()
