"""
oob_engine.py - Out-Of-Band (OOB) Callback Engine & Interaction Proof
Provides zero-false-positive verification for Blind vulnerabilities (Blind SSRF, Blind RCE, Blind SQLi)
via dedicated callback tokens and listener validation (interactsh / local OAST listener).
"""

import os
import uuid
import time
import json
import logging
from datetime import datetime
from typing import Dict, Any, List, Optional
from .database import get_connection, log_event

logger = logging.getLogger("sentinel.oob")

def init_oob_tables():
    """Initializes tables for OOB token generation and interaction tracking."""
    conn = get_connection()
    c = conn.cursor()
    c.execute("""
    CREATE TABLE IF NOT EXISTS sentinel_oob_tokens (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        token TEXT UNIQUE NOT NULL,
        vuln_type TEXT NOT NULL,
        target TEXT NOT NULL,
        parameter TEXT,
        created_at TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        interacted INTEGER DEFAULT 0,
        interaction_count INTEGER DEFAULT 0
    )
    """)

    c.execute("""
    CREATE TABLE IF NOT EXISTS sentinel_oob_interactions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        token TEXT NOT NULL,
        source_ip TEXT NOT NULL,
        method TEXT NOT NULL,
        headers_json TEXT NOT NULL,
        query_string TEXT,
        timestamp TEXT NOT NULL
    )
    """)
    conn.commit()
    conn.close()

class OOBEngine:
    """
    Manages OOB interaction tokens and correlates callbacks to provide definitive exploit proof.
    """

    def __init__(self):
        init_oob_tables()

    def generate_token(self, vuln_type: str, target: str, parameter: str = "") -> Dict[str, Any]:
        """Generates a high-entropy unique interaction token and payload URLs."""
        token = f"oob_{uuid.uuid4().hex[:16]}"
        now = datetime.now()
        created_at = now.strftime("%Y-%m-%d %H:%M:%S")
        expires_at = (now + (datetime.fromtimestamp(time.time() + 3600) - now)).strftime("%Y-%m-%d %H:%M:%S")

        conn = get_connection()
        c = conn.cursor()
        c.execute("""
        INSERT INTO sentinel_oob_tokens (token, vuln_type, target, parameter, created_at, expires_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """, (token, vuln_type, target, parameter, created_at, expires_at))
        conn.commit()
        conn.close()

        # Build payload URL templates
        callback_path = f"/__sc/security/api/sentinel/oob/callback/{token}"
        dns_payload = f"{token}.oast.site-cloner.local"

        return {
            "token": token,
            "vuln_type": vuln_type,
            "target": target,
            "callback_path": callback_path,
            "dns_payload": dns_payload,
            "http_payload": f"http://127.0.0.1:5006{callback_path}",
            "ssrf_payload": f"http://127.0.0.1:5006{callback_path}",
            "rce_payload": f"curl -s http://127.0.0.1:5006{callback_path} || wget -qO- http://127.0.0.1:5006{callback_path}"
        }

    def record_interaction(self, token: str, source_ip: str, method: str = "GET",
                           headers: Optional[Dict[str, Any]] = None, query: str = "") -> bool:
        """Records an incoming callback from a target system."""
        conn = get_connection()
        c = conn.cursor()

        # Check if token exists
        c.execute("SELECT id, vuln_type, target FROM sentinel_oob_tokens WHERE token = ?", (token,))
        row = c.fetchone()
        if not row:
            conn.close()
            return False

        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        c.execute("""
        INSERT INTO sentinel_oob_interactions (token, source_ip, method, headers_json, query_string, timestamp)
        VALUES (?, ?, ?, ?, ?, ?)
        """, (token, source_ip, method, json.dumps(headers or {}), query, now_str))

        c.execute("""
        UPDATE sentinel_oob_tokens
        SET interacted = 1, interaction_count = interaction_count + 1
        WHERE token = ?
        """, (token,))

        conn.commit()
        conn.close()

        log_event("OOB_INTERACTION_RECEIVED", "CRITICAL", "OOB_ENGINE",
                  f"Interaction OOB confirmée pour le jeton {token} depuis {source_ip} (Type: {row['vuln_type']})")
        return True

    def verify_interaction(self, token: str) -> Dict[str, Any]:
        """Queries if a callback was received for the given token."""
        conn = get_connection()
        c = conn.cursor()
        c.execute("""
        SELECT token, vuln_type, target, parameter, interacted, interaction_count, created_at
        FROM sentinel_oob_tokens WHERE token = ?
        """, (token,))
        row = c.fetchone()

        if not row:
            conn.close()
            return {"verified": False, "error": "Jeton introuvable"}

        interactions = []
        if row["interacted"]:
            c.execute("""
            SELECT source_ip, method, headers_json, timestamp
            FROM sentinel_oob_interactions WHERE token = ? ORDER BY id DESC LIMIT 5
            """, (token,))
            interactions = [dict(r) for r in c.fetchall()]

        conn.close()
        return {
            "verified": bool(row["interacted"]),
            "token": row["token"],
            "vuln_type": row["vuln_type"],
            "target": row["target"],
            "interaction_count": row["interaction_count"],
            "interactions": interactions
        }

# Global singleton
oob_engine = OOBEngine()
