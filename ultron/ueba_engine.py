"""
ueba_engine.py - User and Entity Behavior Analytics (UEBA)
Tracks statistical baselines per session/user to detect account takeover,
credential stuffing, data exfiltration spikes, and abnormal access patterns.
"""

import time
import math
from datetime import datetime
from typing import Dict, Any, List, Optional
from .database import get_connection, log_event

def init_ueba_tables():
    """Initializes tables for UEBA user baselines."""
    conn = get_connection()
    c = conn.cursor()
    c.execute("""
    CREATE TABLE IF NOT EXISTS sentinel_ueba_profiles (
        user_or_session TEXT PRIMARY KEY,
        first_seen TEXT NOT NULL,
        last_seen TEXT NOT NULL,
        total_requests INTEGER DEFAULT 0,
        known_ips_json TEXT DEFAULT '[]',
        data_exports_count INTEGER DEFAULT 0,
        anomaly_score INTEGER DEFAULT 0
    )
    """)
    conn.commit()
    conn.close()

class UEBAEngine:
    """
    Computes real-time behavioral anomaly scores without needing malicious attack payloads.
    """

    def __init__(self):
        init_ueba_tables()
        self._session_cache = {}

    def analyze_event(self, identifier: str, source_ip: str, endpoint: str,
                      bytes_out: int = 0) -> Dict[str, Any]:
        """Calculates an anomaly score (0-100) based on velocity, unusual hours, and data spikes."""
        if not identifier:
            return {"anomaly_score": 0, "flagged": False}

        now = time.time()
        hour = datetime.now().hour
        score = 0
        reasons = []

        # 1. Unusual hour detection (01:00 - 05:00)
        if 1 <= hour <= 5:
            score += 25
            reasons.append("Activité en heures anormales (01h-05h)")

        # 2. Velocity & burst tracking
        history = self._session_cache.setdefault(identifier, [])
        cutoff = now - 60
        history = [ts for ts in history if ts > cutoff]
        history.append(now)
        self._session_cache[identifier] = history

        reqs_per_min = len(history)
        if reqs_per_min > 80:
            score += 45
            reasons.append(f"Vitesse anormale de navigation ({reqs_per_min} req/min)")
        elif reqs_per_min > 40:
            score += 20
            reasons.append(f"Fréquence élevée de requêtes ({reqs_per_min} req/min)")

        # 3. Mass data export / scraping spike
        if bytes_out > 2000000 or any(e in endpoint for e in ("/export", "/download", "/dump", "/backup")):
            score += 35
            reasons.append("Volume d'exfiltration ou tentative de dump de données détecté")

        score = min(score, 100)
        flagged = score >= 65

        if flagged:
            log_event("UEBA_ANOMALY_DETECTED", "WARN", "UEBA_ENGINE",
                      f"Comportement anormal détecté pour '{identifier}' (Score: {score}/100) : {', '.join(reasons)}")

        return {
            "identifier": identifier,
            "anomaly_score": score,
            "flagged": flagged,
            "reasons": reasons,
            "reqs_per_min": reqs_per_min
        }

# Global singleton
ueba_engine = UEBAEngine()
