"""
threat_intel.py - Global Threat Intelligence & IP Reputation Engine
Mirrors Cloudflare's global IP reputation feeds locally by tracking known malicious IPs,
Tor exit nodes, open proxies, cloud scrapers, and high-frequency attack subnets in SQLite.
"""

import ipaddress
import logging
import time
from datetime import datetime
from typing import Dict, Any, List, Optional, Set
from .database import get_connection, log_event

logger = logging.getLogger("sentinel.threat_intel")

# Curated bootstrap reputation list of high-risk IP ranges (Tor exit nodes, bulletproof hosting, botnets)
BOOTSTRAP_MALICIOUS_RANGES = [
    # Known high-abuse test ranges / mock intelligence feeds
    "198.51.100.0/24",    # RFC 5737 Test-Net-2
    "203.0.113.0/24",     # RFC 5737 Test-Net-3
    "185.220.101.0/24",   # Tor Exit node cluster
    "185.220.102.0/24",   # Tor Exit node cluster
    "194.26.29.0/24",     # Bulletproof scanning cluster
    "45.146.164.0/24",    # Automated scanner range
    "103.251.167.0/24",   # Botnet command range
]

def init_threat_intel_tables():
    """Initializes threat intelligence tables."""
    conn = get_connection()
    c = conn.cursor()
    c.execute("""
    CREATE TABLE IF NOT EXISTS sentinel_threat_reputation (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip_or_cidr TEXT UNIQUE NOT NULL,
        threat_type TEXT NOT NULL,
        reputation_score INTEGER NOT NULL DEFAULT 90,
        source_feed TEXT NOT NULL,
        hits_blocked INTEGER DEFAULT 0,
        created_at TEXT NOT NULL,
        last_seen TEXT NOT NULL
    )
    """)
    conn.commit()

    # Pre-populate bootstrap ranges if empty
    c.execute("SELECT COUNT(*) FROM sentinel_threat_reputation")
    count = c.fetchone()[0]
    if count == 0:
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        for cidr in BOOTSTRAP_MALICIOUS_RANGES:
            c.execute("""
            INSERT OR IGNORE INTO sentinel_threat_reputation
            (ip_or_cidr, threat_type, reputation_score, source_feed, created_at, last_seen)
            VALUES (?, 'KNOWN_SCANNER_BOTNET', 95, 'UltronGlobalThreatFeed', ?, ?)
            """, (cidr, now, now))
        conn.commit()

    conn.close()

class ThreatIntelligence:
    """
    High-performance IP reputation checker using CIDR networks in-memory.
    """

    def __init__(self):
        init_threat_intel_tables()
        self._networks_cache = []
        self._exact_ips_cache = set()
        self.refresh_cache()

    def refresh_cache(self):
        """Loads CIDR subnets and exact IPs into memory for microsecond matching."""
        conn = get_connection()
        c = conn.cursor()
        c.execute("SELECT ip_or_cidr, threat_type, reputation_score FROM sentinel_threat_reputation")
        rows = c.fetchall()
        conn.close()

        networks = []
        exact_ips = set()
        for r in rows:
            entry = r["ip_or_cidr"].strip()
            if "/" in entry:
                try:
                    net = ipaddress.ip_network(entry, strict=False)
                    networks.append((net, r["threat_type"], r["reputation_score"], entry))
                except Exception:
                    pass
            else:
                exact_ips.add(entry)

        self._networks_cache = networks
        self._exact_ips_cache = exact_ips

    def check_ip(self, ip_str: str) -> Optional[Dict[str, Any]]:
        """Checks if an IP address is flagged in the global threat intelligence feeds."""
        if not ip_str or ip_str in ("127.0.0.1", "::1", "localhost"):
            return None

        # 1. Exact match fast path
        if ip_str in self._exact_ips_cache:
            self._increment_block_hit(ip_str)
            return {
                "blocked": True,
                "ip": ip_str,
                "threat_type": "EXACT_IP_MATCH",
                "reputation_score": 100,
                "reason": "Adresse IP répertoriée dans la Threat Intelligence Ultron."
            }

        # 2. Subnet / CIDR match
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            for net, threat_type, score, cidr_str in self._networks_cache:
                if ip_obj in net:
                    self._increment_block_hit(cidr_str)
                    return {
                        "blocked": True,
                        "ip": ip_str,
                        "matched_subnet": cidr_str,
                        "threat_type": threat_type,
                        "reputation_score": score,
                        "reason": f"Sous-réseau malveillant identifié ({cidr_str} - {threat_type})"
                    }
        except Exception:
            pass

        return None

    def _increment_block_hit(self, ip_or_cidr: str):
        """Updates block counter asynchronously."""
        try:
            conn = get_connection()
            c = conn.cursor()
            c.execute("UPDATE sentinel_threat_reputation SET hits_blocked = hits_blocked + 1 WHERE ip_or_cidr = ?", (ip_or_cidr,))
            conn.commit()
            conn.close()
        except Exception:
            pass

    def add_malicious_ip(self, ip_or_cidr: str, threat_type: str = "MALICIOUS_PROBE", score: int = 90) -> bool:
        """Manually or dynamically enlists an IP/subnet into the threat intelligence database."""
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        conn = get_connection()
        c = conn.cursor()
        c.execute("""
        INSERT OR REPLACE INTO sentinel_threat_reputation
        (ip_or_cidr, threat_type, reputation_score, source_feed, created_at, last_seen)
        VALUES (?, ?, ?, 'DynamicIncidentCorrelation', ?, ?)
        """, (ip_or_cidr.strip(), threat_type, score, now, now))
        conn.commit()
        conn.close()
        self.refresh_cache()
        log_event("THREAT_INTEL_ENLISTED", "WARN", "THREAT_INTEL",
                  f"Entrée '{ip_or_cidr}' enregistrée dans la Threat Intelligence (Type: {threat_type}).")
        return True

    def get_stats(self) -> Dict[str, Any]:
        """Returns intelligence feed volume and blocked hits."""
        conn = get_connection()
        c = conn.cursor()
        c.execute("SELECT COUNT(*), SUM(hits_blocked) FROM sentinel_threat_reputation")
        total_ranges, total_blocked = c.fetchone()
        conn.close()
        return {
            "total_intel_ranges": total_ranges or 0,
            "total_threat_hits_blocked": total_blocked or 0,
            "in_memory_subnets": len(self._networks_cache)
        }

# Global singleton
threat_intel = ThreatIntelligence()
