"""
cloudflare_connector.py - Cloudflare Edge Bridge & Direct Threat Sync
Bridges Ultron's local brain with Cloudflare's global edge network (330 datacenters)
by pushing blocked IPs, rate limits, and virtual patches directly into Cloudflare's API.
"""

import os
import json
import logging
from datetime import datetime
from typing import Dict, Any, List, Optional
from .database import get_connection, log_event

try:
    import requests
except ImportError:
    requests = None

logger = logging.getLogger("sentinel.cloudflare")

def init_cloudflare_tables():
    """Initializes table for Cloudflare credentials and edge sync history."""
    conn = get_connection()
    c = conn.cursor()
    c.execute("""
    CREATE TABLE IF NOT EXISTS sentinel_cloudflare_config (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        api_token TEXT NOT NULL DEFAULT '',
        zone_id TEXT NOT NULL DEFAULT '',
        is_active INTEGER NOT NULL DEFAULT 0,
        auto_sync_blocks INTEGER NOT NULL DEFAULT 1,
        last_sync TEXT
    )
    """)
    c.execute("""
    CREATE TABLE IF NOT EXISTS sentinel_cloudflare_sync_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        rule_type TEXT NOT NULL,
        target_value TEXT NOT NULL,
        cf_rule_id TEXT,
        status TEXT NOT NULL,
        timestamp TEXT NOT NULL
    )
    """)

    c.execute("SELECT id FROM sentinel_cloudflare_config WHERE id = 1")
    if not c.fetchone():
        c.execute("""
        INSERT INTO sentinel_cloudflare_config (id, api_token, zone_id, is_active, auto_sync_blocks, last_sync)
        VALUES (1, '', '', 0, 1, NULL)
        """)
    conn.commit()
    conn.close()

class CloudflareConnector:
    """
    Connects to Cloudflare API v4 to enforce edge blocking and rule synchronization.
    """

    def __init__(self):
        init_cloudflare_tables()

    def get_config(self) -> Dict[str, Any]:
        """Returns the current Cloudflare configuration."""
        conn = get_connection()
        c = conn.cursor()
        c.execute("SELECT api_token, zone_id, is_active, auto_sync_blocks, last_sync FROM sentinel_cloudflare_config WHERE id = 1")
        row = c.fetchone()
        conn.close()
        if row:
            token = row["api_token"]
            masked = f"{token[:4]}...{token[-4:]}" if len(token) > 8 else ("Configuré" if token else "Non configuré")
            return {
                "configured": bool(token and row["zone_id"]),
                "api_token_masked": masked,
                "zone_id": row["zone_id"],
                "is_active": bool(row["is_active"]),
                "auto_sync_blocks": bool(row["auto_sync_blocks"]),
                "last_sync": row["last_sync"]
            }
        return {"configured": False}

    def save_config(self, api_token: str, zone_id: str, is_active: bool = True, auto_sync_blocks: bool = True) -> bool:
        """Saves Cloudflare API credentials."""
        conn = get_connection()
        c = conn.cursor()
        c.execute("""
        UPDATE sentinel_cloudflare_config
        SET api_token = ?, zone_id = ?, is_active = ?, auto_sync_blocks = ?
        WHERE id = 1
        """, (api_token.strip(), zone_id.strip(), 1 if is_active else 0, 1 if auto_sync_blocks else 0))
        conn.commit()
        conn.close()
        log_event("CLOUDFLARE_CONFIG_UPDATED", "INFO", "CLOUDFLARE_BRIDGE", "Paramètres Cloudflare Edge mis à jour.")
        return True

    def push_ip_block_to_edge(self, ip_str: str, reason: str = "Bloqué par Ultron Sentinel") -> Dict[str, Any]:
        """Pushes an IP block rule directly into Cloudflare's IP Access Rules (Global Edge)."""
        cfg = self.get_config()
        if not cfg.get("configured") or not cfg.get("is_active"):
            return {
                "success": False,
                "synced_to_edge": False,
                "message": "Passerelle Cloudflare inactive ou non configurée. Blocage appliqué localement par Ultron."
            }

        # Query raw config for actual token
        conn = get_connection()
        c = conn.cursor()
        c.execute("SELECT api_token, zone_id FROM sentinel_cloudflare_config WHERE id = 1")
        row = c.fetchone()
        conn.close()

        token = row["api_token"]
        zone_id = row["zone_id"]

        if not requests:
            return {"success": False, "error": "Module requests indisponible"}

        url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/firewall/access_rules/rules"
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        }
        data = {
            "mode": "block",
            "configuration": {"target": "ip", "value": ip_str},
            "notes": f"Ultron Auto-Defense: {reason[:60]}"
        }

        try:
            resp = requests.post(url, json=data, headers=headers, timeout=6)
            res_data = resp.json()
            success = resp.status_code in (200, 201) and res_data.get("success", False)
            cf_rule_id = (res_data.get("result") or {}).get("id")

            # Log sync event
            conn = get_connection()
            c = conn.cursor()
            c.execute("""
            INSERT INTO sentinel_cloudflare_sync_log (rule_type, target_value, cf_rule_id, status, timestamp)
            VALUES ('IP_BLOCK', ?, ?, ?, ?)
            """, (ip_str, cf_rule_id or "ERROR", "SYNCED" if success else "FAILED", datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
            conn.commit()
            conn.close()

            return {
                "success": success,
                "synced_to_edge": True,
                "cf_rule_id": cf_rule_id,
                "message": f"IP '{ip_str}' synchronisée et bannie sur les 330 datacenters Cloudflare." if success else res_data.get("errors")
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

# Global singleton
cloudflare_connector = CloudflareConnector()
