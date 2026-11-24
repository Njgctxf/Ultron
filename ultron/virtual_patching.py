"""
virtual_patching.py - Instant Runtime Virtual Patching Engine
Enforces instantaneous, zero-downtime protective micro-rules at the WAF level
to immunize vulnerable endpoints immediately upon vulnerability discovery,
protecting applications before source-code patches are merged.
"""

import re
import uuid
import logging
from datetime import datetime
from typing import Dict, Any, List, Optional
from .database import get_connection, log_event

logger = logging.getLogger("sentinel.virtual_patch")

def init_virtual_patch_tables():
    """Initializes tables for instant virtual patching rules."""
    conn = get_connection()
    c = conn.cursor()
    c.execute("""
    CREATE TABLE IF NOT EXISTS sentinel_virtual_patches (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        target_path TEXT NOT NULL,
        http_method TEXT NOT NULL DEFAULT '*',
        parameter_target TEXT,
        block_pattern TEXT NOT NULL,
        action TEXT NOT NULL DEFAULT 'BLOCK',
        vulnerability_ref TEXT,
        hits_blocked INTEGER DEFAULT 0,
        is_active INTEGER DEFAULT 1,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    )
    """)
    conn.commit()
    conn.close()

class VirtualPatchEngine:
    """
    Manages and enforces instant virtual patches across endpoints.
    """

    def __init__(self):
        init_virtual_patch_tables()
        self._compiled_cache = {}
        self._refresh_cache()

    def _refresh_cache(self):
        """Loads and compiles active virtual patches in-memory for microsecond enforcement."""
        conn = get_connection()
        c = conn.cursor()
        c.execute("""
        SELECT id, name, target_path, http_method, parameter_target, block_pattern, action
        FROM sentinel_virtual_patches WHERE is_active = 1
        """)
        rows = c.fetchall()
        conn.close()

        cache = []
        for r in rows:
            try:
                path_re = re.compile(r["target_path"], re.IGNORECASE)
                block_re = re.compile(r["block_pattern"], re.IGNORECASE)
                cache.append({
                    "id": r["id"],
                    "name": r["name"],
                    "path_re": path_re,
                    "method": r["http_method"].upper(),
                    "param": r["parameter_target"],
                    "block_re": block_re,
                    "action": r["action"]
                })
            except Exception as e:
                logger.warning(f"Impossible de compiler le patch {r['id']}: {e}")
        self._compiled_cache = cache

    def create_patch(self, name: str, target_path: str, block_pattern: str,
                     http_method: str = "*", parameter_target: str = "",
                     vulnerability_ref: str = "", action: str = "BLOCK") -> Dict[str, Any]:
        """Creates and activates an instant virtual patch."""
        patch_id = f"vp_{uuid.uuid4().hex[:10]}"
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        conn = get_connection()
        c = conn.cursor()
        c.execute("""
        INSERT INTO sentinel_virtual_patches
        (id, name, target_path, http_method, parameter_target, block_pattern, action, vulnerability_ref, hits_blocked, is_active, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, 1, ?, ?)
        """, (patch_id, name, target_path, http_method, parameter_target, block_pattern, action, vulnerability_ref, now, now))
        conn.commit()
        conn.close()

        self._refresh_cache()
        log_event("VIRTUAL_PATCH_ACTIVATED", "INFO", "VIRTUAL_PATCH",
                  f"Patch virtuel '{name}' ({patch_id}) activé sur '{target_path}'.")
        return {"id": patch_id, "name": name, "status": "ACTIVE"}

    def inspect_request(self, method: str, path: str, query: str = "", body: str = "") -> Optional[Dict[str, Any]]:
        """
        Fast-path check against all compiled virtual patches.
        Returns match metadata if request must be blocked.
        """
        method = (method or "GET").upper()
        payload_blob = f"{query} {body}"

        for p in self._compiled_cache:
            # 1. Match HTTP Method
            if p["method"] != "*" and p["method"] != method:
                continue

            # 2. Match Target Path
            if not p["path_re"].search(path):
                continue

            # 3. Match Attack Pattern
            if p["block_re"].search(payload_blob):
                # Increment hit counter
                try:
                    conn = get_connection()
                    c = conn.cursor()
                    c.execute("UPDATE sentinel_virtual_patches SET hits_blocked = hits_blocked + 1 WHERE id = ?", (p["id"],))
                    conn.commit()
                    conn.close()
                except Exception:
                    pass

                return {
                    "blocked": True,
                    "patch_id": p["id"],
                    "patch_name": p["name"],
                    "action": p["action"]
                }

        return None

    def list_patches(self) -> List[Dict[str, Any]]:
        """Returns all virtual patches and their operational stats."""
        conn = get_connection()
        c = conn.cursor()
        c.execute("""
        SELECT id, name, target_path, http_method, parameter_target, block_pattern, action,
               vulnerability_ref, hits_blocked, is_active, created_at, updated_at
        FROM sentinel_virtual_patches ORDER BY created_at DESC
        """)
        rows = [dict(r) for r in c.fetchall()]
        conn.close()
        return rows

    def toggle_patch(self, patch_id: str, is_active: bool) -> bool:
        """Enables or disables an existing virtual patch."""
        conn = get_connection()
        c = conn.cursor()
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        c.execute("UPDATE sentinel_virtual_patches SET is_active = ?, updated_at = ? WHERE id = ?",
                  (1 if is_active else 0, now, patch_id))
        affected = c.rowcount > 0
        conn.commit()
        conn.close()
        self._refresh_cache()
        return affected

# Global singleton
virtual_patch_engine = VirtualPatchEngine()
