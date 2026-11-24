"""
alert_dispatcher.py - Real-Time SOC Alert Dispatcher & Webhook Notification Engine
Broadcasts high-priority security incidents to Discord, Slack, and SSE live streams.
"""

import json
import queue
import logging
from datetime import datetime
from typing import Dict, Any, List, Optional
from .database import get_connection, log_event

try:
    import requests
except ImportError:
    requests = None

logger = logging.getLogger("sentinel.alerts")

def init_alert_tables():
    """Initializes tables for alert destinations and incident dispatch logs."""
    conn = get_connection()
    c = conn.cursor()
    c.execute("""
    CREATE TABLE IF NOT EXISTS sentinel_alert_destinations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        channel_type TEXT NOT NULL, -- 'DISCORD', 'SLACK', 'WEBHOOK'
        webhook_url TEXT NOT NULL,
        is_active INTEGER NOT NULL DEFAULT 1,
        created_at TEXT NOT NULL
    )
    """)
    conn.commit()
    conn.close()

class AlertDispatcher:
    """
    Dispatches alerts to external channels and streams events to web dashboards.
    """

    def __init__(self):
        init_alert_tables()
        self._sse_listeners: List[queue.Queue] = []

    def subscribe_live_stream(self) -> queue.Queue:
        """Subscribes an SSE connection to live incident stream."""
        q = queue.Queue(maxsize=100)
        self._sse_listeners.append(q)
        return q

    def unsubscribe_live_stream(self, q: queue.Queue):
        """Unsubscribes a listener."""
        if q in self._sse_listeners:
            self._sse_listeners.remove(q)

    def broadcast_incident(self, attack_type: str, severity: str, source_ip: str,
                           details: str = "", target: str = "") -> Dict[str, Any]:
        """Broadcasts incident to active SSE listeners and external webhooks."""
        event_payload = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "attack_type": attack_type,
            "severity": severity,
            "source_ip": source_ip,
            "details": details[:200],
            "target": target
        }

        # 1. Broadcast to SSE WebSockets/listeners
        dead_queues = []
        for q in self._sse_listeners:
            try:
                q.put_nowait(event_payload)
            except Exception:
                dead_queues.append(q)
        for dq in dead_queues:
            self.unsubscribe_live_stream(dq)

        # 2. Dispatch to registered Webhooks (Discord / Slack)
        self._dispatch_to_webhooks(event_payload)
        return {"broadcasted": True, "listeners_count": len(self._sse_listeners)}

    def _dispatch_to_webhooks(self, event: Dict[str, Any]):
        """Sends formatted messages to Discord/Slack webhooks."""
        if not requests:
            return

        conn = get_connection()
        c = conn.cursor()
        c.execute("SELECT name, channel_type, webhook_url FROM sentinel_alert_destinations WHERE is_active = 1")
        dests = [dict(r) for r in c.fetchall()]
        conn.close()

        for d in dests:
            try:
                url = d["webhook_url"]
                ch = d["channel_type"].upper()

                if ch == "DISCORD":
                    payload = {
                        "username": "Ultron Sentinel SOC",
                        "embeds": [{
                            "title": f"🚨 ALERTE CYBER : {event['attack_type']}",
                            "description": f"**Détails :** {event['details']}\n**IP Attaquante :** `{event['source_ip']}`\n**Cible :** `{event['target']}`",
                            "color": 15158332 if event["severity"] == "CRITICAL" else 15844367,
                            "timestamp": datetime.utcnow().isoformat()
                        }]
                    }
                else:  # Slack / generic webhook
                    payload = {
                        "text": f"🚨 *[ULTRON SOC ALERTE - {event['severity']}]* {event['attack_type']} depuis `{event['source_ip']}` sur `{event['target']}` : {event['details']}"
                    }

                requests.post(url, json=payload, timeout=3)
            except Exception as e:
                logger.warning(f"Échec envoi webhook {d['name']}: {e}")

    def add_destination(self, name: str, channel_type: str, webhook_url: str) -> Dict[str, Any]:
        """Registers a new webhook destination."""
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        conn = get_connection()
        c = conn.cursor()
        c.execute("""
        INSERT INTO sentinel_alert_destinations (name, channel_type, webhook_url, is_active, created_at)
        VALUES (?, ?, ?, 1, ?)
        """, (name, channel_type.upper(), webhook_url.strip(), now))
        conn.commit()
        new_id = c.lastrowid
        conn.close()
        return {"id": new_id, "name": name, "status": "ACTIVE"}

    def list_destinations(self) -> List[Dict[str, Any]]:
        """Lists all configured alert destinations."""
        conn = get_connection()
        c = conn.cursor()
        c.execute("SELECT id, name, channel_type, is_active, created_at FROM sentinel_alert_destinations")
        rows = [dict(r) for r in c.fetchall()]
        conn.close()
        return rows

# Global singleton
alert_dispatcher = AlertDispatcher()
