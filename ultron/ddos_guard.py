"""
ddos_guard.py - High-Performance Sliding Window Anti-DDoS & Adaptive Throttling
Guards applications against HTTP floods, brute force, and layer-7 denial-of-service
using an in-memory sliding window rate limiter and automatic IP jailing.
"""

import time
import threading
from typing import Dict, Any, List, Optional, Tuple
from .database import log_event

class DDoSGuard:
    """
    Sliding window rate-limiter and layer-7 DoS mitigator.
    """

    def __init__(self, default_limit: int = 60, window_seconds: int = 60, jail_seconds: int = 900):
        self.default_limit = default_limit      # requests allowed per window
        self.window_seconds = window_seconds    # 60s window
        self.jail_seconds = jail_seconds        # 15 minutes jail time on repeated breach
        self._history = {}                      # ip -> list of timestamps
        self._jailed = {}                       # ip -> jail expiration timestamp
        self._lock = threading.Lock()

    def inspect_ip(self, ip_str: str, route_path: str = "") -> Optional[Dict[str, Any]]:
        """
        Evaluates incoming request from ip_str.
        Returns block payload if rate limit exceeded or IP is jailed.
        """
        if not ip_str or ip_str in ("127.0.0.1", "::1", "localhost"):
            return None

        now = time.time()

        with self._lock:
            # 1. Check if IP is currently in Jail
            if ip_str in self._jailed:
                exp = self._jailed[ip_str]
                if now < exp:
                    remaining = int(exp - now)
                    return {
                        "blocked": True,
                        "status_code": 429,
                        "reason": f"IP temporairement isolée pour saturation DoS. Réessayez dans {remaining} secondes.",
                        "retry_after": remaining
                    }
                else:
                    del self._jailed[ip_str]

            # 2. Sliding window check
            timestamps = self._history.get(ip_str, [])
            # Prune timestamps older than window
            cutoff = now - self.window_seconds
            timestamps = [ts for ts in timestamps if ts > cutoff]

            # Sensitive routes (login, register, api) have tighter limits
            limit = 20 if any(s in route_path for s in ("/login", "/register", "/auth", "/api/")) else self.default_limit

            if len(timestamps) >= limit:
                # Exceeded! Put into Jail
                jail_until = now + self.jail_seconds
                self._jailed[ip_str] = jail_until
                self._history[ip_str] = timestamps
                log_event("DDOS_JAIL_TRIGGERED", "CRITICAL", "DDOS_GUARD",
                          f"Seuil de requêtes dépassé ({len(timestamps)}/{limit}) par {ip_str}. Mise en cellule d'isolement pour {self.jail_seconds}s.")
                return {
                    "blocked": True,
                    "status_code": 429,
                    "reason": f"Seuil de trafic dépassé (Anti-DDoS). IP isolée pour {self.jail_seconds}s.",
                    "retry_after": self.jail_seconds
                }

            timestamps.append(now)
            self._history[ip_str] = timestamps

        return None

    def unjail_ip(self, ip_str: str) -> bool:
        """Manually releases an IP from jail."""
        with self._lock:
            if ip_str in self._jailed:
                del self._jailed[ip_str]
                return True
        return False

    def get_status(self) -> Dict[str, Any]:
        """Returns active rate limiter stats."""
        now = time.time()
        with self._lock:
            active_jailed = {ip: int(exp - now) for ip, exp in self._jailed.items() if exp > now}
            active_tracked = len(self._history)
        return {
            "jailed_ips_count": len(active_jailed),
            "jailed_ips": active_jailed,
            "tracked_ips_count": active_tracked,
            "window_seconds": self.window_seconds,
            "default_limit": self.default_limit
        }

# Global singleton
ddos_guard = DDoSGuard()
