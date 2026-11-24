"""
cloud_guard.py - Cloud Metadata & Container Socket Protection Engine
Guards applications against Cloud Instance Metadata abuse (AWS IMDSv1/v2, GCP, Azure),
Kubernetes service account token extraction, and Docker socket exposure.
"""

import re
import os
from typing import Dict, Any, List, Optional
from .database import log_event

class CloudGuard:
    """
    Blocks cloud metadata extraction and audits container escape vectors.
    """

    CLOUD_METADATA_IPS = [
        "169.254.169.254",                      # AWS / GCP / OpenStack / Azure
        "metadata.google.internal",             # Google Cloud
        "169.254.169.250",                      # AWS ECS task metadata
        "100.100.100.200",                      # Alibaba Cloud
    ]

    SENSITIVE_SOCKETS_AND_PATHS = [
        "/var/run/docker.sock",
        "/run/containerd/containerd.sock",
        "/var/run/secrets/kubernetes.io/serviceaccount",
        "/.aws/credentials",
        "/.kube/config",
        "/.docker/config.json"
    ]

    def inspect_url_target(self, target_url: str) -> Optional[Dict[str, Any]]:
        """Checks if a target URL attempts to probe cloud metadata services."""
        if not target_url:
            return None

        clean = target_url.lower()
        for meta in self.CLOUD_METADATA_IPS:
            if meta in clean:
                log_event("CLOUD_METADATA_PROBE_BLOCKED", "CRITICAL", "CLOUD_GUARD",
                          f"Tentative d'accès au service de métadonnées Cloud '{meta}' bloquée.")
                return {
                    "blocked": True,
                    "category": "cloud_metadata_abuse",
                    "severity": "CRITICAL",
                    "target": meta,
                    "reason": f"Tentative d'exfiltration de métadonnées d'instance cloud ({meta}) neutralisée."
                }
        return None

    def audit_container_environment(self) -> Dict[str, Any]:
        """Audits the local environment to detect exposed container sockets or cloud credentials."""
        exposures = []

        for p in self.SENSITIVE_SOCKETS_AND_PATHS:
            if os.path.exists(p):
                exposures.append({
                    "path": p,
                    "severity": "CRITICAL",
                    "risk": "Fichier ou socket hautement sensible accessible (risque d'évasion de conteneur ou vol IAM)."
                })

        # Check if inside container
        is_container = os.path.exists("/.dockerenv") or os.path.exists("/run/.containerenv")

        return {
            "is_container": is_container,
            "exposures_count": len(exposures),
            "exposures": exposures,
            "status": "VULNERABLE" if exposures else "HARDENED"
        }

# Global singleton
cloud_guard = CloudGuard()
