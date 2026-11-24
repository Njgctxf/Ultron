"""
flask_middleware.py - Instant 2-Line Integration of Ultron RASP for Flask
Protects any Flask application with Inbound WAF, Threat Intelligence, Anti-DDoS,
Virtual Patching, and Outbound Data Loss Prevention (DLP).

Usage:
    from flask import Flask
    from ultron.middleware.flask_middleware import UltronShield

    app = Flask(__name__)
    UltronShield(app)
"""

from flask import request, Response
from ..semantic_waf import semantic_analyzer
from ..waf_signatures import inspect_request
from ..virtual_patching import virtual_patch_engine
from ..threat_intel import threat_intel
from ..ddos_guard import ddos_guard
from ..dlp_engine import dlp_engine
from ..deserialization_guard import deserialization_guard
from ..cloud_guard import cloud_guard
from ..alert_dispatcher import alert_dispatcher

class UltronShield:
    """
    Complete Autonomous Runtime Application Self-Protection (RASP) middleware.
    """

    def __init__(self, app=None):
        if app is not None:
            self.init_app(app)

    def init_app(self, app):
        """Registers before_request and after_request security hooks."""
        app.before_request(self.before_request_hook)
        app.after_request(self.after_request_hook)

    def before_request_hook(self):
        """Inbound protection: Threat Intel, Anti-DDoS, Virtual Patches & Semantic WAF."""
        client_ip = request.remote_addr or "unknown"
        path = request.path
        method = request.method
        query = (request.query_string or b"").decode("utf-8", errors="replace")

        body = ""
        try:
            if method in ("POST", "PUT", "PATCH") and (request.content_length or 0) < 50000:
                body = request.get_data(as_text=True, parse_form_data=False) or ""
        except Exception:
            body = ""

        # 1. Threat Intelligence IP check
        ti_hit = threat_intel.check_ip(client_ip)
        if ti_hit:
            alert_dispatcher.broadcast_incident("THREAT_INTEL_BLOCKED", "HIGH", client_ip, ti_hit["reason"], path)
            return Response(f"Accès refusé par Ultron Sentinel : {ti_hit['reason']}", 403, mimetype="text/plain")

        # 2. Anti-DDoS & Adaptive Throttling
        ddos_hit = ddos_guard.inspect_ip(client_ip, path)
        if ddos_hit:
            return Response(f"Ultron Anti-DDoS : {ddos_hit['reason']}", 429,
                            headers={"Retry-After": str(ddos_hit.get("retry_after", 900))}, mimetype="text/plain")

        # 2.5 Insecure Deserialization & Cloud Metadata Abuse Guard
        deser_hit = deserialization_guard.inspect_payload(body or query)
        if deser_hit:
            alert_dispatcher.broadcast_incident("DESERIALIZATION_ATTACK", "CRITICAL", client_ip, deser_hit["reason"], path)
            return Response(f"Attaque neutralisée par Ultron : {deser_hit['reason']}", 403,
                            headers={"X-Ultron-Threat": "insecure_deserialization"}, mimetype="text/plain")

        cloud_hit = cloud_guard.inspect_url_target(query)
        if cloud_hit:
            alert_dispatcher.broadcast_incident("CLOUD_METADATA_PROBE", "CRITICAL", client_ip, cloud_hit["reason"], path)
            return Response(f"Attaque neutralisée par Ultron : {cloud_hit['reason']}", 403,
                            headers={"X-Ultron-Threat": "cloud_metadata_abuse"}, mimetype="text/plain")

        # 3. Virtual Patching Check
        vp_hit = virtual_patch_engine.inspect_request(method, path, query, body)
        if vp_hit:
            alert_dispatcher.broadcast_incident("VIRTUAL_PATCH_TRIGGERED", "CRITICAL", client_ip, vp_hit["patch_name"], path)
            return Response(f"Accès bloqué par Ultron Virtual Patch : {vp_hit['patch_name']}", 403,
                            headers={"X-Ultron-Virtual-Patch": vp_hit["patch_id"]}, mimetype="text/plain")

        # 4. Semantic WAF & AST Inspection
        waf_hits = inspect_request(method, path, query, body, dict(request.headers))
        if waf_hits:
            hit = waf_hits[0]
            alert_dispatcher.broadcast_incident(f"WAF_ATTACK_{hit['category'].upper()}", hit["severity"], client_ip, hit["pattern"], path)
            return Response(f"Attaque neutralisée par le Bouclier Ultron : [{hit['category'].upper()}]", 403,
                            headers={"X-Ultron-Threat-Detected": hit["category"]}, mimetype="text/plain")

        return None

    def after_request_hook(self, response):
        """Outbound protection: Data Loss Prevention (DLP)."""
        try:
            ctype = response.headers.get("Content-Type", "")
            if any(t in ctype for t in ("text", "json", "html")) and not response.direct_passthrough:
                text = response.get_data(as_text=True)
                sanitized, leaks = dlp_engine.sanitize_response(text, ctype)
                if leaks:
                    response.set_data(sanitized)
                    response.headers["X-Ultron-DLP-Protected"] = "true"
        except Exception:
            pass
        return response
