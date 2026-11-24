"""
server.py - Standalone Ultron AI Cyber SOC Platform & API Gateway
Runs the autonomous Ultron SOC interface, real-time threat stream, and REST APIs.

Usage:
    python web/server.py
    # or
    python -m web.server --port 8080
"""

import os
import sys
from pathlib import Path
from flask import Flask, request, jsonify, render_template, Response

# Ensure project root is in path
project_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(project_root))

from ultron import init_ultron
from ultron.shield import emergency_shield, ShieldTier
from ultron.virtual_patching import virtual_patch_engine
from ultron.threat_intel import threat_intel
from ultron.ddos_guard import ddos_guard
from ultron.crypto_challenge import crypto_challenge
from ultron.oob_engine import oob_engine
from ultron.spa_crawler import spa_crawler
from ultron.active_prober import active_prober
from ultron.deserialization_guard import deserialization_guard
from ultron.prompt_guard import prompt_guard
from ultron.crypto_audit import crypto_auditor
from ultron.cloud_guard import cloud_guard
from ultron.race_engine import audit_race_condition
from ultron.logic_engine import audit_price_tampering, audit_role_pollution
from ultron.alert_dispatcher import alert_dispatcher
from ultron.ueba_engine import ueba_engine
from ultron.cluster_bus import cluster_bus
from ultron.cloudflare_connector import cloudflare_connector
from ultron.middleware.flask_middleware import UltronShield

app = Flask(
    __name__,
    template_folder=str(project_root / "web" / "templates"),
    static_folder=str(project_root / "web" / "static")
)
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Self-protect the Ultron SOC dashboard with its own shield
UltronShield(app)

# -------------------------------------------------------------
# Web UI Pages
# -------------------------------------------------------------
@app.route("/")
def dashboard_page():
    """Renders the executive standalone Ultron Cyber SOC Dashboard."""
    shield_status = emergency_shield.get_status()
    ti_stats = threat_intel.get_stats()
    ddos_stats = ddos_guard.get_status()
    vp_list = virtual_patch_engine.list_patches()
    cluster_st = cluster_bus.get_cluster_status()

    return render_template(
        "dashboard.html",
        shield=shield_status,
        threat_intel=ti_stats,
        ddos=ddos_stats,
        patches_count=len(vp_list),
        cluster=cluster_st
    )

@app.route("/challenge")
def browser_challenge_page():
    """Serves the autonomous Proof-of-Work browser challenge page."""
    src_ip = request.remote_addr or "unknown"
    target = request.args.get("target", "/")
    challenge = crypto_challenge.generate_challenge(src_ip)
    return crypto_challenge.render_challenge_html(challenge, redirect_target=target)

# -------------------------------------------------------------
# REST APIs
# -------------------------------------------------------------
@app.route("/api/challenge/verify", methods=["POST"])
def verify_challenge_api():
    src_ip = request.remote_addr or "unknown"
    data = request.get_json(silent=True) or {}
    token = data.get("token", "")
    nonce = data.get("nonce", "")

    if crypto_challenge.verify_solution(token, nonce, src_ip):
        clearance = crypto_challenge.issue_clearance_token(src_ip)
        resp = jsonify({"success": True, "message": "Défi cryptographique validé."})
        resp.set_cookie("ultron_clearance", clearance, max_age=86400, httponly=True, samesite="Lax")
        return resp, 200
    return jsonify({"success": False, "error": "Défi invalide ou expiré."}), 400

@app.route("/api/shield/status", methods=["GET"])
def shield_status_api():
    return jsonify(emergency_shield.get_status())

@app.route("/api/threat-intel", methods=["GET", "POST"])
def threat_intel_api():
    if request.method == "POST":
        data = request.get_json(silent=True) or {}
        ip_or_cidr = data.get("ip_or_cidr", "").strip()
        if not ip_or_cidr:
            return jsonify({"error": "ip_or_cidr obligatoire"}), 400
        threat_intel.add_malicious_ip(ip_or_cidr, threat_type=data.get("threat_type", "MANUAL_BLOCK"))
        return jsonify({"success": True, "enlisted": ip_or_cidr}), 201
    return jsonify(threat_intel.get_stats())

@app.route("/api/virtual-patches", methods=["GET", "POST"])
def virtual_patches_api():
    if request.method == "POST":
        data = request.get_json(silent=True) or {}
        res = virtual_patch_engine.create_patch(
            name=data.get("name", "Patch"),
            target_path=data.get("target_path", ".*"),
            block_pattern=data.get("block_pattern", ""),
            action=data.get("action", "BLOCK")
        )
        return jsonify({"success": True, "patch": res}), 201
    return jsonify({"patches": virtual_patch_engine.list_patches()})

@app.route("/api/oob/generate", methods=["POST"])
def oob_generate_api():
    data = request.get_json(silent=True) or {}
    res = oob_engine.generate_token(
        vuln_type=data.get("vuln_type", "blind_ssrf"),
        target=data.get("target", "target_system")
    )
    return jsonify({"success": True, "payload": res})

@app.route("/api/oob/callback/<token>", methods=["GET", "POST", "HEAD"])
def oob_callback_listener(token):
    src_ip = request.remote_addr or "unknown"
    headers = dict(request.headers)
    query = (request.query_string or b"").decode("utf-8", errors="replace")
    matched = oob_engine.record_interaction(token, source_ip=src_ip, method=request.method, headers=headers, query=query)
    if matched:
        return jsonify({"status": "acknowledged", "verified": True}), 200
    return jsonify({"status": "unknown_token"}), 404

@app.route("/api/spa/crawl", methods=["POST"])
def spa_crawl_api():
    data = request.get_json(silent=True) or {}
    url = data.get("target_url")
    if not url:
        return jsonify({"error": "target_url obligatoire"}), 400
    return jsonify(spa_crawler.crawl_target(url))

@app.route("/api/soc/live-stream")
def live_stream_api():
    import json
    def stream():
        q = alert_dispatcher.subscribe_live_stream()
        try:
            yield f"data: {json.dumps({'type': 'CONNECTED', 'message': 'Ultron SOC Live Stream Connecté'})}\\n\\n"
            while True:
                try:
                    event = q.get(timeout=20.0)
                    yield f"data: {json.dumps(event)}\\n\\n"
                except Exception:
                    yield ": keepalive\\n\\n"
        finally:
            alert_dispatcher.unsubscribe_live_stream(q)
    return Response(stream(), mimetype="text/event-stream")


@app.route("/api/probe/active", methods=["POST"])
def active_probe_api():
    """Runs active non-destructive probing (CORS, Verb Tampering, Hidden Params) on a target URL."""
    data = request.get_json(silent=True) or {}
    url = (data.get("target_url") or "").strip()
    if not url:
        return jsonify({"error": "target_url est obligatoire"}), 400
    res = active_prober.run_full_active_probe(url)
    return jsonify(res)


@app.route("/api/audit/crypto", methods=["POST"])
def audit_crypto_api():
    """Audits Python source code for timing attacks and insecure randomness."""
    data = request.get_json(silent=True) or {}
    code = data.get("source_code", "")
    filename = data.get("filename", "app.py")
    findings = crypto_auditor.audit_python_code(code, filename)
    return jsonify({"findings_count": len(findings), "findings": findings})

@app.route("/api/audit/cloud", methods=["GET"])
def audit_cloud_api():
    """Audits environment for exposed cloud metadata or container sockets."""
    return jsonify(cloud_guard.audit_container_environment())

@app.route("/api/guard/prompt-sanitize", methods=["POST"])
def guard_prompt_api():
    """Sanitizes untrusted text and defangs indirect prompt injections."""
    data = request.get_json(silent=True) or {}
    text = data.get("untrusted_text", "")
    sanitized, findings = prompt_guard.inspect_and_sanitize(text)
    return jsonify({"sanitized_text": sanitized, "threats_detected": len(findings), "findings": findings})

if __name__ == "__main__":
    init_ultron()
    port = int(os.environ.get("PORT", 8080))
    print(f"\n=======================================================")
    print(f"  ULTRON CYBER SOC PLATFORM - DÉMARRAGE SUR LE PORT {port}")
    print(f"  Interface Web : http://localhost:{port}")
    print(f"=======================================================\n")
    app.run(host="0.0.0.0", port=port, debug=False)
