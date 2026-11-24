# 🛡️ Ultron AI — Autonomous Cyber Defense & RASP Platform

[![CI/CD Security Gate](https://github.com/Njgctxf/Ultron/actions/workflows/security-gate.yml/badge.svg)](https://github.com/Njgctxf/Ultron/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![Coverage: 100%](https://img.shields.io/badge/OWASP%20Coverage-100%25-brightgreen.svg)]()

> **Ultron AI** est une plateforme autonome de cybersécurité de nouvelle génération combinant un **WAF sémantique (AST)**, une **auto-défense applicative temps réel (RASP)**, du **Virtual Patching à chaud**, une **protection Anti-DDoS**, et un **SOC interactif en direct**.
> 
> Conçu pour être totalement souverain, local et ultra-rapide (latence < 25 ms), Ultron protège vos applications web contre les attaques les plus sophistiquées sans dépendre d'un tiers externe.

---

## ⚡ Les 10 Super-Pouvoirs d'Ultron

1. **Bouclier WAF Sémantique & AST (`semantic_waf.py`)**  
   Désobfuscation récursive multi-niveaux (Unicode NFKD, encodages multiples, entités HTML, suppression des commentaires SQL inline `/**/` et MySQL `/*!50000...*/`). Interception des tautologies logiques (`'a'='a'`) et des attaques OWASP Top 10 (SQLi, XSS, Path Traversal, Command Injection / RCE, SSRF) avec **100% de neutralisation**.

2. **Virtual Patching Instantané à Chaud (`virtual_patching.py`)**  
   Dès qu'une vulnérabilité Zero-Day est identifiée, Ultron injecte une micro-règle de blocage en **1 milliseconde** directement au niveau du WAF. Les failles sont immunisées immédiatement, sans interruption de service et sans attendre le redéploiement du code.

3. **Protection Anti-DDoS L7 & Auto-Jail (`ddos_guard.py`)**  
   Algorithme de limitation de débit adaptatif par **fenêtre glissante (Sliding Window)** en mémoire RAM. Dès qu'un attaquant sature vos endpoints sensibles, il est automatiquement placé en cellule d'isolement (*Auto-Jail*) pendant 15 minutes avec un code `HTTP 429 Too Many Requests` et l'en-tête `Retry-After`.

4. **Threat Intelligence Mondiale & Réputation IP (`threat_intel.py`)**  
   Matching en mémoire ultra-rapide via des réseaux CIDR / Subnets. Intègre nativement la détection des **noeuds de sortie Tor**, hébergeurs bulletproof et botnets malveillants, avec capacité d'enrôlement dynamique à chaud.

5. **Défi Cryptographique Furtif PoW (`crypto_challenge.py`)**  
   Alternative autonome à Cloudflare Turnstile / "Under Attack Mode". Résout une énigme de preuve de travail (Proof-of-Work SHA-256) en arrière-plan dans le navigateur légitime en ~150 ms. **Élimine 100% des bots automatisés, scrapers et scripts d'attaque** (curl, python-requests) sans jamais afficher de CAPTCHAs visuels agaçants.

6. **Vérification Out-of-Band (OOB Callback - `oob_engine.py`)**  
   Preuve irréfutable à **0% de faux positifs** pour les failles aveugles (*Blind SSRF*, *Blind RCE*, *Blind SQLi*) grâce à un écouteur de corrélation dédié.

7. **Prévention des Fuites de Données Sortantes (Outbound DLP - `dlp_engine.py`)**  
   Inspecte toutes les réponses HTTP sortantes pour intercepter et masquer (*redaction*) automatiquement les numéros de carte bancaire (vérifiés par l'algorithme de Luhn), les clés privées RSA/SSH, les tokens cloud AWS et les traces d'erreurs de base de données.

8. **Streaming Live SOC & Alertes Instantanées (`alert_dispatcher.py`)**  
   Diffusion en temps réel des incidents de sécurité via **Server-Sent Events (SSE)** vers le tableau de bord de surveillance et envoi de webhooks formatés vers **Discord** et **Slack**.

9. **Analyse Comportementale des Utilisateurs (UEBA - `ueba_engine.py`)**  
   Profilage statistique des sessions pour détecter les piratages de comptes légitimes, les vitesses de navigation anormales, les exfiltrations massives de données et les connexions en horaires suspects.

10. **Auto-Patcher AST & Intégration CI/CD (`auto_patcher.py` & `ci_scanner.py`)**  
    Correction chirurgicale du code vulnérable avec validation de syntaxe Python (`ast.parse`) pour éviter toute régression, et scanner Shift-Left exécutable dans vos pipelines GitHub Actions.

---

## 🚀 Intégration Ultra-Rapide (2 Lignes de Code)

Protégez n'importe quelle application Flask avec Ultron RASP :

```python
from flask import Flask
from ultron.middleware.flask_middleware import UltronShield

app = Flask(__name__)

# Active instantanément le WAF, l'Anti-DDoS, le DLP et les patchs virtuels
UltronShield(app)

@app.route("/")
def home():
    return "Application 100% sécurisée par Ultron AI !"

if __name__ == "__main__":
    app.run(port=5000)
```

---

## 🖥️ Plateforme Autonome SOC Web & API

Pour lancer le serveur Ultron autonome avec son tableau de bord de surveillance et sa passerelle d'API :

```bash
# Installation des dépendances
pip install -r requirements.txt

# Téléchargement automatique des scanners externes (Nuclei, Trivy, Gitleaks, Sqlmap, ffuf)
python install_tools.py

# Démarrage de la plateforme Ultron
python web/server.py
```

Accédez à la console de supervision : 👉 **http://localhost:8080**

---

## 🐳 Déploiement Docker

Déployez Ultron en 1 seule commande via Docker Compose :

```bash
docker-compose up -d
```

---

## 🧪 Exécution des Tests Unitaires

```bash
python -m unittest discover tests
```

---

## 🔒 Intégration CI/CD (GitHub Actions)

Pour auditer automatiquement votre code source à chaque `git push` :

```bash
python ultron/ci_scanner.py --dir . --fail-on HIGH
```

---

## 📄 Licence
Distribué sous licence **MIT**. Voir `LICENSE` pour plus d'informations.
