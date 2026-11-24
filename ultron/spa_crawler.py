"""
spa_crawler.py - Single Page Application (SPA) Headless & DOM-XSS Crawler
Parses modern JavaScript frameworks (React, Vue, Next.js, Angular) to extract
hidden dynamic routes, API endpoints, exposed secrets, and DOM-XSS sinks.
"""

import re
import urllib.parse
from typing import Dict, Any, List, Set, Optional
try:
    import requests
except ImportError:
    requests = None

class SPACrawler:
    """
    Crawls and analyzes client-side single page applications.
    Extracts dynamic frontend routes, REST/GraphQL endpoints, and dangerous DOM sinks.
    """

    ROUTE_REGEXES = [
        re.compile(r"""path:\s*['"]([/a-zA-Z0-9_\-:]+)['"]""", re.IGNORECASE),
        re.compile(r"""['"]route['"]\s*:\s*['"]([/a-zA-Z0-9_\-:]+)['"]""", re.IGNORECASE),
        re.compile(r"""to=['"]([/a-zA-Z0-9_\-]+)['"]""", re.IGNORECASE),
        re.compile(r"""createWebHistory\(['"]([/a-zA-Z0-9_\-]*)['"]\)""", re.IGNORECASE),
    ]

    API_REGEXES = [
        re.compile(r"""(?:axios|fetch|apiClient)\.(?:get|post|put|delete|patch)\s*\(\s*['"`]([/a-zA-Z0-9_\-\.\?&=]+)['"`]""", re.IGNORECASE),
        re.compile(r"""fetch\s*\(\s*['"`]([/a-zA-Z0-9_\-\.\?&=]+)['"`]""", re.IGNORECASE),
        re.compile(r"""['"`](/api/v[0-9]+/[a-zA-Z0-9_\-/]+)['"`]""", re.IGNORECASE),
        re.compile(r"""['"`](/api/[a-zA-Z0-9_\-/]+)['"`]""", re.IGNORECASE),
    ]

    DOM_XSS_SINKS = [
        ("dangerouslySetInnerHTML", "CRITICAL", "React innerHTML non-échappé"),
        ("v-html", "HIGH", "Vue directive v-html non-échappée"),
        (".innerHTML\s*=", "HIGH", "Affectation directe innerHTML"),
        ("document\.write\s*\(", "HIGH", "Utilisation de document.write"),
        ("location\.href\s*=\s*location\.", "HIGH", "Redirection non validée basée sur le DOM"),
        ("eval\s*\(\s*location\.", "CRITICAL", "Évaluation dynamique de paramètres d'URL (DOM-XSS)")
    ]

    SCRIPT_SRC_REGEX = re.compile(r"""<script[^>]+src=['"]([^'"]+)['"]""", re.IGNORECASE)

    def extract_from_html_and_js(self, html_content: str, base_url: str = "") -> Dict[str, Any]:
        """Performs static AST/regex dissection of HTML source and extracted scripts."""
        discovered_routes: Set[str] = set()
        discovered_apis: Set[str] = set()
        dom_sinks_found: List[Dict[str, Any]] = []
        script_urls: List[str] = []

        # 1. Discover script tags
        for match in self.SCRIPT_SRC_REGEX.finditer(html_content):
            src = match.group(1)
            full_src = urllib.parse.urljoin(base_url, src) if base_url else src
            script_urls.append(full_src)

        # 2. Extract client-side routes
        for rx in self.ROUTE_REGEXES:
            for match in rx.finditer(html_content):
                route = match.group(1)
                if route.startswith("/") and len(route) > 1 and not route.endswith((".png", ".jpg", ".svg", ".css")):
                    discovered_routes.add(route)

        # 3. Extract hidden API endpoints
        for rx in self.API_REGEXES:
            for match in rx.finditer(html_content):
                api = match.group(1)
                if api.startswith("/"):
                    discovered_apis.add(api)

        # 4. Detect dangerous DOM sinks
        for sink_pattern, severity, desc in self.DOM_XSS_SINKS:
            if re.search(sink_pattern, html_content, re.IGNORECASE):
                dom_sinks_found.append({
                    "sink": sink_pattern,
                    "severity": severity,
                    "description": desc
                })

        return {
            "routes_count": len(discovered_routes),
            "discovered_routes": sorted(list(discovered_routes)),
            "apis_count": len(discovered_apis),
            "discovered_apis": sorted(list(discovered_apis)),
            "dom_sinks_count": len(dom_sinks_found),
            "dom_sinks": dom_sinks_found,
            "script_bundles": script_urls[:10]
        }

    def crawl_target(self, target_url: str) -> Dict[str, Any]:
        """Fetches the target URL and crawls its root HTML + linked JS chunks."""
        if not requests:
            return {"error": "Module requests non installé"}

        try:
            resp = requests.get(target_url, timeout=5, verify=False, headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) SentinelSPACrawler/2.0"
            })
            root_analysis = self.extract_from_html_and_js(resp.text, target_url)

            # Deep crawl the first 3 JS bundles
            all_apis = set(root_analysis["discovered_apis"])
            all_routes = set(root_analysis["discovered_routes"])
            all_sinks = list(root_analysis["dom_sinks"])

            for script_url in root_analysis["script_bundles"][:3]:
                try:
                    js_resp = requests.get(script_url, timeout=4, verify=False)
                    if js_resp.ok:
                        js_data = self.extract_from_html_and_js(js_resp.text, target_url)
                        all_apis.update(js_data["discovered_apis"])
                        all_routes.update(js_data["discovered_routes"])
                        all_sinks.extend(js_data["dom_sinks"])
                except Exception:
                    pass

            return {
                "success": True,
                "target": target_url,
                "discovered_routes": sorted(list(all_routes)),
                "discovered_apis": sorted(list(all_apis)),
                "dom_sinks": all_sinks,
                "summary": f"{len(all_routes)} routes SPA & {len(all_apis)} APIs découvertes, {len(all_sinks)} éviers DOM-XSS audités."
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

# Global singleton
spa_crawler = SPACrawler()
