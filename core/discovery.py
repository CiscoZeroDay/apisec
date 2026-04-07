# core/discovery.py
"""
APIDiscovery — Détection et crawling d'APIs (REST | GraphQL | SOAP | Unknown)

Phase 1 : Détection du type d'API via système de scoring
Phase 2 : Crawling des endpoints (wordlist + Swagger/OpenAPI + WSDL)
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

from core.requester import Requester
from logger.logger import logger


# ─────────────────────────────────────────────────────────────────────────────
#  Constantes — chemins de détection
# ─────────────────────────────────────────────────────────────────────────────

GRAPHQL_PATHS: list[str] = [
    "/graphql", "/api/graphql", "/query",
    "/gql", "/graphql/v1", "/v1/graphql",
]

SWAGGER_PATHS: list[str] = [
    "/swagger.json",          "/swagger/v1/swagger.json",
    "/openapi.json",          "/api/openapi.json",
    "/api-docs",              "/api/docs",
    "/v1/swagger.json",       "/v2/swagger.json",
    "/v3/api-docs",           "/docs/openapi.json",
]

WSDL_PATHS: list[str] = [
    "/?wsdl",        "/service?wsdl",  "/api?wsdl",
    "/ws?wsdl",      "/soap?wsdl",     "/webservice?wsdl",
    "/soap",         "/ws",            "/webservice",
    "/service",      "/RPC",           "/endpoint",
]

REST_VERSION_PATHS: list[str] = [
    "/api", "/api/v1", "/api/v2", "/api/v3",
    "/v1",  "/v2",     "/v3",
]

COMMON_REST_PATHS: list[str] = [
    "/users",    "/posts",     "/products", "/items",
    "/todos",    "/comments",  "/articles", "/orders",
    "/accounts", "/auth",      "/health",   "/status",
]

# Enveloppe SOAP minimale pour test de détection
_SOAP_PROBE = (
    '<?xml version="1.0" encoding="utf-8"?>'
    '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">'
    "<soap:Body/>"
    "</soap:Envelope>"
)
_SOAP_HEADERS = {"Content-Type": "text/xml; charset=utf-8"}

# Seuils de scoring
_GQL_THRESHOLD  = 4
_GQL_MAX_SCORE  = 9
_REST_THRESHOLD = 2
_REST_MAX_SCORE = 6
_SOAP_THRESHOLD = 4
_SOAP_MAX_SCORE = 7


# ─────────────────────────────────────────────────────────────────────────────
#  DetectionResult
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class DetectionResult:
    """Résultat structuré de la détection du type d'API."""

    api_type:   str              # "REST" | "GraphQL" | "SOAP" | "Unknown"
    confidence: float            # 0.0 – 1.0
    score:      int
    reasons:    list[str] = field(default_factory=list)

    def __str__(self) -> str:
        pct = int(self.confidence * 100)
        tag = f"{self.api_type} ({pct}%)"
        if self.reasons:
            tag += " — " + ", ".join(self.reasons)
        return tag

    def to_dict(self) -> dict:
        return {
            "api_type":   self.api_type,
            "confidence": self.confidence,
            "score":      self.score,
            "reasons":    self.reasons,
        }


# ─────────────────────────────────────────────────────────────────────────────
#  APIDiscovery
# ─────────────────────────────────────────────────────────────────────────────

class APIDiscovery:
    """
    Détecte le type d'une API distante et crawle ses endpoints.

    Utilisation :
        discovery = APIDiscovery("https://api.example.com")
        result    = discovery.run("wordlist.txt", mode="quick")
        print(result)
    """

    def __init__(self, base_url: str, timeout: int = 5) -> None:
        self.base_url  = base_url.rstrip("/")
        self.http      = Requester(self.base_url, timeout=timeout)
        self.api_type  = "Unknown"

        # Résultats accumulés
        self.tech_stack:        list[str] = []
        self.endpoints:         list[str] = []
        self.swagger_endpoints: list[str] = []

    # =========================================================================
    #  Helpers internes
    # =========================================================================

    def _is_real_html(self, r) -> bool:
        """
        True seulement si la réponse est vraiment du HTML pur.
        Évite de pénaliser une API REST dont le Content-Type est mal configuré.
        """
        ct = r.headers.get("Content-Type", "")
        if "html" not in ct and "xml" not in ct:
            return False
        try:
            r.json()
            return False   # JSON valide malgré le mauvais Content-Type
        except Exception:
            return True    # Vraiment du HTML/XML

    def _contains_xml(self, r) -> bool:
        """True si la réponse contient du XML (détection SOAP)."""
        ct = r.headers.get("Content-Type", "")
        if "xml" in ct or "soap" in ct:
            return True
        # Vérification légère du corps
        try:
            text = r.text[:200]
            return "<?xml" in text or "<soap:" in text or "<wsdl:" in text
        except Exception:
            return False

    @staticmethod
    def _safe_json(r) -> Optional[dict | list]:
        """Parse JSON sans lever d'exception."""
        try:
            return r.json()
        except Exception:
            return None

    # =========================================================================
    #  PHASE 1 — Scoring SOAP
    # =========================================================================

    def _score_soap(self) -> tuple[int, list[str]]:
        score:   int       = 0
        reasons: list[str] = []

        # Signal 1 : WSDL
        for path in WSDL_PATHS:
            r = self.http.get(path)
            if r is None or r.status_code != 200:
                continue

            ct  = r.headers.get("Content-Type", "").lower()
            has_xml_ct   = any(t in ct for t in ("xml", "wsdl", "soap"))
            has_xml_body = self._contains_xml(r)

            if not (has_xml_ct or has_xml_body):
                continue

            # Tente de lire le corps pour confirmer
            try:
                text = r.content.decode("utf-8", errors="ignore").lower()
            except Exception:
                text = ""

            WSDL_KEYWORDS = (
                "wsdl", "definitions", "porttype",
                "binding", "soap", "targetnamespace",
                "webservice", "operation",
            )

            matched = [k for k in WSDL_KEYWORDS if k in text]

            if len(matched) >= 2:
                # Confirmation forte — plusieurs mots-clés WSDL trouvés
                score += 4
                reasons.append(f"WSDL confirmé sur {path} ({', '.join(matched[:3])})")
                return score, reasons   # certitude maximale

            elif len(matched) == 1:
                # Confirmation partielle
                score += 3
                reasons.append(f"WSDL probable sur {path} ({matched[0]})")
                return score, reasons

            elif has_xml_ct:
                # XML dans Content-Type mais pas de mots-clés WSDL
                score += 2
                reasons.append(f"XML Content-Type sur {path}")

            elif has_xml_body:
                # XML détecté dans le corps seulement
                score += 2
                reasons.append(f"XML détecté dans le corps sur {path}")

        # Signal 2 : POST avec enveloppe SOAP
        for path in ["/soap", "/ws", "/service", "/api", "/endpoint", "/"]:
            r = self.http.post(path, data=_SOAP_PROBE, headers=_SOAP_HEADERS)
            if r is None:
                continue

            if self._contains_xml(r):
                score += 3
                reasons.append(f"Réponse XML/SOAP sur POST {path}")
                break

            if "SOAPAction" in r.headers:
                score += 2
                reasons.append(f"Header SOAPAction présent sur {path}")
                break
        return score, reasons
    

    # =========================================================================
    #  PHASE 1 — Scoring GraphQL
    # =========================================================================

    def _score_graphql(self) -> tuple[int, list[str]]:
        """
        Signaux GraphQL — signaux forts et non ambigus uniquement.

        Règle anti-biais :
          - 400/422 seul  → ignoré  (toute API REST répond 400 sur /graphql)
          - data/errors   → compté seulement si status 200
          - break         → seulement sur introspection __schema confirmée
        """
        score:   int       = 0
        reasons: list[str] = []

        for path in GRAPHQL_PATHS:

            # Signal 1 : POST { __typename } → 200 JSON
            r = self.http.post(path, json={"query": "{ __typename }"})
            if r is None:
                continue

            if r.status_code == 200 and Requester.is_json(r):
                score += 3
                reasons.append(f"POST {path} → 200 JSON")

                # Signal 2 : corps contient "data" ou "errors" (conditionnel au 200)
                body = self._safe_json(r)
                if isinstance(body, dict) and ("data" in body or "errors" in body):
                    score += 2
                    reasons.append(f'Corps "{path}" contient data/errors')

            # Signal 3 : introspection __schema (signal le plus fort)
            r_intro = self.http.post(
                path,
                json={"query": "{ __schema { queryType { name } } }"},
            )
            if r_intro and r_intro.status_code == 200:
                body_intro = self._safe_json(r_intro)
                if (
                    isinstance(body_intro, dict)
                    and body_intro.get("data", {}).get("__schema")
                ):
                    score += 4
                    reasons.append(f"Introspection __schema réussie sur {path}")
                    return score, reasons   # certitude maximale

        return score, reasons

    # =========================================================================
    #  PHASE 1 — Scoring REST
    # =========================================================================

    def _score_rest(self) -> tuple[int, list[str]]:
        """
        Signaux REST progressifs avec malus HTML.
        """
        score:          int       = 0
        reasons:        list[str] = []
        has_json_signal: bool     = False

        # Signal 1 : GET /
        r = self.http.get("/")
        if r and r.status_code == 200:
            if Requester.is_json(r):
                score += 2
                reasons.append("GET / → 200 JSON")
                has_json_signal = True
            else:
                score += 1
                reasons.append("GET / → 200")

            body = self._safe_json(r)
            if isinstance(body, (list, dict)) and "data" not in (body or {}):
                score += 1
                has_json_signal = True
                reasons.append("Corps JSON sans enveloppe GraphQL")

        # Signal 2 : endpoints versionnés
        for path in REST_VERSION_PATHS:
            rv = self.http.get(path)
            if rv and rv.status_code in (200, 201, 401, 403):
                score += 2
                reasons.append(f"GET {path} → {rv.status_code}")
                break

        # Signal 3 : endpoints REST courants
        for path in COMMON_REST_PATHS:
            rv = self.http.get(path)
            if rv and rv.status_code == 200 and Requester.is_json(rv):
                score += 2
                has_json_signal = True
                reasons.append(f"GET {path} → 200 JSON")
                break

        # Signal 4 : OPTIONS /
        ro = self.http.options("/")
        if ro and "Allow" in ro.headers:
            allow = ro.headers["Allow"]
            # Vérifie que les verbes REST classiques sont présents
            if any(v in allow for v in ("GET", "POST", "PUT", "DELETE")):
                score += 1
                reasons.append(f"OPTIONS / → Allow: {allow}")

        # Malus HTML — seulement si AUCUN signal JSON trouvé
        if not has_json_signal:
            r2 = self.http.get("/")
            if r2 and self._is_real_html(r2):
                score -= 1
                reasons.append("Contenu HTML pur (malus)")

        return score, reasons

    # =========================================================================
    #  PHASE 1 — Décision finale
    # =========================================================================

    def detect_api_type(self) -> DetectionResult:
        """
        Compare les scores SOAP / GraphQL / REST et retourne un DetectionResult.

        Priorité :
          1. SOAP    : score >= 4
          2. GraphQL : score >= 4 ET score > rest_score
          3. REST    : score >= 2
          4. Unknown : sinon
        """
        logger.info("[*] Detecting API type...")

        soap_score, soap_reasons = self._score_soap()
        gql_score,  gql_reasons  = self._score_graphql()
        rest_score, rest_reasons = self._score_rest()

        logger.debug(f"    SOAP    score = {soap_score}")
        logger.debug(f"    GraphQL score = {gql_score}")
        logger.debug(f"    REST    score = {rest_score}")

        if soap_score >= _SOAP_THRESHOLD:
            result = DetectionResult(
                api_type   = "SOAP",
                confidence = round(min(soap_score / _SOAP_MAX_SCORE, 1.0), 2),
                score      = soap_score,
                reasons    = soap_reasons,
            )
        elif gql_score >= _GQL_THRESHOLD and gql_score > rest_score:
            result = DetectionResult(
                api_type   = "GraphQL",
                confidence = round(min(gql_score / _GQL_MAX_SCORE, 1.0), 2),
                score      = gql_score,
                reasons    = gql_reasons,
            )
        elif rest_score >= _REST_THRESHOLD:
            result = DetectionResult(
                api_type   = "REST",
                confidence = round(min(rest_score / _REST_MAX_SCORE, 1.0), 2),
                score      = rest_score,
                reasons    = rest_reasons,
            )
        else:
            result = DetectionResult(
                api_type   = "Unknown",
                confidence = 0.0,
                score      = max(soap_score, gql_score, rest_score),
                reasons    = soap_reasons + gql_reasons + rest_reasons,
            )

        self.api_type = result.api_type
        logger.info(f"[+] {result}")
        return result

    # =========================================================================
    #  Détection de la stack technique
    # =========================================================================

    def detect_technology(self) -> list[str]:
        """
        Lit les headers HTTP pour deviner la stack technique.
        Retourne la liste des technologies détectées.
        """
        r = self.http.get("/")
        if not r:
            return []

        server     = r.headers.get("Server",       "").lower()
        powered_by = r.headers.get("X-Powered-By", "").lower()
        via        = r.headers.get("Via",           "").lower()

        checks = [
            ("nginx",    "Nginx",              server),
            ("apache",   "Apache",             server),
            ("express",  "Node.js (Express)",  server),
            ("express",  "Node.js (Express)",  powered_by),
            ("django",   "Django",             server),
            ("django",   "Django",             powered_by),
            ("rails",    "Ruby on Rails",      server),
            ("php",      "PHP",                powered_by),
            ("laravel",  "Laravel",            powered_by),
            ("next.js",  "Next.js",            powered_by),
            ("fastapi",  "FastAPI",            server),
            ("uvicorn",  "FastAPI/Uvicorn",    server),
            ("flask",    "Flask",              server),
            ("gunicorn", "Gunicorn",           server),
            ("iis",      "IIS (Microsoft)",    server),
            ("tomcat",   "Apache Tomcat",      server),
            ("jetty",    "Jetty",              server),
            ("spring",   "Spring Boot",        powered_by),
            ("caddy",    "Caddy",              server),
            ("cloudflare","Cloudflare",        via),
        ]

        seen: set[str] = set()
        for keyword, label, source in checks:
            if keyword in source and label not in seen:
                self.tech_stack.append(label)
                seen.add(label)

        return self.tech_stack

    # =========================================================================
    #  PHASE 2 — Swagger / OpenAPI
    # =========================================================================

    def parse_swagger(self) -> list[str]:
        """
        Cherche un fichier Swagger/OpenAPI et extrait tous les endpoints.
        Retourne une liste d'URLs complètes.
        """
        found: list[str] = []

        for path in SWAGGER_PATHS:
            r = self.http.get(path)
            if r is None or r.status_code != 200:
                continue

            spec = self._safe_json(r)
            if not spec or not isinstance(spec, dict):
                continue

            paths = spec.get("paths", {})
            if not paths:
                continue

            logger.info(f"[+] Swagger/OpenAPI trouvé sur {path} — {len(paths)} paths")

            # Support OpenAPI 2.x (basePath) et 3.x (servers)
            base = spec.get("basePath", "")
            if not base:
                servers = spec.get("servers", [])
                if servers:
                    server_url = servers[0].get("url", "")
                    # Garde uniquement le path si l'URL est absolue
                    if server_url.startswith("http"):
                        from urllib.parse import urlparse
                        base = urlparse(server_url).path.rstrip("/")
                    else:
                        base = server_url.rstrip("/")

            for endpoint_path in paths:
                full_url = self.base_url + base + endpoint_path
                if full_url not in found:
                    found.append(full_url)
                    logger.debug(f"    [swagger] {full_url}")

            break   # spec valide trouvé → inutile de continuer

        self.swagger_endpoints = found
        return found

    # =========================================================================
    #  PHASE 2 — Crawling wordlist
    # =========================================================================

    def crawl_endpoints(
        self,
        wordlist_path: str,
        limit: Optional[int] = None,
    ) -> list[str]:
        """
        Teste chaque chemin de la wordlist par GET.
        Filtre les faux positifs : catch-all, redirects auth, HTML pur, body dupliqué.

        Args:
            wordlist_path : chemin vers le fichier de wordlist
            limit         : nombre maximum de chemins à tester (None = tous)

        Returns:
            Liste des URLs accessibles (sans faux positifs).
        """
        import hashlib

        # ── Lecture & déduplication wordlist ─────────────────────────────────
        try:
            with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
                raw_paths = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            logger.error(f"[crawl] Wordlist introuvable : {wordlist_path}")
            return []

        seen_paths: set[str] = set()
        paths: list[str] = []
        for p in raw_paths:
            if p not in seen_paths:
                seen_paths.add(p)
                paths.append(p)

        total = len(paths) if limit is None else min(limit, len(paths))
        logger.info(f"[*] Crawling {total} paths...")

        # ── Baseline catch-all ────────────────────────────────────────────────
        # Teste un chemin aléatoire pour fingerprinter la réponse "inexistante"
        # Si le serveur retourne 200 sur n'importe quoi → on filtre par comparaison
        baseline = self._get_baseline()
        if baseline.get("status") == 200:
            logger.warning("[crawl] Serveur catch-all détecté — filtrage renforcé activé")

        # ── État interne ──────────────────────────────────────────────────────
        already_known: set[str] = set(self.endpoints + self.swagger_endpoints)
        found_this_run: list[str] = []   # endpoints trouvés dans CE crawl uniquement
        seen_bodies:    set[str] = set() # hashes des bodies déjà vus (déduplication contenu)
        count = 0

        for path in paths:
            if limit is not None and count >= limit:
                break

            count += 1

            # Normalise le chemin
            if not path.startswith("/"):
                path = "/" + path

            url = self.base_url + path

            # Évite les doublons d'URL
            if url in already_known:
                continue

            r = self.http.get(path, allow_redirects=False)
            if r is None:
                continue

            # ── Filtres faux positifs ─────────────────────────────────────────

            # Filtre 1 — status >= 400 → pas un endpoint
            if r.status_code >= 400:
                continue

            # Filtre 2 — redirect vers page d'auth → faux positif
            if self._is_redirect_to_auth(r):
                logger.debug(f"    [FP-redirect] {path}")
                continue

            # Filtre 3 — catch-all / même fingerprint que la baseline 404
            if self._is_false_positive(r, baseline):
                logger.debug(f"    [FP-baseline] {path}")
                continue

            # Filtre 4 — HTML pur (frontend SPA servi sur /api/*)
            if self._is_html_frontend(r):
                logger.debug(f"    [FP-html] {path}")
                continue

            # Filtre 5 — body identique à un endpoint déjà trouvé
            body_hash = hashlib.md5(r.content).hexdigest()
            if body_hash in seen_bodies:
                logger.debug(f"    [FP-duplicate-body] {path}")
                continue

            # ── Endpoint confirmé ─────────────────────────────────────────────
            seen_bodies.add(body_hash)
            already_known.add(url)
            found_this_run.append(url)
            self.endpoints.append(url)
            logger.info(f"    [crawl] {r.status_code} → {url}")

        logger.info(f"[+] Crawl terminé — {len(found_this_run)} nouveaux endpoints trouvés")
        return self.endpoints


    # ── Helpers appelés par crawl_endpoints ───────────────────────────────────────

    def _get_baseline(self) -> dict:
        import hashlib, uuid
        fake_path = f"/xXx{uuid.uuid4().hex[:8]}xXx"
        r = self.http.get(fake_path, allow_redirects=False)
        if r is None:
            return {}

        return {
            "status":         r.status_code,
            "body_hash":      hashlib.md5(r.content).hexdigest(),
            "content_length": len(r.content),
            "content_type":   r.headers.get("Content-Type", ""),
            "is_html":        "text/html" in r.headers.get("Content-Type", ""),
        }


    def _is_false_positive(self, r, baseline: dict) -> bool:
        import hashlib
        if not baseline:
            return False

        body_hash      = hashlib.md5(r.content).hexdigest()
        content_length = len(r.content)
        content_type   = r.headers.get("Content-Type", "")

        # Si la baseline est du HTML (SPA) ET que la réponse est du JSON → garder
        if baseline.get("is_html") and "application/json" in content_type:
            return False

        # Si la baseline est du HTML ET que la réponse est aussi du HTML → FP
        if baseline.get("is_html") and "text/html" in content_type:
            return True

        # Même hash exact → FP
        if body_hash == baseline.get("body_hash"):
            return True

        # Même taille → FP probable
        if content_length == baseline.get("content_length") and content_length > 0:
            return True

        # Body trop court
        if content_length < 10:
            return True

        return False

    def _is_redirect_to_auth(self, r) -> bool:
        """
        True si la réponse est une redirection vers une page d'authentification.
        Un redirect vers /login n'est pas un endpoint API accessible.
        """
        if r.status_code not in (301, 302, 303, 307, 308):
            return False

        location = r.headers.get("Location", "").lower()
        auth_patterns = ["/login", "/signin", "/auth", "/connect", "/sso", "/oauth"]
        return any(p in location for p in auth_patterns)

    def _is_html_frontend(self, r) -> bool:
        ct = r.headers.get("Content-Type", "")
        if "text/html" not in ct:
            return False
        try:
            r.json()
            return False  # JSON valide → garder
        except Exception:
            return True

    # =========================================================================
    #  run() — Orchestrateur principal
    # =========================================================================

    def run(self, wordlist_path: str, mode: str = "quick") -> dict:
        """
        Lance la découverte complète dans l'ordre :
          1. detect_api_type()    — REST | GraphQL | SOAP | Unknown
          2. detect_technology()  — stack technique via headers
          3. parse_swagger()      — endpoints Swagger/OpenAPI
          4. crawl_endpoints()    — wordlist

        Args:
            wordlist_path : chemin vers la wordlist
            mode          : "quick" (50 paths) | "full" (wordlist complète)

        Returns:
            dict avec tous les résultats.
        """
        logger.info(f"[*] Starting discovery on {self.base_url}")

        # 1. Type d'API
        detection = self.detect_api_type()

        # 2. Stack technique
        self.detect_technology()
        if self.tech_stack:
            logger.info(f"[+] Tech stack : {', '.join(self.tech_stack)}")

        # 3. Swagger / OpenAPI
        swagger_found = self.parse_swagger()

        # 4. Crawl wordlist
        limit = 50 if mode == "quick" else None
        self.crawl_endpoints(wordlist_path, limit=limit)

        # Fusion sans doublons : swagger en premier
        all_endpoints = list(dict.fromkeys(swagger_found + self.endpoints))

        return {
            "api_type":          self.api_type,
            "confidence":        detection.confidence,
            "score":             detection.score,
            "reasons":           detection.reasons,
            "tech_stack":        self.tech_stack,
            "endpoints":         all_endpoints,
            "swagger_endpoints": swagger_found,
            "crawled_endpoints": self.endpoints,
        }