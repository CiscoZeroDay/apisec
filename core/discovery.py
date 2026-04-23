# core/discovery.py
"""
APIDiscovery — API detection and crawling (REST | GraphQL | SOAP | Unknown)

Phase 1 : API type detection via scoring system
Phase 2 : Endpoint crawling (wordlist + Swagger/OpenAPI + WSDL)
"""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse

from core.requester import Requester
from logger.logger import logger


# ─────────────────────────────────────────────────────────────────────────────
#  Constants
# ─────────────────────────────────────────────────────────────────────────────

GRAPHQL_PATHS: list[str] = [
    "/graphql", "/api/graphql", "/query",
    "/gql", "/graphql/v1", "/v1/graphql",
]

SWAGGER_PATHS: list[str] = [
    "/swagger.json",        "/swagger/v1/swagger.json",
    "/openapi.json",        "/api/openapi.json",
    "/api-docs",            "/api/docs",
    "/v1/swagger.json",     "/v2/swagger.json",
    "/v3/api-docs",         "/docs/openapi.json",
]

WSDL_PATHS: list[str] = [
    "/?wsdl",       "/service?wsdl", "/api?wsdl",
    "/ws?wsdl",     "/soap?wsdl",    "/webservice?wsdl",
    "/soap",        "/ws",           "/webservice",
    "/service",     "/RPC",          "/endpoint",
]

# Versioned API paths — universal signals for REST detection
REST_VERSION_PATHS: list[str] = [
    "/api", "/api/v1", "/api/v2", "/api/v3",
    "/v1",  "/v2",     "/v3",
]

# Common REST resource paths — universal, not app-specific
# Tested only during scoring, not during crawl
COMMON_REST_PATHS: list[str] = [
    "/users",    "/posts",    "/products", "/items",
    "/todos",    "/comments", "/articles", "/orders",
    "/accounts", "/auth",     "/health",   "/status",
]

# Minimal SOAP envelope for detection probe
_SOAP_PROBE = (
    '<?xml version="1.0" encoding="utf-8"?>'
    '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">'
    "<soap:Body/>"
    "</soap:Envelope>"
)
_SOAP_HEADERS = {"Content-Type": "text/xml; charset=utf-8"}

# Scoring thresholds
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
    """Structured result from API type detection."""

    api_type:   str
    confidence: float
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
    Detects the type of a remote API and crawls its endpoints.

    Usage:
        discovery = APIDiscovery("https://api.example.com")
        result    = discovery.run("wordlist.txt", mode="quick")
        print(result)
    """

    def __init__(self, base_url: str, timeout: int = 5) -> None:
        self.base_url  = base_url.rstrip("/")
        self.http      = Requester(self.base_url, timeout=timeout)
        self.api_type  = "Unknown"

        self.tech_stack:        list[str] = []
        self.endpoints:         list[str] = []
        self.swagger_endpoints: list[str] = []

    # =========================================================================
    #  Internal helpers
    # =========================================================================

    def _is_real_html(self, r) -> bool:
        """True only if response is genuine HTML."""
        ct = r.headers.get("Content-Type", "")
        if "html" not in ct and "xml" not in ct:
            return False
        try:
            r.json()
            return False  # valid JSON despite wrong Content-Type
        except Exception:
            return True

    def _contains_xml(self, r) -> bool:
        """True if response contains XML (SOAP detection)."""
        ct = r.headers.get("Content-Type", "")
        if "xml" in ct or "soap" in ct:
            return True
        try:
            text = r.text[:200]
            return "<?xml" in text or "<soap:" in text or "<wsdl:" in text
        except Exception:
            return False

    @staticmethod
    def _safe_json(r) -> Optional[dict | list]:
        """Parse JSON without raising exceptions."""
        try:
            return r.json()
        except Exception:
            return None

    # =========================================================================
    #  PHASE 1 — SOAP scoring
    # =========================================================================

    def _score_soap(self) -> tuple[int, list[str]]:
        score:   int       = 0
        reasons: list[str] = []

        for path in WSDL_PATHS:
            r = self.http.get(path)
            if r is None or r.status_code != 200:
                continue

            ct           = r.headers.get("Content-Type", "").lower()
            has_xml_ct   = any(t in ct for t in ("xml", "wsdl", "soap"))
            has_xml_body = self._contains_xml(r)

            if not (has_xml_ct or has_xml_body):
                continue

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
                score += 4
                reasons.append(f"WSDL confirmed on {path} ({', '.join(matched[:3])})")
                return score, reasons

            elif len(matched) == 1:
                score += 3
                reasons.append(f"WSDL probable on {path} ({matched[0]})")
                return score, reasons

            elif has_xml_ct:
                score += 2
                reasons.append(f"XML Content-Type on {path}")

            elif has_xml_body:
                score += 2
                reasons.append(f"XML body detected on {path}")

        for path in ["/soap", "/ws", "/service", "/api", "/endpoint", "/"]:
            r = self.http.post(path, data=_SOAP_PROBE, headers=_SOAP_HEADERS)
            if r is None:
                continue
            if self._contains_xml(r):
                score += 3
                reasons.append(f"XML/SOAP response on POST {path}")
                break
            if "SOAPAction" in r.headers:
                score += 2
                reasons.append(f"SOAPAction header on {path}")
                break

        return score, reasons

    # =========================================================================
    #  PHASE 1 — GraphQL scoring
    # =========================================================================

    def _score_graphql(self) -> tuple[int, list[str]]:
        score:   int       = 0
        reasons: list[str] = []

        for path in GRAPHQL_PATHS:
            r = self.http.post(path, json={"query": "{ __typename }"})
            if r is None:
                continue

            if r.status_code == 200 and Requester.is_json(r):
                score += 3
                reasons.append(f"POST {path} → 200 JSON")

                body = self._safe_json(r)
                if isinstance(body, dict) and ("data" in body or "errors" in body):
                    score += 2
                    reasons.append(f'Body "{path}" contains data/errors')

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
                    reasons.append(f"Introspection __schema succeeded on {path}")
                    return score, reasons

        return score, reasons

    # =========================================================================
    #  PHASE 1 — REST scoring
    #
    #  Design principles:
    #  - Only universal signals (no app-specific paths)
    #  - REST_VERSION_PATHS tested in Signal 2 only (no duplication in Signal 3)
    #  - COMMON_REST_PATHS tested in Signal 3 only
    #  - SPA detection: HTML on / + JSON on sub-paths → boost score
    #  - HTML penalty only if zero JSON signals found
    # =========================================================================

    def _score_rest(self) -> tuple[int, list[str]]:
        score:           int       = 0
        reasons:         list[str] = []
        has_json_signal: bool      = False
        has_html_root:   bool      = False

        # Signal 1 — GET /
        r = self.http.get("/")
        if r and r.status_code == 200:
            if Requester.is_json(r):
                score += 2
                reasons.append("GET / → 200 JSON")
                has_json_signal = True
            else:
                score += 1
                reasons.append("GET / → 200")
                if self._is_real_html(r):
                    has_html_root = True
                    logger.debug("[score_rest] HTML root — likely SPA, checking sub-paths...")

            body = self._safe_json(r)
            if isinstance(body, (list, dict)) and "data" not in (body or {}):
                score += 1
                has_json_signal = True
                reasons.append("JSON body without GraphQL envelope")

        # Signal 2 — versioned API paths (/api, /v1, /v2...)
        # Tested here ONLY — not duplicated in Signal 3
        for path in REST_VERSION_PATHS:
            rv = self.http.get(path)
            if rv is None:
                continue
            if rv.status_code in (200, 201) and Requester.is_json(rv):
                score += 2
                has_json_signal = True
                reasons.append(f"GET {path} → {rv.status_code} JSON")
                break
            elif rv.status_code in (200, 201, 401, 403):
                score += 1
                reasons.append(f"GET {path} → {rv.status_code}")
                break

        # Signal 3 — common REST resource paths (/users, /products...)
        # COMMON_REST_PATHS only — no duplication with REST_VERSION_PATHS
        for path in COMMON_REST_PATHS:
            rv = self.http.get(path)
            if rv is None:
                continue
            if rv.status_code in (200, 201) and Requester.is_json(rv):
                score += 2
                has_json_signal = True
                reasons.append(f"GET {path} → {rv.status_code} JSON")
                break
            elif rv.status_code in (401, 403) and Requester.is_json(rv):
                score += 1
                has_json_signal = True
                reasons.append(f"GET {path} → {rv.status_code} JSON (auth required)")
                break

        # Signal 4 — OPTIONS verbs
        ro = self.http.options("/")
        if ro and "Allow" in ro.headers:
            allow = ro.headers["Allow"]
            if any(v in allow for v in ("GET", "POST", "PUT", "DELETE")):
                score += 1
                reasons.append(f"OPTIONS / → Allow: {allow}")

        # SPA boost — root is HTML but found JSON on sub-paths
        if has_html_root and has_json_signal:
            score += 2
            reasons.append("SPA frontend with JSON API on sub-paths")

        # HTML penalty — only if absolutely no JSON signal found
        if not has_json_signal and not has_html_root:
            r2 = self.http.get("/")
            if r2 and self._is_real_html(r2):
                score -= 1
                reasons.append("Pure HTML (penalty)")

        return score, reasons

    # =========================================================================
    #  PHASE 1 — Final decision
    # =========================================================================

    def detect_api_type(self) -> DetectionResult:
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
    #  Tech stack detection
    # =========================================================================

    def detect_technology(self) -> list[str]:
        r = self.http.get("/")
        if not r:
            return []

        server     = r.headers.get("Server",       "").lower()
        powered_by = r.headers.get("X-Powered-By", "").lower()
        via        = r.headers.get("Via",           "").lower()

        checks = [
            ("nginx",      "Nginx",             server),
            ("apache",     "Apache",            server),
            ("express",    "Node.js (Express)", server),
            ("express",    "Node.js (Express)", powered_by),
            ("django",     "Django",            server),
            ("django",     "Django",            powered_by),
            ("rails",      "Ruby on Rails",     server),
            ("php",        "PHP",               powered_by),
            ("laravel",    "Laravel",           powered_by),
            ("next.js",    "Next.js",           powered_by),
            ("fastapi",    "FastAPI",           server),
            ("uvicorn",    "FastAPI/Uvicorn",   server),
            ("flask",      "Flask",             server),
            ("gunicorn",   "Gunicorn",          server),
            ("iis",        "IIS (Microsoft)",   server),
            ("tomcat",     "Apache Tomcat",     server),
            ("jetty",      "Jetty",             server),
            ("spring",     "Spring Boot",       powered_by),
            ("caddy",      "Caddy",             server),
            ("cloudflare", "Cloudflare",        via),
        ]

        seen: set[str] = set()
        for keyword, label, source in checks:
            if keyword in source and label not in seen:
                self.tech_stack.append(label)
                seen.add(label)

        return self.tech_stack

    # =========================================================================
    #  PHASE 2 — Swagger / OpenAPI parsing
    # =========================================================================

    def parse_swagger(self) -> list[str]:
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

            logger.info(f"[+] Swagger/OpenAPI found on {path} — {len(paths)} paths")

            base = spec.get("basePath", "")
            if not base:
                servers = spec.get("servers", [])
                if servers:
                    server_url = servers[0].get("url", "")
                    if server_url.startswith("http"):
                        base = urlparse(server_url).path.rstrip("/")
                    else:
                        base = server_url.rstrip("/")

            for endpoint_path in paths:
                full_url = self.base_url + base + endpoint_path
                if full_url not in found:
                    found.append(full_url)
                    logger.debug(f"    [swagger] {full_url}")

            break

        self.swagger_endpoints = found
        return found

    # =========================================================================
    #  PHASE 2 — Wordlist crawling
    #
    #  SPA-aware filtering:
    #  - If root returns HTML (SPA), JSON responses on sub-paths are ALWAYS kept
    #  - 401/403 on JSON endpoints = protected API endpoint → kept
    #  - This handles crAPI, Juice Shop, DVWA and any modern SPA + REST API
    # =========================================================================

    def crawl_endpoints(
        self,
        wordlist_path: str,
        limit: Optional[int] = None,
    ) -> list[str]:

        try:
            with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
                raw_paths = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            logger.error(f"[crawl] Wordlist not found: {wordlist_path}")
            return []

        # Deduplicate wordlist
        seen_paths: set[str] = set()
        paths: list[str] = []
        for p in raw_paths:
            if p not in seen_paths:
                seen_paths.add(p)
                paths.append(p)

        total = len(paths) if limit is None else min(limit, len(paths))
        logger.info(f"[*] Crawling {total} paths...")

        # Baseline fingerprint for catch-all detection
        baseline = self._get_baseline()
        if baseline.get("status") == 200:
            logger.warning("[crawl] Catch-all server detected — enhanced filtering enabled")

        # SPA detection: if root returns HTML → keep JSON sub-paths
        root_r       = self.http.get("/")
        root_is_html = root_r is not None and self._is_real_html(root_r)
        if root_is_html:
            logger.info("[*] SPA frontend detected — JSON endpoints on sub-paths will be kept")

        already_known:  set[str] = set(self.endpoints + self.swagger_endpoints)
        found_this_run: list[str] = []
        seen_bodies:    set[str] = set()
        count = 0

        for path in paths:
            if limit is not None and count >= limit:
                break
            count += 1

            if not path.startswith("/"):
                path = "/" + path

            url = self.base_url + path
            if url in already_known:
                continue

            r = self.http.get(path, allow_redirects=False)
            if r is None:
                continue

            content_type = r.headers.get("Content-Type", "")

            # Filter 1 — HTTP errors
            # Keep 401/403 — they indicate real protected endpoints
            if r.status_code in (401, 403):
                if "application/json" not in content_type and not root_is_html:
                    continue
                # Protected API endpoint confirmed
                already_known.add(url)
                found_this_run.append(url)
                self.endpoints.append(url)
                logger.info(f"    [crawl] {r.status_code} → {url}")
                continue

            elif r.status_code >= 400:
                continue

            # Filter 2 — auth redirect
            if self._is_redirect_to_auth(r):
                logger.debug(f"    [FP-redirect] {path}")
                continue

            # Filter 3 — catch-all / baseline fingerprint
            # Exception: SPA root is HTML + sub-path returns JSON → always keep
            if root_is_html and "application/json" in content_type:
                pass  # SPA + JSON API → never filter
            elif self._is_false_positive(r, baseline):
                logger.debug(f"    [FP-baseline] {path}")
                continue

            # Filter 4 — pure HTML frontend page
            # Skip if root is already HTML (SPA)
            if not root_is_html and self._is_html_frontend(r):
                logger.debug(f"    [FP-html] {path}")
                continue

            # Filter 5 — duplicate body
            body_hash = hashlib.md5(r.content).hexdigest()
            if body_hash in seen_bodies:
                logger.debug(f"    [FP-duplicate-body] {path}")
                continue

            # Endpoint confirmed
            seen_bodies.add(body_hash)
            already_known.add(url)
            found_this_run.append(url)
            self.endpoints.append(url)
            logger.info(f"    [crawl] {r.status_code} → {url}")

        logger.info(f"[+] Crawl complete — {len(found_this_run)} new endpoints found")
        return self.endpoints

    # ── Crawl helpers ─────────────────────────────────────────────────────────

    def _get_baseline(self) -> dict:
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
        if not baseline:
            return False

        body_hash      = hashlib.md5(r.content).hexdigest()
        content_length = len(r.content)
        content_type   = r.headers.get("Content-Type", "")

        # JSON response → never a false positive
        if "application/json" in content_type:
            return False

        # Same exact hash as baseline → FP
        if body_hash == baseline.get("body_hash"):
            return True

        # Same size as baseline → FP probable
        if content_length == baseline.get("content_length") and content_length > 0:
            return True

        # Too short to be meaningful
        if content_length < 10:
            return True

        return False

    def _is_redirect_to_auth(self, r) -> bool:
        if r.status_code not in (301, 302, 303, 307, 308):
            return False
        location      = r.headers.get("Location", "").lower()
        auth_patterns = ["/login", "/signin", "/auth", "/connect", "/sso", "/oauth"]
        return any(p in location for p in auth_patterns)

    def _is_html_frontend(self, r) -> bool:
        ct = r.headers.get("Content-Type", "")
        if "text/html" not in ct:
            return False
        try:
            r.json()
            return False  # valid JSON → keep
        except Exception:
            return True

    # =========================================================================
    #  run() — Main orchestrator
    # =========================================================================

    def run(self, wordlist_path: str, mode: str = "quick") -> dict:
        """
        Runs full discovery in order:
          1. detect_api_type()   — REST | GraphQL | SOAP | Unknown
          2. detect_technology() — tech stack from headers
          3. parse_swagger()     — Swagger/OpenAPI endpoints
          4. crawl_endpoints()   — wordlist crawling

        Args:
            wordlist_path : path to wordlist file
            mode          : "quick" (50 paths) | "full" (complete wordlist)

        Returns:
            dict with all results.
        """
        logger.info(f"[*] Starting discovery on {self.base_url}")

        # 1. API type
        detection = self.detect_api_type()

        # 2. Tech stack
        self.detect_technology()
        if self.tech_stack:
            logger.info(f"[+] Tech stack: {', '.join(self.tech_stack)}")

        # 3. Swagger
        swagger_found = self.parse_swagger()

        # 4. Crawl (REST/SOAP) — ou Schema fetch (GraphQL)
        gql_schema = None

        if detection.api_type == "GraphQL":
            # Pour GraphQL, pas de crawl wordlist — on récupère le schéma
            from core.graphql_schema import fetch_graphql_schema

            # Récupérer l'endpoint GraphQL déjà confirmé par _score_graphql
            known_ep = None
            for reason in detection.reasons:
                for path in GRAPHQL_PATHS:
                    if path in reason:
                        known_ep = f"{self.base_url}{path}"
                        break
                if known_ep:
                    break

            schema_result = fetch_graphql_schema(
                base_url       = self.base_url,
                timeout        = self.http.timeout,
                known_endpoint = known_ep,
            )
            gql_schema = schema_result.to_dict()

            # L'endpoint GraphQL lui-même devient le seul "endpoint"
            ep_url = schema_result.endpoint or known_ep or f"{self.base_url}/graphql"
            if ep_url not in self.endpoints:
                self.endpoints.append(ep_url)

            logger.info(
                f"[+] GraphQL schema — method: {schema_result.method} | "
                f"queries: {len(schema_result.queries)} | "
                f"mutations: {len(schema_result.mutations)}"
            )

        else:
            # REST / SOAP / Unknown → crawl wordlist classique
            limit = 50 if mode == "quick" else None
            self.crawl_endpoints(wordlist_path, limit=limit)

            # Upgrade Unknown → REST if crawl found JSON endpoints
            if detection.api_type == "Unknown" and len(self.endpoints) > 0:
                logger.info(
                    f"[*] API type upgraded to REST — "
                    f"{len(self.endpoints)} endpoint(s) found during crawl"
                )
                detection.api_type   = "REST"
                detection.confidence = 0.5
                detection.score      = max(detection.score, 2)
                detection.reasons.append(
                    f"REST confirmed from {len(self.endpoints)} crawled endpoint(s)"
                )
                self.api_type = "REST"

        # Merge without duplicates — swagger first
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
            "target_url":        self.base_url,
            "schema":            gql_schema,       # None pour REST/SOAP
        }