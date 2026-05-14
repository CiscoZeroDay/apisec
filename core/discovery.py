# core/discovery.py
"""
APIDiscovery — API detection and crawling (REST | GraphQL | SOAP | Unknown)

Pipeline:
  Phase 1 : HTTP header fingerprinting  (NEW)
  Phase 2 : Multi-signal scoring        (REST | GraphQL | SOAP)
  Phase 3 : Swagger / OpenAPI parsing
  Phase 4 : Wordlist crawl + active probing on every 200 (NEW)
  Phase 5 : Recursive depth crawl       (NEW)

What is NEW vs original:
  Phase 1 — Header fingerprinting
    Reads engine-specific headers (Hasura, Apollo, WCF, Express, Django...)
    from a single GET / response. Boosts relevant scores before active probing.
    Zero extra requests — reuses the root response already fetched.

  Phase 4 — Active probing on every 200
    Every endpoint that returns 200 during wordlist crawl is probed with
    a GraphQL __typename query and a SOAP envelope. This detects GraphQL/SOAP
    on non-standard paths like /api/backend or /internal/service.

  Phase 5 — Recursive depth crawl (depth=3)
    After the wordlist crawl, discovered 200 paths are extended with known
    GQL/REST suffixes and probed recursively up to depth 3.
    Example: /api → 200 → probe /api/graphql, /api/v1 → /api/v1/graphql ✓

All original logic is preserved unchanged.
"""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse

from core.requester import Requester
from logger.logger  import logger


# ─────────────────────────────────────────────────────────────────────────────
#  Constants
# ─────────────────────────────────────────────────────────────────────────────

GRAPHQL_PATHS: list[str] = [
    "/graphql", "/api/graphql", "/query",
    "/gql", "/graphql/v1", "/v1/graphql",
    "/api/v1/graphql", "/api/v2/graphql",
    "/graphql/api", "/graph",
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

REST_VERSION_PATHS: list[str] = [
    "/api", "/api/v1", "/api/v2", "/api/v3",
    "/v1",  "/v2",     "/v3",
]

COMMON_REST_PATHS: list[str] = [
    "/users",    "/posts",    "/products", "/items",
    "/todos",    "/comments", "/articles", "/orders",
    "/accounts", "/auth",     "/health",   "/status",
]

# Suffixes appended to discovered paths during recursive crawl
_GQL_SUFFIXES: list[str] = [
    "/graphql", "/gql", "/query",
    "/graphql/v1", "/api/graphql",
    "/v1/graphql", "/v2/graphql",
]

_REST_SUFFIXES: list[str] = [
    "/v1", "/v2", "/v3",
    "/api", "/api/v1", "/api/v2",
    "/rest", "/rest/v1",
]

# Probes
_SOAP_PROBE = (
    '<?xml version="1.0" encoding="utf-8"?>'
    '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">'
    "<soap:Body/>"
    "</soap:Envelope>"
)
_SOAP_HEADERS = {"Content-Type": "text/xml; charset=utf-8"}

# ── Header fingerprint signatures ────────────────────────────────────────────
# (header_name_lower, value_contains, api_type, score_bonus, reason)
_HEADER_SIGNATURES: list[tuple[str, str, str, int, str]] = [
    # ── GraphQL engines ───────────────────────────────────────────────────────
    ("x-hasura-trace-id",        "",         "GraphQL", 4, "Hasura GraphQL engine (x-hasura-trace-id)"),
    ("x-hasura-role",            "",         "GraphQL", 4, "Hasura GraphQL engine (x-hasura-role)"),
    ("apollo-require-preflight", "",         "GraphQL", 4, "Apollo Server (apollo-require-preflight)"),
    ("x-apollo-operation-id",    "",         "GraphQL", 3, "Apollo Server (x-apollo-operation-id)"),
    ("x-graphql-event-stream",   "",         "GraphQL", 3, "GraphQL subscription endpoint"),
    ("server",                   "cowboy",   "GraphQL", 3, "Hasura GraphQL (Cowboy server)"),
    ("x-powered-by",             "hasura",   "GraphQL", 4, "Hasura GraphQL (x-powered-by)"),
    ("content-type",             "graphql",  "GraphQL", 3, "GraphQL content-type"),
    # ── REST frameworks ───────────────────────────────────────────────────────
    ("x-ratelimit-limit",        "",         "REST",    2, "Rate-limit headers (REST pattern)"),
    ("x-ratelimit-remaining",    "",         "REST",    1, "Rate-limit headers (REST pattern)"),
    ("x-api-version",            "",         "REST",    2, "API version header"),
    ("x-request-id",             "",         "REST",    1, "Request-ID header (REST pattern)"),
    ("x-powered-by",             "express",  "REST",    2, "Node.js Express"),
    ("x-powered-by",             "django",   "REST",    2, "Django REST Framework"),
    ("x-powered-by",             "fastapi",  "REST",    2, "FastAPI"),
    ("x-powered-by",             "flask",    "REST",    2, "Flask"),
    ("x-powered-by",             "rails",    "REST",    2, "Ruby on Rails"),
    ("x-powered-by",             "laravel",  "REST",    2, "Laravel"),
    ("www-authenticate",         "bearer",   "REST",    2, "Bearer token auth (REST/OAuth2)"),
    # ── SOAP ──────────────────────────────────────────────────────────────────
    ("content-type",             "text/xml", "SOAP",    3, "SOAP XML content-type"),
    ("content-type",             "soap",     "SOAP",    4, "SOAP content-type"),
    ("soapaction",               "",         "SOAP",    4, "SOAPAction header present"),
    ("x-powered-by",             "wcf",      "SOAP",    3, "Microsoft WCF (SOAP)"),
]

# ── Scoring thresholds ────────────────────────────────────────────────────────
_GQL_THRESHOLD  = 4
_GQL_MAX_SCORE  = 12   # raised to account for header bonus
_REST_THRESHOLD = 3
_REST_MAX_SCORE = 10
_SOAP_THRESHOLD = 4
_SOAP_MAX_SCORE = 10

_WSDL_KEYWORDS = (
    "wsdl", "definitions", "porttype",
    "binding", "soap", "targetnamespace",
    "webservice", "operation",
)

_INVALID_PATH_PATTERNS: list[str] = [
    "?", "#", "javascript:", "mailto:", "data:",
]


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

    Detection pipeline (5 phases):

    Phase 1 — Header fingerprinting (NEW)
        Reads engine headers from GET / — zero extra requests.
        Hasura, Apollo, WCF, Express, Django, FastAPI... all detected here.

    Phase 2 — Multi-signal scoring
        SOAP/GraphQL/REST scored independently. Highest threshold wins.

    Phase 3 — Swagger/OpenAPI parsing
        Upgrades Unknown → REST when spec is found.

    Phase 4 — Wordlist crawl + active probing (ENHANCED)
        Every 200 → fire GraphQL probe + SOAP probe.
        Detects GQL/SOAP on /api/backend, /internal/service, etc.
        Upgrades api_type in-flight when confirmed.

    Phase 5 — Recursive depth crawl (NEW)
        After wordlist: /api → probe /api/graphql, /api/v1, /api/v1/graphql...
        Finds deeply nested endpoints wordlist alone would miss.
    """

    def __init__(self, base_url: str, timeout: int = 5) -> None:
        self.base_url  = base_url.rstrip("/")
        self.http      = Requester(self.base_url, timeout=timeout)
        self.api_type  = "Unknown"

        self.tech_stack:        list[str] = []
        self.endpoints:         list[str] = []
        self.swagger_endpoints: list[str] = []

        # Internal state
        self._root_response      = None   # cached GET / — fetched once
        self._header_gql_bonus:  int      = 0
        self._header_rest_bonus: int      = 0
        self._header_soap_bonus: int      = 0
        self._header_reasons:    list[str] = []

    # =========================================================================
    #  Helpers
    # =========================================================================

    def _root(self):
        """Return GET / response, fetching once and caching."""
        if self._root_response is None:
            self._root_response = self.http.get("/")
        return self._root_response

    def _is_real_html(self, r) -> bool:
        ct = r.headers.get("Content-Type", "")
        if "html" not in ct and "xml" not in ct:
            return False
        try:
            r.json()
            return False
        except Exception:
            return True

    def _is_json_response(self, r) -> bool:
        if Requester.is_json(r):
            return True
        try:
            r.json()
            return True
        except Exception:
            return False

    def _contains_xml(self, r) -> bool:
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
        try:
            return r.json()
        except Exception:
            return None

    def _is_valid_path(self, path: str) -> bool:
        if not path or not path.strip():
            return False
        p = path.strip()
        if not p.startswith("/"):
            p = "/" + p
        for pattern in _INVALID_PATH_PATTERNS:
            if pattern in p and not p.startswith("/"):
                return False
        if p.startswith("/?") or p == "/?:":
            return False
        return True

    def _is_gql_body(self, r) -> bool:
        """True if response has GraphQL data/errors envelope."""
        if r is None or r.status_code not in (200, 400):
            return False
        body = self._safe_json(r)
        return isinstance(body, dict) and ("data" in body or "errors" in body)

    # =========================================================================
    #  PHASE 1 — Header fingerprinting  (NEW)
    # =========================================================================

    def fingerprint_headers(self) -> None:
        """
        Reads HTTP response headers and boosts scoring before active probing.

        Uses a single GET / (already cached in _root_response).
        Additionally fires one POST /graphql to catch engine headers that
        only appear on the actual GraphQL endpoint.

        Populates:
            self._header_gql_bonus   : score bonus for GraphQL detection
            self._header_rest_bonus  : score bonus for REST detection
            self._header_soap_bonus  : score bonus for SOAP detection
            self._header_reasons     : human-readable reason list
        """
        r = self._root()
        if r is None:
            return

        headers_lower = {k.lower(): v.lower() for k, v in r.headers.items()}

        gql_bonus  = 0
        rest_bonus = 0
        soap_bonus = 0
        reasons: list[str] = []
        seen:    set[str]  = set()

        for hdr_name, val_contains, api_type, bonus, reason in _HEADER_SIGNATURES:
            hdr_val = headers_lower.get(hdr_name.lower(), "")
            if not hdr_val:
                continue
            if val_contains and val_contains.lower() not in hdr_val:
                continue
            if reason in seen:
                continue
            seen.add(reason)

            if api_type == "GraphQL":
                gql_bonus  += bonus
            elif api_type == "REST":
                rest_bonus += bonus
            elif api_type == "SOAP":
                soap_bonus += bonus
            reasons.append(reason)

        # Secondary probe: POST /graphql reveals engine headers not on /
        r_gql = self.http.post(
            "/graphql",
            data='{"query": "{ __typename }"}',
            headers={"Content-Type": "application/json"},
        )
        if r_gql is not None:
            gql_hdrs = {k.lower() for k in r_gql.headers}
            if "x-hasura-trace-id" in gql_hdrs or "apollo-require-preflight" in gql_hdrs:
                gql_bonus += 4
                reasons.append("Engine header confirmed on POST /graphql")

        # Cap bonuses to prevent header fingerprinting alone from deciding
        self._header_gql_bonus  = min(gql_bonus,  6)
        self._header_rest_bonus = min(rest_bonus, 4)
        self._header_soap_bonus = min(soap_bonus, 5)
        self._header_reasons    = reasons

        if reasons:
            logger.info(f"[+] Header fingerprint: {', '.join(reasons[:3])}")

    # =========================================================================
    #  PHASE 2 — SOAP scoring
    # =========================================================================

    def _score_soap(self) -> tuple[int, list[str]]:
        score   = self._header_soap_bonus
        reasons = [r for r in self._header_reasons
                   if any(k in r.lower() for k in ("soap", "wsdl", "wcf", "xml"))]

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

            matched = [k for k in _WSDL_KEYWORDS if k in text]

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
                reasons.append(f"XML body on {path}")

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
    #  PHASE 2 — GraphQL scoring
    # =========================================================================

    def _score_graphql(self) -> tuple[int, list[str], str | None]:
        score          = self._header_gql_bonus
        reasons        = [r for r in self._header_reasons
                          if any(k in r.lower()
                                 for k in ("graphql", "apollo", "hasura", "subscription"))]
        confirmed_path = None

        for path in GRAPHQL_PATHS:
            r = self.http.post(path, json={"query": "{ __typename }"})
            if r is None:
                continue

            if r.status_code == 200 and self._is_json_response(r):
                score += 3
                reasons.append(f"POST {path} → 200 JSON")

                body = self._safe_json(r)
                if isinstance(body, dict) and ("data" in body or "errors" in body):
                    score += 2
                    confirmed_path = path
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
                    score         += 4
                    confirmed_path = path
                    reasons.append(f"Introspection __schema succeeded on {path}")
                    return score, reasons, confirmed_path

        return score, reasons, confirmed_path

    # =========================================================================
    #  PHASE 2 — REST scoring
    # =========================================================================

    def _score_rest(self) -> tuple[int, list[str]]:
        """
        Scores REST likelihood based on JSON response signals.
        HTML responses NEVER contribute to score.
        """
        score           = self._header_rest_bonus
        reasons         = [r for r in self._header_reasons
                           if any(k in r.lower()
                                  for k in ("rest", "express", "django", "flask",
                                            "fastapi", "rails", "laravel", "bearer",
                                            "rate-limit", "request-id", "version"))]
        has_json_signal = False
        has_html_root   = False

        r_root = self._root()
        if r_root and r_root.status_code == 200:
            if self._is_json_response(r_root):
                score += 2
                reasons.append("GET / → 200 JSON")
                has_json_signal = True
                body = self._safe_json(r_root)
                if isinstance(body, (list, dict)) and "data" not in (body or {}):
                    score += 1
                    reasons.append("JSON body without GraphQL envelope")
            elif self._is_real_html(r_root):
                has_html_root = True
                logger.debug("[score_rest] HTML root detected — SPA check pending")

        for path in REST_VERSION_PATHS:
            rv = self.http.get(path)
            if rv is None:
                continue
            if rv.status_code in (200, 201) and self._is_json_response(rv):
                score += 2
                has_json_signal = True
                reasons.append(f"GET {path} → {rv.status_code} JSON")
                break
            elif rv.status_code in (401, 403) and self._is_json_response(rv):
                score += 1
                has_json_signal = True
                reasons.append(f"GET {path} → {rv.status_code} JSON (auth required)")
                break

        for path in COMMON_REST_PATHS:
            rv = self.http.get(path)
            if rv is None:
                continue
            if rv.status_code in (200, 201) and self._is_json_response(rv):
                score += 2
                has_json_signal = True
                reasons.append(f"GET {path} → {rv.status_code} JSON")
                break
            elif rv.status_code in (401, 403) and self._is_json_response(rv):
                score += 1
                has_json_signal = True
                reasons.append(f"GET {path} → {rv.status_code} JSON (auth required)")
                break

        ro = self.http.options("/")
        if ro and "Allow" in ro.headers:
            allow = ro.headers["Allow"]
            if any(v in allow for v in ("POST", "PUT", "DELETE", "PATCH")):
                score += 1
                reasons.append(f"OPTIONS / → Allow: {allow}")

        if has_html_root and has_json_signal:
            score += 2
            reasons.append("SPA frontend with JSON API on sub-paths")

        return score, reasons

    # =========================================================================
    #  PHASE 2 — Final decision
    # =========================================================================

    def detect_api_type(self) -> DetectionResult:
        """
        Phase 1 (headers) → Phase 2 (scoring) → DetectionResult.
        Priority: SOAP > GraphQL > REST > Unknown.
        """
        logger.info("[*] Detecting API type...")

        # Phase 1 first — enriches all scores before active scoring
        self.fingerprint_headers()

        soap_score, soap_reasons               = self._score_soap()
        gql_score,  gql_reasons, gql_confirmed = self._score_graphql()
        rest_score, rest_reasons               = self._score_rest()

        logger.debug(f"    SOAP    score = {soap_score} (threshold: {_SOAP_THRESHOLD})")
        logger.debug(f"    GraphQL score = {gql_score} (threshold: {_GQL_THRESHOLD})")
        logger.debug(f"    REST    score = {rest_score} (threshold: {_REST_THRESHOLD})")

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
            result.gql_confirmed_path = gql_confirmed

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
                reasons    = rest_reasons + gql_reasons + soap_reasons,
            )

        self.api_type = result.api_type
        logger.info(f"[+] {result}")
        return result

    # =========================================================================
    #  Tech stack detection
    # =========================================================================

    def detect_technology(self) -> list[str]:
        """Fingerprints backend technology from HTTP response headers."""
        r = self._root()
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
            ("cowboy",     "Hasura (Cowboy)",   server),
            ("hasura",     "Hasura GraphQL",    powered_by),
        ]

        seen: set[str] = set()
        for keyword, label, source in checks:
            if keyword in source and label not in seen:
                self.tech_stack.append(label)
                seen.add(label)

        return self.tech_stack

    # =========================================================================
    #  PHASE 3 — Swagger / OpenAPI parsing
    # =========================================================================

    def parse_swagger(self) -> list[str]:
        """Discovers endpoints from Swagger/OpenAPI specification files."""
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

            break

        self.swagger_endpoints = found
        return found

    # =========================================================================
    #  PHASE 4 helpers — Active probing  (NEW)
    # =========================================================================

    def _probe_graphql(self, path: str) -> bool:
        """
        Fire a GraphQL __typename probe on the given path.

        Returns True if GraphQL is confirmed — regardless of path name.
        Called on every 200 response during the wordlist crawl.

        Two-step confirmation:
          1. { __typename } → data/errors envelope → candidate
          2. introspection  → __schema present     → confirmed
        """
        r = self.http.post(path, json={"query": "{ __typename }"})
        if not self._is_gql_body(r):
            return False

        # Strengthen with introspection probe
        r_intro = self.http.post(
            path,
            json={"query": "{ __schema { queryType { name } } }"},
        )
        body = self._safe_json(r_intro)
        if isinstance(body, dict) and body.get("data", {}).get("__schema"):
            logger.info(f"    [GQL-probe] Introspection confirmed → {path}")
            return True

        # __typename alone — weaker but sufficient
        logger.info(f"    [GQL-probe] GraphQL __typename confirmed → {path}")
        return True

    def _probe_soap(self, path: str) -> bool:
        """
        Fire a SOAP envelope probe on the given path.

        Returns True if a SOAP/XML response or SOAPAction header is detected.
        Called on every 200 response during the wordlist crawl.
        """
        r = self.http.post(path, data=_SOAP_PROBE, headers=_SOAP_HEADERS)
        if r is None:
            return False
        if self._contains_xml(r):
            logger.info(f"    [SOAP-probe] SOAP/XML response → {path}")
            return True
        if "SOAPAction" in r.headers:
            logger.info(f"    [SOAP-probe] SOAPAction header → {path}")
            return True
        return False

    # =========================================================================
    #  PHASE 5 — Recursive depth crawl  (NEW)
    # =========================================================================

    def _recursive_crawl(
        self,
        seed_paths:    list[str],
        already_probed: set[str],
        max_depth:     int = 3,
    ) -> list[str]:
        """
        Extends discovered paths with known GQL/REST suffixes recursively.

        Called after the wordlist crawl with all confirmed 200 paths as seeds.

        Algorithm (BFS, capped at max_depth):
          For each seed path, build candidate sub-paths by appending suffixes.
          Probe each candidate:
            - GraphQL probe → confirmed → add to endpoints, stop branch
            - SOAP probe    → confirmed → add to endpoints, stop branch
            - 200 JSON      → add to endpoints, enqueue for next depth level
            - otherwise     → skip

        This ensures /api → /api/v1 → /api/v1/graphql is found even if only
        /api appears in the wordlist.

        Args:
            seed_paths     : list of path strings (e.g. ["/api", "/backend"])
            already_probed : shared set to prevent re-probing paths
            max_depth      : maximum recursion depth (default: 3)

        Returns:
            List of newly found endpoint URLs.
        """
        new_endpoints: list[str] = []
        # BFS queue: (path, current_depth)
        queue: list[tuple[str, int]] = [(p, 0) for p in seed_paths]

        while queue:
            current_path, depth = queue.pop(0)

            if depth >= max_depth:
                continue

            # Build candidates from all GQL + REST suffixes
            candidates: set[str] = set()
            for suffix in _GQL_SUFFIXES + _REST_SUFFIXES:
                candidate = current_path.rstrip("/") + suffix
                if candidate not in already_probed:
                    candidates.add(candidate)

            for candidate in sorted(candidates):
                already_probed.add(candidate)
                url = self.base_url + candidate

                r = self.http.get(candidate, allow_redirects=False)
                if r is None or r.status_code not in (200, 201, 401, 403):
                    continue

                # GraphQL check
                if self._probe_graphql(candidate):
                    if url not in self.endpoints:
                        self.endpoints.append(url)
                        new_endpoints.append(url)
                        logger.info(
                            f"    [recursive] GraphQL at depth {depth+1}: {url}"
                        )
                        # Upgrade api_type if discovery started as REST/Unknown
                        if self.api_type not in ("GraphQL", "SOAP"):
                            self.api_type = "GraphQL"
                    continue

                # SOAP check
                if self._probe_soap(candidate):
                    if url not in self.endpoints:
                        self.endpoints.append(url)
                        new_endpoints.append(url)
                        logger.info(
                            f"    [recursive] SOAP at depth {depth+1}: {url}"
                        )
                        if self.api_type not in ("GraphQL", "SOAP"):
                            self.api_type = "SOAP"
                    continue

                # Valid REST JSON endpoint
                if r.status_code in (200, 201) and self._is_json_response(r):
                    if url not in self.endpoints:
                        self.endpoints.append(url)
                        logger.info(
                            f"    [recursive] REST at depth {depth+1}: {url}"
                        )
                    # Enqueue for deeper crawl
                    queue.append((candidate, depth + 1))

        if new_endpoints:
            logger.info(
                f"[+] Recursive crawl — {len(new_endpoints)} additional endpoint(s)"
            )

        return new_endpoints

    # =========================================================================
    #  PHASE 4 — Wordlist crawl (enhanced)
    # =========================================================================

    def crawl_endpoints(
        self,
        wordlist_path: str,
        limit:         Optional[int] = None,
    ) -> list[str]:
        """
        Wordlist crawl with active probing on every 200.

        Enhancements vs original:
          - Every 200 path → _probe_graphql() + _probe_soap()
          - api_type upgraded in-flight when GQL/SOAP confirmed
          - All confirmed 200 paths collected → triggers Phase 5 at end
        """
        try:
            with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
                raw_paths = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            logger.error(f"[crawl] Wordlist not found: {wordlist_path}")
            return []

        seen_paths: set[str] = set()
        paths: list[str] = []
        for p in raw_paths:
            if p and p not in seen_paths:
                seen_paths.add(p)
                paths.append(p)

        total = len(paths) if limit is None else min(limit, len(paths))
        logger.info(f"[*] Crawling {total} paths...")

        baseline     = self._get_baseline()
        root_r       = self._root()
        root_is_html = root_r is not None and self._is_real_html(root_r)

        if root_is_html:
            logger.info("[*] SPA frontend detected — JSON endpoints on sub-paths will be kept")
        if baseline.get("status") == 200:
            logger.warning("[crawl] Catch-all server detected — enhanced filtering enabled")

        already_known:  set[str]  = set(self.endpoints + self.swagger_endpoints)
        seen_bodies:    set[str]  = set()
        probed_paths:   set[str]  = set()   # paths sent to active probes
        paths_200:      list[str] = []      # seeds for recursive crawl
        count = 0

        for path in paths:
            if limit is not None and count >= limit:
                break
            count += 1

            if not path.startswith("/"):
                path = "/" + path

            if not self._is_valid_path(path):
                logger.debug(f"    [FP-invalid-path] {path}:")
                continue

            url = self.base_url + path
            if url in already_known:
                continue

            r = self.http.get(path, allow_redirects=False)
            if r is None:
                continue

            is_json = self._is_json_response(r)

            # 401/403 — keep if JSON or SPA
            if r.status_code in (401, 403):
                if not is_json and not root_is_html:
                    continue
                already_known.add(url)
                self.endpoints.append(url)
                logger.info(f"    [crawl] {r.status_code} → {url}")
                continue

            elif r.status_code >= 400:
                continue

            if self._is_redirect_to_auth(r):
                logger.debug(f"    [FP-redirect] {path}")
                continue

            if root_is_html and is_json:
                pass  # SPA + JSON → always keep
            elif self._is_false_positive(r, baseline):
                logger.debug(f"    [FP-baseline] {path}")
                continue

            if not root_is_html and self._is_html_frontend(r):
                logger.debug(f"    [FP-html] {path}")
                continue

            body_hash = hashlib.md5(r.content).hexdigest()
            if body_hash in seen_bodies:
                logger.debug(f"    [FP-duplicate-body] {path}")
                continue

            # ── Active probing on every confirmed 200  (NEW) ─────────────────
            if path not in probed_paths:
                probed_paths.add(path)

                if self._probe_graphql(path):
                    if url not in already_known:
                        already_known.add(url)
                        self.endpoints.append(url)
                        logger.info(f"    [+] GraphQL on non-standard path: {url}")
                    if self.api_type not in ("GraphQL", "SOAP"):
                        self.api_type = "GraphQL"
                        logger.info(f"[*] API type upgraded to GraphQL — {path}")
                    continue

                if self._probe_soap(path):
                    if url not in already_known:
                        already_known.add(url)
                        self.endpoints.append(url)
                        logger.info(f"    [+] SOAP on non-standard path: {url}")
                    if self.api_type not in ("GraphQL", "SOAP"):
                        self.api_type = "SOAP"
                        logger.info(f"[*] API type upgraded to SOAP — {path}")
                    continue

            # Standard REST/Unknown endpoint
            seen_bodies.add(body_hash)
            already_known.add(url)
            self.endpoints.append(url)
            paths_200.append(path)
            logger.info(f"    [crawl] {r.status_code} → {url}")

        new_count = len([e for e in self.endpoints
                         if e not in self.swagger_endpoints])
        logger.info(f"[+] Crawl complete — {new_count} new endpoints found")

        # ── Phase 5 — Recursive depth crawl  (NEW) ───────────────────────────
        if paths_200:
            logger.info(
                f"[*] Recursive crawl starting on {len(paths_200)} path(s)..."
            )
            self._recursive_crawl(paths_200, probed_paths, max_depth=3)

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
        }

    def _is_false_positive(self, r, baseline: dict) -> bool:
        if not baseline:
            return False
        body_hash      = hashlib.md5(r.content).hexdigest()
        content_length = len(r.content)
        content_type   = r.headers.get("Content-Type", "")
        if "application/json" in content_type:
            return False
        if body_hash == baseline.get("body_hash"):
            return True
        if content_length == baseline.get("content_length") and content_length > 0:
            return True
        if content_length < 10:
            return True
        return False

    def _is_redirect_to_auth(self, r) -> bool:
        if r.status_code not in (301, 302, 303, 307, 308):
            return False
        location = r.headers.get("Location", "").lower()
        return any(p in location for p in ("/login", "/signin", "/auth", "/sso", "/oauth"))

    def _is_html_frontend(self, r) -> bool:
        ct = r.headers.get("Content-Type", "")
        if "text/html" not in ct:
            return False
        try:
            r.json()
            return False
        except Exception:
            return True

    # =========================================================================
    #  run() — Main orchestrator
    # =========================================================================

    def run(self, wordlist_path: str, mode: str = "quick") -> dict:
        """
        Full discovery pipeline in 5 phases.

        Args:
            wordlist_path : path to endpoint wordlist file
            mode          : "quick" (50 paths) | "full" (entire wordlist)
        """
        logger.info(f"[*] Starting discovery on {self.base_url}")

        # Phases 1 + 2
        detection = self.detect_api_type()

        # Tech stack
        self.detect_technology()
        if self.tech_stack:
            logger.info(f"[+] Tech stack: {', '.join(self.tech_stack)}")

        # Phase 3
        swagger_found = self.parse_swagger()

        if swagger_found and detection.api_type in ("Unknown", "REST"):
            if detection.api_type == "Unknown":
                logger.info(
                    f"[*] API type upgraded to REST — "
                    f"Swagger/OpenAPI confirmed {len(swagger_found)} endpoint(s)"
                )
            detection.api_type   = "REST"
            detection.confidence = max(detection.confidence, 0.75)
            detection.score      = max(detection.score, 3)
            detection.reasons.append(
                f"REST confirmed from Swagger/OpenAPI ({len(swagger_found)} endpoint(s))"
            )
            self.api_type = "REST"

        # Phases 4 + 5
        gql_schema = None

        if detection.api_type == "GraphQL":
            from core.graphql_schema import fetch_graphql_schema

            gql_path = getattr(detection, "gql_confirmed_path", None)
            known_ep = f"{self.base_url}{gql_path}" if gql_path else None

            schema_result = fetch_graphql_schema(
                base_url       = self.base_url,
                timeout        = self.http.timeout,
                known_endpoint = known_ep,
            )
            gql_schema = schema_result.to_dict()

            ep_url = known_ep or schema_result.endpoint or f"{self.base_url}/graphql"
            if ep_url not in self.endpoints:
                self.endpoints.append(ep_url)

            logger.info(
                f"[+] GraphQL schema — method: {schema_result.method} | "
                f"queries: {len(schema_result.queries)} | "
                f"mutations: {len(schema_result.mutations)}"
            )

        elif detection.api_type == "SOAP":
            soap_ep = self.base_url
            if soap_ep not in self.endpoints:
                self.endpoints.append(soap_ep)
                logger.info(f"[+] SOAP endpoint registered: {soap_ep}")

            for path in WSDL_PATHS:
                r = self.http.get(path)
                if r is None or r.status_code != 200:
                    continue
                try:
                    text = r.content.decode("utf-8", errors="ignore").lower()
                except Exception:
                    text = ""

                wsdl_keywords = ("wsdl", "definitions", "porttype", "binding")
                if any(k in text for k in wsdl_keywords):
                    soap_tech_map = {
                        "dataaccess": "Visual DataFlex",
                        "dataflex":   "Visual DataFlex",
                        "axis":       "Apache Axis",
                        "cxf":        "Apache CXF",
                        "wcf":        "Microsoft WCF",
                        "microsoft":  "Microsoft WCF",
                        "jboss":      "JBoss WS",
                        "spring":     "Spring-WS",
                    }
                    for keyword, label in soap_tech_map.items():
                        if keyword in text and label not in self.tech_stack:
                            self.tech_stack.append(label)

                    if "schemas.xmlsoap.org/soap/envelope" in text:
                        if "SOAP 1.1" not in self.tech_stack:
                            self.tech_stack.append("SOAP 1.1")
                    elif "www.w3.org/2003/05/soap-envelope" in text:
                        if "SOAP 1.2" not in self.tech_stack:
                            self.tech_stack.append("SOAP 1.2")

                    logger.info(f"[+] WSDL confirmed at {path}")
                    break

            self.tech_stack = list(dict.fromkeys(self.tech_stack))

        else:
            # REST or Unknown → phases 4 + 5
            limit = 50 if mode == "quick" else None
            self.crawl_endpoints(wordlist_path, limit=limit)

            if detection.api_type == "Unknown" and len(self.endpoints) > 0:
                if self.api_type in ("GraphQL", "SOAP"):
                    detection.api_type   = self.api_type
                    detection.confidence = 0.8
                    detection.score      = max(detection.score, 4)
                    detection.reasons.append(
                        f"{self.api_type} confirmed during active probing"
                    )
                else:
                    logger.info(
                        f"[*] API type upgraded to REST — "
                        f"{len(self.endpoints)} endpoint(s) found"
                    )
                    detection.api_type   = "REST"
                    detection.confidence = 0.5
                    detection.score      = max(detection.score, 2)
                    detection.reasons.append(
                        f"REST confirmed from {len(self.endpoints)} crawled endpoint(s)"
                    )
                    self.api_type = "REST"

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
            "schema":            gql_schema,
        }