# core/discovery.py
"""
APIDiscovery — API detection and crawling (REST | GraphQL | SOAP | Unknown)

Phase 1 : API type detection via multi-signal scoring system
Phase 2 : Endpoint crawling (wordlist + Swagger/OpenAPI + WSDL)

Design principles:
  - REST detection requires at least one confirmed JSON signal
    (a plain HTML 200 never contributes to the REST score)
  - Threshold raised from 2 to 3 to eliminate false positives
    on standard web applications that have no REST API
  - SPA awareness: HTML root + JSON sub-paths = valid REST API
  - Catch-all detection via baseline fingerprinting
  - GraphQL and SOAP take priority over REST when confirmed
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

# Versioned API paths — strong REST indicator when they return JSON
REST_VERSION_PATHS: list[str] = [
    "/api", "/api/v1", "/api/v2", "/api/v3",
    "/v1",  "/v2",     "/v3",
]

# Common REST resource paths — secondary REST signals
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

# ── Scoring thresholds ────────────────────────────────────────────────────────
_GQL_THRESHOLD  = 4
_GQL_MAX_SCORE  = 9

# REST threshold raised to 3 — requires at least one confirmed JSON signal.
# Score of 2 was too permissive: any HTML site scoring GET/→200 (+1) plus
# a versioned path responding 200 (+1) would incorrectly be classified REST.
_REST_THRESHOLD = 3
_REST_MAX_SCORE = 8

_SOAP_THRESHOLD = 4
_SOAP_MAX_SCORE = 7

# Invalid path patterns — filtered during crawl
_INVALID_PATH_PATTERNS: list[str] = [
    "?",            # query string without path
    "#",            # HTML anchor
    "javascript:",  # javascript: pseudo-protocol
    "mailto:",      # mailto: links
    "data:",        # data: URIs
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

    Detection logic (in priority order):
      1. SOAP   — WSDL/XML confirmed on dedicated paths
      2. GraphQL — introspection or __typename response confirmed
      3. REST   — JSON responses on API paths OR SPA + JSON sub-paths
      4. Unknown — none of the above confirmed

    REST false-positive prevention:
      - HTML 200 on / never scores (web apps always return 200 HTML)
      - Versioned paths (/api, /v1) must return JSON to contribute
      - Threshold is 3 (requires at least one confirmed JSON signal)
      - SPA detection grants a boost only when JSON is also found

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
        """
        True only if the response is genuine HTML content.

        Rejects JSON responses that carry an HTML Content-Type
        (common misconfiguration in some frameworks).
        """
        ct = r.headers.get("Content-Type", "")
        if "html" not in ct and "xml" not in ct:
            return False
        try:
            r.json()
            return False  # valid JSON despite wrong Content-Type
        except Exception:
            return True

    def _is_json_response(self, r) -> bool:
        """
        True if the response contains valid JSON.

        Uses both Content-Type header and body parsing as fallback,
        since some APIs set incorrect Content-Type headers.
        """
        if Requester.is_json(r):
            return True
        try:
            r.json()
            return True
        except Exception:
            return False

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

    def _is_valid_path(self, path: str) -> bool:
        """
        Validate a crawled path before adding it as an endpoint.

        Rejects:
          - Paths starting with invalid patterns (?, #, javascript:, etc.)
          - Empty paths
          - Paths that are clearly not API endpoints
        """
        if not path or not path.strip():
            return False

        # Normalize
        p = path.strip()

        # Must start with /
        if not p.startswith("/"):
            p = "/" + p

        # Check against invalid patterns
        for pattern in _INVALID_PATH_PATTERNS:
            if pattern in p and not p.startswith("/"):
                return False
            # Special case: paths like /?something
            if p.startswith("/?") or p == "/?:":
                return False

        return True

    # =========================================================================
    #  PHASE 1 — SOAP scoring
    # =========================================================================

    def _score_soap(self) -> tuple[int, list[str]]:
        """
        Detects SOAP APIs via WSDL and XML response analysis.

        Strategy:
          - Check common WSDL paths for XML/WSDL content
          - Send a SOAP probe to API-like paths
          - Count WSDL keyword matches for confidence
        """
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

    def _score_graphql(self) -> tuple[int, list[str], str | None]:
        """
        Detects GraphQL APIs via introspection and __typename probes.

        Returns (score, reasons, confirmed_path) where confirmed_path
        is the exact GraphQL endpoint URL path.
        """
        score:          int        = 0
        reasons:        list[str]  = []
        confirmed_path: str | None = None

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
    #  PHASE 1 — REST scoring
    #
    #  False-positive prevention principles:
    #
    #  1. GET / → 200 HTML  : ZERO points
    #     Any website returns 200 on /. HTML response means web app, not API.
    #     This was the main cause of false positives — now completely removed.
    #
    #  2. GET /api → 200 HTML : ZERO points
    #     /api returning HTML is a web app route, not a REST API.
    #     Only JSON responses on versioned paths contribute to score.
    #
    #  3. GET /api → 401/403 JSON : +1 point (weak signal)
    #     Auth-protected JSON endpoints are likely REST APIs.
    #     Requires JSON response, not just a 401 HTML page.
    #
    #  4. SPA boost (+2) : only when JSON sub-paths are confirmed
    #     React/Vue/Angular apps serve HTML on / and JSON on /api/*.
    #     Boost is granted only if has_json_signal = True.
    #
    #  5. Threshold = 3 : requires at least one strong JSON signal
    #     Minimum winning scenario: /api → JSON (+2) + OPTIONS (+1) = 3 ✅
    #     A plain HTML site: / → HTML (+0) + /api → HTML (+0) = 0 ✅
    # =========================================================================

    def _score_rest(self) -> tuple[int, list[str]]:
        """
        Scores REST API likelihood based on JSON response signals.

        Critical design decision: HTML responses NEVER contribute to score.
        Only confirmed JSON signals count toward REST detection.
        """
        score:           int  = 0
        reasons:         list[str] = []
        has_json_signal: bool = False
        has_html_root:   bool = False

        # ── Signal 1 — Root endpoint ──────────────────────────────────────────
        # Only JSON root responses score. HTML root = web app, not an API.
        r_root = self.http.get("/")
        if r_root and r_root.status_code == 200:
            if self._is_json_response(r_root):
                # Strong signal: root returns JSON → clearly an API
                score += 2
                reasons.append("GET / → 200 JSON")
                has_json_signal = True

                body = self._safe_json(r_root)
                if isinstance(body, (list, dict)) and "data" not in (body or {}):
                    score += 1
                    reasons.append("JSON body without GraphQL envelope")

            elif self._is_real_html(r_root):
                # HTML root — could be SPA. Record but do NOT score.
                # Score will come from sub-paths if they return JSON.
                has_html_root = True
                logger.debug("[score_rest] HTML root detected — SPA check pending")
            # else: non-HTML, non-JSON (binary, etc.) — no score

        # ── Signal 2 — Versioned API paths ───────────────────────────────────
        # /api, /v1, /v2, /v3 — strong REST indicator if JSON
        for path in REST_VERSION_PATHS:
            rv = self.http.get(path)
            if rv is None:
                continue

            if rv.status_code in (200, 201) and self._is_json_response(rv):
                # Strong signal: versioned path returns JSON
                score += 2
                has_json_signal = True
                reasons.append(f"GET {path} → {rv.status_code} JSON")
                break

            elif rv.status_code in (401, 403) and self._is_json_response(rv):
                # Weak signal: auth-required JSON — still an API
                score += 1
                has_json_signal = True
                reasons.append(f"GET {path} → {rv.status_code} JSON (auth required)")
                break

            # NOTE: 200 HTML on /api is intentionally NOT scored.
            # It indicates a web app route, not a REST API endpoint.

        # ── Signal 3 — Common REST resource paths ────────────────────────────
        # /users, /products, /orders, etc. — secondary confirmation
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

        # ── Signal 4 — HTTP OPTIONS ───────────────────────────────────────────
        # REST APIs typically expose multiple HTTP verbs
        ro = self.http.options("/")
        if ro and "Allow" in ro.headers:
            allow = ro.headers["Allow"]
            if any(v in allow for v in ("POST", "PUT", "DELETE", "PATCH")):
                score += 1
                reasons.append(f"OPTIONS / → Allow: {allow}")

        # ── Signal 5 — SPA boost ──────────────────────────────────────────────
        # React/Vue/Angular: HTML on /, JSON on /api/* → valid REST API
        # Boost is ONLY granted when JSON was also confirmed (has_json_signal)
        # Without this guard, any SPA without API would be classified REST.
        if has_html_root and has_json_signal:
            score += 2
            reasons.append("SPA frontend with JSON API on sub-paths")

        return score, reasons

    # =========================================================================
    #  PHASE 1 — Final decision
    # =========================================================================

    def detect_api_type(self) -> DetectionResult:
        """
        Runs all scoring functions and returns the most likely API type.

        Priority order: SOAP > GraphQL > REST > Unknown
        SOAP and GraphQL require higher confidence thresholds (4+) to avoid
        false positives against REST APIs that also use XML occasionally.
        """
        logger.info("[*] Detecting API type...")

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
            # Not enough signals to classify → Unknown
            # The crawler will attempt wordlist discovery and may upgrade to REST
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
        """
        Fingerprints the backend technology from HTTP response headers.
        Uses Server, X-Powered-By, and Via headers.
        """
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
        """
        Discovers API endpoints from Swagger/OpenAPI specification files.
        Checks all known Swagger paths and parses the paths object.
        Returns full endpoint URLs.
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

            logger.info(f"[+] Swagger/OpenAPI found on {path} — {len(paths)} paths")

            # Resolve base path (differs between OpenAPI 2.x and 3.x)
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

            break  # First valid spec found is sufficient

        self.swagger_endpoints = found
        return found

    # =========================================================================
    #  PHASE 2 — Wordlist crawling
    #
    #  SPA-aware filtering:
    #  - If root returns HTML (SPA), JSON responses on sub-paths are ALWAYS kept
    #  - 401/403 on JSON endpoints = protected API endpoint → kept
    #  - Invalid paths (/?:, #anchor, javascript:) are rejected at entry
    #  - Catch-all detection via baseline fingerprinting
    # =========================================================================

    def crawl_endpoints(
        self,
        wordlist_path: str,
        limit: Optional[int] = None,
    ) -> list[str]:
        """
        Crawls the target using a wordlist to discover API endpoints.

        Filtering layers (in order):
          1. Invalid path pattern rejection (?, #, javascript:, etc.)
          2. HTTP error filtering (keep 401/403 JSON, reject 4xx/5xx HTML)
          3. Auth redirect detection (login pages disguised as 200)
          4. Catch-all / baseline fingerprint comparison
          5. HTML frontend page rejection (unless root is also HTML = SPA)
          6. Duplicate body hash deduplication
        """
        try:
            with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
                raw_paths = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            logger.error(f"[crawl] Wordlist not found: {wordlist_path}")
            return []

        # Deduplicate wordlist while preserving order
        seen_paths: set[str] = set()
        paths: list[str] = []
        for p in raw_paths:
            if p and p not in seen_paths:
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

            # Normalize path
            if not path.startswith("/"):
                path = "/" + path

            # Filter 0 — Reject invalid paths before sending any request
            if not self._is_valid_path(path):
                logger.debug(f"    [FP-invalid-path] {path}")
                continue

            url = self.base_url + path
            if url in already_known:
                continue

            r = self.http.get(path, allow_redirects=False)
            if r is None:
                continue

            content_type = r.headers.get("Content-Type", "")
            is_json      = self._is_json_response(r)

            # Filter 1 — Auth-protected endpoints (401/403)
            # Keep ONLY if response is JSON or root is an SPA (HTML frontend)
            if r.status_code in (401, 403):
                if not is_json and not root_is_html:
                    continue
                # Protected API endpoint confirmed
                already_known.add(url)
                found_this_run.append(url)
                self.endpoints.append(url)
                logger.info(f"    [crawl] {r.status_code} → {url}")
                continue

            elif r.status_code >= 400:
                continue

            # Filter 2 — Auth redirect (login page disguised as 3xx)
            if self._is_redirect_to_auth(r):
                logger.debug(f"    [FP-redirect] {path}")
                continue

            # Filter 3 — Catch-all / baseline fingerprint
            # Exception: SPA root HTML + sub-path JSON → never filter
            if root_is_html and is_json:
                pass  # SPA + JSON API → always keep
            elif self._is_false_positive(r, baseline):
                logger.debug(f"    [FP-baseline] {path}")
                continue

            # Filter 4 — Pure HTML frontend pages
            # Skip if root is already HTML (SPA detection)
            if not root_is_html and self._is_html_frontend(r):
                logger.debug(f"    [FP-html] {path}")
                continue

            # Filter 5 — Duplicate body hash
            body_hash = hashlib.md5(r.content).hexdigest()
            if body_hash in seen_bodies:
                logger.debug(f"    [FP-duplicate-body] {path}")
                continue

            # Endpoint confirmed — add to results
            seen_bodies.add(body_hash)
            already_known.add(url)
            found_this_run.append(url)
            self.endpoints.append(url)
            logger.info(f"    [crawl] {r.status_code} → {url}")

        logger.info(f"[+] Crawl complete — {len(found_this_run)} new endpoints found")
        return self.endpoints

    # ── Crawl helpers ─────────────────────────────────────────────────────────

    def _get_baseline(self) -> dict:
        """
        Probes a non-existent path to fingerprint the server's default response.
        Used to detect catch-all servers that return 200 for any path.
        """
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
        """
        Detects catch-all false positives by comparing response to baseline.

        A response is a false positive if:
          - Its body hash matches the baseline (same catch-all response)
          - Its content length matches the baseline exactly
          - It is too short to be a meaningful API response (<10 bytes)

        JSON responses are never considered false positives.
        """
        if not baseline:
            return False

        body_hash      = hashlib.md5(r.content).hexdigest()
        content_length = len(r.content)
        content_type   = r.headers.get("Content-Type", "")

        # JSON responses are real — never a catch-all false positive
        if "application/json" in content_type:
            return False

        # Exact hash match → catch-all
        if body_hash == baseline.get("body_hash"):
            return True

        # Same size as baseline → very likely catch-all
        if content_length == baseline.get("content_length") and content_length > 0:
            return True

        # Too short to be meaningful
        if content_length < 10:
            return True

        return False

    def _is_redirect_to_auth(self, r) -> bool:
        """Detects redirects to login/auth pages (auth walls disguised as endpoints)."""
        if r.status_code not in (301, 302, 303, 307, 308):
            return False
        location      = r.headers.get("Location", "").lower()
        auth_patterns = ["/login", "/signin", "/auth", "/connect", "/sso", "/oauth"]
        return any(p in location for p in auth_patterns)

    def _is_html_frontend(self, r) -> bool:
        """
        True if the response is an HTML page (frontend route, not API endpoint).
        JSON responses with wrong Content-Type are correctly identified as non-HTML.
        """
        ct = r.headers.get("Content-Type", "")
        if "text/html" not in ct:
            return False
        try:
            r.json()
            return False  # valid JSON → API endpoint, not frontend
        except Exception:
            return True

    # =========================================================================
    #  run() — Main orchestrator
    # =========================================================================

    def run(self, wordlist_path: str, mode: str = "quick") -> dict:
        """
        Runs the full discovery pipeline in order:
          1. detect_api_type()   — REST | GraphQL | SOAP | Unknown
          2. detect_technology() — tech stack from response headers
          3. parse_swagger()     — Swagger/OpenAPI endpoint extraction
          4. crawl_endpoints()   — wordlist-based crawling (REST/Unknown only)
             or fetch_graphql_schema() for GraphQL
             or WSDL endpoint registration for SOAP

        Args:
            wordlist_path : path to endpoint wordlist file
            mode          : "quick" (50 paths max) | "full" (entire wordlist)

        Returns:
            dict with api_type, confidence, endpoints, schema, tech_stack, etc.
        """
        logger.info(f"[*] Starting discovery on {self.base_url}")

        # Step 1 — API type detection
        detection = self.detect_api_type()

        # Step 2 — Tech stack fingerprinting
        self.detect_technology()
        if self.tech_stack:
            logger.info(f"[+] Tech stack: {', '.join(self.tech_stack)}")

        # Step 3 — Swagger/OpenAPI (universal — works for REST and hybrid APIs)
        swagger_found = self.parse_swagger()

        # Step 4 — API-type-specific endpoint collection
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
                    wsdl_url = self.base_url + path
                    if wsdl_url not in self.endpoints:
                        self.endpoints.append(self.base_url)

                    # Enrich tech stack from WSDL content
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

            # Deduplicate tech stack
            self.tech_stack = list(dict.fromkeys(self.tech_stack))

        else:
            # REST or Unknown → wordlist crawl
            limit = 50 if mode == "quick" else None
            self.crawl_endpoints(wordlist_path, limit=limit)

            # Upgrade Unknown → REST if crawl found confirmed endpoints
            # This handles APIs that don't respond to common REST paths
            # but DO have endpoints discoverable via wordlist
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

        # Merge all endpoints — swagger first, then crawled, deduped
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