# core/rest_scanner.py
"""
RESTScanner — Automated REST API vulnerability detection engine.

Architecture:
    Inspired by Nuclei (rule-based checks) and OWASP ZAP (per-parameter testing).
    Each vulnerability class is an isolated, self-documented check with full
    metadata: OWASP mapping, CWE, severity, confidence, solution, and reference.

Vulnerability classes implemented:
    [API8] Security Misconfiguration
        CORS-001 : Reflected Origin
        CORS-002 : Wildcard with Credentials
        CORS-003 : Wildcard Origin
        HDR-001  : Missing Strict-Transport-Security
        HDR-002  : Missing X-Content-Type-Options
        HDR-003  : Missing X-Frame-Options
        HDR-004  : Missing Content-Security-Policy
        INFO-001 : Server Version Disclosure
        INFO-002 : X-Powered-By Disclosure
       ***** VERB-001 : HTTP TRACE Method Enabled
        ERR-001  : Verbose Error Messages / Stack Trace Exposure

    [API2] Broken Authentication
        AUTH-001 : Endpoint accessible without token
        AUTH-002 : Endpoint accepts invalid/forged token
        AUTH-003 : JWT 'none' algorithm accepted
        AUTH-004 : JWT algorithm confusion (RS256 -> HS256)

Usage:
    # With manual token
    scanner = RESTScanner("https://api.example.com", token="eyJ...")

    # With automatic login
    scanner = RESTScanner(
        "https://api.example.com",
        login_url = "/identity/api/auth/login",
        username  = "user@test.com",
        password  = "pass123",
    )
    results = scanner.scan(endpoints, tests=["misconfig", "auth"])
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import time
from dataclasses import dataclass, field
from typing import Optional, Callable
from urllib.parse import urlparse

from core.models   import ScanResult
from core.requester import Requester
from core.vuln_db   import VulnDB
from logger.logger  import logger

# Load REST vulnerability knowledge base once at module level
_restdb = VulnDB("rest")


def _vuln(
    vuln_id:   str,
    endpoint:  str,
    method:    str,
    evidence:  str,
    payload:   Optional[str] = None,
    parameter: Optional[str] = None,
    extra_desc: Optional[str] = None,
    # Override fields — used when the scanner has more context than the DB
    severity:  Optional[str] = None,
    confidence: Optional[str] = None,
) -> ScanResult:
    """
    Build a ScanResult from the REST knowledge base.
    vuln_id maps to a key in data/rest_vulns.json (e.g. "CORS-001", "AUTH-003").
    """
    meta = _restdb.get(vuln_id)
    description = meta.get("description", f"Vulnerability: {vuln_id}")
    if extra_desc:
        description = f"{description} {extra_desc}"

    return ScanResult(
        vuln_id     = meta.get("id",         vuln_id),
        vuln_type   = meta.get("label",       vuln_id),
        severity    = severity    or meta.get("severity",   "MEDIUM"),
        confidence  = confidence  or meta.get("confidence", "HIGH"),
        owasp       = meta.get("owasp",       "API8:2023"),
        cwe         = meta.get("cwe",         "CWE-200"),
        endpoint    = endpoint,
        method      = method,
        parameter   = parameter,
        payload     = payload,
        evidence    = evidence,
        description = description,
        solution    = meta.get("solution",  "See OWASP API Security Cheat Sheet."),
        reference   = meta.get("reference", "https://owasp.org/API-Security/"),
    )
# =============================================================================
#  ScanResult
# =============================================================================

'''@dataclass
class ScanResult:
    """Enriched vulnerability finding — OWASP ZAP alert structure."""

    vuln_id:     str            # "CORS-001"
    vuln_type:   str            # "Reflected Origin CORS Misconfiguration"
    owasp:       str            # "API8"
    cwe:         str            # "CWE-942"
    severity:    str            # CRITICAL | HIGH | MEDIUM | LOW | INFO
    confidence:  str            # HIGH | MEDIUM | LOW
    endpoint:    str
    method:      str
    parameter:   Optional[str]
    payload:     Optional[str]
    evidence:    str
    description: str
    solution:    str
    reference:   str

    def to_dict(self) -> dict:
        return {
            "vuln_id":     self.vuln_id,
            "vuln_type":   self.vuln_type,
            "owasp":       self.owasp,
            "cwe":         self.cwe,
            "severity":    self.severity,
            "confidence":  self.confidence,
            "endpoint":    self.endpoint,
            "method":      self.method,
            "parameter":   self.parameter,
            "payload":     self.payload,
            "evidence":    self.evidence,
            "description": self.description,
            "solution":    self.solution,
            "reference":   self.reference,
        }

    def __str__(self) -> str:
        lines = [
            f"[{self.severity}] [{self.vuln_id}] {self.vuln_type}",
            f"  Endpoint  : {self.endpoint}",
            f"  Method    : {self.method}",
        ]
        if self.parameter:
            lines.append(f"  Parameter : {self.parameter}")
        if self.payload:
            lines.append(f"  Payload   : {self.payload}")
        lines.append(f"  Evidence  : {self.evidence[:200]}")
        lines.append(f"  OWASP     : {self.owasp}  |  CWE: {self.cwe}  |  Confidence: {self.confidence}")
        lines.append(f"  Solution  : {self.solution}")
        return "\n".join(lines)
'''

# =============================================================================
#  Module-level constants
# =============================================================================

# ── CORS ──────────────────────────────────────────────────────────────────────
_CORS_CANARY = "https://evil-apisec-test.attacker.com"

# ── Security Headers ──────────────────────────────────────────────────────────
# (header_name, check_id, vuln_type, severity, cwe, description, solution, reference)
SECURITY_HEADERS: list[tuple] = [
    (
        "Strict-Transport-Security", "HDR-001",
        "Missing Strict-Transport-Security (HSTS)", "MEDIUM", "CWE-319",
        "The Strict-Transport-Security (HSTS) header is absent. Without HSTS, browsers "
        "may connect to the API over plain HTTP, exposing credentials and session tokens "
        "to network-level interception (man-in-the-middle attacks).",
        "Add the header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security",
    ),
    (
        "X-Content-Type-Options", "HDR-002",
        "Missing X-Content-Type-Options", "LOW", "CWE-693",
        "The X-Content-Type-Options header is absent. Without it, browsers may "
        "MIME-sniff responses away from the declared content type, potentially "
        "executing malicious scripts disguised as benign content.",
        "Add the header: X-Content-Type-Options: nosniff",
        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options",
    ),
    (
        "X-Frame-Options", "HDR-003",
        "Missing X-Frame-Options", "MEDIUM", "CWE-1021",
        "The X-Frame-Options header is absent. This allows the API responses to be "
        "embedded in iframes on third-party pages, enabling clickjacking attacks "
        "where users are tricked into performing unintended actions.",
        "Add the header: X-Frame-Options: DENY  (or SAMEORIGIN if framing is needed internally)",
        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options",
    ),
    (
        "Content-Security-Policy", "HDR-004",
        "Missing Content-Security-Policy (CSP)", "MEDIUM", "CWE-693",
        "The Content-Security-Policy header is absent. CSP is a critical defense "
        "against Cross-Site Scripting (XSS) attacks by specifying which sources "
        "of content are allowed to be loaded and executed by the browser.",
        "Define a strict CSP policy. Minimum: Content-Security-Policy: default-src 'self'",
        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy",
    ),
]

# ── Server Information Disclosure ─────────────────────────────────────────────
# (header_name, check_id, vuln_type, cwe, description, solution, reference)
INFO_HEADERS: list[tuple] = [
    (
        "Server", "INFO-001", "Server Version Disclosure", "CWE-200",
        "The Server header exposes the web server software name and version. "
        "This information allows attackers to identify known CVEs targeting "
        "the specific version and craft targeted exploits.",
        "Configure the server to return a generic value (e.g. Server: webserver) "
        "or suppress the header entirely.",
        "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/"
        "01-Information_Gathering/02-Fingerprint_Web_Server",
    ),
    (
        "X-Powered-By", "INFO-002", "Technology Stack Disclosure via X-Powered-By", "CWE-200",
        "The X-Powered-By header reveals the backend technology and version "
        "(e.g. PHP/7.2.1, ASP.NET). This fingerprinting information aids attackers "
        "in identifying framework-specific vulnerabilities.",
        "Remove the X-Powered-By header from server configuration. "
        "In Express.js: app.disable('x-powered-by'). In PHP: expose_php = Off.",
        "https://owasp.org/www-project-web-security-testing-guide/",
    ),
]

_VERSION_PATTERN = re.compile(r"[\d]+\.[\d]+")

# ── Verbose Error Patterns ────────────────────────────────────────────────────
VERBOSE_ERROR_PATTERNS: list[tuple[str, str]] = [
    (r"at\s+[\w\.]+\([\w\.]+:\d+\)",             "Java/Kotlin stack trace"),
    (r"at\s+System\.",                             ".NET stack trace"),
    (r"at\s+Microsoft\.",                          ".NET/ASP.NET stack trace"),
    (r"Traceback \(most recent call last\)",       "Python stack trace"),
    (r"File \"[^\"]+\", line \d+",                 "Python file path disclosure"),
    (r"in /(?:var|home|srv|app|usr)/\w+",         "Linux file path disclosure"),
    (r"(?:mysqli?|pg|sqlite|odbc)_",               "Database function name disclosure"),
    (r"ORA-\d{5}",                                 "Oracle database error code"),
    (r"Microsoft OLE DB",                          "Microsoft database driver disclosure"),
    (r"SQLSTATE\[\w+\]",                           "PDO/SQL state error disclosure"),
    (r"(?:Laravel|Symfony|Django|Rails|Spring|Express)\s+[\d\.]+", "Framework version disclosure"),
    (r"(?:PHP Fatal error|PHP Warning|PHP Notice)", "PHP error disclosure"),
    (r"on line \d+",                               "Source code line number disclosure"),
]

VERBOSE_ERROR_TRIGGERS: list[dict] = [
    {"method": "GET",  "params": {"id": "' OR 1=1--"}},
    {"method": "GET",  "params": {"id": None}},
    {"method": "POST", "json":   {"id": None, "data": [1, 2, 3] * 1000}},
    {"method": "GET",  "params": {"id": "A" * 8192}},
]

# ── Broken Authentication ─────────────────────────────────────────────────────
_INVALID_TOKEN = "apisec.invalid.token.test.xyz123abc456"

_LOGIN_FIELD_CANDIDATES: list[str] = [
    "email", "username", "user", "login",
    "identifier", "account", "mail", "name",
]

_TOKEN_FIELD_CANDIDATES: list[str] = [
    "token", "access_token", "accessToken", "jwt",
    "id_token", "idToken", "auth_token", "authToken",
]


_RATE_LIMIT_ATTEMPTS   = 20
_RATE_LIMIT_HEADERS    = {
    "retry-after",
    "x-ratelimit-limit",
    "x-ratelimit-remaining",
    "x-ratelimit-reset",
    "x-rate-limit-limit",
    "x-rate-limit-remaining",
    "ratelimit-limit",
    "ratelimit-remaining",
}

# =============================================================================
#  RESTScanner
# =============================================================================

class RESTScanner:
    """
    Automated REST API vulnerability scanner.

    Implements a rule-based detection engine inspired by Nuclei templates
    combined with OWASP ZAP per-parameter active scanning approach.
    """

    _TEST_REGISTRY: dict[str, str] = {
        "misconfig": "_test_misconfig",
        "auth":      "_test_auth",
        "sqli":        "_test_sqli",
        # "blind_sqli":  "_test_blind_sqli",
        # "nosql":       "_test_nosql",
        # "xss":         "_test_xss",
        # "ssrf":        "_test_ssrf",
        # "idor":        "_test_idor",
        # "mass_assign": "_test_mass_assignment",
        # "rate_limit":  "_test_rate_limit",
    }

    def __init__(
        self,
        base_url:   str,
        timeout:    int = 10,
        token:      Optional[str] = None,
        login_url:  Optional[str] = None,
        username:   Optional[str] = None,
        password:   Optional[str] = None,
        login_body: Optional[str] = None,
        params_map: Optional[dict] = None,
        deep:       bool = False,
    ) -> None:
        self.base_url  = base_url.rstrip("/")
        self.http      = Requester(self.base_url, timeout=timeout)
        self.token     = None
        self.login_url = login_url
        self._auth005_done = False
        self.params_map = params_map or {} 
        self.deep = deep
        self._jwks_public_key_cache: Optional[str] = None

        if token:
            self.token = token
            self.http.set_token(token)
            logger.info("[scanner] Token provided manually")

        elif login_url and login_body:
            self.token = self._auto_login_raw(login_url, login_body)
            if self.token:
                self.http.set_token(self.token)

        elif login_url and username and password:
            self.token = self._auto_login_detect(login_url, username, password)
            if self.token:
                self.http.set_token(self.token)

        else:
            logger.info("[scanner] No token or credentials — AUTH-001/003/004 will be skipped")

    # =========================================================================
    #  Entry point
    # =========================================================================

    def scan(
        self,
        endpoints: list[str],
        tests:     Optional[list[str]] = None,
    ) -> list[ScanResult]:
        if tests is None:
            active = list(self._TEST_REGISTRY.keys())
        else:
            active  = [t for t in tests if t in self._TEST_REGISTRY]
            unknown = [t for t in tests if t not in self._TEST_REGISTRY]
            if unknown:
                logger.warning(f"[scanner] Unknown tests ignored: {', '.join(unknown)}")

        if not active:
            logger.error("[scanner] No valid tests selected.")
            return []

        logger.info(f"[*] REST Scanner — {len(endpoints)} endpoint(s) — active tests: {active}")

        findings: list[ScanResult] = []
        for endpoint in endpoints:
            logger.debug(f"    [scan] {endpoint}")
            for test_name in active:
                test_method = getattr(self, self._TEST_REGISTRY[test_name])
                try:
                    results = test_method(endpoint)
                    if results:
                        findings.extend(results)
                except Exception as e:
                    logger.debug(f"    [scan:{test_name}] Error on {endpoint}: {e}")

        logger.info(f"[+] Scan complete — {len(findings)} finding(s) detected")
        return self._deduplicate(findings)

    # =========================================================================
    #  [API8] Security Misconfiguration
    # =========================================================================

    def _test_misconfig(self, endpoint: str) -> list[ScanResult]:
        findings: list[ScanResult] = []
        path = self._to_path(endpoint)

        baseline = self.http.get(path)
        if baseline is None:
            logger.debug(f"    [misconfig] No response from {endpoint} — skipping")
            return findings

        findings += self._check_cors(endpoint, path)
        findings += self._check_security_headers(endpoint, baseline)
        findings += self._check_server_disclosure(endpoint, baseline)
        findings += self._check_trace_method(endpoint, path)
        findings += self._check_verbose_errors(endpoint, path)
        return findings

    def _check_cors(self, endpoint: str, path: str) -> list[ScanResult]:
        findings: list[ScanResult] = []

        r    = self.http.get(path, headers={"Origin": _CORS_CANARY})
        if r is None:
            return findings

        acao = r.headers.get("Access-Control-Allow-Origin",      "").strip()
        acac = r.headers.get("Access-Control-Allow-Credentials", "").strip().lower()
        acam = r.headers.get("Access-Control-Allow-Methods",     "").strip()

        if _CORS_CANARY in acao:
            severity      = "CRITICAL" if acac == "true" else "HIGH"
            evidence_parts = [f"Access-Control-Allow-Origin: {acao}"]
            if acac == "true":
                evidence_parts.append("Access-Control-Allow-Credentials: true")
            if acam:
                evidence_parts.append(f"Access-Control-Allow-Methods: {acam}")
            description = (
                "The server reflects the attacker-controlled Origin header without validation. "
                "Any malicious website can send cross-origin requests to this API and read "
                "the response on behalf of an authenticated victim."
            )
            if acac == "true":
                description += (
                    " With Allow-Credentials: true, this is CRITICAL — the attacker receives "
                    "the victim's authenticated session cookies and tokens in the API response."
                )
            findings.append(_vuln(
                vuln_id    = "CORS-001",
                endpoint   = endpoint,
                method     = "GET",
                parameter  = "Origin (request header)",
                payload    = f"Origin: {_CORS_CANARY}",
                evidence   = " | ".join(evidence_parts),
                severity   = severity,
                extra_desc = description,
            ))
            logger.info(f"    [VULN] CORS-001 Reflected Origin ({severity}) -> {endpoint}")
            return findings

        if acao == "*" and acac == "true":
            findings.append(_vuln(
                vuln_id   = "CORS-002",
                endpoint  = endpoint,
                method    = "GET",
                parameter = "Origin (request header)",
                evidence  = "Access-Control-Allow-Origin: * | Access-Control-Allow-Credentials: true",
            ))
            logger.info(f"    [VULN] CORS-002 Wildcard + Credentials -> {endpoint}")
            return findings

        if acao == "*":
            findings.append(_vuln(
                vuln_id   = "CORS-003",
                endpoint  = endpoint,
                method    = "GET",
                parameter = "Origin (request header)",
                evidence  = "Access-Control-Allow-Origin: *",
            ))
            logger.info(f"    [VULN] CORS-003 Wildcard Origin -> {endpoint}")

        return findings

    def _check_security_headers(self, endpoint: str, baseline) -> list[ScanResult]:
        findings: list[ScanResult] = []
        is_http = endpoint.startswith("http://")
        headers_lower = {k.lower(): v for k, v in baseline.headers.items()}

        for (header, check_id, vuln_type, severity, cwe, description, solution, reference) in SECURITY_HEADERS:
            if header == "Strict-Transport-Security" and is_http:
                logger.debug(f"    [misconfig] HDR-001 skipped — HSTS not applicable over HTTP -> {endpoint}")
                continue
            if header.lower() not in headers_lower:
                findings.append(_vuln(
                    vuln_id   = check_id,
                    endpoint  = endpoint,
                    method    = "GET",
                    parameter = f"{header} (response header)",
                    evidence  = f"Header '{header}' is absent from the response",
                ))
                logger.info(f"    [VULN] {check_id} Missing {header} -> {endpoint}")

        return findings

    def _check_server_disclosure(self, endpoint: str, baseline) -> list[ScanResult]:
        findings: list[ScanResult] = []
        for (header, check_id, vuln_type, cwe, description, solution, reference) in INFO_HEADERS:
            value = baseline.headers.get(header, "").strip()
            if value and _VERSION_PATTERN.search(value):
                findings.append(_vuln(
                    vuln_id   = check_id,
                    endpoint  = endpoint,
                    method    = "GET",
                    parameter = f"{header} (response header)",
                    evidence  = f"{header}: {value}",
                ))
                logger.info(f"    [VULN] {check_id} {header} discloses version: {value} -> {endpoint}")
        return findings

    def _check_trace_method(self, endpoint: str, path: str) -> list[ScanResult]:
        findings: list[ScanResult] = []
        r = self.http._request("TRACE", path)
        if r is None:
            return findings

        if r.status_code == 200:
            body        = r.text or ""
            is_confirmed = (
                "TRACE" in body
                or r.headers.get("Content-Type", "").lower().startswith("message/http")
            )
            confidence = "HIGH" if is_confirmed else "MEDIUM"
            findings.append(_vuln(
                vuln_id    = "VERB-001",
                endpoint   = endpoint,
                method     = "TRACE",
                payload    = "TRACE / HTTP/1.1",
                evidence   = (
                    f"TRACE returned HTTP {r.status_code}. "
                    f"Content-Type: {r.headers.get('Content-Type', 'N/A')}. "
                    f"Body preview: {body[:100].replace(chr(10), ' ')}"
                ),
                confidence = confidence,
            ))
            logger.info(f"    [VULN] VERB-001 TRACE enabled (confidence: {confidence}) -> {endpoint}")

        return findings

    def _check_verbose_errors(self, endpoint: str, path: str) -> list[ScanResult]:
        findings: list[ScanResult] = []
        for trigger in VERBOSE_ERROR_TRIGGERS:
            method = trigger["method"]
            r = (
                self.http.get(path, params=trigger.get("params"))
                if method == "GET"
                else self.http.post(path, json=trigger.get("json"))
            )
            if r is None or r.status_code < 400:
                continue
            body = r.text or ""
            for pattern, leak_type in VERBOSE_ERROR_PATTERNS:
                match = re.search(pattern, body, re.IGNORECASE)
                if not match:
                    continue
                start   = max(0, match.start() - 30)
                end     = min(len(body), match.end() + 100)
                excerpt = body[start:end].strip().replace("\n", " ")
                findings.append(_vuln(
                    vuln_id    = "ERR-001",
                    endpoint   = endpoint,
                    method     = method,
                    payload    = str(trigger.get("params") or trigger.get("json")),
                    evidence   = f"HTTP {r.status_code} — {leak_type} detected. Excerpt: \"{excerpt[:150]}\"",
                    extra_desc = f"Detected: {leak_type}.",
                ))
                logger.info(f"    [VULN] ERR-001 Verbose error ({leak_type}) HTTP {r.status_code} -> {endpoint}")
                return findings
        return findings

    # =========================================================================
    #  [API2] Broken Authentication
    # =========================================================================

    def _test_auth(self, endpoint: str) -> list[ScanResult]:
        """
        Runs all Broken Authentication checks.

        AUTH-001 : Endpoint accessible without token
        AUTH-002 : Endpoint accepts invalid/forged token
        AUTH-003 : JWT 'none' algorithm accepted
        AUTH-004 : JWT algorithm confusion (RS256 -> HS256)
        AUTH-005 : No rate limiting on login endpoint
        """
        findings: list[ScanResult] = []
        path = self._to_path(endpoint)

        findings += self._check_no_token_required(endpoint, path)
        findings += self._check_invalid_token_accepted(endpoint, path)

        if self.token:
            findings += self._check_jwt_none_algorithm(endpoint, path)
            findings += self._check_jwt_alg_confusion(endpoint, path)
        else:
            logger.debug(f"    [auth] AUTH-003/004 skipped — no token -> {endpoint}")
        
        if self.login_url and not self._auth005_done:
            self._auth005_done = True
            findings += self._check_login_rate_limit(endpoint)
       
        return findings

    def _check_no_token_required(self, endpoint: str, path: str) -> list[ScanResult]:
        """AUTH-001: Tests if a protected endpoint returns data without any token."""
        findings: list[ScanResult] = []

        if not self.token:
            return findings

        # Step 1 — authenticated request
        r_auth = self.http.get(path)
        if r_auth is None or r_auth.status_code not in (200, 201):
            return findings
        auth_body = (r_auth.text or "").strip()

        # Step 2 — unauthenticated request
        self.http.clear_token()
        r_unauth = self.http.get(path)
        self.http.set_token(self.token)

        if r_unauth is None:
            return findings

        unauth_status = r_unauth.status_code
        unauth_body   = (r_unauth.text or "").strip()

        # Step 3 — analyze
        if unauth_status in (401, 403):
            logger.debug(f"    [auth] AUTH-001 protected (HTTP {unauth_status}) -> {endpoint}")
            return findings

        if unauth_status in (200, 201):
            if unauth_body == auth_body:
                logger.debug(f"    [auth] AUTH-001 public endpoint -> {endpoint}")
                return findings
            findings.append(_vuln(
                vuln_id   = "AUTH-001",
                endpoint  = endpoint,
                method    = "GET",
                parameter = "Authorization (request header)",
                payload   = "No Authorization header sent",
                evidence  = (
                    f"HTTP {unauth_status} without token. "
                    f"Auth response: {len(auth_body)} bytes. "
                    f"Unauth response: {len(unauth_body)} bytes. "
                    f"Preview: {unauth_body[:100]}"
                ),
            ))
            logger.info(f"    [VULN] AUTH-001 No token required -> {endpoint}")

        return findings

    def _check_invalid_token_accepted(self, endpoint: str, path: str) -> list[ScanResult]:
        """AUTH-002: Tests if the server accepts a completely invalid token."""
        findings: list[ScanResult] = []

        self.http.clear_token()
        self.http.set_token(_INVALID_TOKEN)
        r = self.http.get(path)
        self.http.clear_token()
        if self.token:
            self.http.set_token(self.token)

        if r is None:
            return findings

        if r.status_code in (200, 201):
            findings.append(_vuln(
                vuln_id   = "AUTH-002",
                endpoint  = endpoint,
                method    = "GET",
                parameter = "Authorization (request header)",
                payload   = f"Bearer {_INVALID_TOKEN}",
                evidence  = (
                    f"HTTP {r.status_code} with a clearly invalid non-JWT token. "
                    f"Preview: {(r.text or '')[:100]}"
                ),
            ))
            logger.info(f"    [VULN] AUTH-002 Invalid token accepted -> {endpoint}")
        else:
            logger.debug(f"    [auth] AUTH-002 invalid token rejected (HTTP {r.status_code}) -> {endpoint}")
        return findings

    def _check_jwt_none_algorithm(self, endpoint: str, path: str) -> list[ScanResult]:
        """AUTH-003: Tests if the server accepts a JWT with alg: none (no signature)."""
        findings: list[ScanResult] = []

        decoded = self._decode_jwt_payload(self.token)
        if not decoded:
            return findings

        # ← capturer l'alg AVANT toute manipulation
        original_alg = self._get_jwt_alg(self.token)
    
        none_token = self._forge_jwt_none(decoded)
        if not none_token:
            return findings

        self.http.clear_token()
        self.http.set_token(none_token)
        r = self.http.get(path)
        self.http.clear_token()
        self.http.set_token(self.token)

        if r and r.status_code in (200, 201):
            findings.append(_vuln(
                vuln_id   = "AUTH-003",
                endpoint  = endpoint,
                method    = "GET",
                parameter = "Authorization (JWT alg field)",
                payload   = f"Bearer {none_token[:80]}... (alg:none, empty signature)",
                evidence  = (
                    f"HTTP {r.status_code} with JWT alg:none (no signature). "
                    f"Original alg: {self._get_jwt_alg(self.token)}."
                ),
            ))
            logger.info(f"    [VULN] AUTH-003 JWT none algorithm accepted -> {endpoint}")

        return findings

    def _check_jwt_alg_confusion(self, endpoint: str, path: str) -> list[ScanResult]:
        """AUTH-004: Tests JWT algorithm confusion attack (RS256 -> HS256 with public key)."""
        findings: list[ScanResult] = []

        original_alg = self._get_jwt_alg(self.token)
        if original_alg not in ("RS256", "RS384", "RS512", "ES256", "ES384", "ES512"):
            logger.debug(f"    [auth] AUTH-004 skipped — {original_alg} not asymmetric -> {endpoint}")
            return findings

        public_key_pem = self._fetch_jwks_public_key()
        if not public_key_pem:
            logger.debug(f"    [auth] AUTH-004 skipped — no JWKS endpoint found -> {endpoint}")
            return findings

        decoded = self._decode_jwt_payload(self.token)
        if not decoded:
            return findings

        forged = self._forge_jwt_hs256(decoded, public_key_pem)
        if not forged:
            return findings

        self.http.clear_token()
        self.http.set_token(forged)
        r = self.http.get(path)
        self.http.clear_token()
        self.http.set_token(self.token)

        if r and r.status_code in (200, 201):
            findings.append(_vuln(
                vuln_id    = "AUTH-004",
                endpoint   = endpoint,
                method     = "GET",
                parameter  = "Authorization (JWT alg field)",
                payload    = f"Bearer {forged[:80]}... ({original_alg} -> HS256 with public key)",
                evidence   = (
                    f"HTTP {r.status_code} with HS256 token signed using server RSA public key. "
                    f"Original algorithm: {original_alg}."
                ),
                extra_desc = f"Algorithm changed from {original_alg} to HS256.",
            ))
            logger.info(f"    [VULN] AUTH-004 JWT alg confusion ({original_alg}->HS256) -> {endpoint}")

        return findings
    def _check_login_rate_limit(self, endpoint: str) -> list[ScanResult]:
        """
        AUTH-005: Tests if the login endpoint enforces rate limiting.

        Sends _RATE_LIMIT_ATTEMPTS rapid POST requests with wrong credentials.
        Vulnerable if: no HTTP 429 received AND no rate-limit headers detected
        across all attempts.
        """
        findings: list[ScanResult] = []

        login_path = self._to_path(self.login_url)
        dummy_body = {"username": "apisec_ratelimit_test", "password": "Wr0ng!Pass#2024"}

        got_429            = False
        got_ratelimit_hdr  = False
        first_block_at     = None

        logger.debug(
            f"    [auth] AUTH-005 sending {_RATE_LIMIT_ATTEMPTS} requests -> {self.login_url}"
        )

        for attempt in range(1, _RATE_LIMIT_ATTEMPTS + 1):
            r = self.http.post(login_path, json=dummy_body)

            if r is None:
                logger.debug(f"    [auth] AUTH-005 no response at attempt {attempt}")
                continue

            # Check 1 — HTTP 429
            if r.status_code == 429:
                got_429         = True
                first_block_at  = attempt
                logger.debug(f"    [auth] AUTH-005 HTTP 429 at attempt {attempt} -> protected")
                break

            # Check 2 — Rate-limit headers (any attempt)
            response_headers_lower = {h.lower() for h in r.headers.keys()}
            matched_headers = response_headers_lower & _RATE_LIMIT_HEADERS
            if matched_headers:
                got_ratelimit_hdr = True
                first_block_at    = attempt
                logger.debug(
                    f"    [auth] AUTH-005 rate-limit header(s) detected at attempt {attempt}: "
                    f"{matched_headers} -> protected"
                )
                break

        # Verdict
        if got_429 or got_ratelimit_hdr:
            mechanism = "HTTP 429" if got_429 else f"header(s): {matched_headers}"
            logger.debug(
                f"    [auth] AUTH-005 rate limiting detected ({mechanism}) "
                f"at attempt {first_block_at} -> {self.login_url}"
            )
            return findings  # Protected — no finding

        # No rate limiting detected across all attempts → vulnerable
        findings.append(_vuln(
            vuln_id   = "AUTH-005",
            endpoint  = self.login_url,
            method    = "POST",
            parameter = "username / password (request body)",
            payload   = f"{_RATE_LIMIT_ATTEMPTS}x POST with wrong credentials — no block triggered",
            evidence  = (
                f"Sent {_RATE_LIMIT_ATTEMPTS} rapid login attempts. "
                f"No HTTP 429 and no rate-limit headers detected."
            ),
        ))
        logger.info(f"    [VULN] AUTH-005 No rate limiting on login -> {self.login_url}")

        return findings
    # =========================================================================
    #  Auto-login helpers
    # =========================================================================

    def _auto_login_detect(self, login_url: str, username: str, password: str) -> Optional[str]:
        """Tries common login field names until one succeeds."""
        logger.info(f"[scanner] Auto-login: detecting field on {login_url}")
        for field_name in _LOGIN_FIELD_CANDIDATES:
            r = self.http.post(login_url, json={field_name: username, "password": password})
            if r is None or r.status_code not in (200, 201):
                continue
            token = self._extract_token_from_response(r)
            if token:
                logger.info(f"[scanner] Auto-login OK — field: '{field_name}'")
                return token
        logger.warning("[scanner] Auto-login failed — try --login-body with a custom JSON body")
        return None

    def _auto_login_raw(self, login_url: str, login_body: str) -> Optional[str]:
        """Logs in using a raw JSON body string."""
        try:
            body = json.loads(login_body)
        except json.JSONDecodeError as e:
            logger.error(f"[scanner] Invalid --login-body JSON: {e}")
            return None
        r = self.http.post(login_url, json=body)
        if r is None or r.status_code not in (200, 201):
            logger.warning(f"[scanner] Auto-login failed HTTP {r.status_code if r else 'None'}")
            return None
        token = self._extract_token_from_response(r)
        if token:
            logger.info("[scanner] Auto-login OK — token obtained")
        return token

    def _extract_token_from_response(self, r) -> Optional[str]:
        """Extracts a JWT from a login response — checks headers and common JSON fields."""
        if r is None:
            return None
        auth_header = r.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            return auth_header[7:]
        try:
            body = r.json()
        except Exception:
            return None
        if not isinstance(body, dict):
            return None
        for field_name in _TOKEN_FIELD_CANDIDATES:
            value = body.get(field_name)
            if value and isinstance(value, str) and len(value) > 20:
                return value
        for nested_key in ("data", "result", "user", "auth"):
            nested = body.get(nested_key)
            if isinstance(nested, dict):
                for field_name in _TOKEN_FIELD_CANDIDATES:
                    value = nested.get(field_name)
                    if value and isinstance(value, str) and len(value) > 20:
                        return value
        return None

    # =========================================================================
    #  JWT helpers
    # =========================================================================

    @staticmethod
    def _b64_decode_jwt(segment: str) -> Optional[bytes]:
        """Base64url-decode a JWT segment, handling missing padding."""
        try:
            padding = 4 - len(segment) % 4
            if padding != 4:
                segment += "=" * padding
            return base64.urlsafe_b64decode(segment)
        except Exception:
            return None

    @staticmethod
    def _b64_encode_jwt(data: bytes) -> str:
        """Base64url-encode without padding (JWT standard)."""
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode("utf-8")

    def _decode_jwt_payload(self, token: str) -> Optional[dict]:
        """Decodes the payload of a JWT without verifying the signature."""
        try:
            parts = token.split(".")
            if len(parts) != 3:
                return None
            raw = self._b64_decode_jwt(parts[1])
            if not raw:
                return None
            return json.loads(raw.decode("utf-8"))
        except Exception:
            return None

    def _get_jwt_alg(self, token: str) -> str:
        """Returns the algorithm from a JWT header (e.g. 'RS256')."""
        try:
            parts = token.split(".")
            if len(parts) < 2:
                return "UNKNOWN"
            raw = self._b64_decode_jwt(parts[0])
            if not raw:
                return "UNKNOWN"
            return json.loads(raw.decode("utf-8")).get("alg", "UNKNOWN")
        except Exception:
            return "UNKNOWN"

    def _forge_jwt_none(self, payload: dict) -> Optional[str]:
        """Forges a JWT with alg:none and an empty signature."""
        try:
            header = {"alg": "none", "typ": "JWT"}
            h_enc  = self._b64_encode_jwt(json.dumps(header,  separators=(",", ":")).encode())
            p_enc  = self._b64_encode_jwt(json.dumps(payload, separators=(",", ":")).encode())
            return f"{h_enc}.{p_enc}."
        except Exception as e:
            logger.debug(f"    [auth] JWT none forge failed: {e}")
            return None

    def _fetch_jwks_public_key(self) -> Optional[str]:
        """Fetches the server's RSA public key from common JWKS endpoints.
        Result is cached after the first successful fetch.
        """
        # Cache — évite de refaire la requête à chaque endpoint scanné
        if self._jwks_public_key_cache is not None:
            return self._jwks_public_key_cache

        jwks_paths = [
            "/.well-known/jwks.json",
            "/jwks.json",
            "/api/jwks.json",
            "/auth/jwks.json",
            "/identity/jwks.json",
            "/.well-known/openid-configuration",
        ]
        for path in jwks_paths:
            r = self.http.get(path)
            if r is None or r.status_code != 200:
                continue
            try:
                data = r.json()
            except Exception:
                continue
            if "jwks_uri" in data:
                r2 = self.http.get(urlparse(data["jwks_uri"]).path)
                if r2 and r2.status_code == 200:
                    try:
                        data = r2.json()
                    except Exception:
                        continue
            for key in data.get("keys", []):
                if key.get("kty") == "RSA":
                    pem = self._jwks_key_to_pem(key)
                    if pem:
                        logger.info(f"[scanner] JWKS public key found at {path}")
                        self._jwks_public_key_cache = pem
                        return pem
        return None

    @staticmethod
    def _jwks_key_to_pem(jwk: dict) -> Optional[str]:
        """Converts a JWK RSA public key to PEM format (stdlib only, no cryptography lib)."""
        try:
            def b64url_to_int(s: str) -> int:
                padding = 4 - len(s) % 4
                if padding != 4:
                    s += "=" * padding
                return int.from_bytes(base64.urlsafe_b64decode(s), "big")

            n = b64url_to_int(jwk.get("n", ""))
            e = b64url_to_int(jwk.get("e", ""))

            def enc_len(length: int) -> bytes:
                if length < 0x80:
                    return bytes([length])
                lb = length.to_bytes((length.bit_length() + 7) // 8, "big")
                return bytes([0x80 | len(lb)]) + lb

            def enc_int(v: int) -> bytes:
                raw = v.to_bytes((v.bit_length() + 7) // 8, "big")
                if raw[0] & 0x80:
                    raw = b"\x00" + raw
                return b"\x02" + enc_len(len(raw)) + raw

            n_der = enc_int(n)
            e_der = enc_int(e)
            seq   = b"\x30" + enc_len(len(n_der) + len(e_der)) + n_der + e_der
            alg   = bytes.fromhex("300d06092a864886f70d0101010500")
            bits  = b"\x03" + enc_len(len(seq) + 1) + b"\x00" + seq
            spki  = b"\x30" + enc_len(len(alg) + len(bits)) + alg + bits

            b64   = base64.b64encode(spki).decode()
            lines = [b64[i:i + 64] for i in range(0, len(b64), 64)]
            return "-----BEGIN PUBLIC KEY-----\n" + "\n".join(lines) + "\n-----END PUBLIC KEY-----\n"
        except Exception as e:
            logger.debug(f"    [auth] JWK to PEM failed: {e}")
            return None

    def _forge_jwt_hs256(self, payload: dict, public_key_pem: str) -> Optional[str]:
        """Forges a JWT signed with HS256 using the server's public key as HMAC secret."""
        try:
            header        = {"alg": "HS256", "typ": "JWT"}
            h_enc         = self._b64_encode_jwt(json.dumps(header,  separators=(",", ":")).encode())
            p_enc         = self._b64_encode_jwt(json.dumps(payload, separators=(",", ":")).encode())
            signing_input = f"{h_enc}.{p_enc}".encode("utf-8")
            secret        = public_key_pem.encode("utf-8")
            signature     = hmac.new(secret, signing_input, hashlib.sha256).digest()
            return f"{h_enc}.{p_enc}.{self._b64_encode_jwt(signature)}"
        except Exception as e:
            logger.debug(f"    [auth] JWT HS256 forge failed: {e}")
            return None

    # =========================================================================
    #  Private helpers
    # =========================================================================

    def _to_path(self, endpoint: str) -> str:
        """Extracts the relative path from a full URL."""
        return endpoint.replace(self.base_url, "") or "/"

    def _preview(self, r, length: int = 80) -> str:
        """Returns a sanitized short preview of the response body."""
        try:
            return r.text[:length].replace("\n", " ").strip()
        except Exception:
            return ""

    def _get_injection_params(
        self,
        endpoint: str,
        path:     str,
    ) -> list[str]:
        """
        Builds the list of parameters to test for injection.

        Sources :
        1. params_map  — confirmed params from ParamDiscoverer
        2. Path variables — numeric/UUID segments in URL
        3. Response body keys — JSON keys from baseline GET response

        No whitelist — all discovered params are passed to the injection engine.
        Blacklisting is handled by SQLiEngine._filter_params().
        """
        collected: set[str] = set()

        # Source 1 — params_map
        for param in self.params_map.get(endpoint, []):
            collected.add(param)

        # Source 2 — path variables
        segments = [s for s in path.split("/") if s]
        for i, seg in enumerate(segments):
            if seg.isdigit():
                prev = segments[i - 1] if i > 0 else "resource"
                name = prev.rstrip("s") + "_id" if prev.endswith("s") else prev + "_id"
                collected.add(name)
            elif re.match(
                r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
                seg, re.IGNORECASE
            ):
                prev = segments[i - 1] if i > 0 else "resource"
                name = prev.rstrip("s") + "_id" if prev.endswith("s") else prev + "_id"
                collected.add(name)

        # Source 3 — response body keys
        try:
            r = self.http.get(path)
            if r and r.status_code in (200, 201):
                body = r.json()
                if isinstance(body, dict):
                    collected.update(body.keys())
                elif isinstance(body, list) and body and isinstance(body[0], dict):
                    collected.update(body[0].keys())
        except Exception:
            pass

        if collected:
            logger.debug(
                f"    [inject] {len(collected)} param(s) discovered "
                f"for {endpoint}: {list(collected)}"
            )
            return list(collected)

        logger.debug(f"    [inject] No params found for {endpoint}")
        return []

    def _test_sqli(self, endpoint: str) -> list[ScanResult]:
        """SQL Injection via sqlmap — see exploit/sqli_engine.py"""
        from exploit.sqli_engine import SQLiEngine

        path   = self._to_path(endpoint)
        params = self._get_injection_params(endpoint, path)

        if not params:
            logger.debug(f"    [sqli] No params found — skipping -> {endpoint}")
            return []

        engine = SQLiEngine(
            base_url = self.base_url,
            token    = self.token,
            timeout  = self.http.timeout,
            deep     = self.deep,
        )
        return engine.scan(endpoint, params)
    
    def _deduplicate(self, findings: list[ScanResult]) -> list[ScanResult]:
        """
        Deduplicates global findings (CORS, headers, server info) by vuln_id.
        Endpoint-specific findings (auth, SQLi, IDOR) are kept as-is.
        """
        GLOBAL_CHECKS = {
            "CORS-001", "CORS-002", "CORS-003",
            "HDR-001",  "HDR-002",  "HDR-003",  "HDR-004",
            "INFO-001", "INFO-002", "VERB-001",
        }

        seen:   dict[str, ScanResult] = {}
        unique: list[ScanResult]      = []

        for finding in findings:
            if finding.vuln_id not in GLOBAL_CHECKS:
                unique.append(finding)
                continue
            if finding.vuln_id not in seen:
                seen[finding.vuln_id] = finding
                finding._affected_endpoints = [finding.endpoint]
                unique.append(finding)
            else:
                seen[finding.vuln_id]._affected_endpoints.append(finding.endpoint)

        for finding in unique:
            affected = getattr(finding, "_affected_endpoints", None)
            if not affected or len(affected) == 1:
                continue

            total    = len(affected)
            parsed   = urlparse(finding.endpoint)
            base_url = f"{parsed.scheme}://{parsed.netloc}"
            finding.endpoint = f"{base_url} ({total} endpoints affected)"

            original_evidence = finding.evidence.split(" | Affects")[0]
            path_str = "\n             ".join(
                f"• {urlparse(ep).path}" for ep in affected
            )
            finding.evidence = (
                f"{original_evidence}\n"
                f"           Affects {total} endpoint(s):\n"
                f"             {path_str}"
            )

        logger.info(f"[*] Deduplication: {len(findings)} raw findings -> {len(unique)} unique findings")
        return unique