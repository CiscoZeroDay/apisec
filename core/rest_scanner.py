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
        VERB-001 : HTTP TRACE Method Enabled
        ERR-001  : Verbose Error Messages / Stack Trace Exposure

Usage:
    scanner = RESTScanner("https://api.example.com", token="Bearer ...")
    results = scanner.scan(endpoints, tests=["misconfig", "sqli"])
    for r in results:
        print(r)
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from typing import Optional, Callable

from core.requester import Requester
from logger.logger import logger


# ─────────────────────────────────────────────────────────────────────────────
#  ScanResult — Enriched vulnerability finding
#  Format inspired by OWASP ZAP alert structure
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class ScanResult:
    """
    Represents a single detected vulnerability finding.

    Fields follow the OWASP ZAP alert structure enriched with
    Nuclei-style metadata for maximum reporting value.
    """

    # ── Identity ──────────────────────────────────────────────────────────────
    vuln_id:    str   # Unique check identifier    e.g. "CORS-001"
    vuln_type:  str   # Human-readable name        e.g. "Reflected Origin CORS"
    owasp:      str   # OWASP API Top 10 mapping   e.g. "API8"
    cwe:        str   # CWE identifier             e.g. "CWE-942"
    severity:   str   # CRITICAL | HIGH | MEDIUM | LOW | INFO
    confidence: str   # HIGH | MEDIUM | LOW

    # ── Location ──────────────────────────────────────────────────────────────
    endpoint:   str           # Full URL tested
    method:     str           # HTTP method used
    parameter:  Optional[str] # Specific parameter or header tested (None if N/A)

    # ── Proof ─────────────────────────────────────────────────────────────────
    payload:    Optional[str] # Input sent to trigger the vulnerability
    evidence:   str           # Concrete proof extracted from the response

    # ── Guidance ──────────────────────────────────────────────────────────────
    description: str  # Clear explanation of the vulnerability and its risk
    solution:    str  # Actionable remediation steps
    reference:   str  # Link to OWASP / CWE / official documentation

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


# ─────────────────────────────────────────────────────────────────────────────
#  Constants & Patterns
# ─────────────────────────────────────────────────────────────────────────────

# ── CORS ──────────────────────────────────────────────────────────────────────

# Unique canary origin used to detect reflected CORS — unlikely to be allowlisted
_CORS_CANARY = "https://evil-apisec-test.attacker.com"

# ── Security Headers ──────────────────────────────────────────────────────────

# Each entry: (header_name, check_id, vuln_type, severity, cwe, description, solution, reference)
SECURITY_HEADERS: list[tuple] = [
    (
        "Strict-Transport-Security",
        "HDR-001",
        "Missing Strict-Transport-Security (HSTS)",
        "MEDIUM",
        "CWE-319",
        (
            "The Strict-Transport-Security (HSTS) header is absent. Without HSTS, browsers "
            "may connect to the API over plain HTTP, exposing credentials and session tokens "
            "to network-level interception (man-in-the-middle attacks)."
        ),
        "Add the header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security",
    ),
    (
        "X-Content-Type-Options",
        "HDR-002",
        "Missing X-Content-Type-Options",
        "LOW",
        "CWE-693",
        (
            "The X-Content-Type-Options header is absent. Without it, browsers may "
            "MIME-sniff responses away from the declared content type, potentially "
            "executing malicious scripts disguised as benign content."
        ),
        "Add the header: X-Content-Type-Options: nosniff",
        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options",
    ),
    (
        "X-Frame-Options",
        "HDR-003",
        "Missing X-Frame-Options",
        "MEDIUM",
        "CWE-1021",
        (
            "The X-Frame-Options header is absent. This allows the API responses to be "
            "embedded in iframes on third-party pages, enabling clickjacking attacks "
            "where users are tricked into performing unintended actions."
        ),
        "Add the header: X-Frame-Options: DENY  (or SAMEORIGIN if framing is needed internally)",
        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options",
    ),
    (
        "Content-Security-Policy",
        "HDR-004",
        "Missing Content-Security-Policy (CSP)",
        "MEDIUM",
        "CWE-693",
        (
            "The Content-Security-Policy header is absent. CSP is a critical defense "
            "against Cross-Site Scripting (XSS) attacks by specifying which sources "
            "of content are allowed to be loaded and executed by the browser."
        ),
        "Define a strict CSP policy. Minimum: Content-Security-Policy: default-src 'self'",
        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy",
    ),
]

# ── Server Information Disclosure ─────────────────────────────────────────────

# Patterns that indicate version information is being disclosed
# Each: (header_name, check_id, vuln_type, cwe)
INFO_HEADERS: list[tuple] = [
    (
        "Server",
        "INFO-001",
        "Server Version Disclosure",
        "CWE-200",
        (
            "The Server header exposes the web server software name and version. "
            "This information allows attackers to identify known CVEs targeting "
            "the specific version and craft targeted exploits."
        ),
        "Configure the server to return a generic value (e.g. Server: webserver) "
        "or suppress the header entirely.",
        "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/"
        "01-Information_Gathering/02-Fingerprint_Web_Server",
    ),
    (
        "X-Powered-By",
        "INFO-002",
        "Technology Stack Disclosure via X-Powered-By",
        "CWE-200",
        (
            "The X-Powered-By header reveals the backend technology and version "
            "(e.g. PHP/7.2.1, ASP.NET). This fingerprinting information aids attackers "
            "in identifying framework-specific vulnerabilities."
        ),
        "Remove the X-Powered-By header from server configuration. "
        "In Express.js: app.disable('x-powered-by'). In PHP: expose_php = Off.",
        "https://owasp.org/www-project-web-security-testing-guide/",
    ),
]

# Version pattern — detects version numbers in header values (e.g. Apache/2.4.1, PHP/7.2)
_VERSION_PATTERN = re.compile(r"[\d]+\.[\d]+")

# ── Verbose Error Patterns ────────────────────────────────────────────────────

# Patterns indicating stack traces or internal technical information in responses
VERBOSE_ERROR_PATTERNS: list[tuple[str, str]] = [
    # (regex_pattern, description_of_what_it_reveals)
    (r"at\s+[\w\.]+\([\w\.]+:\d+\)",        "Java/Kotlin stack trace"),
    (r"at\s+System\.",                        ".NET stack trace"),
    (r"at\s+Microsoft\.",                     ".NET/ASP.NET stack trace"),
    (r"Traceback \(most recent call last\)",  "Python stack trace"),
    (r"File \"[^\"]+\", line \d+",            "Python file path disclosure"),
    (r"in /(?:var|home|srv|app|usr)/\w+",    "Linux file path disclosure"),
    (r"(?:mysqli?|pg|sqlite|odbc)_",          "Database function name disclosure"),
    (r"ORA-\d{5}",                            "Oracle database error code"),
    (r"Microsoft OLE DB",                     "Microsoft database driver disclosure"),
    (r"SQLSTATE\[\w+\]",                      "PDO/SQL state error disclosure"),
    (r"(?:Laravel|Symfony|Django|Rails|Spring|Express)\s+[\d\.]+",
                                              "Framework version disclosure"),
    (r"(?:PHP Fatal error|PHP Warning|PHP Notice)", "PHP error disclosure"),
    (r"on line \d+",                          "Source code line number disclosure"),
]

# Payloads designed to trigger verbose errors without causing actual damage
VERBOSE_ERROR_TRIGGERS: list[dict] = [
    {"method": "GET",  "params": {"id": "' OR 1=1--"}},
    {"method": "GET",  "params": {"id": None}},
    {"method": "POST", "json":   {"id": None, "data": [1, 2, 3] * 1000}},
    {"method": "GET",  "params": {"id": "A" * 8192}},
]


# ─────────────────────────────────────────────────────────────────────────────
#  RESTScanner
# ─────────────────────────────────────────────────────────────────────────────

class RESTScanner:
    """
    Automated REST API vulnerability scanner.

    Implements a rule-based detection engine inspired by Nuclei templates
    combined with OWASP ZAP's per-parameter active scanning approach.

    Each vulnerability category is a self-contained method that:
      1. Sends targeted HTTP requests
      2. Applies precise matchers to the response
      3. Returns enriched ScanResult findings with full metadata

    Usage:
        scanner = RESTScanner("https://api.example.com", token="Bearer eyJ...")
        results = scanner.scan(endpoints, tests=["misconfig"])
        for finding in results:
            print(finding)
    """

    # Maps test names to their handler methods
    _TEST_REGISTRY: dict[str, str] = {
        "misconfig":   "_test_misconfig",
        # Coming in next iterations:
        # "sqli":        "_test_sqli",
        # "blind_sqli":  "_test_blind_sqli",
        # "nosql":       "_test_nosql",
        # "xss":         "_test_xss",
        # "ssrf":        "_test_ssrf",
        # "idor":        "_test_idor",
        # "auth":        "_test_auth",
        # "mass_assign": "_test_mass_assignment",
        # "rate_limit":  "_test_rate_limit",
    }

    def __init__(
        self,
        base_url: str,
        timeout:  int = 10,
        token:    Optional[str] = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.http     = Requester(self.base_url, timeout=timeout)

        if token:
            self.http.set_token(token)

    # =========================================================================
    #  Entry point
    # =========================================================================

    def scan(
        self,
        endpoints: list[str],
        tests:     Optional[list[str]] = None,
    ) -> list[ScanResult]:
        """
        Run vulnerability checks against a list of endpoints.

        Args:
            endpoints : List of full URLs to test (from discovery phase).
            tests     : Subset of test names to run. None runs all available.
                        Available: misconfig, sqli, blind_sqli, nosql,
                                   xss, ssrf, idor, auth, mass_assign, rate_limit

        Returns:
            List of ScanResult — one entry per detected vulnerability.
        """
        # Resolve active test methods
        if tests is None:
            active = list(self._TEST_REGISTRY.keys())
        else:
            active = [t for t in tests if t in self._TEST_REGISTRY]
            unknown = [t for t in tests if t not in self._TEST_REGISTRY]
            if unknown:
                logger.warning(f"[scanner] Unknown tests ignored: {', '.join(unknown)}")

        if not active:
            logger.error("[scanner] No valid tests selected.")
            return []

        logger.info(
            f"[*] REST Scanner — {len(endpoints)} endpoint(s) — "
            f"active tests: {active}"
        )

        findings: list[ScanResult] = []

        for endpoint in endpoints:
            logger.debug(f"    [scan] {endpoint}")
            for test_name in active:
                method_name = self._TEST_REGISTRY[test_name]
                test_method = getattr(self, method_name)
                try:
                    results = test_method(endpoint)
                    if results:
                        findings.extend(results)
                except Exception as e:
                    logger.debug(f"    [scan:{test_name}] Unexpected error on {endpoint}: {e}")

        logger.info(
            f"[+] Scan complete — {len(findings)} finding(s) detected"
        )
        return self._deduplicate(findings)

    # =========================================================================
    #  [API8] Security Misconfiguration
    # =========================================================================

    def _test_misconfig(self, endpoint: str) -> list[ScanResult]:
        """
        Runs all Security Misconfiguration checks against a single endpoint.

        Checks performed:
            CORS-001 : Reflected Origin
            CORS-002 : Wildcard Origin + Credentials
            CORS-003 : Wildcard Origin
            HDR-001  : Missing HSTS
            HDR-002  : Missing X-Content-Type-Options
            HDR-003  : Missing X-Frame-Options
            HDR-004  : Missing Content-Security-Policy
            INFO-001 : Server Version Disclosure
            INFO-002 : X-Powered-By Disclosure
            VERB-001 : HTTP TRACE Method Enabled
            ERR-001  : Verbose Error / Stack Trace Exposure
        """
        findings: list[ScanResult] = []
        path = self._to_path(endpoint)

        # Fetch baseline response — reused by multiple checks
        baseline = self.http.get(path)
        if baseline is None:
            logger.debug(f"    [misconfig] No response from {endpoint} — skipping")
            return findings

        # Run all misconfig sub-checks
        findings += self._check_cors(endpoint, path)
        findings += self._check_security_headers(endpoint, baseline)
        findings += self._check_server_disclosure(endpoint, baseline)
        findings += self._check_trace_method(endpoint, path)
        findings += self._check_verbose_errors(endpoint, path)

        return findings

    # ── CORS checks ───────────────────────────────────────────────────────────

    def _check_cors(self, endpoint: str, path: str) -> list[ScanResult]:
        """
        Detects CORS misconfigurations via three checks:
          CORS-001: Server reflects the attacker-controlled Origin header
          CORS-002: Wildcard origin combined with Allow-Credentials
          CORS-003: Unrestricted wildcard origin (no credentials)
        """
        findings: list[ScanResult] = []

        # Send GET with a canary Origin that should never be allowlisted
        r = self.http.get(path, headers={"Origin": _CORS_CANARY})
        if r is None:
            return findings

        acao  = r.headers.get("Access-Control-Allow-Origin",  "").strip()
        acac  = r.headers.get("Access-Control-Allow-Credentials", "").strip().lower()
        acam  = r.headers.get("Access-Control-Allow-Methods", "").strip()

        # ── CORS-001 : Reflected Origin ───────────────────────────────────────
        if _CORS_CANARY in acao:
            # Determine if credentials are also allowed → escalate to CRITICAL
            severity   = "CRITICAL" if acac == "true" else "HIGH"
            confidence = "HIGH"

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

            findings.append(ScanResult(
                vuln_id     = "CORS-001",
                vuln_type   = "Reflected Origin CORS Misconfiguration",
                owasp       = "API8",
                cwe         = "CWE-942",
                severity    = severity,
                confidence  = confidence,
                endpoint    = endpoint,
                method      = "GET",
                parameter   = "Origin (request header)",
                payload     = f"Origin: {_CORS_CANARY}",
                evidence    = " | ".join(evidence_parts),
                description = description,
                solution    = (
                    "Maintain an explicit server-side allowlist of trusted origins. "
                    "Validate the Origin header against this allowlist before reflecting it. "
                    "Never use request-derived values as the Allow-Origin response value."
                ),
                reference   = (
                    "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application"
                    "_Security_Testing/11-Client-Side_Testing/07-Testing_Cross_Origin_Resource_Sharing"
                ),
            ))
            logger.info(f"    [VULN] CORS-001 Reflected Origin ({severity}) → {endpoint}")
            # If CORS-001 fires we do not report CORS-003 — same root cause
            return findings

        # ── CORS-002 : Wildcard + Credentials ────────────────────────────────
        if acao == "*" and acac == "true":
            findings.append(ScanResult(
                vuln_id     = "CORS-002",
                vuln_type   = "Wildcard CORS with Credentials Enabled",
                owasp       = "API8",
                cwe         = "CWE-942",
                severity    = "CRITICAL",
                confidence  = "HIGH",
                endpoint    = endpoint,
                method      = "GET",
                parameter   = "Origin (request header)",
                payload     = None,
                evidence    = (
                    "Access-Control-Allow-Origin: * | "
                    "Access-Control-Allow-Credentials: true"
                ),
                description = (
                    "The API sets both Access-Control-Allow-Origin: * and "
                    "Access-Control-Allow-Credentials: true. This combination is "
                    "explicitly forbidden by the CORS specification because browsers "
                    "must not expose credentials to wildcard origins. Some implementations "
                    "bypass this restriction, making this configuration critically dangerous."
                ),
                solution    = (
                    "Never combine wildcard CORS with credentials. "
                    "If credentials are required, use a strict origin allowlist instead of *. "
                    "Remove Access-Control-Allow-Credentials: true if a wildcard is needed."
                ),
                reference   = (
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS/Errors/"
                    "CORSNotSupportingCredentials"
                ),
            ))
            logger.info(f"    [VULN] CORS-002 Wildcard + Credentials → {endpoint}")
            return findings

        # ── CORS-003 : Wildcard Origin (no credentials) ───────────────────────
        if acao == "*":
            findings.append(ScanResult(
                vuln_id     = "CORS-003",
                vuln_type   = "Unrestricted Wildcard CORS Origin",
                owasp       = "API8",
                cwe         = "CWE-942",
                severity    = "MEDIUM",
                confidence  = "HIGH",
                endpoint    = endpoint,
                method      = "GET",
                parameter   = "Origin (request header)",
                payload     = None,
                evidence    = "Access-Control-Allow-Origin: *",
                description = (
                    "The API allows cross-origin requests from any domain via a wildcard. "
                    "While less critical without credentials, any website can read this "
                    "API's responses. If the API returns any user-specific or sensitive "
                    "data, this becomes a significant information disclosure risk."
                ),
                solution    = (
                    "Restrict CORS to an explicit allowlist of trusted origins. "
                    "If the API is truly public and returns no sensitive data, "
                    "document this decision explicitly."
                ),
                reference   = (
                    "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application"
                    "_Security_Testing/11-Client-Side_Testing/07-Testing_Cross_Origin_Resource_Sharing"
                ),
            ))
            logger.info(f"    [VULN] CORS-003 Wildcard Origin → {endpoint}")

        return findings

    # ── Security Headers checks ───────────────────────────────────────────────

    def _check_security_headers(self, endpoint: str, baseline) -> list[ScanResult]:
        """
        Checks for the presence and correctness of HTTP security headers.
        Uses the baseline response — no additional HTTP requests needed.

        Checks: HSTS, X-Content-Type-Options, X-Frame-Options, CSP

        Fix 1: HSTS is skipped for HTTP endpoints — it only applies to HTTPS.
        """
        findings: list[ScanResult] = []
        is_http = endpoint.startswith("http://")

        # Normalize response headers to lowercase for case-insensitive comparison
        response_headers_lower = {k.lower(): v for k, v in baseline.headers.items()}

        for (header, check_id, vuln_type, severity, cwe,
             description, solution, reference) in SECURITY_HEADERS:

            # Fix 1 — HSTS false positive: only meaningful over HTTPS
            if header == "Strict-Transport-Security" and is_http:
                logger.debug(
                    f"    [misconfig] HDR-001 skipped — HSTS not applicable over HTTP → {endpoint}"
                )
                continue

            if header.lower() not in response_headers_lower:
                findings.append(ScanResult(
                    vuln_id     = check_id,
                    vuln_type   = vuln_type,
                    owasp       = "API8",
                    cwe         = cwe,
                    severity    = severity,
                    confidence  = "HIGH",
                    endpoint    = endpoint,
                    method      = "GET",
                    parameter   = f"{header} (response header)",
                    payload     = None,
                    evidence    = f"Header '{header}' is absent from the response",
                    description = description,
                    solution    = solution,
                    reference   = reference,
                ))
                logger.info(f"    [VULN] {check_id} Missing {header} → {endpoint}")

        return findings

    # ── Server Information Disclosure checks ──────────────────────────────────

    def _check_server_disclosure(self, endpoint: str, baseline) -> list[ScanResult]:
        """
        Detects version information disclosure in response headers.
        Flags Server and X-Powered-By headers that contain version numbers.

        INFO-001: Server version disclosure
        INFO-002: X-Powered-By technology disclosure
        """
        findings: list[ScanResult] = []

        for (header, check_id, vuln_type, cwe,
             description, solution, reference) in INFO_HEADERS:

            value = baseline.headers.get(header, "").strip()
            if not value:
                continue

            # Only flag if a version number is present — e.g. Apache/2.4.1, PHP/7.2
            if _VERSION_PATTERN.search(value):
                findings.append(ScanResult(
                    vuln_id     = check_id,
                    vuln_type   = vuln_type,
                    owasp       = "API8",
                    cwe         = cwe,
                    severity    = "LOW",
                    confidence  = "HIGH",
                    endpoint    = endpoint,
                    method      = "GET",
                    parameter   = f"{header} (response header)",
                    payload     = None,
                    evidence    = f"{header}: {value}",
                    description = description,
                    solution    = solution,
                    reference   = reference,
                ))
                logger.info(f"    [VULN] {check_id} {header} discloses version: {value} → {endpoint}")

        return findings

    # ── HTTP TRACE Method check ───────────────────────────────────────────────

    def _check_trace_method(self, endpoint: str, path: str) -> list[ScanResult]:
        """
        VERB-001: Detects if the HTTP TRACE method is enabled.

        TRACE is designed for diagnostic purposes and should never be
        enabled in production. It reflects the full request back to the
        client, enabling Cross-Site Tracing (XST) attacks that can expose
        HttpOnly cookies and Authorization headers to JavaScript.
        """
        findings: list[ScanResult] = []

        r = self.http._request("TRACE", path)
        if r is None:
            return findings

        # TRACE is confirmed if:
        # 1. Server returns 200 with the request body reflected, OR
        # 2. Server returns 200 (some servers reflect without echo)
        if r.status_code == 200:
            # Verify the response echoes back request content (definitive proof)
            body = r.text or ""
            is_confirmed = (
                "TRACE" in body
                or "trace" in body.lower()
                or r.headers.get("Content-Type", "").lower().startswith("message/http")
            )
            confidence = "HIGH" if is_confirmed else "MEDIUM"

            findings.append(ScanResult(
                vuln_id     = "VERB-001",
                vuln_type   = "HTTP TRACE Method Enabled",
                owasp       = "API8",
                cwe         = "CWE-16",
                severity    = "MEDIUM",
                confidence  = confidence,
                endpoint    = endpoint,
                method      = "TRACE",
                parameter   = None,
                payload     = "TRACE / HTTP/1.1",
                evidence    = (
                    f"TRACE method returned HTTP {r.status_code}. "
                    f"Content-Type: {r.headers.get('Content-Type', 'N/A')}. "
                    f"Body preview: {body[:100].replace(chr(10), ' ')}"
                    if body else f"TRACE method returned HTTP {r.status_code}"
                ),
                description = (
                    "The HTTP TRACE method is enabled on this endpoint. TRACE reflects "
                    "the entire request back to the client, including all headers. "
                    "When combined with Cross-Site Scripting (XST), this allows attackers "
                    "to steal HttpOnly cookies and Authorization headers that are "
                    "normally inaccessible to JavaScript."
                ),
                solution    = (
                    "Disable the TRACE method at the web server level. "
                    "Apache: TraceEnable Off. "
                    "Nginx: if ($request_method = TRACE) { return 405; }. "
                    "IIS: Remove TRACE from allowed verbs."
                ),
                reference   = "https://owasp.org/www-community/attacks/Cross_Site_Tracing",
            ))
            logger.info(f"    [VULN] VERB-001 TRACE enabled (confidence: {confidence}) → {endpoint}")

        return findings

    # ── Verbose Error / Stack Trace check ─────────────────────────────────────

    def _check_verbose_errors(self, endpoint: str, path: str) -> list[ScanResult]:
        """
        ERR-001: Detects verbose error messages and stack trace disclosure.

        Sends intentionally malformed inputs to provoke error responses,
        then scans the response body for patterns indicating:
        - Stack traces (Java, .NET, Python, PHP)
        - Internal file paths
        - Database error details
        - Framework version information

        Only one finding is reported per endpoint (first match wins).
        """
        findings: list[ScanResult] = []

        for trigger in VERBOSE_ERROR_TRIGGERS:
            method = trigger["method"]

            if method == "GET":
                r = self.http.get(path, params=trigger.get("params"))
            else:
                r = self.http.post(path, json=trigger.get("json"))

            if r is None:
                continue

            # Only analyze error responses — 4xx and 5xx
            if r.status_code < 400:
                continue

            body = r.text or ""
            body_lower = body.lower()

            for pattern, leak_type in VERBOSE_ERROR_PATTERNS:
                match = re.search(pattern, body, re.IGNORECASE)
                if not match:
                    continue

                # Extract surrounding context for evidence
                start   = max(0, match.start() - 30)
                end     = min(len(body), match.end() + 100)
                excerpt = body[start:end].strip().replace("\n", " ")

                findings.append(ScanResult(
                    vuln_id     = "ERR-001",
                    vuln_type   = "Verbose Error / Stack Trace Exposure",
                    owasp       = "API8",
                    cwe         = "CWE-209",
                    severity    = "MEDIUM",
                    confidence  = "HIGH",
                    endpoint    = endpoint,
                    method      = method,
                    parameter   = None,
                    payload     = str(trigger.get("params") or trigger.get("json")),
                    evidence    = (
                        f"HTTP {r.status_code} — {leak_type} detected. "
                        f"Excerpt: \"{excerpt[:150]}\""
                    ),
                    description = (
                        f"The API returns a verbose error response containing {leak_type}. "
                        "Detailed error messages expose internal implementation details "
                        "(file paths, library versions, database structure) that give "
                        "attackers a precise roadmap of the backend infrastructure."
                    ),
                    solution    = (
                        "Configure the application to return generic error messages in production. "
                        "Log detailed errors server-side only (never in API responses). "
                        "Set environment to production mode to suppress stack traces. "
                        "Implement a global exception handler that returns sanitized errors."
                    ),
                    reference   = (
                        "https://owasp.org/www-community/Improper_Error_Handling"
                    ),
                ))
                logger.info(
                    f"    [VULN] ERR-001 Verbose error ({leak_type}) "
                    f"HTTP {r.status_code} → {endpoint}"
                )
                # One finding per endpoint is sufficient
                return findings

        return findings

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

    def _deduplicate(self, findings: list[ScanResult]) -> list[ScanResult]:
        """
        Deduplicate findings by vuln_id across all endpoints.

        Global misconfigurations (CORS, headers, server info) are reported once
        with the full list of affected endpoints in the evidence — instead of
        repeating the same finding 15 times.

        Endpoint-specific findings (IDOR, auth bypass, SQLi) are kept as-is.
        """
        # vuln_ids that represent global server-level issues
        GLOBAL_CHECKS = {
            "CORS-001", "CORS-002", "CORS-003",
            "HDR-001",  "HDR-002",  "HDR-003",  "HDR-004",
            "INFO-001", "INFO-002",
            "VERB-001",
        }

        seen:   dict[str, ScanResult] = {}  # vuln_id → representative finding
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

        # Rebuild endpoint + evidence for deduplicated global findings
        from urllib.parse import urlparse
        for finding in unique:
            affected = getattr(finding, "_affected_endpoints", None)
            if not affected:
                continue

            total = len(affected)

            if total == 1:
                # Single endpoint — keep as-is
                continue

            # Replace endpoint with a cleaner representation
            parsed   = urlparse(finding.endpoint)
            base_url = f"{parsed.scheme}://{parsed.netloc}"
            finding.endpoint = f"{base_url} ({total} endpoints affected)"

            # Rebuild evidence with clean path list
            original_evidence = finding.evidence.split(" | Affects")[0]  # strip old suffix
            paths = [
                urlparse(ep).path
                for ep in affected
            ]
            # Show all affected paths
            path_str = "\n             ".join(f"• {p}" for p in paths)

            finding.evidence = (
                f"{original_evidence}\n"
                f"           Affects {total} endpoint(s):\n"
                f"             {path_str}"
            )

        logger.info(
            f"[*] Deduplication: {len(findings)} raw findings → {len(unique)} unique findings"
        )
        return unique