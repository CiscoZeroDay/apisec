# core/param_discoverer.py
"""
ParamDiscoverer — HTTP parameter discovery module.

Implements Arjun's exact algorithm:
  - define()  : builds a factors dict from 2 baseline responses
  - compare() : detects anomalies by comparing a response against factors
  - bruter()  : sends a chunk of params and returns anomalous ones
  - narrower(): recursively narrows down until individual params confirmed
  - confirm() : verifies each candidate individually (verify mode)

Sources:
  Source 1 — Wordlist GET  : query params via chunk testing (Arjun algo)
  Source 2 — Wordlist POST : JSON body params via chunk testing
  Source 3 — Response body : keys extracted from JSON GET response
  Source 4 — Path variables: numeric/UUID segments in URL path

Anomaly signals (same as Arjun anomaly.py):
  same_code       : HTTP status code changed
  same_headers    : Response headers changed
  same_redirect   : Redirect location changed
  same_body       : Body content changed
  lines_num       : Number of lines changed
  same_plaintext  : Plain text (no HTML tags) changed
  lines_diff      : Specific lines changed
  param_missing   : Param name reflected in response
  value_missing   : Param value reflected in response (6-char random value)
"""

from __future__ import annotations

import os
import re
import json
import random
import string
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional

import requests as req_lib

from core.requester import Requester
from logger.logger  import logger


# =============================================================================
#  Constants
# =============================================================================

ARJUN_WORDLIST_PATHS: list[str] = [
    os.path.expanduser("~/.local/lib/python3.13/site-packages/arjun/db/large.txt"),
    os.path.expanduser("~/.local/lib/python3.12/site-packages/arjun/db/large.txt"),
    os.path.expanduser("~/.local/lib/python3.11/site-packages/arjun/db/large.txt"),
    os.path.expanduser("~/.local/lib/python3.10/site-packages/arjun/db/large.txt"),
    "/usr/lib/python3/dist-packages/arjun/db/large.txt",
    "/usr/local/lib/python3/dist-packages/arjun/db/large.txt",
    os.path.join(os.getcwd(), "Arjun", "arjun", "db", "large.txt"),
    os.path.expanduser("~/Arjun/arjun/db/large.txt"),
    os.path.join(os.getcwd(), "venv", "Lib", "site-packages", "arjun", "db", "large.txt"),
    os.path.join(os.getcwd(), "wordlists", "params-large.txt"),
]

FALLBACK_PARAMS: list[str] = [
    "q", "query", "search", "keyword", "term", "filter", "name", "id",
    "user_id", "userId", "email", "username", "password", "token", "key",
    "api_key", "apikey", "secret", "callback", "redirect", "url", "uri",
    "page", "limit", "offset", "sort", "order", "type", "category",
    "status", "action", "method", "lang", "locale", "country",
    "city", "address", "phone", "code", "ref", "source", "medium",
    "content", "body", "message", "comment", "description", "title",
    "value", "data", "payload", "input", "output", "result", "response",
    "admin", "debug", "test", "dev", "verbose", "trace", "log",
    "role", "permission", "scope", "grant", "access", "auth",
    "file", "filename", "path", "dir", "folder", "upload",
    "date", "time", "from", "to", "start", "end", "range",
    "version", "v", "api", "mode", "config", "setting",
]

# Parameters that are known false positives — never injectable
_PARAM_BLACKLIST: frozenset[str] = frozenset({
    "format", "output", "callback", "jsonp", "pretty",
    "indent", "wt", "alt", "wrap", "envelope",
    "_", "_dc", "_ts", "nocache", "jsoncallback",
})

# Keys to ignore from JSON response body
_BODY_KEY_IGNORE: set[str] = {
    "message", "error", "errors", "success", "ok", "status",
    "timestamp", "created_at", "updated_at", "createdAt", "updatedAt",
    "_id", "__v", "links", "meta", "pagination",
}

# Path variable patterns
_UUID_PATTERN     = re.compile(
    r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
    re.IGNORECASE
)
_MONGO_ID_PATTERN = re.compile(r'^[0-9a-f]{24}$', re.IGNORECASE)

# Arjun defaults
CHUNK_SIZE       = 250
DEFAULT_THREADS  = 5

# HTML tag removal regex (same as Arjun's remove_tags)
_HTML_TAG_RE = re.compile(r'<[^>]+>')


# =============================================================================
#  Arjun anomaly helpers — exact port of anomaly.py
# =============================================================================

def _remove_tags(text: str) -> str:
    """Remove HTML tags from text — same as Arjun's remove_tags()."""
    return _HTML_TAG_RE.sub('', text)


def _diff_map(body1: str, body2: str) -> list[str]:
    """
    Returns lines that are common to both bodies.
    Same as Arjun's diff_map().
    """
    lines1 = set(body1.split('\n'))
    lines2 = set(body2.split('\n'))
    return list(lines1 & lines2)


def _define(response_1, response_2, param: str, value: str, wordlist: list[str]) -> dict:
    """
    Defines a rule list (factors) for anomaly detection by comparing two
    baseline HTTP responses.

    Exact port of Arjun's anomaly.define().

    Args:
        response_1: First baseline response
        response_2: Second baseline response (same request, different random value)
        param:      The fuzz parameter name used
        value:      The fuzz value used
        wordlist:   Full parameter wordlist (for param_missing detection)

    Returns:
        factors dict with same structure as Arjun
    """
    factors = {
        'same_code':      None,
        'same_body':      None,
        'same_plaintext': None,
        'lines_num':      None,
        'lines_diff':     None,
        'same_headers':   None,
        'same_redirect':  None,
        'param_missing':  None,
        'value_missing':  None,
    }

    if response_1 is None or response_2 is None:
        return factors

    body_1, body_2 = response_1.text or '', response_2.text or ''

    if response_1.status_code == response_2.status_code:
        factors['same_code'] = response_1.status_code

    h1 = sorted(response_1.headers.keys())
    h2 = sorted(response_2.headers.keys())
    if h1 == h2:
        factors['same_headers'] = h1

    # Redirect factor
    loc1 = response_1.headers.get('Location', '')
    loc2 = response_2.headers.get('Location', '')
    if loc1 == loc2:
        factors['same_redirect'] = loc1

    # Body factors
    if body_1 == body_2:
        factors['same_body'] = body_1
    elif body_1.count('\n') == body_2.count('\n'):
        factors['lines_num'] = body_1.count('\n')
    elif _remove_tags(body_1) == _remove_tags(body_2):
        factors['same_plaintext'] = _remove_tags(body_1)
    elif body_1 and body_2 and body_1.count('\\n') == body_2.count('\\n'):
        factors['lines_diff'] = _diff_map(body_1, body_2)

    # Param/value reflection detection
    if param not in response_2.text:
        factors['param_missing'] = [w for w in wordlist if w in response_2.text]

    if value not in response_2.text:
        factors['value_missing'] = True

    return factors


def _compare(response, factors: dict, params: dict) -> tuple[str, dict, str]:
    """
    Detects anomalies by comparing an HTTP response against a factors rule list.

    Exact port of Arjun's anomaly.compare().

    Returns:
        (anomaly_type, params_dict, factor_key)
        Empty strings if no anomaly detected.
    """
    if response is None or isinstance(response, str):
        return ('', {}, '')

    these_headers = sorted(response.headers.keys())

    if factors['same_code'] is not None and response.status_code != factors['same_code']:
        return ('http code', params, 'same_code')

    if factors['same_headers'] is not None and these_headers != factors['same_headers']:
        return ('http headers', params, 'same_headers')

    if factors['same_redirect'] is not None:
        loc = response.headers.get('Location', '')
        if loc != factors['same_redirect']:
            return ('redirection', params, 'same_redirect')

    if factors['same_body'] is not None and response.text != factors['same_body']:
        return ('body length', params, 'same_body')

    if factors['lines_num'] is not None and response.text.count('\n') != factors['lines_num']:
        return ('number of lines', params, 'lines_num')

    if factors['same_plaintext'] is not None and _remove_tags(response.text) != factors['same_plaintext']:
        return ('text length', params, 'same_plaintext')

    if factors['lines_diff'] is not None:
        for line in factors['lines_diff']:
            if line and line not in response.text:
                return ('lines', params, 'lines_diff')

    # Param name reflection (Arjun: only params with len >= 5)
    if factors['param_missing'] is not None:
        for param_name in params.keys():
            if len(param_name) < 5:
                continue
            if (param_name not in factors['param_missing'] and
                    re.search(r'[\'"\s]%s[\'"\s]' % re.escape(param_name), response.text)):
                return ('param name reflection', params, 'param_missing')

    # Value reflection (Arjun: only 6-char values)
    if factors['value_missing'] is not None:
        for value in params.values():
            if not isinstance(value, str) or len(value) != 6:
                continue
            if (value in response.text and
                    re.search(r'[\'"\s]%s[\'"\s]' % re.escape(value), response.text)):
                return ('param value reflection', params, 'value_missing')

    return ('', {}, '')


# =============================================================================
#  ParamDiscoverer
# =============================================================================

class ParamDiscoverer:
    """
    Discovers HTTP parameters accepted by an endpoint.

    Implements Arjun's exact algorithm for GET and POST methods,
    plus two additional sources: response body keys and path variables.

    Sources:
      Source 1a — GET  wordlist (Arjun algo)
      Source 1b — POST JSON body wordlist (Arjun algo)
      Source 2  — Response body key extraction
      Source 3  — Path variable detection (numeric/UUID)
    """

    def __init__(
        self,
        base_url: str,
        timeout:  int = 10,
        token:    Optional[str] = None,
        wordlist: Optional[str] = None,
        threads:  int = DEFAULT_THREADS,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout  = timeout
        self.threads  = threads
        self._token   = token
        self._lock    = threading.Lock()
        self._local   = threading.local()
        self._params  = self._load_wordlist(wordlist)

        logger.info(
            f"[ParamDiscoverer] Loaded {len(self._params)} params | "
            f"{self.threads} threads | chunk size: {CHUNK_SIZE}"
        )

    # =========================================================================
    #  Thread-local HTTP client
    # =========================================================================

    def _get_http(self) -> Requester:
        """Returns a thread-local Requester instance."""
        if not hasattr(self._local, "http"):
            self._local.http = Requester(self.base_url, timeout=self.timeout)
            if self._token:
                self._local.http.set_token(self._token)
        return self._local.http

    # =========================================================================
    #  Public API
    # =========================================================================

    def discover(self, path: str) -> list[tuple[str, str]]:
        """
        Discover valid parameters for a given endpoint path.
        Combines all sources and deduplicates results.

        Returns:
            List of (param_name, detection_reason) tuples
        """
        logger.info(f"[ParamDiscoverer] Scanning {self.base_url}{path}")

        all_params: dict[str, str] = {}

        # Source 1a — GET wordlist (Arjun algorithm)
        for param, reason in self._discover_method(path, method='GET'):
            if param not in all_params:
                all_params[param] = f"GET — {reason}"

        # Source 1b — POST JSON body (Arjun algorithm)
        for param, reason in self._discover_method(path, method='POST'):
            if param not in all_params:
                all_params[param] = f"POST body — {reason}"

        # Source 2 — Response body key extraction
        for param, reason in self._discover_from_response_body(path):
            if param not in all_params:
                all_params[param] = reason

        # Source 3 — Path variable extraction
        for param, reason in self._discover_path_variables(path):
            if param not in all_params:
                all_params[param] = reason

        result = list(all_params.items())

        if result:
            logger.info(f"[ParamDiscoverer] Found {len(result)} param(s) on {path}:")
            for param, reason in result:
                logger.info(f"    [v] parameter detected: {param}, based on: {reason}")
        else:
            logger.debug(f"[ParamDiscoverer] No params found for {path}")

        return result

    def discover_names(self, path: str) -> list[str]:
        """Returns only parameter names."""
        return [p for p, _ in self.discover(path)]

    def discover_all(self, endpoints: list[str]) -> dict[str, list[tuple[str, str]]]:
        """Discover params for multiple endpoints sequentially."""
        results = {}
        for endpoint in endpoints:
            path   = endpoint.replace(self.base_url, "") or "/"
            params = self.discover(path)
            if params:
                results[endpoint] = params
        return results

    # =========================================================================
    #  Source 1 — Arjun algorithm (GET + POST)
    # =========================================================================

    def _discover_method(self, path: str, method: str = 'GET') -> list[tuple[str, str]]:
        """
        Arjun-style parameter discovery for a given HTTP method.

        Algorithm:
          1. Probe stability — two baseline requests to build factors dict
          2. Chunk testing  — send 250 params at once, detect anomalous chunks
          3. Narrowing      — recursively halve anomalous chunks
          4. Confirmation   — verify each param individually (verify mode)

        This is a faithful reimplementation of Arjun's initialize() + narrower()
        + confirm() flow from __main__.py.
        """
        http = self._get_http()

        # ── Step 1 — Stability probe ──────────────────────────────────────────
        fuzz1 = "z" + self._random_value(6)   # 7-char fuzz param name
        val1  = self._random_value(6)          # 6-char value (Arjun uses 6 for reflection)
        fuzz2 = "z" + self._random_value(6)
        val2  = self._random_value(6)

        r1 = self._request(http, path, method, {fuzz1: val1})
        r2 = self._request(http, path, method, {fuzz1: val1})

        if r1 is None or r2 is None:
            return []

        # Build factors from two identical requests
        factors = _define(r1, r2, fuzz1, val1, self._params)

        # ── Step 2 — Stability check with different fuzz ───────────────────────
        # If even a third fuzz triggers an anomaly, skip this endpoint
        r3 = self._request(http, path, method, {fuzz2: val2})
        if r3 is not None:
            while True:
                reason = _compare(r3, factors, {fuzz2: val2})[2]
                if not reason:
                    break
                # Unstable factor — nullify it
                factors[reason] = None

        # ── Step 3 — Chunk testing + narrowing ────────────────────────────────
        populated   = {p: self._random_value(6) for p in self._params
                       if p not in _PARAM_BLACKLIST}
        param_groups = self._slicer(populated)

        last_params: list[dict] = []
        prev_count  = len(param_groups)

        logger.debug(
            f"    [params] {method} {path} — {len(param_groups)} chunk(s) to test"
        )

        iteration = 0
        while True:
            param_groups = self._narrower(http, path, method, factors, param_groups)
            iteration   += 1

            if not param_groups:
                break

            # Dynamic instability check — if more groups than before, re-check factors
            if len(param_groups) > prev_count:
                r_check = self._request(http, path, method, {fuzz2: val2})
                if r_check and _compare(r_check, factors, {fuzz2: val2})[0]:
                    logger.debug(
                        f"    [params] {method} {path} — "
                        f"dynamic response detected, skipping"
                    )
                    return []

            param_groups = self._confirm_groups(param_groups, last_params)
            prev_count   = len(param_groups)

            if not param_groups:
                break

            if iteration > 20:  # safety cap
                break

        # ── Step 4 — Individual verification ─────────────────────────────────
        confirmed: list[tuple[str, str]] = []
        for param_dict in last_params:
            reason = self._bruter_verify(http, path, method, factors, param_dict)
            if reason:
                name = list(param_dict.keys())[0]
                if name not in _PARAM_BLACKLIST:
                    confirmed.append((name, reason))
                    logger.debug(
                        f"    [param] Confirmed {method}: '{name}' based on: {reason}"
                    )

        return confirmed

    def _narrower(
        self,
        http:         Requester,
        path:         str,
        method:       str,
        factors:      dict,
        param_groups: list[dict],
    ) -> list[dict]:
        """
        Sends each param group and collects groups that trigger anomalies.
        Parallel execution via ThreadPoolExecutor.
        Same as Arjun's narrower().
        """
        anomalous: list[dict] = []
        completed = [0]
        total     = len(param_groups)

        def test_group(params: dict) -> list[dict]:
            r = self._request(self._get_http(), path, method, params)
            if r is None:
                return []
            result = _compare(r, factors, params)
            if result[0]:
                # Anomaly detected — split and return sub-groups
                return self._slicer(params)
            return []

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(test_group, pg): pg for pg in param_groups}
            for future in as_completed(futures):
                with self._lock:
                    completed[0] += 1
                    if completed[0] % 20 == 0 or completed[0] == total:
                        logger.debug(
                            f"    [params] {method} {path} — "
                            f"{completed[0]}/{total} chunks"
                        )
                try:
                    sub = future.result()
                    if sub:
                        with self._lock:
                            anomalous.extend(sub)
                except Exception as e:
                    logger.debug(f"    [params] Chunk error: {e}")

        return anomalous

    def _bruter_verify(
        self,
        http:    Requester,
        path:    str,
        method:  str,
        factors: dict,
        params:  dict,
    ) -> str:
        """
        Verifies a single param individually.
        Returns the anomaly reason string or empty string.
        Same as Arjun's bruter(mode='verify').
        """
        r = self._request(http, path, method, params)
        if r is None:
            return ''
        return _compare(r, factors, params)[0]

    def _confirm_groups(
        self,
        param_groups: list[dict],
        last_params:  list[dict],
    ) -> list[dict]:
        """
        Separates single-param groups (confirmed) from multi-param groups
        (need further narrowing).
        Same as Arjun's confirm().
        """
        still_anomalous: list[dict] = []
        for group in param_groups:
            if len(group) == 1:
                last_params.append(group)
            else:
                still_anomalous.append(group)
        return still_anomalous

    def _slicer(self, params: dict) -> list[dict]:
        """
        Splits a params dict into chunks of CHUNK_SIZE.
        Same as Arjun's slicer().
        """
        items  = list(params.items())
        chunks = []
        for i in range(0, len(items), CHUNK_SIZE):
            chunks.append(dict(items[i:i + CHUNK_SIZE]))
        return chunks

    # =========================================================================
    #  HTTP request dispatcher
    # =========================================================================

    def _request(
        self,
        http:   Requester,
        path:   str,
        method: str,
        params: dict,
    ):
        """
        Sends a request with the given params.
        GET  → query string params
        POST → JSON body params
        """
        try:
            if method == 'GET':
                return http.get(path, params=params)
            elif method == 'POST':
                return http.post(path, json=params)
        except Exception as e:
            logger.debug(f"    [params] Request error ({method} {path}): {e}")
        return None

    # =========================================================================
    #  Source 2 — Response body key extraction
    # =========================================================================

    def _discover_from_response_body(self, path: str) -> list[tuple[str, str]]:
        """
        Extracts JSON keys from the GET response body as parameter candidates.

        Example:
            GET /products → [{"id":1, "name":"Seat", "price":100}]
            → discovered: id, name, price
        """
        http = self._get_http()
        r    = http.get(path)
        if r is None or r.status_code not in (200, 201):
            return []

        try:
            body = r.json()
        except Exception:
            return []

        keys: set[str] = set()

        def extract_keys(obj, depth: int = 0) -> None:
            if depth > 3:
                return
            if isinstance(obj, dict):
                for k, v in obj.items():
                    if isinstance(k, str) and k not in _BODY_KEY_IGNORE:
                        keys.add(k)
                    if isinstance(v, (dict, list)):
                        extract_keys(v, depth + 1)
            elif isinstance(obj, list):
                for item in obj[:3]:
                    extract_keys(item, depth + 1)

        extract_keys(body)
        keys -= _PARAM_BLACKLIST

        result = [(k, "response body key") for k in sorted(keys)]
        if result:
            logger.debug(
                f"    [params] Source 2 — body keys: "
                f"{[k for k, _ in result]} -> {path}"
            )
        return result

    # =========================================================================
    #  Source 3 — Path variable extraction
    # =========================================================================

    def _discover_path_variables(self, path: str) -> list[tuple[str, str]]:
        """
        Extracts path variables from URL segments.

        Examples:
            /users/1/orders/5  → user_id=1, order_id=5
            /products/UUID     → product_id=UUID
        """
        segments = [s for s in path.split("/") if s]
        result:  list[tuple[str, str]] = []

        for i, segment in enumerate(segments):
            prev = segments[i - 1] if i > 0 else "resource"
            name = prev.rstrip("s") + "_id" if prev.endswith("s") else prev + "_id"

            if segment.isdigit():
                result.append((name, "path variable"))
                logger.debug(f"    [params] Source 3 — path var: {name}={segment}")

            elif _UUID_PATTERN.match(segment):
                result.append((name, "path variable (UUID)"))
                logger.debug(f"    [params] Source 3 — UUID var: {name}={segment}")

            elif _MONGO_ID_PATTERN.match(segment):
                result.append((name, "path variable (ObjectId)"))

        return result

    # =========================================================================
    #  Wordlist loading
    # =========================================================================

    def _load_wordlist(self, custom_path: Optional[str] = None) -> list[str]:
        """Load parameter wordlist — priority: custom → Arjun → fallback."""
        if custom_path and os.path.isfile(custom_path):
            return self._read_wordlist(custom_path)
        for path in ARJUN_WORDLIST_PATHS:
            if os.path.isfile(path):
                logger.debug(f"[ParamDiscoverer] Using Arjun wordlist: {path}")
                return self._read_wordlist(path)
        logger.warning("[ParamDiscoverer] Arjun wordlist not found — using fallback")
        return FALLBACK_PARAMS

    def _read_wordlist(self, path: str) -> list[str]:
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                return [
                    line.strip()
                    for line in f
                    if line.strip() and not line.startswith("#")
                ]
        except Exception as e:
            logger.error(f"[ParamDiscoverer] Error reading wordlist: {e}")
            return FALLBACK_PARAMS

    # =========================================================================
    #  Helpers
    # =========================================================================

    def _random_value(self, length: int = 8) -> str:
        """Generate a random alphanumeric value."""
        return "".join(random.choices(string.ascii_lowercase + string.digits, k=length))