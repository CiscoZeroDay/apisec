# core/param_discoverer.py
"""
ParamDiscoverer — HTTP parameter discovery module.

Discovery sources :
  Source 1 — Wordlist-based (Arjun algorithm) : query params via chunk testing
  Source 2 — Response body analysis           : keys extracted from JSON response
  Source 3 — Path variable extraction         : numeric/UUID segments in URL
  Source 4 — POST field discovery             : fields revealed by 422/400 errors

Reproduces Arjun's core logic:
  - Sends parameters in chunks (250 at a time)
  - Multi-threaded chunk testing (5 workers by default)
  - Compares responses: body length + status code + headers
  - Reports WHY each param was detected (like Arjun)
  - Confirms each candidate param individually
  - Uses Arjun's wordlist (large.txt) if available
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

from core.requester import Requester
from logger.logger import logger


# ─────────────────────────────────────────────────────────────────────────────
#  Constants
# ─────────────────────────────────────────────────────────────────────────────

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
    "status", "action", "method", "format", "lang", "locale", "country",
    "city", "address", "phone", "code", "ref", "source", "medium",
    "content", "body", "message", "comment", "description", "title",
    "value", "data", "payload", "input", "output", "result", "response",
    "admin", "debug", "test", "dev", "verbose", "trace", "log",
    "role", "permission", "scope", "grant", "access", "auth",
    "file", "filename", "path", "dir", "folder", "upload",
    "date", "time", "from", "to", "start", "end", "range",
    "version", "v", "api", "mode", "config", "setting",
]

# ── POST body discovery — common field names to probe ─────────────────────────
POST_FIELD_CANDIDATES: list[str] = [
    "email", "username", "password", "name", "title", "body",
    "content", "message", "description", "phone", "address",
    "first_name", "last_name", "firstName", "lastName",
    "id", "user_id", "userId", "post_id", "postId",
    "category", "type", "status", "role", "tag", "tags",
    "url", "link", "image", "file", "avatar", "photo",
    "amount", "price", "quantity", "total", "code",
    "token", "otp", "pin", "secret", "key",
    "date", "from", "to", "start_date", "end_date",
    "limit", "offset", "page", "sort", "order", "filter",
    "mechanic_code", "vin", "pincode", "number",
    "model", "year", "color", "fuel_type",
    "service_type", "problem_details",
    "vehicleLocation", "mechanic_api",
]

# ── Path variable patterns ────────────────────────────────────────────────────
_UUID_PATTERN  = re.compile(
    r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
    re.IGNORECASE
)
_MONGO_ID_PATTERN = re.compile(r'^[0-9a-f]{24}$', re.IGNORECASE)

CHUNK_SIZE        = 250
DEFAULT_THREADS   = 5
MIN_DIFF_THRESHOLD = 0.10

# Keys to ignore from response body (too generic, not useful as params)
_BODY_KEY_IGNORE = {
    "message", "error", "errors", "success", "ok", "status",
    "timestamp", "created_at", "updated_at", "createdAt", "updatedAt",
    "_id", "__v", "links", "meta", "pagination",
}


# ─────────────────────────────────────────────────────────────────────────────
#  ParamDiscoverer
# ─────────────────────────────────────────────────────────────────────────────

class ParamDiscoverer:
    """
    Discovers HTTP parameters accepted by an endpoint using 4 sources:

      Source 1 — Wordlist (Arjun algorithm) : query params via chunk testing
      Source 2 — Response body analysis     : JSON keys from GET response
      Source 3 — Path variable extraction   : numeric/UUID segments in URL
      Source 4 — POST field discovery       : fields from 422/400 error bodies
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
        self._params  = self._load_wordlist(wordlist)
        self._lock    = threading.Lock()
        self._local   = threading.local()
        self._token   = token

        logger.info(
            f"[ParamDiscoverer] Loaded {len(self._params)} params | "
            f"{self.threads} threads | chunk size: {CHUNK_SIZE}"
        )

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
        Combines all 4 sources and deduplicates results.

        Returns:
            List of (param_name, detection_reason) tuples
        """
        logger.info(f"[ParamDiscoverer] Scanning {self.base_url}{path}")

        all_params: dict[str, str] = {}  # param → reason

        # ── Source 1 — Wordlist-based (Arjun algorithm) ───────────────────────
        wordlist_params = self._discover_wordlist(path)
        for param, reason in wordlist_params:
            if param not in all_params:
                all_params[param] = reason

        # ── Source 2 — Response body analysis ────────────────────────────────
        body_params = self._discover_from_response_body(path)
        for param, reason in body_params:
            if param not in all_params:
                all_params[param] = reason

        # ── Source 3 — Path variable extraction ──────────────────────────────
        path_params = self._discover_path_variables(path)
        for param, reason in path_params:
            if param not in all_params:
                all_params[param] = reason

        # ── Source 4 — POST field discovery ──────────────────────────────────
        post_params = self._discover_post_fields(path)
        for param, reason in post_params:
            if param not in all_params:
                all_params[param] = reason

        # ── Summary ───────────────────────────────────────────────────────────
        result = list(all_params.items())

        if result:
            logger.info(f"[ParamDiscoverer] Found {len(result)} param(s) on {path}:")
            for param, reason in result:
                logger.info(f"    [v] parameter detected: {param}, based on: {reason}")
        else:
            logger.debug(f"[ParamDiscoverer] No params found for {path}")

        return result

    def discover_names(self, path: str) -> list[str]:
        """Returns only parameter names (no reasons)."""
        return [param for param, _ in self.discover(path)]

    def discover_all(
        self, endpoints: list[str]
    ) -> dict[str, list[tuple[str, str]]]:
        """Discover params for multiple endpoints sequentially."""
        results = {}
        for endpoint in endpoints:
            path   = endpoint.replace(self.base_url, "") or "/"
            params = self.discover(path)
            if params:
                results[endpoint] = params
        return results

    # =========================================================================
    #  Source 1 — Wordlist-based (Arjun algorithm)
    # =========================================================================

    def _discover_wordlist(self, path: str) -> list[tuple[str, str]]:
        """
        Arjun-style wordlist discovery via chunk testing.
        Sends params in batches and confirms individually.
        """
        http       = self._get_http()
        r_baseline = http.get(path)
        if r_baseline is None:
            return []

        baseline_features = self._extract_features(r_baseline)
        chunks            = self._make_chunks(self._params, CHUNK_SIZE)
        total             = len(chunks)
        candidates: list[tuple[str, str]] = []
        completed = [0]

        def test_chunk(chunk: list[str]) -> list[tuple[str, str]]:
            http        = self._get_http()
            params_dict = {p: self._random_value() for p in chunk}
            r           = http.get(path, params=params_dict)
            if r is None:
                return []
            chunk_features = self._extract_features(r)
            differs, _     = self._features_differ(baseline_features, chunk_features)
            if not differs:
                return []
            return self._narrow_down(path, baseline_features, chunk)

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(test_chunk, chunk): chunk for chunk in chunks}
            for future in as_completed(futures):
                with self._lock:
                    completed[0] += 1
                    if completed[0] % 20 == 0 or completed[0] == total:
                        logger.debug(
                            f"[ParamDiscoverer] Wordlist: {completed[0]}/{total} chunks"
                        )
                try:
                    result = future.result()
                    if result:
                        with self._lock:
                            candidates.extend(result)
                except Exception as e:
                    logger.debug(f"[ParamDiscoverer] Chunk error: {e}")

        # Deduplicate
        seen, unique = set(), []
        for param, reason in candidates:
            if param not in seen:
                seen.add(param)
                unique.append((param, reason))
        return unique

    # =========================================================================
    #  Source 2 — Response body analysis
    # =========================================================================

    def _discover_from_response_body(
        self, path: str
    ) -> list[tuple[str, str]]:
        """
        Extracts parameter names from the JSON keys of the GET response.

        Example :
            GET /products → [{"id":1, "name":"Seat", "price":100, "category":"car"}]
            → discovered: id, name, price, category
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
            """Recursively extract keys from JSON object/list."""
            if depth > 3:  # max depth to avoid infinite recursion
                return
            if isinstance(obj, dict):
                for k, v in obj.items():
                    if isinstance(k, str) and k not in _BODY_KEY_IGNORE:
                        keys.add(k)
                    if isinstance(v, (dict, list)):
                        extract_keys(v, depth + 1)
            elif isinstance(obj, list):
                for item in obj[:3]:  # analyse first 3 items only
                    extract_keys(item, depth + 1)

        extract_keys(body)

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

    def _discover_path_variables(
        self, path: str
    ) -> list[tuple[str, str]]:
        """
        Extracts path variables from URL segments.

        Examples :
            /users/1/orders/5   → user_id=1, order_id=5
            /products/abc-123   → product_id=abc-123
            /vehicles/UUID      → vehicle_id=UUID
        """
        segments = [s for s in path.split("/") if s]
        result: list[tuple[str, str]] = []

        for i, segment in enumerate(segments):
            # Numeric path variable → likely an ID
            if segment.isdigit():
                prev = segments[i - 1] if i > 0 else "resource"
                # Singularize: "orders" → "order_id", "users" → "user_id"
                name = prev.rstrip("s") + "_id" if prev.endswith("s") else prev + "_id"
                result.append((name, "path variable"))
                logger.debug(
                    f"    [params] Source 3 — path var: {name}={segment} -> {path}"
                )

            # UUID path variable
            elif _UUID_PATTERN.match(segment):
                prev = segments[i - 1] if i > 0 else "resource"
                name = prev.rstrip("s") + "_id" if prev.endswith("s") else prev + "_id"
                result.append((name, "path variable (UUID)"))
                logger.debug(
                    f"    [params] Source 3 — UUID var: {name}={segment} -> {path}"
                )

            # MongoDB ObjectId
            elif _MONGO_ID_PATTERN.match(segment):
                prev = segments[i - 1] if i > 0 else "resource"
                name = prev.rstrip("s") + "_id" if prev.endswith("s") else prev + "_id"
                result.append((name, "path variable (ObjectId)"))

        return result

    # =========================================================================
    #  Source 4 — POST field discovery
    # =========================================================================

    def _discover_post_fields(
        self, path: str
    ) -> list[tuple[str, str]]:
        """
        Discovers POST body fields by:
          1. Sending an empty POST → 422/400 may reveal required fields
          2. Sending POST with all candidate fields → checks which are accepted
          3. Parsing validation error messages for field names
        """
        http   = self._get_http()
        result: list[tuple[str, str]] = []

        # Step 1 — Empty POST body → look for validation errors
        r_empty = http.post(path, json={})
        if r_empty and r_empty.status_code in (400, 422):
            fields = self._parse_validation_error(r_empty)
            for field in fields:
                result.append((field, "POST validation error"))
                logger.debug(
                    f"    [params] Source 4 — validation field: {field} -> {path}"
                )

        # Step 2 — POST with all candidates → check which fields affect response
        if not result:
            baseline_r    = http.post(path, json={})
            baseline_feat = self._extract_features(baseline_r) if baseline_r else {}

            for field in POST_FIELD_CANDIDATES:
                test_body = {field: self._random_value()}
                r = http.post(path, json=test_body)
                if r is None:
                    continue

                feat     = self._extract_features(r)
                differs, reason = self._features_differ(baseline_feat, feat)
                if differs:
                    result.append((field, f"POST response change ({reason})"))
                    logger.debug(
                        f"    [params] Source 4 — POST field: {field} ({reason}) -> {path}"
                    )

        return result

    def _parse_validation_error(self, r) -> list[str]:
        """
        Parses 400/422 error responses to extract field names.

        Handles common formats :
          - FastAPI/Pydantic : {"detail": [{"loc": ["body", "email"], "msg": "..."}]}
          - Express/Joi      : {"errors": {"email": "required"}}
          - Django REST      : {"email": ["This field is required."]}
          - Spring Boot      : {"errors": [{"field": "email", "message": "..."}]}
        """
        fields: list[str] = []

        try:
            body = r.json()
        except Exception:
            # Try to extract field names from plain text error
            text = r.text or ""
            matches = re.findall(r'"(\w+)":\s*\[?"[^"]*required', text, re.IGNORECASE)
            return list(set(matches))

        if not isinstance(body, dict):
            return fields

        # FastAPI/Pydantic format
        detail = body.get("detail", [])
        if isinstance(detail, list):
            for item in detail:
                if isinstance(item, dict):
                    loc = item.get("loc", [])
                    if isinstance(loc, list) and len(loc) >= 2:
                        field = loc[-1]
                        if isinstance(field, str) and field not in ("body", "query"):
                            fields.append(field)

        # Express/Joi format : {"errors": {"email": "...", "password": "..."}}
        errors = body.get("errors", {})
        if isinstance(errors, dict):
            fields.extend(errors.keys())
        elif isinstance(errors, list):
            for item in errors:
                if isinstance(item, dict):
                    field = item.get("field") or item.get("param") or item.get("path")
                    if field and isinstance(field, str):
                        fields.append(field)

        # Django REST format : {"email": ["This field is required."]}
        for key, val in body.items():
            if key not in ("detail", "errors", "message", "status", "code"):
                if isinstance(val, list) and val:
                    fields.append(key)

        return list(set(fields))

    # =========================================================================
    #  Core Arjun algorithm helpers
    # =========================================================================

    def _narrow_down(
        self,
        path:              str,
        baseline_features: dict,
        chunk:             list[str],
    ) -> list[tuple[str, str]]:
        """Find which specific params in a chunk cause a response difference."""
        found = []
        http  = self._get_http()

        for param in chunk:
            val1 = self._random_value()
            r1   = http.get(path, params={param: val1})
            if r1 is None:
                continue

            features1, reason = self._extract_features(r1), ""
            differs1, reason  = self._features_differ(baseline_features, features1)

            if differs1:
                val2 = self._random_value()
                r2   = http.get(path, params={param: val2})
                if r2 is None:
                    continue

                features2         = self._extract_features(r2)
                differs2, reason2 = self._features_differ(baseline_features, features2)

                if differs2:
                    final_reason = reason if reason else reason2
                    found.append((param, final_reason))
                    with self._lock:
                        logger.debug(
                            f"    [param] Confirmed: '{param}' based on: {final_reason}"
                        )

        return found

    # =========================================================================
    #  Feature extraction & comparison
    # =========================================================================

    def _extract_features(self, r) -> dict:
        """Extract response features for comparison."""
        if r is None:
            return {}
        body = (r.text or "").strip()
        return {
            "status":       r.status_code,
            "length":       len(body),
            "content_type": r.headers.get("Content-Type", "").split(";")[0].strip(),
            "location":     r.headers.get("Location", ""),
            "set_cookie":   r.headers.get("Set-Cookie", ""),
        }

    def _features_differ(self, baseline: dict, current: dict) -> tuple[bool, str]:
        """
        Returns (differs, reason) — same signals as Arjun.
        """
        if not baseline or not current:
            return False, ""

        if baseline.get("status") != current.get("status"):
            return True, "http code"
        if baseline.get("location") != current.get("location"):
            return True, "http redirect"
        if baseline.get("set_cookie") != current.get("set_cookie"):
            return True, "http headers"
        if baseline.get("content_type") != current.get("content_type"):
            return True, "content type"

        base_len = baseline.get("length", 0)
        curr_len = current.get("length", 0)
        if base_len == 0 and curr_len == 0:
            return False, ""
        if base_len == 0:
            return (curr_len > 0), "body length"
        diff = abs(base_len - curr_len) / max(base_len, 1)
        if diff > MIN_DIFF_THRESHOLD:
            return True, "body length"

        return False, ""

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
        """Read wordlist file."""
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

    def _make_chunks(self, lst: list, size: int) -> list[list]:
        """Split list into chunks."""
        return [lst[i:i + size] for i in range(0, len(lst), size)]