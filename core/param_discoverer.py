# core/param_discoverer.py
"""
ParamDiscoverer — HTTP parameter discovery module.

Reproduces Arjun's core logic:
  - Sends parameters in chunks (250 at a time)
  - Multi-threaded chunk testing (5 workers by default — same as Arjun)
  - Compares responses: body length + status code + headers
  - Reports WHY each param was detected (like Arjun)
  - Confirms each candidate param individually
  - Uses Arjun's wordlist (large.txt) if available

Usage:
    discoverer = ParamDiscoverer("https://api.example.com", token="Bearer ...")
    params = discoverer.discover("/api/Products")
    # → [("q", "body length"), ("name", "http code"), ...]
"""

from __future__ import annotations

import os
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

# Arjun wordlist locations (tries each in order)
ARJUN_WORDLIST_PATHS: list[str] = [
    # Kali pip install
    os.path.expanduser("~/.local/lib/python3.13/site-packages/arjun/db/large.txt"),
    os.path.expanduser("~/.local/lib/python3.12/site-packages/arjun/db/large.txt"),
    os.path.expanduser("~/.local/lib/python3.11/site-packages/arjun/db/large.txt"),
    os.path.expanduser("~/.local/lib/python3.10/site-packages/arjun/db/large.txt"),
    # Kali apt install
    "/usr/lib/python3/dist-packages/arjun/db/large.txt",
    "/usr/local/lib/python3/dist-packages/arjun/db/large.txt",
    # Git clone
    os.path.join(os.getcwd(), "Arjun", "arjun", "db", "large.txt"),
    os.path.expanduser("~/Arjun/arjun/db/large.txt"),
    # Windows venv
    os.path.join(os.getcwd(), "venv", "Lib", "site-packages", "arjun", "db", "large.txt"),
    # Downloaded manually
    os.path.join(os.getcwd(), "wordlists", "params-large.txt"),
]

# Fallback — common params if Arjun wordlist not found
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

# Number of params to send per request (same as Arjun default)
CHUNK_SIZE = 250

# Number of concurrent threads (same as Arjun default)
DEFAULT_THREADS = 5

# Minimum body length difference to consider a param as valid (10%)
MIN_DIFF_THRESHOLD = 0.10


# ─────────────────────────────────────────────────────────────────────────────
#  ParamDiscoverer
# ─────────────────────────────────────────────────────────────────────────────

class ParamDiscoverer:
    """
    Discovers real HTTP parameters accepted by an endpoint.

    Reproduces Arjun's algorithm with multi-threading:
      1. Send baseline request (no params)
      2. Send chunks of params with random values — in parallel (5 threads)
      3. If chunk response differs → one of the params in the chunk is valid
      4. Confirm each param individually
      5. Report WHY each param was detected (body length / http code / etc.)

    Usage:
        disc = ParamDiscoverer("https://api.example.com", token="...", threads=5)
        params = disc.discover("/api/Products")
        # → [("q", "body length"), ("name", "http code")]
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
        self._lock    = threading.Lock()  # thread-safe logging

        # Each thread gets its own Requester to avoid session conflicts
        self._local = threading.local()
        self._token = token

        if token:
            # Store token for thread-local requesters
            self._token = token

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

        Args:
            path : relative path (e.g. "/api/Products")

        Returns:
            List of (param_name, detection_reason) tuples
            e.g. [("q", "body length"), ("name", "http code")]
        """
        logger.info(f"[ParamDiscoverer] Scanning {self.base_url}{path}")

        # Step 1: baseline — request without any params
        http       = self._get_http()
        r_baseline = http.get(path)
        if r_baseline is None:
            logger.warning(f"[ParamDiscoverer] Could not get baseline for {path}")
            return []

        baseline_features = self._extract_features(r_baseline)
        logger.debug(
            f"[ParamDiscoverer] Baseline → "
            f"status:{baseline_features['status']} "
            f"length:{baseline_features['length']}"
        )

        # Step 2: split params into chunks
        chunks = self._make_chunks(self._params, CHUNK_SIZE)
        total  = len(chunks)
        logger.info(f"[ParamDiscoverer] Testing {total} chunks with {self.threads} threads...")

        # Step 3: test chunks in parallel
        candidates: list[tuple[str, str]] = []
        completed  = [0]  # mutable counter for progress

        def test_chunk(chunk: list[str]) -> list[tuple[str, str]]:
            """Test one chunk — runs in a thread."""
            http = self._get_http()
            params_dict = {p: self._random_value() for p in chunk}
            r = http.get(path, params=params_dict)
            if r is None:
                return []

            chunk_features = self._extract_features(r)
            differs, _     = self._features_differ(baseline_features, chunk_features)

            if not differs:
                return []

            # A param in this chunk triggered a difference — find which one
            return self._narrow_down(path, baseline_features, chunk)

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(test_chunk, chunk): chunk for chunk in chunks}

            for future in as_completed(futures):
                with self._lock:
                    completed[0] += 1
                    if completed[0] % 20 == 0 or completed[0] == total:
                        logger.debug(
                            f"[ParamDiscoverer] Progress: {completed[0]}/{total} chunks"
                        )
                try:
                    result = future.result()
                    if result:
                        with self._lock:
                            candidates.extend(result)
                except Exception as e:
                    logger.debug(f"[ParamDiscoverer] Chunk error: {e}")

        # Step 4: deduplicate preserving order
        seen   = set()
        unique = []
        for param, reason in candidates:
            if param not in seen:
                seen.add(param)
                unique.append((param, reason))

        # Summary
        if unique:
            logger.info(f"[ParamDiscoverer] Found {len(unique)} param(s) on {path}:")
            for param, reason in unique:
                logger.info(f"    [v] parameter detected: {param}, based on: {reason}")
        else:
            logger.debug(f"[ParamDiscoverer] No params found for {path}")

        return unique

    def discover_names(self, path: str) -> list[str]:
        """
        Same as discover() but returns only parameter names (no reasons).
        Convenience method for use in scanners.
        """
        return [param for param, _ in self.discover(path)]

    def discover_all(self, endpoints: list[str]) -> dict[str, list[tuple[str, str]]]:
        """
        Discover params for multiple endpoints sequentially.
        (Each endpoint uses multi-threaded chunk testing internally)

        Returns:
            Dict mapping endpoint URL → list of (param, reason) tuples
        """
        results = {}
        for endpoint in endpoints:
            path   = endpoint.replace(self.base_url, "") or "/"
            params = self.discover(path)
            if params:
                results[endpoint] = params
        return results

    # =========================================================================
    #  Core algorithm
    # =========================================================================

    def _narrow_down(
        self,
        path:              str,
        baseline_features: dict,
        chunk:             list[str],
    ) -> list[tuple[str, str]]:
        """
        Find which specific params in a chunk cause a response difference.
        Tests each param individually and confirms with a second request.

        Returns:
            List of (param_name, detection_reason) tuples
        """
        found = []
        http  = self._get_http()

        for param in chunk:
            val1 = self._random_value()
            r1   = http.get(path, params={param: val1})
            if r1 is None:
                continue

            features1        = self._extract_features(r1)
            differs1, reason = self._features_differ(baseline_features, features1)

            if differs1:
                # Confirm with a second request (different random value)
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
                        logger.debug(f"    [param] Confirmed: '{param}' based on: {final_reason}")

        return found

    # =========================================================================
    #  Feature extraction & comparison
    # =========================================================================

    def _extract_features(self, r) -> dict:
        """
        Extract response features used for comparison.
        Same signals as Arjun: body length + status code + headers.
        """
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
        True if current response differs significantly from baseline.
        Returns (differs: bool, reason: str) — exactly like Arjun output.

        Detection signals (in priority order):
          1. HTTP status code changed   → "http code"
          2. Location redirect changed  → "http redirect"
          3. Set-Cookie header changed  → "http headers"
          4. Content-Type changed       → "content type"
          5. Body length changed > 10%  → "body length"
        """
        if not baseline or not current:
            return False, ""

        # 1. Status code changed
        if baseline.get("status") != current.get("status"):
            return True, "http code"

        # 2. Location redirect changed
        if baseline.get("location") != current.get("location"):
            return True, "http redirect"

        # 3. Set-Cookie header changed
        if baseline.get("set_cookie") != current.get("set_cookie"):
            return True, "http headers"

        # 4. Content-Type changed
        if baseline.get("content_type") != current.get("content_type"):
            return True, "content type"

        # 5. Body length changed significantly (>10%)
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
        """
        Load parameter wordlist.
        Priority: custom path → Arjun wordlist → fallback list
        """
        if custom_path and os.path.isfile(custom_path):
            logger.debug(f"[ParamDiscoverer] Using custom wordlist: {custom_path}")
            return self._read_wordlist(custom_path)

        for path in ARJUN_WORDLIST_PATHS:
            if os.path.isfile(path):
                logger.debug(f"[ParamDiscoverer] Using Arjun wordlist: {path}")
                return self._read_wordlist(path)

        logger.warning("[ParamDiscoverer] Arjun wordlist not found — using fallback list (60 params)")
        return FALLBACK_PARAMS

    def _read_wordlist(self, path: str) -> list[str]:
        """Read wordlist file and return cleaned list of params."""
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                params = [
                    line.strip()
                    for line in f
                    if line.strip() and not line.startswith("#")
                ]
            return params
        except Exception as e:
            logger.error(f"[ParamDiscoverer] Error reading wordlist: {e}")
            return FALLBACK_PARAMS

    # =========================================================================
    #  Helpers
    # =========================================================================

    def _random_value(self, length: int = 8) -> str:
        """Generate a random alphanumeric value for param testing."""
        return "".join(random.choices(string.ascii_lowercase + string.digits, k=length))

    def _make_chunks(self, lst: list, size: int) -> list[list]:
        """Split a list into chunks of given size."""
        return [lst[i:i + size] for i in range(0, len(lst), size)]