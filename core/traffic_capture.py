# core/traffic_capture.py
"""
TrafficCapture — Real-time HTTP/HTTPS traffic capture and endpoint extraction.

Architecture:
    Uses mitmproxy's Python API (DumpMaster) to run a transparent proxy
    that intercepts all browser traffic. Captured flows are saved to disk
    via a custom FlowSaver addon, then converted to an OpenAPI/Swagger spec
    via mitmproxy2swagger. The resulting spec is parsed to produce a clean
    endpoints.json file compatible with the apisec scan pipeline.

Pipeline:
    Browser → mitmproxy proxy (port 8080) → target API
                      ↓
               traffic.mitm  (raw mitmproxy flows)
                      ↓
           mitmproxy2swagger (OpenAPI/Swagger spec)
                      ↓
              endpoints.json (apisec format)

SSL/TLS:
    mitmproxy generates a self-signed CA certificate on first run (~/.mitmproxy/).
    This module installs it automatically into the OS trust store so HTTPS
    traffic is captured transparently without browser warnings.

Compatibility:
    Tested with mitmproxy 11.x — uses FlowWriter addon instead of the
    deprecated save_stream_file option removed in mitmproxy 11.

Usage:
    capture = TrafficCapture(
        target_url  = "http://localhost:8888",
        proxy_port  = 8080,
        output_path = "endpoints.json",
    )
    result = capture.run()
"""

from __future__ import annotations

import asyncio
import json
import platform
import shutil
import subprocess
import threading
import time
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

from logger.logger import logger


# =============================================================================
#  Constants
# =============================================================================

_DEFAULT_PROXY_PORT = 8080
_DEFAULT_PROXY_HOST = "127.0.0.1"
_MITM_CERT_DIR      = Path.home() / ".mitmproxy"
_MITM_CA_CERT_PEM   = _MITM_CERT_DIR / "mitmproxy-ca-cert.pem"
_MITM_CA_CERT_CRT   = _MITM_CERT_DIR / "mitmproxy-ca-cert.cer"

# Static asset extensions — not API endpoints
_IGNORE_EXTENSIONS = {
    ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg",
    ".ico", ".woff", ".woff2", ".ttf", ".eot", ".map",
    ".html", ".htm", ".txt", ".pdf", ".zip", ".gz",
}

# Static paths — not API endpoints
_IGNORE_PATHS = {
    "/favicon.ico", "/robots.txt", "/sitemap.xml",
    "/manifest.json", "/service-worker.js",
}


# =============================================================================
#  CaptureResult
# =============================================================================

@dataclass
class CaptureResult:
    """Structured result from a traffic capture session."""

    target_url:        str
    api_type:          str            = "REST"
    endpoints:         list[str]      = field(default_factory=list)
    captured_queries:  list[dict]     = field(default_factory=list)  # GraphQL queries observed
    flow_count:        int            = 0
    api_flows:         int            = 0
    traffic_file:      Optional[str] = None
    swagger_file:      Optional[str] = None

    def to_dict(self) -> dict:
        result = {
            "target_url": self.target_url,
            "api_type":   self.api_type,
            "endpoints":  self.endpoints,
            "source":     "traffic_capture",
        }
        # Include captured GraphQL queries in schema section
        if self.captured_queries:
            result["schema"] = {
                "method":            "traffic_capture",
                "endpoint":          next((e for e in self.endpoints if "graphql" in e.lower()), ""),
                "captured_queries":  self.captured_queries,
                "queries":           [],
                "mutations":         [],
                "types":             [],
                "raw_introspection": None,
            }
        return result


# =============================================================================
#  mitmproxy Addons
# =============================================================================

class _FlowSaver:
    """
    mitmproxy addon that saves every completed HTTP flow to a .mitm file.
    Replaces the deprecated save_stream_file option removed in mitmproxy 11.x.
    """

    def __init__(self, traffic_file: str) -> None:
        import mitmproxy.io as mitm_io
        self._file   = open(traffic_file, "wb")
        self._writer = mitm_io.FlowWriter(self._file)
        self._count  = 0

    def response(self, flow) -> None:
        """Save each completed flow (request + response) to disk."""
        try:
            self._writer.add(flow)
            self._count += 1
        except Exception as e:
            logger.debug(f"[capture] FlowSaver write error: {e}")

    def done(self) -> None:
        """Flush and close the file when mitmproxy shuts down."""
        try:
            self._file.flush()
            self._file.close()
        except Exception:
            pass

    @property
    def count(self) -> int:
        return self._count


class _RealtimeDisplay:
    """
    mitmproxy addon that displays captured API requests in real time.
    Only shows requests targeting the specified API host.
    Filters out static assets and duplicate paths.
    Captures GraphQL query bodies for later analysis.
    """

    def __init__(self, target_host: str) -> None:
        self.target_host     = target_host.lower()
        self.flow_count      = 0
        self.api_flows       = 0
        self.gql_queries:    list[dict] = []   # captured GraphQL operations
        self._seen_paths:    set[str]   = set()
        self._seen_gql:      set[str]   = set()  # dedup GraphQL queries

    def request(self, flow) -> None:
        """Display each intercepted API request in the terminal."""
        host   = flow.request.pretty_host.lower()
        method = flow.request.method
        url    = flow.request.pretty_url
        path   = flow.request.path.split("?")[0]

        self.flow_count += 1

        # Only process requests targeting our API
        if self.target_host not in host:
            return

        # Skip static assets
        ext = Path(path).suffix.lower()
        if ext in _IGNORE_EXTENSIONS or path in _IGNORE_PATHS:
            return

        self.api_flows += 1

        # ── Capture GraphQL query bodies ──────────────────────────────────────
        is_graphql = "graphql" in path.lower() or "gql" in path.lower()

        if is_graphql and method == "POST":
            try:
                body = flow.request.get_text(strict=False) or ""
                if body:
                    import json as _json
                    payload = _json.loads(body)

                    # Handle both single queries and batch arrays
                    items = payload if isinstance(payload, list) else [payload]
                    for item in items:
                        query    = item.get("query", "").strip()
                        variables = item.get("variables")
                        op_name  = item.get("operationName")

                        if query and query not in self._seen_gql:
                            self._seen_gql.add(query)
                            entry = {"query": query}
                            if variables:
                                entry["variables"] = variables
                            if op_name:
                                entry["operationName"] = op_name
                            self.gql_queries.append(entry)
                            # Show GraphQL operation type
                            op_type = "mutation" if query.strip().startswith("mutation") else "query"
                            print(f"  \033[92m[+]\033[0m {method:<7} {url}  \033[94m[GQL:{op_type}]\033[0m")
                        elif query:
                            # Already seen this exact query — just show the request
                            pass
            except Exception:
                pass

        # Display each unique path only once (for non-GQL or GQL GET)
        if path not in self._seen_paths:
            self._seen_paths.add(path)
            if not is_graphql:
                print(f"  \033[92m[+]\033[0m {method:<7} {url}")



# =============================================================================
#  TrafficReader — Read and analyze existing .mitm flow files
# =============================================================================

# GraphQL detection signals
_GQL_PATHS      = {"/graphql", "/api/graphql", "/graphql/v1", "/v1/graphql", "/gql", "/query"}
_GQL_PATH_HINTS = ("graphql", "/gql", "graphiql")
_SOAP_HINTS     = (".wsdl", "/service", "soap", "text/xml", "application/soap")

# Content types that indicate API traffic
_API_CONTENT_TYPES = (
    "application/json",
    "application/graphql",
    "text/xml",
    "application/soap+xml",
    "application/x-www-form-urlencoded",
)

# Static asset extensions to skip
_STATIC_EXTENSIONS = {
    ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg",
    ".ico", ".woff", ".woff2", ".ttf", ".eot", ".map",
    ".html", ".htm", ".txt", ".pdf", ".zip", ".gz",
}


@dataclass
class CapturedRequest:
    """
    A single captured HTTP request with its response.
    Stored in requests.json — kept separate from endpoints.json.
    """
    index:        int
    method:       str
    url:          str
    path:         str
    status_code:  int
    request_headers:  dict
    response_headers: dict
    request_body:     Optional[str]   = None
    response_body:    Optional[str]   = None
    api_type:         str             = "REST"    # REST | GraphQL | SOAP
    gql_operation:    Optional[str]   = None      # query | mutation | subscription
    gql_query:        Optional[str]   = None      # the actual GraphQL query string
    error:            Optional[str]   = None

    def to_dict(self) -> dict:
        d = {
            "index":            self.index,
            "method":           self.method,
            "url":              self.url,
            "path":             self.path,
            "status_code":      self.status_code,
            "request_headers":  self.request_headers,
            "response_headers": self.response_headers,
        }
        if self.request_body:
            d["request_body"]  = self.request_body
        if self.response_body:
            d["response_body"] = self.response_body
        if self.api_type != "REST":
            d["api_type"]      = self.api_type
        if self.gql_operation:
            d["gql_operation"] = self.gql_operation
        if self.gql_query:
            d["gql_query"]     = self.gql_query
        if self.error:
            d["error"]         = self.error
        return d


@dataclass
class ReadResult:
    """
    Result of reading a .mitm flow file.
    Produces two separate output files:
      - endpoints.json  : unique URLs + api_type detection
      - requests.json   : all requests with full bodies and metadata
    """
    source_file:      str
    target_url:       str
    api_type:         str               = "REST"
    requests:         list              = field(default_factory=list)   # list[CapturedRequest]
    endpoints:        list[str]         = field(default_factory=list)
    gql_queries:      list[dict]        = field(default_factory=list)
    total_flows:      int               = 0
    api_flows:        int               = 0
    gql_flows:        int               = 0
    soap_flows:       int               = 0

    @property
    def summary(self) -> str:
        lines = [
            f"Source         : {self.source_file}",
            f"API type       : {self.api_type}",
            f"Total flows    : {self.total_flows}",
            f"API flows      : {self.api_flows}",
        ]
        if self.gql_flows:
            lines.append(f"GraphQL ops    : {self.gql_flows}")
        if self.soap_flows:
            lines.append(f"SOAP ops       : {self.soap_flows}")
        lines.append(f"Unique endpoints: {len(self.endpoints)}")
        return "\n".join(f"  {l}" for l in lines)


class TrafficReader:
    """
    Reads and analyzes a mitmproxy .mitm flow file.

    Produces two separate outputs:
      - endpoints.json  : unique endpoint URLs with api_type detection
                          (compatible with apisec scan pipeline)
      - requests.json   : all captured requests with full HTTP details,
                          bodies, GraphQL queries, SOAP envelopes

    GraphQL detection:
      - Path contains /graphql, /gql, graphiql
      - Content-Type: application/json + body contains "query" key
      - Body starts with { or [ and contains __schema, mutation, query keyword

    Args:
        target_url       : base URL of the target API
        endpoints_path   : output path for endpoints.json (default: endpoints.json)
        requests_path    : output path for requests.json  (default: requests.json)
        max_body_size    : max response body size to store in bytes (default: 10KB)
        filter_target    : if True, only process flows targeting target_url
    """

    def __init__(
        self,
        target_url:     str,
        endpoints_path: str  = "endpoints.json",
        requests_path:  str  = "requests.json",
        max_body_size:  int  = 10_240,
        filter_target:  bool = True,
    ) -> None:
        self.target_url     = target_url.rstrip("/")
        self.endpoints_path = endpoints_path
        self.requests_path  = requests_path
        self.max_body_size  = max_body_size
        self.filter_target  = filter_target

        parsed           = urlparse(self.target_url)
        self.target_host = parsed.hostname or ""

    # =========================================================================
    #  Public entry point
    # =========================================================================

    def read(self, mitm_file: str) -> ReadResult:
        """
        Parse a .mitm flow file and produce endpoints.json + requests.json.

        Args:
            mitm_file : path to the .mitm file (e.g. traffic.mitm)

        Returns:
            ReadResult with all parsed data.
        """
        if not Path(mitm_file).exists():
            logger.error(f"[reader] File not found: {mitm_file}")
            return ReadResult(source_file=mitm_file, target_url=self.target_url)

        if Path(mitm_file).stat().st_size == 0:
            logger.error(f"[reader] File is empty: {mitm_file}")
            return ReadResult(source_file=mitm_file, target_url=self.target_url)

        result = ReadResult(source_file=mitm_file, target_url=self.target_url)

        try:
            import mitmproxy.io as mitm_io
        except ImportError:
            logger.error("[reader] mitmproxy not installed — pip install mitmproxy")
            return result

        logger.info(f"[reader] Reading {mitm_file}...")

        try:
            with open(mitm_file, "rb") as f:
                reader = mitm_io.FlowReader(f)
                for flow in reader.stream():
                    try:
                        self._process_flow(flow, result)
                    except Exception as e:
                        logger.debug(f"[reader] Flow parse error: {e}")
        except Exception as e:
            logger.error(f"[reader] Cannot read {mitm_file}: {e}")
            return result

        # Detect overall API type
        result.api_type = self._detect_api_type(result)

        logger.info(
            f"[reader] Parsed {result.total_flows} flows — "
            f"{result.api_flows} API | {result.gql_flows} GraphQL | "
            f"{len(result.endpoints)} unique endpoints"
        )

        # Save outputs
        self._save_endpoints(result)
        self._save_requests(result)

        return result

    # =========================================================================
    #  Flow processing
    # =========================================================================

    def _process_flow(self, flow, result: ReadResult) -> None:
        """Parse a single mitmproxy flow into a CapturedRequest."""
        # Only handle HTTP flows
        if not hasattr(flow, "request") or not hasattr(flow, "response"):
            return
        if flow.response is None:
            return

        result.total_flows += 1

        req  = flow.request
        resp = flow.response
        host = req.pretty_host.lower()
        path = req.path.split("?")[0]
        url  = req.pretty_url

        # Filter by target host if requested
        if self.filter_target and self.target_host and self.target_host not in host:
            return

        # Skip static assets
        ext = Path(path).suffix.lower()
        if ext in _STATIC_EXTENSIONS:
            return

        # Skip non-API content types (only for responses with content-type header)
        resp_ct = (resp.headers.get("content-type") or "").lower()
        if resp_ct and not any(ct in resp_ct for ct in ("json", "xml", "graphql", "text/plain")):
            if resp_ct.startswith(("text/html", "image/", "font/")):
                return

        result.api_flows += 1

        # ── Parse request body ────────────────────────────────────────────────
        req_body:     Optional[str] = None
        req_body_raw: Optional[str] = None
        try:
            raw = req.get_text(strict=False)
            if raw and raw.strip():
                req_body_raw = raw.strip()
                # Truncate large bodies
                if len(req_body_raw) > self.max_body_size:
                    req_body = req_body_raw[:self.max_body_size] + "... [truncated]"
                else:
                    req_body = req_body_raw
        except Exception:
            pass

        # ── Parse response body ───────────────────────────────────────────────
        resp_body: Optional[str] = None
        try:
            raw_resp = resp.get_text(strict=False)
            if raw_resp and raw_resp.strip():
                if len(raw_resp) > self.max_body_size:
                    resp_body = raw_resp[:self.max_body_size] + "... [truncated]"
                else:
                    resp_body = raw_resp
        except Exception:
            pass

        # ── Classify request type ─────────────────────────────────────────────
        api_type, gql_op, gql_query = self._classify_request(
            path      = path,
            method    = req.method,
            req_ct    = (req.headers.get("content-type") or "").lower(),
            body_raw  = req_body_raw,
        )

        # ── Update counters ───────────────────────────────────────────────────
        if api_type == "GraphQL":
            result.gql_flows += 1
            if gql_query and gql_query not in [q.get("query") for q in result.gql_queries]:
                entry = {"query": gql_query}
                if gql_op:
                    entry["operation"] = gql_op
                result.gql_queries.append(entry)
        elif api_type == "SOAP":
            result.soap_flows += 1

        # ── Track unique endpoints ────────────────────────────────────────────
        parsed    = urlparse(url)
        clean_url = f"{parsed.scheme}://{parsed.netloc}{path}"
        if clean_url not in result.endpoints:
            result.endpoints.append(clean_url)

        # ── Build request headers dict (filtered) ─────────────────────────────
        req_headers  = self._safe_headers(req.headers,  ["authorization", "cookie", "content-type", "accept", "origin", "referer"])
        resp_headers = self._safe_headers(resp.headers, ["content-type", "content-length", "set-cookie", "x-powered-by", "server"])

        # ── Create CapturedRequest ────────────────────────────────────────────
        captured = CapturedRequest(
            index            = result.total_flows,
            method           = req.method,
            url              = url,
            path             = path,
            status_code      = resp.status_code,
            request_headers  = req_headers,
            response_headers = resp_headers,
            request_body     = req_body,
            response_body    = resp_body,
            api_type         = api_type,
            gql_operation    = gql_op,
            gql_query        = gql_query,
        )
        result.requests.append(captured)

    # =========================================================================
    #  Classification
    # =========================================================================

    def _classify_request(
        self,
        path:     str,
        method:   str,
        req_ct:   str,
        body_raw: Optional[str],
    ) -> tuple[str, Optional[str], Optional[str]]:
        """
        Classify an HTTP request as GraphQL, SOAP, or REST.

        Returns:
            (api_type, gql_operation, gql_query)
            api_type      : "GraphQL" | "SOAP" | "REST"
            gql_operation : "query" | "mutation" | "subscription" | None
            gql_query     : the GraphQL query string | None
        """
        path_lower = path.lower()

        # ── SOAP detection ────────────────────────────────────────────────────
        if any(hint in path_lower for hint in _SOAP_HINTS):
            return "SOAP", None, None
        if "text/xml" in req_ct or "soap" in req_ct:
            return "SOAP", None, None

        # ── GraphQL detection ─────────────────────────────────────────────────

        # 1. Path-based detection (strongest signal)
        path_is_gql = any(hint in path_lower for hint in _GQL_PATH_HINTS)

        # 2. Body-based detection
        gql_op    = None
        gql_query = None

        if body_raw and "application/json" in req_ct:
            gql_op, gql_query = self._extract_gql_from_body(body_raw)

        # 3. GET with query param
        if not gql_query and method == "GET" and "query=" in path:
            try:
                from urllib.parse import parse_qs, urlparse as _up
                qs = parse_qs(_up(path).query)
                q  = (qs.get("query") or [""])[0]
                if q and ("{" in q or "mutation" in q.lower()):
                    gql_query = q
                    gql_op    = "mutation" if q.strip().lower().startswith("mutation") else "query"
                    path_is_gql = True
            except Exception:
                pass

        if path_is_gql or gql_query:
            return "GraphQL", gql_op, gql_query

        return "REST", None, None

    def _extract_gql_from_body(self, body: str) -> tuple[Optional[str], Optional[str]]:
        """
        Extract GraphQL operation type and query string from a JSON body.

        Handles:
          - Single query: {"query": "...", "variables": {...}}
          - Batch:        [{"query": "..."}, {"query": "..."}]

        Returns:
            (operation_type, query_string)
        """
        try:
            payload = json.loads(body)
        except Exception:
            return None, None

        # Handle batch — take first item
        if isinstance(payload, list):
            payload = payload[0] if payload else {}

        if not isinstance(payload, dict):
            return None, None

        query = payload.get("query", "").strip()
        if not query:
            return None, None

        # Determine operation type
        q_lower = query.lower().lstrip()
        if q_lower.startswith("mutation"):
            op = "mutation"
        elif q_lower.startswith("subscription"):
            op = "subscription"
        elif q_lower.startswith("query") or q_lower.startswith("{"):
            op = "query"
        else:
            return None, None

        return op, query

    # =========================================================================
    #  API type detection
    # =========================================================================

    def _detect_api_type(self, result: ReadResult) -> str:
        """
        Determine the overall API type from all captured flows.

        Priority: GraphQL > SOAP > REST
        Decision based on majority of API flows, not just path hints.
        """
        total = result.api_flows or 1

        if result.gql_flows / total > 0.3:   # >30% GraphQL flows → GraphQL API
            return "GraphQL"
        if result.soap_flows / total > 0.3:   # >30% SOAP flows    → SOAP API
            return "SOAP"
        return "REST"

    # =========================================================================
    #  Output
    # =========================================================================

    def _save_endpoints(self, result: ReadResult) -> None:
        """
        Save endpoints.json — URL list + api_type detection.
        Compatible with: apisec scan --input endpoints.json
        """
        # Sort endpoints: GraphQL first, then alphabetical
        gql_eps  = [e for e in result.endpoints if any(h in e.lower() for h in _GQL_PATH_HINTS)]
        rest_eps = [e for e in result.endpoints if e not in gql_eps]

        data: dict = {
            "target_url":  self.target_url,
            "api_type":    result.api_type,
            "confidence":  1.0,
            "score":       9 if result.api_type == "GraphQL" else 6,
            "reasons":     [f"Traffic analysis — {result.gql_flows} GraphQL operations detected"]
                           if result.api_type == "GraphQL" else
                           [f"Traffic analysis — {result.api_flows} API requests captured"],
            "endpoints":   gql_eps + rest_eps,
            "tech_stack":  [],
            "source":      "traffic_capture",
        }

        # Add schema stub for GraphQL with captured queries
        if result.api_type == "GraphQL" and result.gql_queries:
            data["schema"] = {
                "method":           "traffic_capture",
                "endpoint":         gql_eps[0] if gql_eps else self.target_url + "/graphql",
                "captured_queries": result.gql_queries,
                "queries":          [],
                "mutations":        [],
                "types":            [],
                "raw_introspection": None,
            }

        try:
            with open(self.endpoints_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            logger.info(f"[reader] endpoints.json → {self.endpoints_path}")
        except OSError as e:
            logger.error(f"[reader] Cannot write {self.endpoints_path}: {e}")

    def _save_requests(self, result: ReadResult) -> None:
        """
        Save requests.json — all captured requests with full HTTP details.
        Separate from endpoints.json to avoid pollution.

        Structure:
        {
          "source":      "traffic.mitm",
          "target_url":  "https://...",
          "api_type":    "GraphQL",
          "total":       31,
          "api_flows":   30,
          "gql_flows":   25,
          "summary": {
            "unique_endpoints": 6,
            "gql_operations":   25,
          },
          "requests": [ CapturedRequest.to_dict(), ... ]
        }
        """
        data = {
            "source":     result.source_file,
            "target_url": self.target_url,
            "api_type":   result.api_type,
            "total":      result.total_flows,
            "api_flows":  result.api_flows,
            "gql_flows":  result.gql_flows,
            "soap_flows": result.soap_flows,
            "summary": {
                "unique_endpoints": len(result.endpoints),
                "gql_operations":   result.gql_flows,
                "gql_unique":       len(result.gql_queries),
            },
            "requests": [r.to_dict() for r in result.requests],
        }

        try:
            with open(self.requests_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            logger.info(f"[reader] requests.json → {self.requests_path}")
        except OSError as e:
            logger.error(f"[reader] Cannot write {self.requests_path}: {e}")

    # =========================================================================
    #  Helpers
    # =========================================================================

    def _safe_headers(self, headers, keys: list[str]) -> dict:
        """Extract specific headers, lowercasing keys."""
        result = {}
        for k in keys:
            val = headers.get(k) or headers.get(k.title()) or headers.get(k.upper())
            if val:
                result[k] = val
        return result

    def print_summary(self, result: ReadResult) -> None:
        """Display a formatted summary of the read operation."""
        RESET  = "\033[0m"
        BLUE   = "\033[94m"
        GREEN  = "\033[92m"
        YELLOW = "\033[93m"
        BOLD   = "\033[1m"

        print(f"""
  {BLUE}╔══════════════════════════════════════════════════════╗
  ║           APISec — Traffic Reader                    ║
  ╚══════════════════════════════════════════════════════╝{RESET}

{result.summary}

  {BOLD}Requests breakdown:{RESET}""")

        # Show first 20 requests
        shown = 0
        for r in result.requests[:20]:
            if r.api_type == "GraphQL":
                op    = f"  {BLUE}[GQL:{r.gql_operation or 'query'}]{RESET}"
                query = f" {r.gql_query[:60]}..." if r.gql_query and len(r.gql_query) > 60 else f" {r.gql_query or ''}"
                print(f"  {GREEN}#{r.index:<3}{RESET} {r.method:<7} {r.path:<35} → {r.status_code}{op}{query}")
            elif r.api_type == "SOAP":
                print(f"  {GREEN}#{r.index:<3}{RESET} {r.method:<7} {r.path:<35} → {r.status_code}  {YELLOW}[SOAP]{RESET}")
            else:
                print(f"  {GREEN}#{r.index:<3}{RESET} {r.method:<7} {r.path:<35} → {r.status_code}")
            shown += 1

        if len(result.requests) > 20:
            print(f"  ... +{len(result.requests) - 20} more requests in {self.requests_path}")

        print(f"""
  {YELLOW}[→] Output files:{RESET}
      endpoints.json : {self.endpoints_path}
      requests.json  : {self.requests_path}

  {YELLOW}[→] Next steps:{RESET}
      apisec scan --input {self.endpoints_path} --tests all
  {BLUE}══════════════════════════════════════════════════════{RESET}
""")

# =============================================================================
#  TrafficCapture
# =============================================================================

class TrafficCapture:
    """
    Real-time HTTP/HTTPS traffic capture using mitmproxy.

    Runs a transparent proxy, captures all browser traffic targeting
    the specified API, and produces an endpoints.json file ready
    for the apisec scan pipeline.

    Args:
        target_url   : URL of the API to capture (e.g. http://localhost:8888)
        proxy_port   : Local port for the mitmproxy listener (default: 8080)
        proxy_host   : Local host for the mitmproxy listener (default: 127.0.0.1)
        output_path  : Path for the generated endpoints.json file
        traffic_file : Path for the raw mitmproxy flow file (.mitm)
        swagger_file : Path for the intermediate OpenAPI spec (.yaml)
    """

    def __init__(
        self,
        target_url:   str,
        proxy_port:   int = _DEFAULT_PROXY_PORT,
        proxy_host:   str = _DEFAULT_PROXY_HOST,
        output_path:  str = "endpoints.json",
        traffic_file: str = "traffic.mitm",
        swagger_file: str = "swagger_captured.yaml",
    ) -> None:
        self.target_url   = target_url.rstrip("/")
        self.proxy_port   = proxy_port
        self.proxy_host   = proxy_host
        self.output_path  = output_path
        self.traffic_file = traffic_file
        self.swagger_file = swagger_file

        parsed           = urlparse(self.target_url)
        self.target_host = parsed.hostname or ""

        self._master:  Optional[object]                    = None
        self._saver:   Optional[_FlowSaver]                = None
        self._display: Optional[_RealtimeDisplay]          = None
        self._loop:    Optional[asyncio.AbstractEventLoop] = None

    # =========================================================================
    #  Dependency checks
    # =========================================================================

    @staticmethod
    def check_dependencies() -> bool:
        """Verify that mitmproxy, mitmproxy2swagger and pyyaml are installed."""
        missing = []

        try:
            from mitmproxy import options  # noqa: F401
            import mitmproxy.io            # noqa: F401
        except ImportError:
            missing.append("mitmproxy")

        if not shutil.which("mitmproxy2swagger"):
            missing.append("mitmproxy2swagger")

        try:
            import yaml  # noqa: F401
        except ImportError:
            missing.append("pyyaml")

        if missing:
            logger.error(
                f"[capture] Missing dependencies: {', '.join(missing)}\n"
                f"          Install with: pip install {' '.join(missing)}"
            )
            return False

        return True

    # =========================================================================
    #  SSL Certificate management
    # =========================================================================

    def _ensure_cert_exists(self) -> bool:
        """
        Generate the mitmproxy CA certificate by starting mitmdump briefly.
        mitmproxy creates the certificate automatically on first startup.
        """
        if _MITM_CA_CERT_PEM.exists():
            return True

        logger.info("[capture] Generating mitmproxy CA certificate (first run)...")

        try:
            # Start mitmdump briefly — certificate is generated on startup
            proc = subprocess.Popen(
                [
                    "mitmdump",
                    "--listen-host", self.proxy_host,
                    "--listen-port", str(self.proxy_port + 1),  # port différent pour éviter conflit
                    "--quiet",
                ],
                stdout = subprocess.DEVNULL,
                stderr = subprocess.DEVNULL,
            )
            time.sleep(3.0)  # Attendre la génération du certificat
            proc.terminate()
            proc.wait()

        except FileNotFoundError:
            logger.error("[capture] mitmdump not found — is mitmproxy installed?")
            return False
        except Exception as e:
            logger.debug(f"[capture] Cert generation error: {e}")

        if _MITM_CA_CERT_PEM.exists():
            logger.info(f"[capture] CA certificate generated: {_MITM_CA_CERT_PEM}")
            return True

        logger.warning("[capture] CA certificate not found after generation attempt")
        return False

    def install_certificate(self) -> bool:
        """
        Install the mitmproxy CA certificate into the OS trust store.
        Supports: Windows, macOS, Linux (Debian/Ubuntu, Fedora/RHEL/Arch).
        """
        if not self._ensure_cert_exists():
            self._print_manual_cert_instructions()
            return False

        system = platform.system()
        logger.info(f"[capture] Installing CA certificate on {system}...")

        try:
            if system == "Windows":
                return self._install_cert_windows()
            elif system == "Darwin":
                return self._install_cert_macos()
            elif system == "Linux":
                return self._install_cert_linux()
            else:
                logger.warning(f"[capture] Unsupported OS: {system}")
                self._print_manual_cert_instructions()
                return False
        except Exception as e:
            logger.error(f"[capture] Certificate installation error: {e}")
            self._print_manual_cert_instructions()
            return False

    def _install_cert_windows(self) -> bool:
        """Install the certificate into the Windows user certificate store."""
        cert = str(_MITM_CA_CERT_CRT if _MITM_CA_CERT_CRT.exists() else _MITM_CA_CERT_PEM)
        result = subprocess.run(
            ["certutil", "-addstore", "-user", "ROOT", cert],
            capture_output=True, text=True,
        )
        if result.returncode == 0:
            logger.info("[capture] Certificate installed into Windows trust store ✓")
            return True
        logger.error(f"[capture] certutil failed: {result.stderr.strip()}")
        self._print_manual_cert_instructions()
        return False

    def _install_cert_macos(self) -> bool:
        """Install the certificate into the macOS system Keychain."""
        result = subprocess.run(
            [
                "sudo", "security", "add-trusted-cert",
                "-d", "-r", "trustRoot",
                "-k", "/Library/Keychains/System.keychain",
                str(_MITM_CA_CERT_PEM),
            ],
            capture_output=True, text=True,
        )
        if result.returncode == 0:
            logger.info("[capture] Certificate installed into macOS Keychain ✓")
            return True
        logger.error(f"[capture] security command failed: {result.stderr.strip()}")
        self._print_manual_cert_instructions()
        return False

    def _install_cert_linux(self) -> bool:
        """
        Install the mitmproxy CA certificate into the Linux system trust store.

        Supports:
            - Debian / Ubuntu  : update-ca-certificates
            - Fedora / RHEL    : update-ca-trust
            - Arch Linux       : trust anchor

        Uses subprocess with sudo for all privileged operations since
        APISec runs as a non-root user.
        """
        # ── Debian / Ubuntu ───────────────────────────────────────────────────
        if shutil.which("update-ca-certificates"):
            dest = "/usr/local/share/ca-certificates/mitmproxy-ca.crt"
            try:
                # Copy certificate with elevated privileges
                copy_result = subprocess.run(
                    ["sudo", "cp", str(_MITM_CA_CERT_PEM), dest],
                    capture_output = True,
                    text           = True,
                )
                if copy_result.returncode != 0:
                    logger.error(
                        f"[capture] Certificate copy failed: {copy_result.stderr.strip()}"
                    )
                    self._print_manual_cert_instructions()
                    return False

                # Update system trust store
                update_result = subprocess.run(
                    ["sudo", "update-ca-certificates"],
                    capture_output = True,
                    text           = True,
                )
                if update_result.returncode == 0:
                    logger.info("[capture] Certificate installed (Debian/Ubuntu) ✓")
                    return True
                else:
                    logger.error(
                        f"[capture] update-ca-certificates failed: "
                        f"{update_result.stderr.strip()}"
                    )

            except FileNotFoundError:
                logger.error("[capture] sudo not found — cannot install certificate")
            except Exception as e:
                logger.debug(f"[capture] Debian cert install error: {e}")

        # ── Fedora / CentOS / RHEL ────────────────────────────────────────────
        elif shutil.which("update-ca-trust"):
            dest = "/etc/pki/ca-trust/source/anchors/mitmproxy-ca.crt"
            try:
                copy_result = subprocess.run(
                    ["sudo", "cp", str(_MITM_CA_CERT_PEM), dest],
                    capture_output = True,
                    text           = True,
                )
                if copy_result.returncode != 0:
                    logger.error(
                        f"[capture] Certificate copy failed: {copy_result.stderr.strip()}"
                    )
                    self._print_manual_cert_instructions()
                    return False

                update_result = subprocess.run(
                    ["sudo", "update-ca-trust", "extract"],
                    capture_output = True,
                    text           = True,
                )
                if update_result.returncode == 0:
                    logger.info("[capture] Certificate installed (Fedora/RHEL) ✓")
                    return True
                else:
                    logger.error(
                        f"[capture] update-ca-trust failed: "
                        f"{update_result.stderr.strip()}"
                    )

            except FileNotFoundError:
                logger.error("[capture] sudo not found — cannot install certificate")
            except Exception as e:
                logger.debug(f"[capture] RHEL cert install error: {e}")

        # ── Arch Linux ────────────────────────────────────────────────────────
        elif shutil.which("trust"):
            try:
                result = subprocess.run(
                    ["sudo", "trust", "anchor", "--store", str(_MITM_CA_CERT_PEM)],
                    capture_output = True,
                    text           = True,
                )
                if result.returncode == 0:
                    logger.info("[capture] Certificate installed (Arch Linux) ✓")
                    return True
                else:
                    logger.error(
                        f"[capture] trust anchor failed: {result.stderr.strip()}"
                    )
            except Exception as e:
                logger.debug(f"[capture] Arch cert install error: {e}")

        else:
            logger.warning(
                "[capture] No supported certificate manager found "
                "(update-ca-certificates / update-ca-trust / trust)"
            )

        self._print_manual_cert_instructions()
        return False

    def _print_manual_cert_instructions(self) -> None:
        """Print manual certificate installation instructions."""
        print(
            f"\n  \033[93m[!] Manual certificate installation required:\033[0m\n"
            f"      Certificate : {_MITM_CA_CERT_PEM}\n\n"
            f"      Windows : certutil -addstore -user ROOT \"{_MITM_CA_CERT_CRT}\"\n"
            f"      macOS   : sudo security add-trusted-cert -d -r trustRoot \\\n"
            f"                  -k /Library/Keychains/System.keychain \"{_MITM_CA_CERT_PEM}\"\n"
            f"      Linux   : sudo cp \"{_MITM_CA_CERT_PEM}\" "
            f"/usr/local/share/ca-certificates/mitmproxy-ca.crt\n"
            f"                sudo update-ca-certificates\n\n"
            f"      Or visit \033[92mhttp://mitm.it\033[0m while the proxy is running.\n"
        )

    # =========================================================================
    #  Proxy — start / stop
    # =========================================================================

    def _start_proxy(self) -> None:
        """
        Start the mitmproxy DumpMaster in a background daemon thread.
        Registers the _FlowSaver and _RealtimeDisplay addons.
        """
        from mitmproxy import options as mitm_options
        from mitmproxy.tools import dump as mitm_dump

        self._saver   = _FlowSaver(self.traffic_file)
        self._display = _RealtimeDisplay(self.target_host)

        async def _run() -> None:
            opts = mitm_options.Options(
                listen_host  = self.proxy_host,
                listen_port  = self.proxy_port,
                ssl_insecure = False,
            )
            self._master = mitm_dump.DumpMaster(
                opts,
                with_termlog = False,
                with_dumper  = False,
            )
            self._master.addons.add(self._saver)
            self._master.addons.add(self._display)

            try:
                await self._master.run()
            except Exception:
                pass

        self._loop = asyncio.new_event_loop()

        def _thread() -> None:
            asyncio.set_event_loop(self._loop)
            self._loop.run_until_complete(_run())

        thread = threading.Thread(target=_thread, daemon=True, name="mitmproxy")
        thread.start()

        # Wait for the proxy to be ready before returning
        time.sleep(2.0)
        logger.debug(f"[capture] Proxy ready on {self.proxy_host}:{self.proxy_port}")

    def _stop_proxy(self) -> None:
        """Gracefully shut down the mitmproxy DumpMaster and flush flows."""
        if self._master:
            try:
                self._master.shutdown()
                time.sleep(1.0)
            except Exception as e:
                logger.debug(f"[capture] Proxy shutdown: {e}")

    # =========================================================================
    #  Swagger generation
    # =========================================================================

    def _generate_swagger(self) -> bool:
        """
        Convert traffic.mitm → swagger_captured.yaml using mitmproxy2swagger.

        Two-pass approach:
        Pass 1 — generate initial spec (unknown paths marked 'ignore: true')
        Pass 2 — remove ignore flags then regenerate with all paths visible
        """
        if not Path(self.traffic_file).exists():
            logger.error(f"[capture] Traffic file not found: {self.traffic_file}")
            return False

        if Path(self.traffic_file).stat().st_size == 0:
            logger.error("[capture] Traffic file is empty — no flows were captured")
            return False

        logger.info("[capture] Generating OpenAPI spec from captured traffic...")

        # Force UTF-8 encoding to avoid Windows cp1252 issues
        env = {**os.environ, "PYTHONIOENCODING": "utf-8", "PYTHONUTF8": "1"}

        cmd = [
            "mitmproxy2swagger",
            "--input",      self.traffic_file,
            "--output",     self.swagger_file,
            "--api-prefix", self.target_url,
            "--format",     "flow",
        ]

        # Pass 1 — generate initial spec
        result = subprocess.run(
            cmd,
            capture_output = True,
            text           = True,
            encoding       = "utf-8",
            errors         = "replace",
            env            = env,
        )
        if result.returncode != 0:
            logger.error(
                f"[capture] mitmproxy2swagger pass 1 failed:\n{result.stderr.strip()}"
            )
            return False

        if not Path(self.swagger_file).exists():
            logger.error("[capture] Swagger file was not created by mitmproxy2swagger")
            return False

        # Pass 2 — remove 'ignore: true' flags
        self._remove_ignore_flags()

        # Pass 3 — regenerate with cleaned spec to apply ignore flag removal
        result = subprocess.run(
            cmd,
            capture_output = True,
            text           = True,
            encoding       = "utf-8",
            errors         = "replace",
            env            = env,
        )
        if result.returncode != 0:
            logger.warning(
                f"[capture] mitmproxy2swagger pass 2 warning:\n{result.stderr.strip()}"
            )

        logger.info(f"[capture] OpenAPI spec ready: {self.swagger_file}")
        return True

    def _remove_ignore_flags(self) -> None:
        """
        mitmproxy2swagger places captured paths in x-path-templates with 'ignore:' prefix.
        Remove those prefixes so paths are promoted to real endpoints on the next pass.
        """
        if not Path(self.swagger_file).exists():
            return
        try:
            with open(self.swagger_file, "r", encoding="utf-8") as f:
                content = f.read()

            # Remove 'ignore:' prefix from x-path-templates entries
            content = content.replace("- ignore:/", "- /")

            # Also handle standard ignore flags
            content = content.replace("ignore: true",   "ignore: false")
            content = content.replace("x-ignore: true", "x-ignore: false")

            with open(self.swagger_file, "w", encoding="utf-8") as f:
                f.write(content)

            logger.debug("[capture] Removed ignore flags from swagger spec")
        except Exception as e:
            logger.warning(f"[capture] Could not remove ignore flags: {e}")
            
    # =========================================================================
    #  Endpoint extraction
    # =========================================================================

    def _parse_swagger(self) -> list[str]:
        """
        Parse the generated OpenAPI spec and extract unique endpoint URLs.
        Filters out static assets, ignored paths, and duplicate entries.
        """
        import yaml

        if not Path(self.swagger_file).exists():
            logger.error(f"[capture] Swagger file not found: {self.swagger_file}")
            return []

        try:
            with open(self.swagger_file, "r", encoding="utf-8") as f:
                spec = yaml.safe_load(f)
        except Exception as e:
            logger.error(f"[capture] Failed to parse swagger file: {e}")
            return []

        if not spec or not isinstance(spec, dict):
            logger.error("[capture] Invalid or empty swagger spec")
            return []

        paths     = spec.get("paths", {})
        base      = self.target_url.rstrip("/")
        endpoints: list[str] = []
        seen:      set[str]  = set()

        for path, methods in paths.items():
            if not isinstance(methods, dict):
                continue

            # Skip static assets
            if Path(path).suffix.lower() in _IGNORE_EXTENSIONS:
                continue

            if path in _IGNORE_PATHS:
                continue

            url = f"{base}{path}"
            if url not in seen:
                seen.add(url)
                endpoints.append(url)
                logger.debug(f"    [capture] endpoint: {url}")

        logger.info(
            f"[capture] Extracted {len(endpoints)} unique endpoint(s) from spec"
        )
        return endpoints

    # =========================================================================
    #  Output
    # =========================================================================

    def _save_endpoints(self, result: "CaptureResult") -> None:
        """
        Save captured endpoints in apisec-compatible JSON format.

        Automatically detects GraphQL if:
          - Any endpoint URL contains /graphql or /gql
          - Any GraphQL queries were captured
        """
        # Auto-detect API type
        gql_endpoints = [e for e in result.endpoints if "graphql" in e.lower() or "/gql" in e.lower()]
        is_graphql    = bool(gql_endpoints or result.captured_queries)
        api_type      = "GraphQL" if is_graphql else "REST"

        data = result.to_dict()
        data["api_type"] = api_type

        if is_graphql:
            logger.info(
                f"[capture] GraphQL detected — {len(result.captured_queries)} "
                f"unique query/mutation(s) captured"
            )
            # Ensure the GraphQL endpoint is at the top of the list
            sorted_endpoints = gql_endpoints + [e for e in result.endpoints if e not in gql_endpoints]
            data["endpoints"] = sorted_endpoints

        try:
            with open(self.output_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            logger.info(f"[capture] Endpoints saved to: {self.output_path}")
        except OSError as e:
            logger.error(f"[capture] Cannot write output file: {e}")

    # =========================================================================
    #  User interface helpers
    # =========================================================================

    def _print_banner(self) -> None:
        """Display proxy configuration instructions to the user."""
        print(f"""
  \033[94m╔══════════════════════════════════════════════════════╗
  ║           APISec — Traffic Capture Mode              ║
  ╚══════════════════════════════════════════════════════╝\033[0m

  \033[93m[→] Configure your browser proxy:\033[0m

      Address  : \033[92m{self.proxy_host}\033[0m
      Port     : \033[92m{self.proxy_port}\033[0m

  \033[93m[→] Navigate on:\033[0m \033[92m{self.target_url}\033[0m
      Login, browse, and use all features of the application.
      Every unique API endpoint you visit will be captured.

  \033[93m[→] Captured requests appear below in real time.\033[0m
  \033[93m[→] Press \033[91mENTER\033[93m when you have finished navigating.\033[0m
  \033[94m══════════════════════════════════════════════════════\033[0m
""")

    def _print_summary(self, result: CaptureResult) -> None:
        """Display a summary of the capture session."""
        gql_line = ""
        if result.captured_queries:
            gql_line = f"\n      GraphQL operations    : {len(result.captured_queries)}"

        print(f"""
  \033[94m══════════════════════════════════════════════════════\033[0m
  \033[92m[✓] Capture complete\033[0m

      Total requests captured  : {result.flow_count}
      API requests captured    : {result.api_flows}
      Unique endpoints found   : {len(result.endpoints)}{gql_line}
      API type detected        : {result.api_type if hasattr(result, "api_type") else "REST"}
      Output file              : {self.output_path}

  \033[93m[→] Run scan:\033[0m
      apisec scan --input {self.output_path} --tests all
  \033[94m══════════════════════════════════════════════════════\033[0m
""")

    # =========================================================================
    #  run() — Main orchestrator
    # =========================================================================

    def run(self) -> CaptureResult:
        """
        Execute the full capture pipeline:

          1. Check dependencies (mitmproxy, mitmproxy2swagger, pyyaml)
          2. Install SSL/TLS CA certificate into OS trust store
          3. Start mitmproxy transparent proxy on configured port
          4. Display instructions and wait for user to navigate
          5. Stop proxy and flush captured flows to traffic.mitm
          6. Generate OpenAPI spec via mitmproxy2swagger (2 passes)
          7. Parse and filter endpoints from OpenAPI spec
          8. Save endpoints.json in apisec-compatible format

        Returns:
            CaptureResult — structured result with endpoints and session stats.
        """
        result = CaptureResult(target_url=self.target_url)

        # ── Step 1: Dependency check ──────────────────────────────────────────
        logger.info("[capture] Checking dependencies...")
        if not self.check_dependencies():
            return result

        # ── Step 2: SSL certificate ───────────────────────────────────────────
        logger.info("[capture] Installing SSL certificate...")
        cert_ok = self.install_certificate()
        if not cert_ok:
            logger.warning(
                "[capture] SSL certificate not installed — "
                "HTTPS traffic may not be captured. HTTP will still work."
            )

        # ── Step 3: Start proxy ───────────────────────────────────────────────
        logger.info(
            f"[capture] Starting proxy on {self.proxy_host}:{self.proxy_port}..."
        )
        try:
            self._start_proxy()
        except Exception as e:
            logger.error(f"[capture] Failed to start proxy: {e}")
            return result

        # ── Step 4: User navigation ───────────────────────────────────────────
        self._print_banner()

        try:
            input()
        except KeyboardInterrupt:
            print("\n  \033[91m[!] Capture interrupted by user.\033[0m")

        # ── Step 5: Stop proxy ────────────────────────────────────────────────
        print("\n  \033[93m[→] Stopping proxy — saving flows...\033[0m")
        self._stop_proxy()

        result.flow_count   = self._display.flow_count if self._display else 0
        result.api_flows    = self._display.api_flows  if self._display else 0
        result.traffic_file = self.traffic_file

        if result.flow_count == 0:
            logger.warning(
                "[capture] No traffic captured.\n"
                f"          Verify your browser proxy is set to "
                f"{self.proxy_host}:{self.proxy_port}"
            )
            return result

        logger.info(
            f"[capture] {result.flow_count} request(s) captured "
            f"({result.api_flows} targeting {self.target_url})"
        )

        # ── Step 6: Generate swagger ──────────────────────────────────────────
        if not self._generate_swagger():
            logger.error("[capture] Failed to generate OpenAPI spec")
            return result

        result.swagger_file = self.swagger_file

        # ── Step 7: Parse endpoints ───────────────────────────────────────────
        result.endpoints = self._parse_swagger()

        if not result.endpoints:
            logger.warning(
                "[capture] No endpoints extracted.\n"
                "          Try navigating more pages and re-running the capture."
            )
            return result

        # ── Step 8: Save endpoints.json ───────────────────────────────────────
        # Collect captured GraphQL queries from the display addon
        if self._display and hasattr(self._display, "gql_queries"):
            result.captured_queries = self._display.gql_queries
            if result.captured_queries:
                logger.info(
                    f"[capture] {len(result.captured_queries)} unique GraphQL "
                    f"operation(s) captured"
                )

        self._save_endpoints(result)

        # ── Summary ───────────────────────────────────────────────────────────
        self._print_summary(result)

        return result