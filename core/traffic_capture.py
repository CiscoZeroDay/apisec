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
#  TrafficReader — Read and display .mitm flow files
# =============================================================================
#
#  Responsibilities:
#    - Parse mitmproxy .mitm flow files
#    - Separate GraphQL operations from REST/UI traffic
#    - Display a clean, auditor-friendly summary
#    - Save two separate output files:
#        endpoints.json  → unique API endpoints (for apisec scan)
#        requests.json   → full HTTP details with bodies
#
#  NOT responsible for:
#    - API type detection (that is discovery's job)
#    - Vulnerability scanning
#    - Schema analysis
# =============================================================================

# GraphQL path signals
_GQL_PATH_HINTS = ("graphql", "/gql", "graphiql")

# SOAP signals
_SOAP_CT_HINTS  = ("text/xml", "application/soap+xml")
_SOAP_PATH_HINTS = (".wsdl", "soap", "/service")

# Static asset extensions — filtered out of display
_STATIC_EXTENSIONS = {
    ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg",
    ".ico", ".woff", ".woff2", ".ttf", ".eot", ".map",
    ".html", ".htm", ".pdf", ".zip", ".gz",
}

# Paths that are clearly UI / frontend — not API
_UI_PATH_HINTS = (
    "labheader", "favicon", "static", "assets",
    "robots.txt", "sitemap", "manifest",
)


@dataclass
class CapturedRequest:
    """Single captured HTTP request with its response."""
    index:            int
    method:           str
    url:              str
    path:             str
    status_code:      int
    request_headers:  dict
    response_headers: dict
    request_body:     Optional[str] = None
    response_body:    Optional[str] = None
    category:         str           = "REST"   # "GraphQL" | "SOAP" | "REST" | "UI"
    gql_operation:    Optional[str] = None     # "query" | "mutation" | "subscription"
    gql_query:        Optional[str] = None     # full GraphQL query string

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
        if self.category != "REST":
            d["category"]      = self.category
        if self.gql_operation:
            d["gql_operation"] = self.gql_operation
        if self.gql_query:
            d["gql_query"]     = self.gql_query
        return d


@dataclass
class ReadResult:
    """Result of parsing a .mitm flow file."""
    source_file:   str
    target_url:    str
    requests:      list = field(default_factory=list)   # list[CapturedRequest]
    total_flows:   int  = 0
    skipped_flows: int  = 0


class TrafficReader:
    """
    Reads a mitmproxy .mitm flow file and produces two output files.

    endpoints.json — unique API endpoint URLs
                     (compatible with: apisec scan --input endpoints.json)

    requests.json  — all captured requests with full HTTP details,
                     bodies, GraphQL queries, SOAP envelopes

    Note: API type detection is NOT done here.
          Run `apisec discovery` after capture for proper detection.

    Args:
        target_url       : base URL of the target (used for filtering)
        endpoints_path   : output path for endpoints.json
        requests_path    : output path for requests.json
        max_body_size    : max body size to store in bytes (default: 8KB)
        filter_target    : only process flows targeting target_url host
    """

    def __init__(
        self,
        target_url:     str,
        endpoints_path: str  = "endpoints.json",
        requests_path:  str  = "requests.json",
        max_body_size:  int  = 8_192,
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
        Parse a .mitm flow file.

        Args:
            mitm_file : path to the .mitm file

        Returns:
            ReadResult containing all parsed requests.
        """
        result = ReadResult(source_file=mitm_file, target_url=self.target_url)

        if not Path(mitm_file).exists():
            logger.error(f"[reader] File not found: {mitm_file}")
            return result

        if Path(mitm_file).stat().st_size == 0:
            logger.error(f"[reader] File is empty: {mitm_file}")
            return result

        try:
            import mitmproxy.io as mitm_io
        except ImportError:
            logger.error("[reader] mitmproxy not installed — pip install mitmproxy")
            return result

        logger.info(f"[reader] Parsing {mitm_file}...")

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

        api_count = sum(1 for r in result.requests if r.category != "UI")
        gql_count = sum(1 for r in result.requests if r.category == "GraphQL")
        logger.info(
            f"[reader] {result.total_flows} flows — "
            f"{api_count} API | {gql_count} GraphQL | "
            f"{result.skipped_flows} skipped"
        )

        self._save_endpoints(result)
        self._save_requests(result)

        return result

    # =========================================================================
    #  Flow processing
    # =========================================================================

    def _process_flow(self, flow, result: ReadResult) -> None:
        """Parse one mitmproxy flow into a CapturedRequest."""
        if not hasattr(flow, "request") or flow.response is None:
            return

        result.total_flows += 1
        req  = flow.request
        resp = flow.response
        host = req.pretty_host.lower()
        path = req.path.split("?")[0]
        url  = req.pretty_url

        # Filter by target host
        if self.filter_target and self.target_host and self.target_host not in host:
            result.skipped_flows += 1
            return

        # Skip static assets
        if Path(path).suffix.lower() in _STATIC_EXTENSIONS:
            result.skipped_flows += 1
            return

        # Parse bodies
        req_body  = self._read_body(req,  is_request=True)
        resp_body = self._read_body(resp, is_request=False)

        # Classify
        category, gql_op, gql_query = self._classify(
            path    = path,
            method  = req.method,
            req_ct  = (req.headers.get("content-type") or "").lower(),
            body    = req_body,
        )

        # Select important headers only
        req_headers  = self._pick_headers(req.headers,  [
            "authorization", "cookie", "content-type",
            "accept", "origin", "referer", "x-csrf-token",
        ])
        resp_headers = self._pick_headers(resp.headers, [
            "content-type", "set-cookie", "x-powered-by",
            "server", "www-authenticate",
        ])

        result.requests.append(CapturedRequest(
            index            = result.total_flows,
            method           = req.method,
            url              = url,
            path             = path,
            status_code      = resp.status_code,
            request_headers  = req_headers,
            response_headers = resp_headers,
            request_body     = req_body,
            response_body    = resp_body,
            category         = category,
            gql_operation    = gql_op,
            gql_query        = gql_query,
        ))

    # =========================================================================
    #  Classification — path + content-type + body
    # =========================================================================

    def _classify(
        self,
        path:   str,
        method: str,
        req_ct: str,
        body:   Optional[str],
    ) -> tuple[str, Optional[str], Optional[str]]:
        """
        Classify a request into: GraphQL | SOAP | REST | UI

        Returns (category, gql_operation, gql_query)
        """
        path_lower = path.lower()

        # UI / frontend — not API traffic
        if any(hint in path_lower for hint in _UI_PATH_HINTS):
            return "UI", None, None

        # SOAP
        if any(hint in req_ct for hint in _SOAP_CT_HINTS):
            return "SOAP", None, None
        if any(hint in path_lower for hint in _SOAP_PATH_HINTS):
            return "SOAP", None, None

        # GraphQL — path signal
        path_is_gql = any(hint in path_lower for hint in _GQL_PATH_HINTS)

        # GraphQL — body signal (POST with JSON body containing "query" key)
        gql_op    = None
        gql_query = None

        if body and "application/json" in req_ct:
            gql_op, gql_query = self._parse_gql_body(body)

        # GraphQL — GET with ?query= param
        if not gql_query and method == "GET" and "query=" in req.path if hasattr(self, "_current_req") else False:
            pass  # handled separately if needed

        if path_is_gql or gql_query:
            return "GraphQL", gql_op, gql_query

        return "REST", None, None

    def _parse_gql_body(self, body: str) -> tuple[Optional[str], Optional[str]]:
        """Extract (operation_type, query_string) from a GraphQL JSON body."""
        try:
            payload = json.loads(body)
        except Exception:
            return None, None

        # Handle batch — use first item
        if isinstance(payload, list):
            payload = payload[0] if payload else {}

        if not isinstance(payload, dict):
            return None, None

        query = payload.get("query", "").strip()
        if not query:
            return None, None

        q = query.lower().lstrip()
        if q.startswith("mutation"):
            return "mutation", query
        if q.startswith("subscription"):
            return "subscription", query
        if q.startswith(("query", "{")):
            return "query", query

        return None, None

    # =========================================================================
    #  Output files
    # =========================================================================

    def _save_endpoints(self, result: ReadResult) -> None:
        """
        Save endpoints.json with unique API endpoint URLs.
        UI requests are excluded. No api_type detection — use apisec discovery.
        """
        seen:      set[str]  = set()
        endpoints: list[str] = []

        for r in result.requests:
            if r.category == "UI":
                continue
            parsed    = urlparse(r.url)
            clean_url = f"{parsed.scheme}://{parsed.netloc}{r.path}"
            if clean_url not in seen:
                seen.add(clean_url)
                endpoints.append(clean_url)

        data = {
            "target_url":  self.target_url,
            "api_type":    "Unknown",
            "confidence":  0.0,
            "endpoints":   endpoints,
            "source":      "traffic_capture",
            "note":        "Run apisec discovery --url TARGET to detect API type properly.",
        }

        # If GraphQL queries were captured, add them as hints
        gql_queries = [
            {"query": r.gql_query, "operation": r.gql_operation}
            for r in result.requests
            if r.category == "GraphQL" and r.gql_query
        ]
        # Deduplicate
        seen_q: set[str] = set()
        unique_gql: list[dict] = []
        for q in gql_queries:
            if q["query"] not in seen_q:
                seen_q.add(q["query"])
                unique_gql.append(q)

        if unique_gql:
            data["captured_queries"] = unique_gql
            data["note"] = (
                f"{len(unique_gql)} unique GraphQL operation(s) captured. "
                "Run apisec discovery to fetch the full schema."
            )

        try:
            with open(self.endpoints_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            logger.info(f"[reader] endpoints.json → {self.endpoints_path}")
        except OSError as e:
            logger.error(f"[reader] Cannot write {self.endpoints_path}: {e}")

    def _save_requests(self, result: ReadResult) -> None:
        """
        Save requests.json with full HTTP details for all captured requests.
        Separated from endpoints.json to keep it clean.
        """
        api_requests = [r for r in result.requests if r.category != "UI"]

        data = {
            "source":        result.source_file,
            "target_url":    self.target_url,
            "total_flows":   result.total_flows,
            "api_requests":  len(api_requests),
            "gql_requests":  sum(1 for r in api_requests if r.category == "GraphQL"),
            "soap_requests": sum(1 for r in api_requests if r.category == "SOAP"),
            "rest_requests": sum(1 for r in api_requests if r.category == "REST"),
            "requests":      [r.to_dict() for r in api_requests],
        }

        try:
            with open(self.requests_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            logger.info(f"[reader] requests.json → {self.requests_path}")
        except OSError as e:
            logger.error(f"[reader] Cannot write {self.requests_path}: {e}")

    # =========================================================================
    #  Display — auditor-friendly summary
    # =========================================================================

    def print_summary(self, result: ReadResult) -> None:
        """
        Print a clean, auditor-friendly summary of the captured traffic.

        Format:
          - Header with stats
          - GraphQL Operations section (grouped by operation name + type)
          - REST/SOAP Endpoints section (grouped by path)
          - Output files
          - Next steps
        """
        RESET  = "\033[0m"
        BOLD   = "\033[1m"
        BLUE   = "\033[94m"
        GREEN  = "\033[92m"
        YELLOW = "\033[93m"
        RED    = "\033[91m"
        GRAY   = "\033[90m"
        CYAN   = "\033[96m"

        # Sensitive keyword hints for mutations
        SENSITIVE_HINTS = (
            "login", "auth", "password", "token", "delete",
            "admin", "email", "reset", "register", "signup",
        )

        api_reqs  = [r for r in result.requests if r.category != "UI"]
        gql_reqs  = [r for r in result.requests if r.category == "GraphQL"]
        rest_reqs = [r for r in result.requests if r.category == "REST"]
        soap_reqs = [r for r in result.requests if r.category == "SOAP"]

        fname     = Path(result.source_file).name
        bar       = "═" * 66

        print(f"""
{BLUE}╔{bar}╗
║{'':^66}║
║{'APISec  ·  Traffic Analyzer':^66}║
║{'':^66}║
║  {CYAN}Source{RESET}{BLUE}  :  {RESET}{fname:<57}{BLUE}║
║  {CYAN}Target{RESET}{BLUE}  :  {RESET}{result.target_url[:57]:<57}{BLUE}║
║{'':^66}║
╠{bar}╣
║{'':^66}║
║  {CYAN}Total flows   {RESET}{BLUE}:{RESET}  {BOLD}{result.total_flows:<6}{RESET}   {GRAY}({result.skipped_flows} filtered — UI/assets){RESET:<18}{BLUE}║
║  {CYAN}API requests  {RESET}{BLUE}:{RESET}  {BOLD}{len(api_reqs):<6}{RESET}{BLUE}{'':>33}║
║  {CYAN}GraphQL ops   {RESET}{BLUE}:{RESET}  {BOLD}{GREEN}{len(gql_reqs):<6}{RESET}{BLUE}{'':>33}║
║{'':^66}║
╚{bar}╝{RESET}
""")

        # ── GraphQL Operations ────────────────────────────────────────────────
        if gql_reqs:
            print(f"  {BOLD}{BLUE}{'─'*64}{RESET}")
            print(f"  {BOLD}{BLUE}GRAPHQL OPERATIONS ({len(gql_reqs)}){RESET}")
            print(f"  {BOLD}{BLUE}{'─'*64}{RESET}\n")

            # Group by (operation_name, operation_type)
            from collections import defaultdict
            gql_groups: dict = defaultdict(list)

            for r in gql_reqs:
                # Extract operation name from query
                op_name = self._extract_gql_op_name(r.gql_query or "")
                key     = (r.gql_operation or "query", op_name)
                gql_groups[key].append(r.index)

            for (op_type, op_name), indices in sorted(gql_groups.items(), key=lambda x: x[0][0]):
                count     = len(indices)
                idx_str   = ", ".join(f"#{i}" for i in indices[:5])
                if len(indices) > 5:
                    idx_str += f" (+{len(indices)-5} more)"

                # Color by operation type
                if op_type == "mutation":
                    type_color = RED
                elif op_type == "subscription":
                    type_color = CYAN
                else:
                    type_color = GREEN

                type_badge = f"[{type_color}{op_type:<12}{RESET}]"

                # Flag sensitive operations
                is_sensitive = any(h in op_name.lower() for h in SENSITIVE_HINTS)
                flag = f"  {YELLOW}⚠ sensitive{RESET}" if is_sensitive else ""

                print(
                    f"  {type_badge}  {BOLD}{op_name:<30}{RESET}  "
                    f"{GRAY}{idx_str:<30}{RESET}  "
                    f"{GRAY}({count}x){RESET}{flag}"
                )

            print()

        # ── REST Endpoints ────────────────────────────────────────────────────
        if rest_reqs:
            print(f"  {BOLD}{'─'*64}{RESET}")
            print(f"  {BOLD}REST / OTHER ENDPOINTS ({len(rest_reqs)}){RESET}")
            print(f"  {BOLD}{'─'*64}{RESET}\n")

            # Group by (method, path)
            from collections import defaultdict
            rest_groups: dict = defaultdict(list)
            for r in rest_reqs:
                rest_groups[(r.method, r.path)].append((r.index, r.status_code))

            for (method, path), entries in sorted(rest_groups.items(), key=lambda x: x[0][1]):
                count   = len(entries)
                idx_str = ", ".join(f"#{i}" for i, _ in entries[:4])
                if count > 4:
                    idx_str += f" (+{count-4} more)"
                statuses = list({s for _, s in entries})
                status_str = ", ".join(str(s) for s in sorted(statuses))

                # Color method
                m_color = GREEN if method == "GET" else YELLOW if method == "POST" else CYAN
                print(
                    f"  {m_color}{method:<7}{RESET}  {path:<40}  "
                    f"{GRAY}{idx_str:<25}  ({count}x)  [{status_str}]{RESET}"
                )

            print()

        # ── SOAP ──────────────────────────────────────────────────────────────
        if soap_reqs:
            print(f"  {BOLD}{'─'*64}{RESET}")
            print(f"  {BOLD}SOAP OPERATIONS ({len(soap_reqs)}){RESET}")
            print(f"  {BOLD}{'─'*64}{RESET}\n")
            for r in soap_reqs:
                print(f"  {YELLOW}[SOAP]{RESET}  {r.method}  {r.path}  → {r.status_code}")
            print()

        # ── Output files + next steps ─────────────────────────────────────────
        print(f"  {BOLD}{YELLOW}{'─'*64}{RESET}")
        print(f"  {BOLD}Output files{RESET}")
        print(f"  {BOLD}{YELLOW}{'─'*64}{RESET}\n")
        print(f"  {GREEN}endpoints.json{RESET}  →  {self.endpoints_path}")
        print(f"  {GREEN}requests.json{RESET}   →  {self.requests_path}\n")

        print(f"  {BOLD}{YELLOW}Next steps:{RESET}")
        print(f"  {YELLOW}1.{RESET} Run discovery to detect API type and fetch schema:")
        print(f"     {GRAY}apisec discovery --url {self.target_url} --wordlist wordlists/api-endpoints.txt{RESET}")
        print(f"  {YELLOW}2.{RESET} Or scan directly if you know the API type:")
        print(f"     {GRAY}apisec scan --input {self.endpoints_path} --tests all{RESET}")
        print(f"\n  {BLUE}{'═'*64}{RESET}\n")

    # =========================================================================
    #  Helpers
    # =========================================================================

    def _read_body(self, msg, is_request: bool) -> Optional[str]:
        """Read and truncate a request/response body."""
        try:
            raw = msg.get_text(strict=False)
            if not raw or not raw.strip():
                return None
            raw = raw.strip()
            if len(raw) > self.max_body_size:
                return raw[:self.max_body_size] + " ...[truncated]"
            return raw
        except Exception:
            return None

    def _pick_headers(self, headers, keys: list[str]) -> dict:
        """Extract specific headers from a mitmproxy headers object."""
        result = {}
        for k in keys:
            val = (
                headers.get(k)
                or headers.get(k.title())
                or headers.get(k.upper())
            )
            if val:
                result[k] = val
        return result

    def _extract_gql_op_name(self, query: str) -> str:
        """
        Extract the operation name from a GraphQL query string.

        Examples:
          "query getBlogPost($id: Int!) { ... }" → "getBlogPost"
          "{ getAllBlogPosts { ... } }"           → "getAllBlogPosts"
          "mutation login($input: LoginInput!) {" → "login"
        """
        if not query:
            return "anonymous"

        q = query.strip()

        # Named operation: query/mutation NAME(...) { or query/mutation NAME {
        import re
        m = re.match(
            r"(?:query|mutation|subscription)\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*[({]",
            q, re.IGNORECASE
        )
        if m:
            return m.group(1)

        # Anonymous shorthand: { fieldName(...) { } }
        # or mutation { fieldName(...) { } }
        m = re.match(r"(?:query|mutation|subscription)?\s*\{\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*[({]", q, re.IGNORECASE)
        if m:
            return m.group(1)

        # First word after operation keyword
        tokens = q.split()
        if len(tokens) >= 2 and tokens[0].lower() in ("query", "mutation", "subscription"):
            name = tokens[1].split("(")[0].split("{")[0].strip()
            if name:
                return name

        return "anonymous"



    def print_full_requests(self, result: ReadResult) -> None:
        """
        Print complete HTTP request/response details for every captured flow.

        Displays:
          - Request line (method + path + status)
          - Operation type badge for GraphQL
          - Request headers (filtered — auth, cookies, content-type)
          - Request body (full, pretty-printed JSON when possible)
          - Response body (full, pretty-printed JSON when possible)

        Skips UI/static flows.
        Called when --full-requests flag is set.
        """
        RESET  = "\033[0m"
        BOLD   = "\033[1m"
        BLUE   = "\033[94m"
        GREEN  = "\033[92m"
        YELLOW = "\033[93m"
        RED    = "\033[91m"
        GRAY   = "\033[90m"
        CYAN   = "\033[96m"
        DIM    = "\033[2m"

        api_reqs = [r for r in result.requests if r.category != "UI"]

        if not api_reqs:
            print(f"  {GRAY}No API requests to display.{RESET}")
            return

        bar   = "─" * 66
        dbar  = "═" * 66

        print(f"\n  {BOLD}{YELLOW}{dbar}{RESET}")
        print(f"  {BOLD}{YELLOW}FULL REQUEST DETAILS  ({len(api_reqs)} requests){RESET}")
        print(f"  {BOLD}{YELLOW}{dbar}{RESET}")

        for r in api_reqs:
            print(f"\n  {BOLD}{BLUE}{bar}{RESET}")

            # ── Request line ──────────────────────────────────────────────────
            method_color = (
                RED    if r.method in ("DELETE", "PATCH") else
                YELLOW if r.method == "POST" else
                GREEN
            )
            status_color = (
                GREEN  if 200 <= r.status_code < 300 else
                YELLOW if 300 <= r.status_code < 400 else
                RED
            )

            print(
                f"  {BOLD}#{r.index:<4}{RESET} "
                f"{method_color}{r.method:<7}{RESET} "
                f"{r.path:<45} "
                f"→ {status_color}{r.status_code}{RESET}"
            )

            # ── GraphQL operation badge ───────────────────────────────────────
            if r.category == "GraphQL":
                op_color = RED if r.gql_operation == "mutation" else GREEN
                op_name  = self._extract_gql_op_name(r.gql_query or "")
                print(
                    f"  {CYAN}[GraphQL]{RESET}  "
                    f"{op_color}{r.gql_operation or 'query'}{RESET}  "
                    f"{BOLD}{op_name}{RESET}"
                )
            elif r.category == "SOAP":
                print(f"  {YELLOW}[SOAP]{RESET}")

            # ── Request headers ───────────────────────────────────────────────
            if r.request_headers:
                print(f"\n  {BOLD}Request Headers:{RESET}")
                for k, v in r.request_headers.items():
                    # Truncate cookies and tokens for readability
                    if k.lower() in ("cookie", "authorization") and len(v) > 80:
                        v = v[:77] + "..."
                    print(f"  {GRAY}  {k:<20} : {v}{RESET}")

            # ── Request body ──────────────────────────────────────────────────
            if r.request_body:
                print(f"\n  {BOLD}Request Body:{RESET}")
                pretty = self._pretty_print(r.request_body)
                for line in pretty.split("\n"):
                    print(f"  {CYAN}  {line}{RESET}")

            # ── Response headers ──────────────────────────────────────────────
            if r.response_headers:
                print(f"\n  {BOLD}Response Headers:{RESET}")
                for k, v in r.response_headers.items():
                    if k.lower() == "set-cookie" and len(v) > 80:
                        v = v[:77] + "..."
                    print(f"  {GRAY}  {k:<20} : {v}{RESET}")

            # ── Response body ─────────────────────────────────────────────────
            if r.response_body:
                print(f"\n  {BOLD}Response Body:{RESET}")
                pretty = self._pretty_print(r.response_body)
                for line in pretty.split("\n"):
                    print(f"  {DIM}  {line}{RESET}")

        print(f"\n  {BOLD}{YELLOW}{dbar}{RESET}\n")

    # -------------------------------------------------------------------------

    def _pretty_print(self, body: str) -> str:
        """
        Pretty-print a body string.
        - JSON → indented with json.dumps
        - XML/SOAP → return as-is (no dependency on lxml)
        - Other → return as-is
        """
        stripped = body.strip()

        # JSON
        if stripped.startswith(("{", "[")):
            try:
                parsed = json.loads(stripped)
                return json.dumps(parsed, indent=2, ensure_ascii=False)
            except Exception:
                pass

        # XML / SOAP — basic indent via textwrap
        if stripped.startswith("<"):
            try:
                import xml.dom.minidom as minidom
                dom = minidom.parseString(stripped.encode("utf-8"))
                return dom.toprettyxml(indent="  ").split("\n", 1)[-1]  # skip XML declaration
            except Exception:
                pass

        return stripped

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