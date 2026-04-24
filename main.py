# main.py
"""
APISec — API Security Audit Tool

Commands:
  discovery  ->  Detect API type, crawl endpoints, fetch GraphQL schema
  params     ->  Discover REST parameters per endpoint (Arjun-style)
  scan       ->  Test endpoints for vulnerabilities
  full       ->  Discovery + Scan chained automatically
  capture    ->  Capture live traffic via mitmproxy

Examples:
  apisec discovery --url https://api.example.com --wordlist wordlists/api.txt
  apisec params    --input endpoints.json
  apisec scan      --input endpoints.json --tests all
  apisec scan      --url https://api.example.com --endpoint /users/1 --tests sqli,idor
  apisec full      --url https://api.example.com --wordlist wordlists/api.txt --tests all
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Optional
from urllib.parse import urlparse

from config.settings      import ScanConfig, ScanMode
from core.discovery       import APIDiscovery
from core.rest_scanner    import RESTScanner
from core.traffic_capture import TrafficCapture
from logger.logger        import logger, set_verbose


# -----------------------------------------------------------------------------
#  Constants
# -----------------------------------------------------------------------------

VERSION = "1.0"

# REST tests — passed to RESTScanner
ALL_REST_TESTS: list[str] = [
    "misconfig", "auth", "sqli", "blind_sqli",
    "nosql", "xss", "idor", "ssrf",
    "mass_assign", "rate_limit",
]

# GraphQL tests — passed to GraphQLScanner
ALL_GQL_TESTS: list[str] = [
    "introspection", "bypass", "fields", "auth",
    "idor", "csrf", "sqli", "nosqli",
    "batch", "alias", "depth",
    "subscription", "error",
]

# SOAP tests — passed to SOAPScanner
ALL_SOAP_TESTS: list[str] = [
    "wsdl", "xxe", "sqli", "injection",
    "auth", "replay", "action_spoofing",
]

# Routing map — api_type -> test registry
_TEST_REGISTRY: dict[str, list[str]] = {
    "REST":    ALL_REST_TESTS,
    "GraphQL": ALL_GQL_TESTS,
    "SOAP":    ALL_SOAP_TESTS,
    "Unknown": ALL_REST_TESTS,
}

# Backward compatibility alias
ALL_TESTS = ALL_REST_TESTS

SCANNER_LABELS: dict[str, str] = {
    "REST":    "REST Scanner    (SQLi, XSS, IDOR, Auth, NoSQL, SSRF...)",
    "GraphQL": "GraphQL Scanner (Introspection, Depth, FieldExposure, Auth...)",
    "SOAP":    "SOAP Scanner    (XXE, WSDL, SQLi, SOAPAction...)",
}

SEVERITY_COLORS: dict[str, str] = {
    "CRITICAL": "\033[91m",
    "HIGH":     "\033[93m",
    "MEDIUM":   "\033[94m",
    "LOW":      "\033[92m",
    "INFO":     "\033[97m",
}
API_COLORS: dict[str, str] = {
    "REST":    "\033[92m",
    "GraphQL": "\033[94m",
    "SOAP":    "\033[93m",
    "Unknown": "\033[91m",
}
RESET = "\033[0m"


# -----------------------------------------------------------------------------
#  Display helpers
# -----------------------------------------------------------------------------

def print_banner() -> None:
    print(f"""
\u2554\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2557
\u2551       APISec - API Security Audit Tool  v{VERSION}        \u2551
\u2551        REST | GraphQL | SOAP  -  Audit              \u2551
\u255a\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u255d
""")


def print_discovery_result(result: dict) -> None:
    confidence_pct = int(result["confidence"] * 100)
    color          = API_COLORS.get(result["api_type"], "")

    print("\n" + "=" * 57)
    print("  DISCOVERY RESULT")
    print("=" * 57)
    print(f"  API Type    : {color}{result['api_type']}{RESET}  ({confidence_pct}% confidence)")
    print(f"  Score       : {result.get('score', 'N/A')}")
    print(f"  Tech Stack  : {', '.join(result['tech_stack']) or 'Unknown'}")
    print("  Reasons     :")
    for r in result["reasons"]:
        print(f"    - {r}")

    print(f"\n  Endpoints found : {len(result['endpoints'])}")

    if result.get("swagger_endpoints"):
        print(f"\n  [Swagger/OpenAPI]  {len(result['swagger_endpoints'])} endpoint(s)")
        for ep in result["swagger_endpoints"]:
            print(f"    - {ep}")

    if result.get("crawled_endpoints"):
        print(f"\n  [Crawl]  {len(result['crawled_endpoints'])} endpoint(s)")
        for ep in result["crawled_endpoints"]:
            print(f"    - {ep}")

    schema = result.get("schema")
    if schema and schema.get("method") != "none":
        print(f"\n  [GraphQL Schema]  method : {schema['method']}")
        print(f"    queries   : {len(schema.get('queries', []))}")
        print(f"    mutations : {len(schema.get('mutations', []))}")
        print(f"    types     : {len(schema.get('types', []))}")

    print("=" * 57 + "\n")


def print_params_result(results: dict) -> None:
    print("\n" + "=" * 57)
    print("  PARAMETER DISCOVERY RESULT")
    print("=" * 57)

    if not results:
        print("\n  [!] No parameters found on any endpoint.\n")
        print("=" * 57 + "\n")
        return

    total = sum(len(p) for p in results.values())
    print(f"\n  Endpoints with params : {len(results)}")
    print(f"  Total params found    : {total}\n")

    for endpoint, params in results.items():
        print(f"  {endpoint}")
        for param, reason in params:
            print(f"    [v] {param:<25} -> {reason}")
        print()

    print("=" * 57 + "\n")


def print_scan_results(results: list) -> None:
    if not results:
        print("\n[OK] No vulnerabilities detected.\n")
        return

    print("\n" + "=" * 65)
    print(f"  SCAN RESULTS - {len(results)} finding(s) detected")
    print("=" * 65)

    for vuln in results:
        color = SEVERITY_COLORS.get(vuln.severity, "")
        print(f"\n  [{color}{vuln.severity}{RESET}] [{vuln.vuln_id}] {vuln.vuln_type}")
        print(f"  Endpoint   : {vuln.endpoint}")
        print(f"  Method     : {vuln.method}")
        if vuln.parameter:
            print(f"  Parameter  : {vuln.parameter}")
        if vuln.payload:
            print(f"  Payload    : {vuln.payload}")
        print(f"  Evidence   : {vuln.evidence}")
        print(f"  OWASP      : {vuln.owasp}  |  CWE: {vuln.cwe}  |  Confidence: {vuln.confidence}")
        print(f"  Description: {vuln.description}")
        print(f"  Solution   : {vuln.solution}")
        print("  " + "-" * 62)

    print("\n  SUMMARY:")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        count = sum(1 for v in results if v.severity == sev)
        if count:
            print(f"    {SEVERITY_COLORS[sev]}{sev}{RESET} : {count}")

    print("=" * 65 + "\n")


# -----------------------------------------------------------------------------
#  Validation
# -----------------------------------------------------------------------------

def validate_url(url: str) -> bool:
    if not url.startswith(("http://", "https://")):
        print(f"[!] Invalid URL: '{url}' - must start with http:// or https://")
        return False
    return True


def validate_wordlist(path: str) -> bool:
    if not os.path.isfile(path):
        print(f"[!] Wordlist not found: '{path}'")
        return False
    return True


def validate_input_file(path: str) -> bool:
    if not os.path.isfile(path):
        print(f"[!] Input file not found: '{path}'")
        return False
    return True


def validate_timeout(timeout: int) -> bool:
    if not 1 <= timeout <= 60:
        print(f"[!] Invalid timeout: {timeout} - must be between 1 and 60")
        return False
    return True


# -----------------------------------------------------------------------------
#  I/O helpers
# -----------------------------------------------------------------------------

def save_json(data: object, path: str) -> None:
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        logger.info(f"[+] Saved to: {path}")
    except OSError as e:
        logger.error(f"[!] Cannot save to '{path}': {e}")


def load_discovery_result(path: str) -> dict:
    """Load a JSON file produced by `apisec discovery`."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        print(f"[!] Cannot read '{path}': {e}")
        return {}

    if isinstance(data, list):
        return {"endpoints": data, "api_type": "REST", "target_url": None}
    if isinstance(data, dict):
        return data

    print(f"[!] Unrecognized JSON format in '{path}'")
    return {}


def parse_tests(tests_arg: str, api_type: str = "REST") -> list[str]:
    """
    Parse --tests argument for the given api_type.

    Args:
        tests_arg : "all" or comma-separated test names
        api_type  : "REST" | "GraphQL" | "SOAP" | "Unknown"

    Returns:
        List of test names valid for the given api_type.
    """
    registry = _TEST_REGISTRY.get(api_type, ALL_REST_TESTS)

    if tests_arg.strip().lower() == "all":
        return list(registry)

    selected = [t.strip().lower() for t in tests_arg.split(",") if t.strip()]
    valid    = [t for t in selected if t in registry]
    unknown  = [t for t in selected if t not in registry]

    if unknown:
        logger.debug(
            f"[tests] Unknown or inapplicable tests for {api_type}: "
            f"{', '.join(unknown)} — ignored"
        )

    return valid


def _resolve_token(args) -> Optional[str]:
    """Resolve auth token from --token or --token-file. --token takes priority."""
    token = getattr(args, "token", None)
    if token:
        return token

    token_file = getattr(args, "token_file", None)
    if token_file:
        try:
            with open(token_file, "r", encoding="utf-8") as f:
                token = f.read().strip()
            logger.info(f"[cli] Token loaded from '{token_file}'")
            return token
        except FileNotFoundError:
            logger.error(f"[!] Token file not found: '{token_file}'")
            sys.exit(1)

    return None


def _resolve_base_url(args, endpoints: list[str]) -> Optional[str]:
    """Derive the base URL from args or the first endpoint."""
    base_url = getattr(args, "url", None)
    if base_url:
        return base_url.rstrip("/")
    if endpoints:
        parsed = urlparse(endpoints[0])
        return f"{parsed.scheme}://{parsed.netloc}"
    return None


# -----------------------------------------------------------------------------
#  Params resolution - REST only
# -----------------------------------------------------------------------------

def _resolve_params_map(
    endpoints: list[str],
    args,
    token:    Optional[str],
    api_type: str,
) -> dict[str, list[str]]:
    """
    Return a {endpoint -> [param, ...]} map for REST scanners.

    Routing:
      GraphQL -> empty dict  (args come from introspection schema)
      SOAP    -> empty dict  (args come from WSDL)
      REST    -> load params.json if present, else run ParamDiscoverer

    This is the single authoritative place where params are resolved.
    run_scan() never calls ParamDiscoverer directly.
    """
    if api_type != "REST":
        logger.debug(f"[params] Skipped for {api_type} - args derived from schema/WSDL")
        return {}

    params_file = "params.json"
    params_map: dict[str, list[str]] = {}

    # Fast path: reuse existing params.json
    if os.path.isfile(params_file):
        try:
            with open(params_file, "r", encoding="utf-8") as f:
                raw = json.load(f)
            params_map = {
                ep: [entry["param"] for entry in param_list]
                for ep, param_list in raw.items()
            }
            total = sum(len(v) for v in params_map.values())
            logger.info(
                f"[params] Loaded {params_file} - "
                f"{len(params_map)} endpoint(s), {total} param(s)"
            )
            return params_map
        except Exception as e:
            logger.warning(f"[params] Could not load {params_file}: {e}")

    # Slow path: run ParamDiscoverer and persist results
    logger.info("[params] params.json not found - running param discovery...")
    try:
        from core.param_discoverer import ParamDiscoverer

        base_url   = _resolve_base_url(args, endpoints)
        discoverer = ParamDiscoverer(base_url, timeout=args.timeout, token=token)
        raw        = discoverer.discover_all(endpoints)

        json_results = {
            ep: [{"param": p, "reason": r} for p, r in params]
            for ep, params in raw.items()
        }
        save_json(json_results, params_file)
        logger.info(f"[params] Discovered and saved to {params_file}")

        return {ep: [p for p, _ in params] for ep, params in raw.items()}

    except Exception as e:
        logger.warning(f"[params] Discovery failed: {e} - proceeding without params")
        return {}


# -----------------------------------------------------------------------------
#  Core pipeline
# -----------------------------------------------------------------------------

def run_discovery(args) -> Optional[dict]:
    """Phase 1 - Detect API type, crawl endpoints, fetch GraphQL schema."""
    if not validate_url(args.url):
        return None
    if not validate_wordlist(args.wordlist):
        return None
    if not validate_timeout(args.timeout):
        return None

    config = ScanConfig(
        target_url = args.url,
        mode       = ScanMode.QUICK if args.mode == "quick" else ScanMode.FULL,
        timeout    = args.timeout,
    )

    logger.info(f"[*] Target   : {config.target_url}")
    logger.info(f"[*] Mode     : {config.mode.value}")
    logger.info(f"[*] Timeout  : {config.timeout}s")
    logger.info(f"[*] Wordlist : {args.wordlist}")

    try:
        discovery = APIDiscovery(config.target_url, timeout=config.timeout)
        return discovery.run(args.wordlist, mode=args.mode)
    except KeyboardInterrupt:
        print("\n[!] Discovery interrupted.")
        sys.exit(0)
    except Exception as e:
        logger.error(f"[!] Discovery error: {e}")
        return None


def run_scan(
    endpoints: list[str],
    args,
    api_type:  str = "REST",
) -> list:
    """
    Phase 3 - Route to the correct scanner based on api_type.

    Routing:
      GraphQL -> GraphQLScanner  (schema pre-loaded, no param discovery)
      SOAP    -> SOAPScanner     (WSDL-based, no param discovery)
      REST    -> RESTScanner     (params resolved via _resolve_params_map)

    _resolve_params_map() is the single place that decides whether and how
    to discover parameters. run_scan() never calls ParamDiscoverer directly.
    """
    from core.graphql_scanner import GraphQLScanner
    from core.soap_scanner    import SOAPScanner

    if not endpoints:
        print("[!] No endpoints to scan.")
        return []

    tests = parse_tests(getattr(args, "tests", "all"), api_type=api_type)
    if not tests:
        print("[!] No valid tests selected.")
        return []

    if not validate_timeout(args.timeout):
        return []

    token    = _resolve_token(args)
    base_url = _resolve_base_url(args, endpoints)

    if not base_url:
        print("[!] Cannot determine base URL.")
        return []

    # Params resolution - REST only, GraphQL/SOAP return {}
    params_map = _resolve_params_map(endpoints, args, token, api_type)

    logger.info(f"[*] {SCANNER_LABELS.get(api_type, f'Unknown scanner ({api_type})')}")
    logger.info(f"[*] {len(endpoints)} endpoint(s) - tests: {', '.join(tests)}")

    try:
        if api_type == "GraphQL":
            # Load pre-fetched schema to avoid redundant introspection during scan
            gql_schema: Optional[dict] = None
            input_file = getattr(args, "input", None)
            if input_file:
                try:
                    disc_data  = load_discovery_result(input_file)
                    gql_schema = disc_data.get("schema")
                except Exception:
                    pass

            scanner = GraphQLScanner(
                base_url,
                timeout = args.timeout,
                token   = token,
                schema  = gql_schema,
            )

        elif api_type == "SOAP":
            scanner = SOAPScanner(base_url, timeout=args.timeout, token=token)

        else:
            if api_type not in ("REST", "Unknown"):
                logger.warning(
                    f"[!] Unsupported API type '{api_type}' - falling back to REST Scanner"
                )
            scanner = RESTScanner(
                base_url,
                timeout    = args.timeout,
                token      = token,
                login_url  = getattr(args, "login_url",  None),
                username   = getattr(args, "username",   None),
                password   = getattr(args, "password",   None),
                login_body = getattr(args, "login_body", None),
                params_map = params_map,
                deep       = getattr(args, "deep", False),
            )

        return scanner.scan(endpoints, tests=tests)

    except KeyboardInterrupt:
        print("\n[!] Scan interrupted.")
        sys.exit(0)
    except Exception as e:
        logger.error(f"[!] Scan error: {e}")
        return []


# -----------------------------------------------------------------------------
#  Subcommands
# -----------------------------------------------------------------------------

def cmd_discovery(args) -> None:
    """apisec discovery --url URL --wordlist FILE [--mode quick|full]"""
    result = run_discovery(args)
    if result is None:
        sys.exit(1)

    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print_discovery_result(result)

    output_path = args.output or "endpoints.json"
    save_json(result, output_path)
    print(f"[->] Endpoints saved to '{output_path}'")

    if result.get("api_type") == "GraphQL":
        print(f"[->] GraphQL schema cached - run: apisec scan --input {output_path}")
    else:
        print(f"[->] Discover params : apisec params --input {output_path}")
        print(f"[->] Run scan        : apisec scan   --input {output_path}")
    print()


def cmd_params(args) -> None:
    """
    apisec params --input endpoints.json [--wordlist FILE]

    GraphQL -> exits immediately (args in schema)
    SOAP    -> exits immediately (args from WSDL)
    REST    -> runs full ParamDiscoverer pipeline
    """
    from core.param_discoverer import ParamDiscoverer

    if not validate_input_file(args.input):
        sys.exit(1)

    disc = load_discovery_result(args.input)
    if not disc:
        print("[!] Empty or malformed input file.")
        sys.exit(1)

    api_type = disc.get("api_type", "REST")

    # GraphQL: arguments already available in schema
    if api_type == "GraphQL":
        schema  = disc.get("schema") or {}
        q_count = len(schema.get("queries",   []))
        m_count = len(schema.get("mutations", []))
        print("[i] GraphQL API detected - param discovery not required.")
        if q_count or m_count:
            print(f"    Schema contains {q_count} query/queries and {m_count} mutation(s).")
            print(f"    Arguments available in '{args.input}' -> schema.queries[].args")
        else:
            print("    No schema found - re-run discovery to fetch the schema.")
        print(f"[->] Run scan: apisec scan --input {args.input}")
        sys.exit(0)

    # SOAP: arguments come from WSDL, not HTTP probing
    if api_type == "SOAP":
        print("[i] SOAP API detected - param discovery not required.")
        print("    Operation parameters are extracted from WSDL during scan.")
        print(f"[->] Run scan: apisec scan --input {args.input}")
        sys.exit(0)

    # REST: run full ParamDiscoverer
    endpoints = disc.get("endpoints", [])
    if not endpoints:
        print("[!] No endpoints found in input file.")
        sys.exit(1)

    base_url = disc.get("target_url") or _resolve_base_url(args, endpoints)
    if not base_url:
        print("[!] Cannot determine base URL.")
        sys.exit(1)

    token    = _resolve_token(args)
    wordlist = getattr(args, "wordlist", None)

    print(f"[->] Discovering parameters on {len(endpoints)} endpoint(s)...")
    print(f"[->] Base URL : {base_url}\n")

    discoverer = ParamDiscoverer(
        base_url,
        timeout  = args.timeout,
        token    = token,
        wordlist = wordlist,
    )
    results = discoverer.discover_all(endpoints)

    if args.json:
        json_out = {
            ep: [{"param": p, "reason": r} for p, r in params]
            for ep, params in results.items()
        }
        print(json.dumps(json_out, indent=2, ensure_ascii=False))
    else:
        print_params_result(results)

    output_path  = args.output or "params.json"
    json_results = {
        ep: [{"param": p, "reason": r} for p, r in params]
        for ep, params in results.items()
    }
    save_json(json_results, output_path)
    print(f"[->] Params saved to '{output_path}'")
    print(f"[->] Run scan: apisec scan --input endpoints.json --tests all\n")


def cmd_scan(args) -> None:
    """
    apisec scan --input endpoints.json [--tests sqli,xss]
    apisec scan --url URL --endpoint /users/1 [--tests all]
    """
    endpoints: list[str] = []
    api_type:  str       = "REST"

    # Source 1: JSON file from discovery
    if getattr(args, "input", None):
        if not validate_input_file(args.input):
            sys.exit(1)

        disc = load_discovery_result(args.input)
        if not disc:
            print("[!] Empty or malformed input file.")
            sys.exit(1)

        endpoints = disc.get("endpoints", [])
        api_type  = disc.get("api_type", "REST")

        if not getattr(args, "url", None) and disc.get("target_url"):
            args.url = disc["target_url"]

        if not endpoints:
            print("[!] No endpoints found in input file.")
            sys.exit(1)

        color = API_COLORS.get(api_type, "")
        print(f"[->] API detected: {color}{api_type}{RESET} - {len(endpoints)} endpoint(s)")

    # Source 2: single endpoint from CLI
    elif getattr(args, "endpoint", None):
        if not getattr(args, "url", None):
            print("[!] --url is required when using --endpoint")
            sys.exit(1)
        if not validate_url(args.url):
            sys.exit(1)

        path      = args.endpoint if args.endpoint.startswith("/") else f"/{args.endpoint}"
        endpoints = [f"{args.url.rstrip('/')}{path}"]
        api_type  = getattr(args, "api_type", "REST")

    else:
        print("[!] Specify --input endpoints.json  OR  --url URL --endpoint /path")
        sys.exit(1)

    results = run_scan(endpoints, args, api_type=api_type)

    if args.json:
        print(json.dumps([r.to_dict() for r in results], indent=2, ensure_ascii=False))
    else:
        print_scan_results(results)

    if args.output:
        save_json([r.to_dict() for r in results], args.output)


def cmd_full(args) -> None:
    """apisec full --url URL --wordlist FILE [--tests all]"""
    print("[1/2] Running discovery...\n")
    result = run_discovery(args)
    if result is None:
        sys.exit(1)

    print_discovery_result(result)

    endpoints_path = args.output or "endpoints.json"
    save_json(result, endpoints_path)

    endpoints = result.get("endpoints", [])
    api_type  = result.get("api_type", "REST")

    if not endpoints:
        print("[!] No endpoints discovered - scan cancelled.")
        sys.exit(0)

    print(f"\n[2/2] Running {api_type} scan on {len(endpoints)} endpoint(s)...\n")

    # Pass endpoints.json path so run_scan can load the GraphQL schema
    args.input = endpoints_path

    results = run_scan(endpoints, args, api_type=api_type)

    if args.json:
        print(json.dumps([r.to_dict() for r in results], indent=2, ensure_ascii=False))
    else:
        print_scan_results(results)

    scan_output = getattr(args, "scan_output", None) or "scan_results.json"
    save_json([r.to_dict() for r in results], scan_output)
    print(f"[->] Scan results saved to '{scan_output}'\n")



def cmd_schema(args) -> None:
    """
    apisec schema --input endpoints.json [--format both] [--output-dir ./schema]

    Exports the GraphQL schema into formats ready to paste into visual tools:
      - Voyager JSON : graphql-kit.com/graphql-voyager  (Introspection tab)
      - SDL          : graphql-kit.com/graphql-voyager  (SDL tab)
                       nathanrandal.com/graphql-visualizer

    Only works with GraphQL discovery results (api_type == "GraphQL").
    """
    from core.graphql_export import export_schema

    if not validate_input_file(args.input):
        sys.exit(1)

    fmt        = getattr(args, "fmt", "both")
    output_dir = getattr(args, "output_dir", ".") or "."

    print(f"[->] Exporting GraphQL schema from '{args.input}'...")
    print(f"[->] Format     : {fmt}")
    print(f"[->] Output dir : {output_dir}\n")

    result = export_schema(
        endpoints_json_path = args.input,
        output_dir          = output_dir,
        fmt                 = fmt,
    )

    if result is None:
        sys.exit(1)

    if not result.files:
        print("[!] No files generated — check that the schema is not empty.")
        sys.exit(1)

    print("[+] Schema exported successfully:\n")
    print(result)
    print()
    print("Usage:")
    if result.voyager_path:
        print(f"  [GraphQL Voyager]")
        print(f"  1. Open  : https://graphql-kit.com/graphql-voyager/")
        print(f"  2. Click : Change Schema -> Introspection")
        print(f"  3. Paste : contents of {result.voyager_path}")
        print()
    if result.nathan_path:
        print(f"  [Nathan Randal Visualizer]")
        print(f"  1. Open  : https://nathanrandal.com/graphql-visualizer/")
        print(f"  2. Paste : contents of {result.nathan_path}")
        print()
    if result.sdl_path:
        print(f"  [GraphQL Voyager — SDL tab]")
        print(f"  1. Open  : https://graphql-kit.com/graphql-voyager/")
        print(f"  2. Click : Change Schema -> SDL")
        print(f"  3. Paste : contents of {result.sdl_path}")
        print()

def cmd_capture(args) -> None:
    """apisec capture --url URL [--port 8080]"""
    capture = TrafficCapture(
        target_url   = args.url,
        proxy_port   = getattr(args, "proxy_port", 8080),
        output_path  = args.output or "endpoints.json",
        traffic_file = getattr(args, "traffic_file", "traffic.mitm"),
        swagger_file = getattr(args, "swagger_file", "swagger_captured.yaml"),
    )
    capture.run()


# -----------------------------------------------------------------------------
#  CLI parser
# -----------------------------------------------------------------------------

def _common_args() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(add_help=False)
    p.add_argument("--timeout",    type=int, default=5,
                   help="HTTP timeout in seconds (default: 5)")
    p.add_argument("--token",      type=str, default=None,
                   help="Bearer token for authenticated scans")
    p.add_argument("--token-file", type=str, default=None, dest="token_file",
                   help="Path to a file containing the Bearer token")
    p.add_argument("--login-url",  type=str, default=None, dest="login_url",
                   help="Login endpoint for auto-authentication")
    p.add_argument("--username",   type=str, default=None,
                   help="Username / email for auto-login")
    p.add_argument("--password",   type=str, default=None,
                   help="Password for auto-login")
    p.add_argument("--login-body", type=str, default=None, dest="login_body",
                   help="Raw JSON body for custom login requests")
    p.add_argument("--output",     type=str, default=None,
                   help="Output JSON file path")
    p.add_argument("--json",       action="store_true",
                   help="Print raw JSON output")
    p.add_argument("--verbose",    action="store_true",
                   help="Enable verbose logging")
    p.add_argument("--deep",       action="store_true", default=False,
                   help="Deep scan - enables time-based techniques (slower)")
    return p


def build_parser() -> argparse.ArgumentParser:
    common = _common_args()

    parser = argparse.ArgumentParser(
        prog            = "apisec",
        description     = "APISec - API Security Audit Tool | REST . GraphQL . SOAP",
        formatter_class = argparse.RawTextHelpFormatter,
        epilog = f"""
Examples:
  apisec discovery --url https://api.example.com --wordlist wordlists/api.txt
  apisec params    --input endpoints.json
  apisec scan      --input endpoints.json --tests all
  apisec scan      --url https://api.example.com --endpoint /users/1 --tests sqli,idor
  apisec full      --url https://api.example.com --wordlist wordlists/api.txt --tests all
  apisec capture   --url https://api.example.com --port 8080

REST tests  : {", ".join(ALL_REST_TESTS)}
Available GQL tests : {", ".join(ALL_GQL_TESTS)}
        """,
    )

    subs = parser.add_subparsers(dest="command", metavar="command")
    subs.required = True

    # discovery
    p = subs.add_parser("discovery", parents=[common],
                        help="Detect API type and collect endpoints")
    p.add_argument("--url",      required=True, help="Target URL")
    p.add_argument("--wordlist", required=True, help="Endpoint wordlist")
    p.add_argument("--mode", choices=["quick", "full"], default="quick",
                   help="quick = first 50 paths  |  full = entire wordlist")
    p.set_defaults(func=cmd_discovery)

    # params
    p = subs.add_parser("params", parents=[common],
                        help="Discover HTTP parameters (REST only)")
    p.add_argument("--input",    required=True, help="endpoints.json from discovery")
    p.add_argument("--wordlist", default=None,  help="Custom params wordlist")
    p.set_defaults(func=cmd_params)

    # scan
    p = subs.add_parser("scan", parents=[common],
                        help="Test endpoints for vulnerabilities")
    p.add_argument("--input",    default=None, help="endpoints.json from discovery")
    p.add_argument("--url",      default=None, help="Base URL (used with --endpoint)")
    p.add_argument("--endpoint", default=None, help="Single path to test (e.g. /users/1)")
    p.add_argument("--tests",    default="all",
                   help="Tests to run: all | see --list-tests for available tests per API type")
    p.set_defaults(func=cmd_scan)

    # full
    p = subs.add_parser("full", parents=[common],
                        help="Discovery + Scan in one command")
    p.add_argument("--url",         required=True, help="Target URL")
    p.add_argument("--wordlist",    required=True, help="Endpoint wordlist")
    p.add_argument("--mode",        choices=["quick", "full"], default="quick")
    p.add_argument("--tests",       default="all",
                   help="Tests to run: all | see --list-tests for available tests per API type")
    p.add_argument("--scan-output", default=None, dest="scan_output",
                   help="Output file for scan results (default: scan_results.json)")
    p.set_defaults(func=cmd_full)

    # capture
    # schema
    p = subs.add_parser("schema", parents=[common],
                        help="Export GraphQL schema for visual tools (Voyager, Nathan Randal)")
    p.add_argument("--input",      required=True,
                   help="endpoints.json from discovery")
    p.add_argument("--format",     dest="fmt",
                   choices=["voyager", "sdl", "both"], default="both",
                   help="voyager = introspection JSON | sdl = SDL | both (default)")
    p.add_argument("--output-dir", dest="output_dir", default=".",
                   help="Directory for output files (default: current directory)")
    p.set_defaults(func=cmd_schema)

    p = subs.add_parser("capture", parents=[common],
                        help="Capture live traffic via mitmproxy")
    p.add_argument("--url",          required=True, help="Target API URL")
    p.add_argument("--port",         type=int, default=8080, dest="proxy_port")
    p.add_argument("--traffic-file", default="traffic.mitm", dest="traffic_file")
    p.add_argument("--swagger-file", default="swagger_captured.yaml", dest="swagger_file")
    p.set_defaults(func=cmd_capture)

    return parser


# -----------------------------------------------------------------------------
#  Entry point
# -----------------------------------------------------------------------------

def main() -> None:
    print_banner()
    parser = build_parser()
    args   = parser.parse_args()

    if getattr(args, "verbose", False):
        set_verbose(True)
        logger.info("[*] Verbose mode enabled")

    args.func(args)


if __name__ == "__main__":
    main()