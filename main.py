# main.py
"""
APISec — API Security Audit Tool

Modes:
  discovery  →  Detects API type and crawls endpoints
  params     →  Discovers real parameters for each endpoint (like Arjun)
  scan       →  Tests discovered endpoints for vulnerabilities
  full       →  Discovery + Scan chained automatically

Examples:
  apisec discovery --url https://api.example.com --wordlist wordlists/api.txt
  apisec params --input endpoints.json
  apisec scan --input endpoints.json --tests sqli,xss,idor
  apisec scan --url https://api.example.com --endpoint /users/1 --tests all
  apisec full --url https://api.example.com --wordlist wordlists/api.txt
"""

import argparse
import json
import sys
import os

from core.discovery    import APIDiscovery
from config.settings   import ScanConfig, ScanMode
from core.rest_scanner import RESTScanner
from logger.logger     import logger, set_verbose
from core.traffic_capture import TrafficCapture


# ─────────────────────────────────────────────────────────────────────────────
#  Banner & display
# ─────────────────────────────────────────────────────────────────────────────

def print_banner():
    print("""
╔═══════════════════════════════════════════════════════╗
║           APISec — API Security Audit Tool  v1.0      ║
║        REST | GraphQL | SOAP  —  Discovery            ║
╚═══════════════════════════════════════════════════════╝
""")


def print_discovery_result(result: dict):
    confidence_pct = int(result["confidence"] * 100)

    api_colors = {
        "REST":    "\033[92m",   # green
        "GraphQL": "\033[94m",   # blue
        "SOAP":    "\033[93m",   # yellow
        "Unknown": "\033[91m",   # red
    }
    RESET = "\033[0m"
    color = api_colors.get(result["api_type"], "")

    print("\n" + "═" * 57)
    print("  DISCOVERY RESULT")
    print("═" * 57)
    print(f"  API Type    : {color}{result['api_type']}{RESET}  ({confidence_pct}% confidence)")
    print(f"  Score       : {result.get('score', 'N/A')}")
    print(f"  Tech Stack  : {', '.join(result['tech_stack']) or 'Unknown'}")
    print(f"  Reasons     :")
    for r in result["reasons"]:
        print(f"    • {r}")

    total = len(result["endpoints"])
    print(f"\n  Endpoints found : {total}")

    if result.get("swagger_endpoints"):
        print(f"\n  [Swagger/OpenAPI]  {len(result['swagger_endpoints'])} endpoints")
        for ep in result["swagger_endpoints"]:
            print(f"    • {ep}")

    if result.get("crawled_endpoints"):
        print(f"\n  [Crawl]  {len(result['crawled_endpoints'])} endpoints")
        for ep in result["crawled_endpoints"]:
            print(f"    • {ep}")

    print("═" * 57 + "\n")


def print_params_result(results: dict):
    """Display discovered parameters per endpoint."""
    print("\n" + "═" * 57)
    print("  PARAMETER DISCOVERY RESULT")
    print("═" * 57)

    if not results:
        print("\n  [!] No parameters found on any endpoint.\n")
        print("═" * 57 + "\n")
        return

    total_params = sum(len(p) for p in results.values())
    print(f"\n  Endpoints with params : {len(results)}")
    print(f"  Total params found    : {total_params}\n")

    for endpoint, params in results.items():
        print(f"  {endpoint}")
        for param, reason in params:
            print(f"    [v] {param:<20} based on: {reason}")
        print()

    print("═" * 57 + "\n")


def print_scan_results(results: list):
    SEVERITY_COLORS = {
        "CRITICAL": "\033[91m",   # red
        "HIGH":     "\033[93m",   # yellow
        "MEDIUM":   "\033[94m",   # blue
        "LOW":      "\033[92m",   # green
        "INFO":     "\033[97m",   # white
    }
    RESET = "\033[0m"

    if not results:
        print("\n[✓] No vulnerabilities detected.\n")
        return

    print("\n" + "═" * 65)
    print(f"  SCAN RESULTS — {len(results)} unique finding(s) detected")
    print("═" * 65)

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
        print("  " + "─" * 62)

    print("\n  SUMMARY:")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        count = sum(1 for v in results if v.severity == sev)
        if count:
            color = SEVERITY_COLORS[sev]
            print(f"    {color}{sev}{RESET} : {count}")

    print("═" * 65 + "\n")


# ─────────────────────────────────────────────────────────────────────────────
#  Validation
# ─────────────────────────────────────────────────────────────────────────────

def validate_url(url: str) -> bool:
    if not url.startswith(("http://", "https://")):
        print(f"[!] Invalid URL: '{url}' — must start with http:// or https://")
        return False
    return True


def validate_wordlist(path: str) -> bool:
    if not os.path.isfile(path):
        print(f"[!] Wordlist not found: '{path}'")
        return False
    return True


def validate_input_file(path: str) -> bool:
    if not os.path.isfile(path):
        print(f"[!] Endpoints file not found: '{path}'")
        return False
    return True


def validate_timeout(timeout: int) -> bool:
    if timeout < 1 or timeout > 60:
        print(f"[!] Invalid timeout: {timeout} — must be between 1 and 60")
        return False
    return True


# ─────────────────────────────────────────────────────────────────────────────
#  Save / Load
# ─────────────────────────────────────────────────────────────────────────────

def save_json(data, path: str):
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        logger.info(f"[+] Saved to: {path}")
    except OSError as e:
        logger.error(f"[!] Cannot save: {e}")


def load_discovery_result(path: str) -> dict:
    """Load the JSON file generated by discovery."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, list):
            return {"endpoints": data, "api_type": "REST", "target_url": None}
        if isinstance(data, dict):
            return data
        print(f"[!] Unrecognized JSON format in '{path}'")
        return {}
    except (json.JSONDecodeError, OSError) as e:
        print(f"[!] Error reading '{path}': {e}")
        return {}


def parse_tests(tests_arg: str) -> list[str]:
    """Parse --tests sqli,xss,idor → ['sqli', 'xss', 'idor']"""
    ALL_TESTS = [
        "sqli", "blind_sqli", "nosql", "xss", "idor",
        "auth", "ssrf", "misconfig", "mass_assign", "rate_limit",
    ]
    if tests_arg == "all":
        return ALL_TESTS
    selected = [t.strip().lower() for t in tests_arg.split(",")]
    unknown  = [t for t in selected if t not in ALL_TESTS]
    if unknown:
        print(f"[!] Unknown tests ignored: {', '.join(unknown)}")
        print(f"    Available tests: {', '.join(ALL_TESTS)}")
    return [t for t in selected if t in ALL_TESTS]


# ─────────────────────────────────────────────────────────────────────────────
#  Core modes
# ─────────────────────────────────────────────────────────────────────────────

def run_discovery(args) -> dict | None:
    """Run the discovery phase and return the result."""
    if not validate_url(args.url):
        return None
    if not validate_wordlist(args.wordlist):
        return None
    if not validate_timeout(args.timeout):
        return None

    config = ScanConfig(
        target_url=args.url,
        mode=ScanMode.QUICK if args.mode == "quick" else ScanMode.FULL,
        timeout=args.timeout,
    )

    logger.info(f"[*] Target   : {config.target_url}")
    logger.info(f"[*] Mode     : {config.mode.value}")
    logger.info(f"[*] Timeout  : {config.timeout}s")
    logger.info(f"[*] Wordlist : {args.wordlist}")

    try:
        discovery = APIDiscovery(config.target_url, timeout=config.timeout)
        result    = discovery.run(args.wordlist, mode=args.mode)
        return result
    except KeyboardInterrupt:
        print("\n[!] Discovery interrupted.")
        sys.exit(0)
    except Exception as e:
        logger.error(f"[!] Discovery error: {e}")
        return None


def run_scan(endpoints: list[str], args, api_type: str = "REST") -> list:
    """
    Run the scan phase on a list of endpoints.
    Automatically routes to the correct scanner based on api_type.
    """
    from urllib.parse import urlparse
    from core.graphql_scanner import GraphQLScanner
    from core.soap_scanner    import SOAPScanner

    if not endpoints:
        print("[!] No endpoints to scan.")
        return []

    tests = parse_tests(getattr(args, "tests", "all"))
    if not tests:
        print("[!] No valid tests selected.")
        return []

    token = getattr(args, "token", None)

     # ── Résolution token-file ──────────────────────────────────────────────
    if not token and getattr(args, "token_file", None):
        try:
            with open(args.token_file, "r") as f:
                token = f.read().strip()
            logger.info(f"[cli] Token loaded from {args.token_file}")
        except FileNotFoundError:
            logger.error(f"[cli] Token file not found: {args.token_file}")
            sys.exit(1)
            
    if not validate_timeout(args.timeout):
        return []

    # Determine base URL
    base_url = getattr(args, "url", None)
    if not base_url and endpoints:
        parsed   = urlparse(endpoints[0])
        base_url = f"{parsed.scheme}://{parsed.netloc}"

    if not base_url:
        print("[!] Cannot determine base URL.")
        return []

    SCANNER_LABELS = {
        "REST":    "REST Scanner    (SQLi, XSS, IDOR, Auth, NoSQL...)",
        "GraphQL": "GraphQL Scanner (Introspection, Depth, FieldExposure...)",
        "SOAP":    "SOAP Scanner    (XXE, WSDL, SQLi, SOAPAction...)",
    }
    logger.info(f"[*] {SCANNER_LABELS.get(api_type, f'Unknown scanner ({api_type})')}")
    logger.info(f"[*] {len(endpoints)} endpoint(s) — tests: {', '.join(tests)}")

    try:
        if api_type == "GraphQL":
            scanner = GraphQLScanner(base_url, timeout=args.timeout, token=token)
        elif api_type == "SOAP":
            scanner = SOAPScanner(base_url, timeout=args.timeout, token=token)
        else:
            if api_type != "REST":
                print(f"[!] Unsupported API type: '{api_type}' — falling back to REST Scanner")
            scanner = RESTScanner(          # ← remplace seulement celui-ci
                base_url,
                timeout    = args.timeout,
                token      = token,
                login_url  = getattr(args, "login_url",  None),
                username   = getattr(args, "username",   None),
                password   = getattr(args, "password",   None),
                login_body = getattr(args, "login_body", None),
            )

        return scanner.scan(endpoints, tests=tests)

    except KeyboardInterrupt:
        print("\n[!] Scan interrupted.")
        sys.exit(0)
    except Exception as e:
        logger.error(f"[!] Scan error: {e}")
        return []


# ─────────────────────────────────────────────────────────────────────────────
#  Subcommands
# ─────────────────────────────────────────────────────────────────────────────

def cmd_discovery(args):
    """apisec discovery --url URL --wordlist FILE"""
    result = run_discovery(args)
    if result is None:
        sys.exit(1)

    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print_discovery_result(result)

    output_path = args.output or "endpoints.json"
    save_json(result, output_path)
    print(f"[→] Endpoints saved to '{output_path}'")
    print(f"[→] Discover params : apisec params --input {output_path}")
    print(f"[→] Run scan        : apisec scan --input {output_path}\n")


def cmd_params(args):
    """
    apisec params --input endpoints.json
    apisec params --input endpoints.json --wordlist wordlists/params-large.txt
    apisec params --input endpoints.json --output params.json
    """
    from core.param_discoverer import ParamDiscoverer
    from urllib.parse import urlparse

    if not validate_input_file(args.input):
        sys.exit(1)

    disc = load_discovery_result(args.input)
    if not disc:
        print("[!] Empty or malformed file.")
        sys.exit(1)

    endpoints = disc.get("endpoints", [])
    if not endpoints:
        print("[!] No endpoints in file.")
        sys.exit(1)

    # Determine base URL
    base_url = disc.get("target_url") or getattr(args, "url", None)
    if not base_url and endpoints:
        parsed   = urlparse(endpoints[0])
        base_url = f"{parsed.scheme}://{parsed.netloc}"

    if not base_url:
        print("[!] Cannot determine base URL.")
        sys.exit(1)

    token    = getattr(args, "token", None)
    wordlist = getattr(args, "wordlist", None)

    print(f"[→] Discovering parameters on {len(endpoints)} endpoint(s)...")
    print(f"[→] Base URL : {base_url}\n")

    discoverer = ParamDiscoverer(
        base_url,
        timeout  = args.timeout,
        token    = token,
        wordlist = wordlist,
    )

    # discover_all returns {endpoint_url: [(param, reason), ...]}
    results = discoverer.discover_all(endpoints)

    # Display results
    if args.json:
        # Convert tuples to dicts for JSON serialization
        json_results = {
            ep: [{"param": p, "reason": r} for p, r in params]
            for ep, params in results.items()
        }
        print(json.dumps(json_results, indent=2, ensure_ascii=False))
    else:
        print_params_result(results)

    # Save results
    output_path = args.output or "params.json"
    json_results = {
        ep: [{"param": p, "reason": r} for p, r in params]
        for ep, params in results.items()
    }
    save_json(json_results, output_path)
    print(f"[→] Results saved to '{output_path}'")
    print(f"[→] Run scan: apisec scan --input endpoints.json --tests blind_sqli,xss,idor\n")


def cmd_scan(args):
    """
    apisec scan --input endpoints.json [--tests sqli,xss]
    apisec scan --url URL --endpoint /users/1 [--tests all]
    """
    endpoints = []
    api_type  = "REST"

    # Source 1: JSON file from discovery
    if hasattr(args, "input") and args.input:
        if not validate_input_file(args.input):
            sys.exit(1)

        disc = load_discovery_result(args.input)
        if not disc:
            print("[!] Empty or malformed file.")
            sys.exit(1)

        endpoints = disc.get("endpoints", [])
        api_type  = disc.get("api_type", "REST")

        if not getattr(args, "url", None) and disc.get("target_url"):
            args.url = disc["target_url"]

        if not endpoints:
            print("[!] No endpoints in file.")
            sys.exit(1)

        print(f"[→] API detected: {api_type} — {len(endpoints)} endpoint(s) loaded")

    # Source 2: single endpoint from CLI
    elif hasattr(args, "endpoint") and args.endpoint:
        if not getattr(args, "url", None):
            print("[!] --url required with --endpoint")
            sys.exit(1)
        if not validate_url(args.url):
            sys.exit(1)
        base      = args.url.rstrip("/")
        ep        = args.endpoint if args.endpoint.startswith("/") else f"/{args.endpoint}"
        endpoints = [f"{base}{ep}"]
        api_type  = getattr(args, "api_type", "REST")

    else:
        print("[!] Specify --input endpoints.json  or  --url URL --endpoint /path")
        sys.exit(1)

    results = run_scan(endpoints, args, api_type=api_type)

    if args.json:
        print(json.dumps([r.to_dict() for r in results], indent=2, ensure_ascii=False))
    else:
        print_scan_results(results)

    if args.output:
        save_json([r.to_dict() for r in results], args.output)


def cmd_full(args):
    """
    apisec full --url URL --wordlist FILE [--tests all]
    Discovery + Scan chained automatically.
    """
    # Step 1: Discovery
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
        print("[!] No endpoints discovered — scan cancelled.")
        sys.exit(0)

    # Step 2: Scan
    print(f"\n[2/2] Running {api_type} scan on {len(endpoints)} endpoint(s)...\n")
    results = run_scan(endpoints, args, api_type=api_type)

    if args.json:
        print(json.dumps([r.to_dict() for r in results], indent=2, ensure_ascii=False))
    else:
        print_scan_results(results)

    scan_output = args.scan_output or "scan_results.json"
    save_json([r.to_dict() for r in results], scan_output)
    print(f"[→] Scan results saved to '{scan_output}'\n")

def cmd_capture(args):
    """apisec capture --url URL [--port 8080] [--output endpoints.json]"""
    capture = TrafficCapture(
        target_url   = args.url,
        proxy_port   = getattr(args, "proxy_port", 8080),
        output_path  = args.output or "endpoints.json",
        traffic_file = getattr(args, "traffic_file", "traffic.mitm"),
        swagger_file = getattr(args, "swagger_file", "swagger_captured.yaml"),
    )
    capture.run()

# ─────────────────────────────────────────────────────────────────────────────
#  CLI Parser
# ─────────────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="APISec — API Security Audit Tool | REST | GraphQL | SOAP",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Examples:
  # Step 1 — Discovery → generates endpoints.json
  apisec discovery --url https://api.example.com --wordlist wordlists/api.txt

  # Step 2 — Parameter discovery → generates params.json
  apisec params --input endpoints.json
  apisec params --input endpoints.json --wordlist wordlists/params-large.txt

  # Step 3 — Vulnerability scan
  apisec scan --input endpoints.json --tests all
  apisec scan --url https://api.example.com --endpoint /users/1 --tests sqli,idor

  # Full pipeline (discovery + scan)
  apisec full --url https://api.example.com --wordlist wordlists/api.txt --tests all
        """
    )

    subparsers = parser.add_subparsers(dest="command", metavar="command")
    subparsers.required = True

    # ── Shared arguments ──────────────────────────────────────────────────────
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--timeout",    type=int, default=5,    help="HTTP timeout in seconds (default: 5)")
    common.add_argument("--token",      type=str, default=None, help="Bearer authentication token")
    common.add_argument("--token-file", type=str, default=None, dest="token_file", help="Path to a file containing the Bearer token")
    common.add_argument("--login-url",  type=str, default=None, dest="login_url",  help="Login endpoint (e.g. /identity/api/auth/login)")
    common.add_argument("--username",   type=str, default=None, help="Username or email for auto-login")
    common.add_argument("--password",   type=str, default=None, help="Password for auto-login")
    common.add_argument("--login-body", type=str, default=None, dest="login_body", help="Raw JSON login body")
    common.add_argument("--output",     type=str, default=None, help="Output JSON file path")
    common.add_argument("--json",       action="store_true",    help="Raw JSON output")
    common.add_argument("--verbose",    action="store_true",    help="Detailed logs")

    # ── discovery ─────────────────────────────────────────────────────────────
    p_disc = subparsers.add_parser(
        "discovery",
        parents=[common],
        help="Detect API type and crawl endpoints",
        description="Phase 1 — Discovery: detects the API type and lists available endpoints.",
    )
    p_disc.add_argument("--url",      required=True, help="Target URL (e.g. https://api.example.com)")
    p_disc.add_argument("--wordlist", required=True, help="Path to wordlist file")
    p_disc.add_argument("--mode",     choices=["quick", "full"], default="quick",
                        help="quick = 50 paths max  |  full = complete wordlist")
    p_disc.set_defaults(func=cmd_discovery)

    # ── params ────────────────────────────────────────────────────────────────
    p_params = subparsers.add_parser(
        "params",
        parents=[common],
        help="Discover real parameters for each endpoint (like Arjun)",
        description="Phase 2 — Parameter Discovery: finds real HTTP parameters accepted by each endpoint.",
    )
    p_params.add_argument("--input",    required=True, type=str,
                          help="JSON file from discovery (e.g. endpoints.json)")
    p_params.add_argument("--wordlist", type=str, default=None,
                          help="Custom params wordlist (default: Arjun large.txt or wordlists/params-large.txt)")
    p_params.set_defaults(func=cmd_params)

    # ── scan ──────────────────────────────────────────────────────────────────
    p_scan = subparsers.add_parser(
        "scan",
        parents=[common],
        help="Test endpoints for vulnerabilities",
        description="Phase 3 — Scan: tests endpoints for vulnerabilities (SQLi, XSS, IDOR, etc.).",
    )
    p_scan.add_argument("--input",    type=str, default=None,
                        help="JSON file from discovery (e.g. endpoints.json)")
    p_scan.add_argument("--url",      type=str, default=None,
                        help="Base URL (required with --endpoint)")
    p_scan.add_argument("--endpoint", type=str, default=None,
                        help="Single endpoint to test (e.g. /users/1)")
    p_scan.add_argument("--tests",    type=str, default="all",
                        help="Tests to run: all | sqli,xss,idor,auth,blind_sqli,nosql,ssrf,misconfig,mass_assign,rate_limit")
    p_scan.set_defaults(func=cmd_scan)

    # ── full ──────────────────────────────────────────────────────────────────
    p_full = subparsers.add_parser(
        "full",
        parents=[common],
        help="Discovery + Scan chained",
        description="Full pipeline: discovery then automatic scan of found endpoints.",
    )
    p_full.add_argument("--url",         required=True, help="Target URL")
    p_full.add_argument("--wordlist",    required=True, help="Path to wordlist file")
    p_full.add_argument("--mode",        choices=["quick", "full"], default="quick",
                        help="quick = 50 paths max  |  full = complete wordlist")
    p_full.add_argument("--tests",       type=str, default="all",
                        help="Tests to run: all | sqli,xss,idor,auth,blind_sqli,nosql,ssrf,misconfig,mass_assign,rate_limit")
    p_full.add_argument("--scan-output", type=str, default=None, dest="scan_output",
                        help="Output file for scan results (e.g. scan_results.json)")
    p_full.set_defaults(func=cmd_full)

    #-----------------------capture--------
    p_capture = subparsers.add_parser(
    "capture",
    parents=[common],
    help="Capture traffic in real time via mitmproxy",
    description="Capture HTTP/HTTPS traffic from browser and extract API endpoints.",
    )
    p_capture.add_argument("--url",          required=True, help="Target API URL")
    p_capture.add_argument("--port",         type=int, default=8080, dest="proxy_port",
                            help="Proxy port (default: 8080)")
    p_capture.add_argument("--traffic-file", type=str, default="traffic.mitm",
                            dest="traffic_file", help="Raw traffic output file")
    p_capture.add_argument("--swagger-file", type=str, default="swagger_captured.yaml",
                            dest="swagger_file", help="Intermediate swagger file")
    p_capture.set_defaults(func=cmd_capture)
    return parser


# ─────────────────────────────────────────────────────────────────────────────
#  Entry point
# ─────────────────────────────────────────────────────────────────────────────

def main():
    print_banner()
    parser = build_parser()
    args   = parser.parse_args()

    if args.verbose:
        set_verbose(True)
        logger.info("[*] Verbose mode enabled")

    args.func(args)


if __name__ == "__main__":
    main()