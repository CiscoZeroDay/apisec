# core/graphql_scanner.py
"""
GraphQLScanner — Automated GraphQL vulnerability detection.

Architecture:
  - Vulnerability metadata lives in data/graphql_vulns.json — never hardcoded.
  - This file contains only detection logic.
  - _vuln() is the single ScanResult factory — all 14 fields always populated.
  - SchemaState tracks introspection availability across all tests.

Schema availability matrix:
  ┌──────────────────────┬─────────────────────────────────────────────┐
  │ Test                 │ Behavior when schema unavailable            │
  ├──────────────────────┼─────────────────────────────────────────────┤
  │ GQL-S1 introspection │ Probes live — logs if blocked               │
  │ GQL-S2 bypass        │ Only runs when S1 is blocked                │
  │ GQL-S3 fields        │ Skipped with INFO log — needs schema        │
  │ GQL-S4 auth          │ Falls back to hardcoded mutation names      │
  │ GQL-S5 idor          │ Falls back to hardcoded query names         │
  │ GQL-S6 csrf          │ Always runs — schema-independent            │
  │ GQL-S9 batch         │ Always runs — schema-independent            │
  │ GQL-S10 alias        │ Always runs — schema-independent            │
  │ GQL-S11 depth        │ Always runs — schema-independent            │
  │ GQL-S13 error        │ Always runs — schema-independent            │
  └──────────────────────┴─────────────────────────────────────────────┘

Tests implemented  : GQL-S1 S2 S3 S4 S5 S6 S9 S10 S11 S13  (10/13)
Tests planned      : GQL-S7 (sqli) S8 (nosqli) S12 (subscription)
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from enum import Enum, auto
from typing import Optional

from core.models    import ScanResult
from core.requester import Requester
from logger.logger  import logger


# -----------------------------------------------------------------------------
#  Paths
# -----------------------------------------------------------------------------

_VULNS_FILE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "data", "graphql_vulns.json",
)


# -----------------------------------------------------------------------------
#  Constants
# -----------------------------------------------------------------------------

GRAPHQL_ENDPOINTS: list[str] = [
    "/graphql", "/api/graphql", "/graphql/v1",
    "/v1/graphql", "/query", "/gql",
]

INTROSPECTION_PROBE = "{ __schema { queryType { name } } }"

INTROSPECTION_QUERY = """
{
  __schema {
    queryType        { name }
    mutationType     { name }
    subscriptionType { name }
    types {
      name
      kind
      fields(includeDeprecated: true) {
        name
        args { name }
        type { kind name ofType { kind name ofType { kind name } } }
      }
    }
  }
}
"""

# GQL-S2 bypass probes
BYPASS_NEWLINE_PROBE  = "{ __schema\n{ queryType { name } } }"
BYPASS_FRAGMENT_PROBE = (
    "query { ...F } "
    "fragment F on Query { __schema { queryType { name } } }"
)

# GQL-S6 safe probe — read-only, no side effects
CSRF_SAFE_PROBE = "{ __typename }"

# -----------------------------------------------------------------------------
#  Wordlist loader
# -----------------------------------------------------------------------------

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_WL_DIR       = os.path.join(_PROJECT_ROOT, "wordlists", "graphql_wordlist", "10k")
_WL_DIR_1K    = os.path.join(_PROJECT_ROOT, "wordlists", "graphql_wordlist", "1k")


def _load_wordlist(filename: str, fallback: list[str]) -> list[str]:
    """
    Load a wordlist file from wordlists/graphql_wordlist/10k/.
    Falls back to wordlists/graphql_wordlist/1k/ then to the hardcoded list.

    Args:
        filename : file name (e.g. "fieldWordlist-10k.txt")
        fallback : hardcoded list used if no file is found

    Returns:
        List of stripped non-empty lines from the file, or fallback.
    """
    for directory in (_WL_DIR, _WL_DIR_1K):
        path = os.path.join(directory, filename)
        if os.path.isfile(path):
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    words = [line.strip() for line in f if line.strip()]
                if words:
                    logger.debug(
                        f"[wordlist] Loaded {len(words)} entries from {path}"
                    )
                    return words
            except OSError as e:
                logger.warning(f"[wordlist] Cannot read {path}: {e}")

    logger.debug(
        f"[wordlist] {filename} not found — "
        f"using built-in fallback ({len(fallback)} entries)"
    )
    return fallback


# -----------------------------------------------------------------------------
#  Sensitive field keywords
# Built-in fallback — replaced by fieldWordlist-10k.txt when available
# -----------------------------------------------------------------------------

_SENSITIVE_FIELDS_FALLBACK: list[str] = [
    "password", "passwd", "secret", "token", "apikey", "api_key",
    "privatekey", "private_key", "ssn", "creditcard", "credit_card",
    "cvv", "pin", "otp", "hash", "salt", "signature", "bearer",
    "auth", "credential", "key", "access", "refresh", "session",
    "private", "master", "admin", "root",
]

SENSITIVE_FIELDS: list[str] = _load_wordlist(
    "fieldWordlist-10k.txt",
    _SENSITIVE_FIELDS_FALLBACK,
)


# -----------------------------------------------------------------------------
#  Dangerous mutation names
# Built-in fallback — replaced by mutationFieldWordlist-10k.txt when available
# -----------------------------------------------------------------------------

_DANGEROUS_MUTATIONS_FALLBACK: list[str] = [
    "deleteUser", "deleteAccount", "promoteUser", "setRole",
    "updateRole", "grantAdmin", "revokeUser", "createAdmin",
    "resetPassword", "disableUser", "enableUser", "updatePermissions",
    "changePassword", "transferOwnership", "deleteOrganization",
    "removeUser", "banUser", "elevatePrivilege", "setAdmin",
    "updatePassword", "createUser", "destroyAccount",
]

DANGEROUS_MUTATIONS: list[str] = _load_wordlist(
    "mutationFieldWordlist-10k.txt",
    _DANGEROUS_MUTATIONS_FALLBACK,
)

ERROR_LEAK_SIGNALS: list[tuple[str, str]] = [
    ("Traceback",                     "Python stack trace"),
    ("traceback",                     "Python stack trace"),
    ("at Object.",                    "JavaScript stack trace"),
    ("at Function.",                  "JavaScript stack trace"),
    ("NullPointerException",          "Java stack trace"),
    ("System.Exception",              ".NET stack trace"),
    ("/home/",                        "Unix file path"),
    ("/var/",                         "Unix file path"),
    ("/usr/",                         "Unix file path"),
    ("C:\\",                          "Windows file path"),
    ("site-packages",                 "Python package path"),
    ("node_modules",                  "Node.js module path"),
    ("syntax error at",               "SQL syntax error"),
    ("ERROR:  syntax",                "PostgreSQL error"),
    ("You have an error in your SQL", "MySQL error"),
    ("ORA-",                          "Oracle error"),
    ("Microsoft SQL Server",          "MSSQL version"),
    ("Django",                        "Django framework"),
    ("Flask",                         "Flask framework"),
    ("graphene",                      "Graphene Python"),
    ("strawberry",                    "Strawberry Python"),
]

DEPTH_BLOCKED_SIGNALS: list[str] = [
    "max depth", "maxdepth", "query depth", "too deep",
    "complexity", "limit exceeded", "query too complex",
    "depth limit", "max complexity",
]

BATCH_BLOCKED_SIGNALS: list[str] = [
    "batch", "too many", "limit", "forbidden",
    "not allowed", "disabled", "batching not supported",
]

AUTH_ERROR_SIGNALS: list[str] = [
    "unauthorized", "unauthenticated", "forbidden",
    "not authorized", "access denied", "permission denied",
    "authentication required", "login required", "invalid token",
]

FIELD_MISSING_SIGNALS: list[str] = [
    "cannot query field", "unknown field",
    "did you mean", "field does not exist", "no field named",
]


# -----------------------------------------------------------------------------
#  SchemaState
# -----------------------------------------------------------------------------

class SchemaStatus(Enum):
    AVAILABLE_FROM_DISCOVERY = auto()
    AVAILABLE_FROM_SCAN      = auto()
    AVAILABLE_FROM_BYPASS    = auto()
    BLOCKED                  = auto()
    UNKNOWN                  = auto()


@dataclass
class SchemaState:
    """
    Tracks schema availability across all test methods in a scan session.

    All tests read and write this shared object to avoid redundant
    introspection requests and to log accurate context messages.
    """
    status:     SchemaStatus = SchemaStatus.UNKNOWN
    raw:        Optional[dict] = None   # raw introspection JSON response
    gql_schema: Optional[dict] = None  # parsed schema from discovery

    @property
    def available(self) -> bool:
        return self.raw is not None

    @property
    def source_label(self) -> str:
        return {
            SchemaStatus.AVAILABLE_FROM_DISCOVERY: "discovery",
            SchemaStatus.AVAILABLE_FROM_SCAN:      "live scan",
            SchemaStatus.AVAILABLE_FROM_BYPASS:    "bypass (GQL-S2)",
            SchemaStatus.BLOCKED:                  "blocked",
            SchemaStatus.UNKNOWN:                  "unknown",
        }.get(self.status, "?")

    def get_types(self) -> list[dict]:
        if not self.raw:
            return []
        return (
            self.raw.get("data", {})
                    .get("__schema", {})
                    .get("types", [])
        )

    def get_mutation_names(self) -> list[str]:
        if not self.raw:
            return []
        schema   = self.raw.get("data", {}).get("__schema", {})
        mut_type = (schema.get("mutationType") or {}).get("name", "")
        if not mut_type:
            return []
        for t in schema.get("types", []):
            if t.get("name") == mut_type:
                return [f.get("name", "") for f in (t.get("fields") or [])]
        return []

    def get_query_fields(self) -> list[dict]:
        """Return query field definitions with their argument names."""
        if self.gql_schema:
            return self.gql_schema.get("queries", [])
        if not self.raw:
            return []
        schema     = self.raw.get("data", {}).get("__schema", {})
        query_type = (schema.get("queryType") or {}).get("name", "Query")
        for t in schema.get("types", []):
            if t.get("name") == query_type:
                return [
                    {
                        "name": f.get("name", ""),
                        "args": [a.get("name", "") for a in (f.get("args") or [])],
                    }
                    for f in (t.get("fields") or [])
                ]
        return []


# -----------------------------------------------------------------------------
#  Knowledge base loader
# -----------------------------------------------------------------------------

class _VulnDB:
    """Singleton — loads data/graphql_vulns.json once."""
    _instance: Optional["_VulnDB"] = None
    _db: dict = {}

    def __new__(cls) -> "_VulnDB":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._load()
        return cls._instance

    def _load(self) -> None:
        try:
            with open(_VULNS_FILE, "r", encoding="utf-8") as f:
                self._db = json.load(f)
            logger.debug(
                f"[vulndb] graphql — {len(self._db) - 1} entries loaded"
            )
        except FileNotFoundError:
            logger.warning(
                f"[vulndb] {_VULNS_FILE} not found — "
                "ScanResults will have empty metadata fields."
            )
            self._db = {}
        except json.JSONDecodeError as e:
            logger.error(f"[vulndb] Malformed {_VULNS_FILE}: {e}")
            self._db = {}

    def get(self, name: str) -> dict:
        return self._db.get(name, {})

    @property
    def all_tests(self) -> list[tuple[str, dict]]:
        return [(k, v) for k, v in self._db.items() if not k.startswith("_")]


_vulndb = _VulnDB()


# -----------------------------------------------------------------------------
#  ScanResult factory
# -----------------------------------------------------------------------------

def _vuln(
    name:       str,
    endpoint:   str,
    method:     str,
    evidence:   str,
    payload:    Optional[str] = None,
    parameter:  Optional[str] = None,
    extra_desc: Optional[str] = None,
) -> ScanResult:
    """
    Build a fully-populated ScanResult from the knowledge base.
    Runtime context comes from the caller.
    All static metadata comes from data/graphql_vulns.json.
    """
    meta        = _vulndb.get(name)
    description = meta.get("description", f"Vulnerability detected: {name}")
    if extra_desc:
        description = f"{description} {extra_desc}"

    return ScanResult(
        vuln_id     = meta.get("id",          f"GQL-{name.upper()[:4]}"),
        vuln_type   = meta.get("label",        name),
        severity    = meta.get("severity",     "MEDIUM"),
        confidence  = meta.get("confidence",   "MEDIUM"),
        owasp       = meta.get("owasp",        "API8:2023"),
        cwe         = meta.get("cwe",          "CWE-200"),
        endpoint    = endpoint,
        method      = method,
        parameter   = parameter,
        payload     = payload,
        evidence    = evidence,
        description = description,
        solution    = meta.get(
            "solution",
            "See OWASP GraphQL Security Cheat Sheet."
        ),
        reference   = meta.get(
            "reference",
            "https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html"
        ),
    )


# -----------------------------------------------------------------------------
#  GraphQLScanner
# -----------------------------------------------------------------------------

class GraphQLScanner:
    """
    Tests GraphQL endpoints for security vulnerabilities.

    Usage:
        scanner = GraphQLScanner(
            base_url = "https://api.example.com",
            schema   = discovery_result["schema"],
        )
        results = scanner.scan(endpoints, tests=["introspection", "auth"])
    """

    _TEST_REGISTRY: dict[str, str] = {
        "introspection": "_test_introspection",
        "bypass":        "_test_introspection_bypass",
        "fields":        "_test_field_exposure",
        "auth":          "_test_broken_auth",
        "idor":          "_test_idor",
        "csrf":          "_test_csrf",
        "batch":         "_test_batch_attack",
        "alias":         "_test_alias_attack",
        "depth":         "_test_depth_attack",
        "error":         "_test_error_disclosure",
    }

    def __init__(
        self,
        base_url: str,
        timeout:  int            = 5,
        token:    Optional[str]  = None,
        schema:   Optional[dict] = None,
    ) -> None:
        self.base_url     = base_url.rstrip("/")
        self.http         = Requester(self.base_url, timeout=timeout)
        self._schema_state = SchemaState()

        if isinstance(schema, dict):
            raw = schema.get("raw_introspection")
            if raw and isinstance(raw, dict) and "data" in raw:
                self._schema_state.raw        = raw
                self._schema_state.gql_schema = schema
                self._schema_state.status     = SchemaStatus.AVAILABLE_FROM_DISCOVERY
                logger.debug(
                    f"[scanner] Schema from discovery — "
                    f"{len(self._schema_state.get_types())} types"
                )

        if token:
            self.http.set_token(token)

    # =========================================================================
    #  Public entry point
    # =========================================================================

    def scan(
        self,
        endpoints: list[str],
        tests:     Optional[list[str]] = None,
    ) -> list[ScanResult]:
        """
        Run vulnerability tests against GraphQL endpoints.
        Unknown test names (REST names) are silently ignored.
        """
        active: dict[str, callable] = {}
        if tests is None:
            active = {n: getattr(self, m) for n, m in self._TEST_REGISTRY.items()}
        else:
            for name in tests:
                if name in self._TEST_REGISTRY:
                    active[name] = getattr(self, self._TEST_REGISTRY[name])

        if not active:
            logger.info("[GraphQL] No applicable tests — skipped.")
            return []

        gql_endpoints = self._resolve_endpoints(endpoints)
        if not gql_endpoints:
            logger.warning("[GraphQL] No GraphQL endpoints found.")
            return []

        logger.info(
            f"[*] GraphQL scan — {len(gql_endpoints)} endpoint(s) | "
            f"schema: {self._schema_state.source_label} | "
            f"tests: {list(active.keys())}"
        )

        results: list[ScanResult] = []
        for endpoint in gql_endpoints:
            for test_name, test_fn in active.items():
                try:
                    results.extend(test_fn(endpoint))
                except Exception as exc:
                    logger.debug(f"    [gql:{test_name}] error: {exc}")

        logger.info(f"[+] GraphQL scan complete — {len(results)} finding(s)")
        return results

    # =========================================================================
    #  GQL-S1 — Introspection exposed
    # =========================================================================

    def _test_introspection(self, endpoint: str) -> list[ScanResult]:
        """
        Confirm introspection is active in production.

        Fast path  : uses pre-fetched schema from discovery.
        Slow path  : probes the endpoint and caches the result.
        Side effect: updates SchemaState for all subsequent tests.
        """
        path = self._to_path(endpoint)

        # Fast path — schema already available from discovery
        if self._schema_state.status == SchemaStatus.AVAILABLE_FROM_DISCOVERY:
            types_count = len(self._schema_state.get_types())
            logger.info(f"    [VULN] GQL-S1 Introspection exposed → {endpoint}")
            return [_vuln(
                name     = "introspection",
                endpoint = endpoint,
                method   = "POST",
                payload  = INTROSPECTION_PROBE,
                evidence = (
                    f"Introspection active — {types_count} types exposed "
                    f"(schema pre-fetched during discovery)"
                ),
            )]

        # Slow path — probe the endpoint
        r = self._gql_post(path, INTROSPECTION_PROBE)

        if not self._is_gql_response(r):
            logger.info(
                f"    [INFO] GQL-S1 — endpoint not reachable or not GraphQL: {endpoint}"
            )
            return []

        body = self._parse_gql(r)

        if not body.get("data", {}).get("__schema"):
            # Introspection is disabled
            self._schema_state.status = SchemaStatus.BLOCKED
            logger.info(
                f"    [INFO] GQL-S1 — introspection disabled on {endpoint}. "
                "GQL-S2 bypass will be attempted next."
            )
            return []

        # Introspection confirmed — fetch full schema and cache
        r_full = self._gql_post(path, INTROSPECTION_QUERY)
        if self._is_gql_response(r_full):
            full = self._parse_gql(r_full)
            if full and full.get("data", {}).get("__schema"):
                self._schema_state.raw    = full
                self._schema_state.status = SchemaStatus.AVAILABLE_FROM_SCAN

        types_count = len(self._schema_state.get_types())
        logger.info(f"    [VULN] GQL-S1 Introspection exposed → {endpoint}")
        return [_vuln(
            name     = "introspection",
            endpoint = endpoint,
            method   = "POST",
            payload  = INTROSPECTION_PROBE,
            evidence = f"Introspection active — {types_count} types exposed",
        )]

    # =========================================================================
    #  GQL-S2 — Introspection bypass
    # =========================================================================

    def _test_introspection_bypass(self, endpoint: str) -> list[ScanResult]:
        """
        Attempt to retrieve the schema when standard introspection is blocked.

        Only runs when SchemaStatus is BLOCKED (S1 confirmed introspection off).
        If S1 succeeded, bypass is irrelevant and is skipped immediately.

        Techniques (in order):
          1. GET ?query=  — bypasses POST-only filters
          2. Newline injection __schema\\n{...}  — bypasses naive string matching
          3. Fragment spreading  — bypasses keyword-based WAF rules

        On success: SchemaState is updated so S3/S4/S5 benefit from the schema.
        """
        # Skip if schema is already available
        if self._schema_state.available:
            logger.debug(
                "[GQL-S2] Skipped — schema already available "
                f"({self._schema_state.source_label})"
            )
            return []

        # Skip if S1 was never run (status UNKNOWN) — don't attempt blind bypass
        if self._schema_state.status == SchemaStatus.UNKNOWN:
            logger.debug(
                "[GQL-S2] Skipped — introspection status unknown. "
                "Run GQL-S1 first."
            )
            return []

        path = self._to_path(endpoint)

        bypass_attempts = [
            ("GET",  INTROSPECTION_PROBE,  "GET request with ?query= parameter"),
            ("POST", BYPASS_NEWLINE_PROBE,  "newline injection in __schema field"),
            ("POST", BYPASS_FRAGMENT_PROBE, "GraphQL fragment spreading"),
        ]

        for method, probe, technique in bypass_attempts:
            if method == "GET":
                r           = self.http.get(path, params={"query": probe})
                payload_str = f"GET {path}?query={probe}"
            else:
                r           = self._gql_post(path, probe)
                payload_str = probe

            if not self._is_introspection_response(r):
                continue

            # Bypass succeeded — cache the schema
            self._schema_state.raw    = self._parse_gql(r)
            self._schema_state.status = SchemaStatus.AVAILABLE_FROM_BYPASS

            logger.info(
                f"    [VULN] GQL-S2 Introspection bypass ({technique}) → {endpoint}"
            )
            return [_vuln(
                name       = "bypass",
                endpoint   = endpoint,
                method     = method,
                payload    = payload_str,
                evidence   = (
                    f"HTTP {r.status_code} — introspection succeeded via {technique} "
                    "despite being blocked on standard POST"
                ),
                extra_desc = f"Bypass technique: {technique}.",
            )]

        logger.info(
            f"    [INFO] GQL-S2 — all bypass techniques failed on {endpoint}. "
            "Schema-dependent tests (GQL-S3) will be skipped."
        )
        return []

    # =========================================================================
    #  GQL-S3 — Sensitive field exposure
    # =========================================================================

    def _test_field_exposure(self, endpoint: str) -> list[ScanResult]:
        """
        Scan the schema for fields with sensitive names.

        Requires schema. Clear log messages explain skip/fallback behavior.
        """
        path = self._to_path(endpoint)

        # Attempt live fetch if status is UNKNOWN
        if not self._schema_state.available and self._schema_state.status == SchemaStatus.UNKNOWN:
            r = self._gql_post(path, INTROSPECTION_QUERY)
            if self._is_gql_response(r):
                full = self._parse_gql(r)
                if full and full.get("data", {}).get("__schema"):
                    self._schema_state.raw    = full
                    self._schema_state.status = SchemaStatus.AVAILABLE_FROM_SCAN

        if not self._schema_state.available:
            if self._schema_state.status == SchemaStatus.BLOCKED:
                logger.info(
                    "    [INFO] GQL-S3 Field Exposure — skipped. "
                    "Introspection blocked and bypass failed. "
                    "Tip: use --token if introspection requires authentication."
                )
            else:
                logger.info(
                    "    [INFO] GQL-S3 Field Exposure — skipped. "
                    "Schema unavailable."
                )
            return []

        # Scan all types for sensitive field names
        found: list[str] = []
        for gql_type in self._schema_state.get_types():
            if not isinstance(gql_type, dict):
                continue
            type_name = gql_type.get("name", "")
            if type_name.startswith("__"):
                continue  # skip introspection meta-types
            for f in (gql_type.get("fields") or []):
                fname = (f.get("name") or "").lower()
                for keyword in SENSITIVE_FIELDS:
                    if keyword in fname:
                        found.append(f"{type_name}.{f.get('name')}")
                        break

        if not found:
            return []

        evidence = f"Sensitive fields in schema: {', '.join(found[:8])}"
        if len(found) > 8:
            evidence += f" (+{len(found) - 8} more)"

        logger.info(
            f"    [VULN] GQL-S3 Field Exposure → {endpoint} | "
            f"{len(found)} field(s) | source: {self._schema_state.source_label}"
        )
        return [_vuln(
            name       = "fields",
            endpoint   = endpoint,
            method     = "POST",
            payload    = f"Introspection analysis ({self._schema_state.source_label})",
            evidence   = evidence,
            parameter  = ", ".join(found[:3]),
            extra_desc = (
                f"Found {len(found)} sensitive field(s): "
                f"{', '.join(found[:5])}{'...' if len(found) > 5 else ''}."
            ),
        )]

    # =========================================================================
    #  GQL-S4 — Broken authentication on mutations
    # =========================================================================

    def _test_broken_auth(self, endpoint: str) -> list[ScanResult]:
        """
        Test dangerous mutations without an auth token.

        Schema-aware: uses real mutation names when schema is available.
        Fallback: tests hardcoded DANGEROUS_MUTATIONS list.
        Always logs which source is being used.
        Token is always restored in the finally block.
        """
        path          = self._to_path(endpoint)
        schema_muts   = self._schema_state.get_mutation_names()
        using_fallback = False

        if schema_muts:
            mutations = schema_muts
            logger.debug(f"[GQL-S4] Using {len(mutations)} mutations from schema")
        else:
            mutations      = DANGEROUS_MUTATIONS
            using_fallback = True
            if self._schema_state.status == SchemaStatus.BLOCKED:
                logger.info(
                    f"    [INFO] GQL-S4 Broken Auth — schema unavailable. "
                    f"Testing {len(mutations)} hardcoded mutation names. "
                    "Results may miss non-standard mutation names."
                )

        saved_auth = self.http._session.headers.get("Authorization")
        self.http.clear_token()
        findings: list[ScanResult] = []

        try:
            for mutation_name in mutations:
                query = (
                    f"mutation {{\n"
                    f"  {mutation_name}(id: 1) {{ id }}\n"
                    f"}}"
                )
                r = self._gql_post(path, query)
                if r is None or r.status_code >= 500:
                    continue

                body_lower = (r.text or "").lower()

                is_auth_error    = (
                    r.status_code in (401, 403)
                    or any(s in body_lower for s in AUTH_ERROR_SIGNALS)
                )
                is_field_missing = (
                    r.status_code == 400
                    and any(s in body_lower for s in FIELD_MISSING_SIGNALS)
                )

                if not is_auth_error and not is_field_missing:
                    source = " (hardcoded)" if using_fallback else " (from schema)"
                    logger.info(
                        f"    [VULN] GQL-S4 Broken Auth → {endpoint} | "
                        f"mutation: {mutation_name}{source}"
                    )
                    findings.append(_vuln(
                        name       = "auth",
                        endpoint   = endpoint,
                        method     = "POST",
                        payload    = query.strip(),
                        parameter  = mutation_name,
                        evidence   = (
                            f"HTTP {r.status_code} — mutation '{mutation_name}' "
                            "responded without an authentication error"
                        ),
                        extra_desc = (
                            f"Mutation '{mutation_name}' is accessible without auth. "
                            f"Schema source: {self._schema_state.source_label}."
                        ),
                    ))
                    break  # one confirmed finding per endpoint is enough
        finally:
            if saved_auth:
                self.http._session.headers["Authorization"] = saved_auth

        return findings

    # =========================================================================
    #  GQL-S5 — IDOR via queries
    # =========================================================================

    def _test_idor(self, endpoint: str) -> list[ScanResult]:
        """
        Test for Insecure Direct Object Reference on queries accepting id arguments.

        Schema-aware: derives candidates from real schema queries.
        Fallback: uses hardcoded common resource names.
        Logs which source is being used.
        """
        path       = self._to_path(endpoint)
        candidates = self._build_idor_candidates()

        for resource, arg_name, query_tpl in candidates:
            r1 = self._gql_post(path, query_tpl % 1)
            if not self._has_data(r1, resource):
                continue

            r2 = self._gql_post(path, query_tpl % 2)
            if not self._has_data(r2, resource):
                continue

            data1 = self._parse_gql(r1).get("data", {}).get(resource)
            data2 = self._parse_gql(r2).get("data", {}).get(resource)

            if data1 and data2 and str(data1) != str(data2):
                logger.info(
                    f"    [VULN] GQL-S5 IDOR → {endpoint} | "
                    f"query: {resource}({arg_name}) | "
                    f"source: {self._schema_state.source_label}"
                )
                return [_vuln(
                    name       = "idor",
                    endpoint   = endpoint,
                    method     = "POST",
                    payload    = query_tpl % 2,
                    parameter  = f"{resource}({arg_name})",
                    evidence   = (
                        f"query {resource}({arg_name}:1) and ({arg_name}:2) "
                        "both return data — no authorization check detected"
                    ),
                    extra_desc = (
                        f"Vulnerable query: {resource}. "
                        f"Schema source: {self._schema_state.source_label}."
                    ),
                )]

        return []

    # =========================================================================
    #  GQL-S6 — CSRF via GET or text/plain
    # =========================================================================

    def _test_csrf(self, endpoint: str) -> list[ScanResult]:
        """
        Test for CSRF via HTTP methods not subject to CORS preflight.

        Schema not required — always runs.
        Uses read-only probe { __typename } — no side effects.

        Techniques:
          1. HTTP GET with ?query=  (no preflight for GET)
          2. POST with Content-Type: text/plain  (CORS-safe, no preflight)
        """
        path     = self._to_path(endpoint)
        findings: list[ScanResult] = []

        # Test 1 — GET
        r_get = self.http.get(path, params={"query": CSRF_SAFE_PROBE})
        if self._is_gql_response(r_get):
            logger.info(f"    [VULN] GQL-S6 CSRF (GET) → {endpoint}")
            findings.append(_vuln(
                name       = "csrf",
                endpoint   = endpoint,
                method     = "GET",
                payload    = f"GET {path}?query={CSRF_SAFE_PROBE}",
                evidence   = (
                    f"HTTP {r_get.status_code} — endpoint accepts "
                    "GraphQL queries via HTTP GET"
                ),
                extra_desc = (
                    "GET requests bypass CORS preflight. "
                    "An attacker can trigger mutations cross-origin."
                ),
            ))

        # Test 2 — POST text/plain
        r_plain = self.http.post(
            path,
            data    = f'{{"query": "{CSRF_SAFE_PROBE}"}}',
            headers = {"Content-Type": "text/plain"},
        )
        if self._is_gql_response(r_plain):
            logger.info(f"    [VULN] GQL-S6 CSRF (text/plain) → {endpoint}")
            findings.append(_vuln(
                name       = "csrf",
                endpoint   = endpoint,
                method     = "POST",
                payload    = (
                    f"POST {path}  Content-Type: text/plain  "
                    f'body: {{"query": "{CSRF_SAFE_PROBE}"}}'
                ),
                evidence   = (
                    f"HTTP {r_plain.status_code} — endpoint accepts "
                    "POST with Content-Type: text/plain"
                ),
                extra_desc = (
                    "text/plain is a CORS-safe type — no preflight sent. "
                    "Mutations can be triggered cross-origin."
                ),
            ))

        return findings

    # =========================================================================
    #  GQL-S9 — Batch attack
    # =========================================================================

    def _test_batch_attack(self, endpoint: str) -> list[ScanResult]:
        """
        Confirm the server accepts large batches without a size limit.
        Schema not required — always runs.
        """
        path       = self._to_path(endpoint)
        batch_size = 100
        batch      = [{"query": "{ __typename }"}] * batch_size

        r = self.http.post(path, json=batch)
        if r is None:
            return []

        body_lower = (r.text or "").lower()
        if (
            r.status_code in (400, 429)
            or r.status_code != 200
            or any(s in body_lower for s in BATCH_BLOCKED_SIGNALS)
        ):
            return []

        try:
            parsed = r.json()
        except Exception:
            return []

        if not isinstance(parsed, list) or len(parsed) < 2:
            return []

        logger.info(
            f"    [VULN] GQL-S9 Batch Attack → {endpoint} | "
            f"{len(parsed)}/{batch_size} queries processed"
        )
        return [_vuln(
            name     = "batch",
            endpoint = endpoint,
            method   = "POST",
            payload  = f"JSON array of {batch_size} query objects",
            evidence = (
                f"HTTP 200 — {len(parsed)}/{batch_size} batched queries "
                "processed without a size limit"
            ),
        )]

    # =========================================================================
    #  GQL-S10 — Alias attack
    # =========================================================================

    def _test_alias_attack(self, endpoint: str) -> list[ScanResult]:
        """
        Confirm the server resolves an unlimited number of aliases.
        Schema not required — always runs.
        """
        path        = self._to_path(endpoint)
        alias_count = 100
        aliases     = "\n  ".join(f"q{i}: __typename" for i in range(alias_count))
        query       = f"{{\n  {aliases}\n}}"

        r = self._gql_post(path, query)
        if r is None or r.status_code != 200:
            return []

        try:
            data = (self._parse_gql(r) or {}).get("data", {})
        except Exception:
            return []

        if not isinstance(data, dict) or len(data) < alias_count * 0.8:
            return []

        logger.info(
            f"    [VULN] GQL-S10 Alias Attack → {endpoint} | "
            f"{len(data)}/{alias_count} aliases resolved"
        )
        return [_vuln(
            name     = "alias",
            endpoint = endpoint,
            method   = "POST",
            payload  = f"Query with {alias_count} aliases",
            evidence = (
                f"HTTP 200 — {len(data)}/{alias_count} aliases resolved "
                "in a single request"
            ),
        )]

    # =========================================================================
    #  GQL-S11 — Depth attack
    # =========================================================================

    def _test_depth_attack(self, endpoint: str) -> list[ScanResult]:
        """
        Confirm the server accepts deeply nested queries without a depth limit.
        Uses __schema fields — always available, no schema needed.
        """
        path  = self._to_path(endpoint)
        depth = 100
        query = self._build_deep_query(depth)

        r = self._gql_post(path, query)
        if r is None:
            return []

        body_lower = (r.text or "").lower()
        if (
            r.status_code in (400, 429)
            or r.status_code >= 500
            or any(s in body_lower for s in DEPTH_BLOCKED_SIGNALS)
        ):
            return []

        logger.info(
            f"    [VULN] GQL-S11 Depth Attack → {endpoint} | "
            f"{depth} levels accepted"
        )
        return [_vuln(
            name     = "depth",
            endpoint = endpoint,
            method   = "POST",
            payload  = f"Nested query — {depth} levels deep",
            evidence = (
                f"HTTP {r.status_code} — query nested {depth} levels "
                "accepted without a depth-limit error"
            ),
        )]

    # =========================================================================
    #  GQL-S13 — Error disclosure
    # =========================================================================

    def _test_error_disclosure(self, endpoint: str) -> list[ScanResult]:
        """
        Test for verbose errors that leak internal implementation details.

        Schema not required — always runs.
        Sends 3 malformed probes and scans responses for 21 leak signals.
        """
        path = self._to_path(endpoint)

        error_probes = [
            "{ __typename nonExistentField_apisec_probe }",
            "{ ??? }",
            '{ __schema { types { fields(includeDeprecated: "INVALID") { name } } } }',
        ]

        for probe in error_probes:
            r = self._gql_post(path, probe)
            if r is None:
                continue

            try:
                body     = self._parse_gql(r)
                errors   = body.get("errors", [])
                raw_text = r.text or ""
            except Exception:
                continue

            for error in errors:
                msg = (
                    str(error.get("message",    ""))
                    + str(error.get("extensions", ""))
                    + raw_text
                )

                for signal, signal_desc in ERROR_LEAK_SIGNALS:
                    if signal.lower() in msg.lower():
                        idx     = msg.lower().find(signal.lower())
                        excerpt = msg[max(0, idx - 20) : idx + 100].strip()

                        logger.info(
                            f"    [VULN] GQL-S13 Error Disclosure → {endpoint} | "
                            f"{signal_desc}"
                        )
                        return [_vuln(
                            name       = "error",
                            endpoint   = endpoint,
                            method     = "POST",
                            payload    = probe,
                            evidence   = (
                                f"Error reveals {signal_desc}. "
                                f'Excerpt: "{excerpt[:120]}"'
                            ),
                            extra_desc = (
                                f"Signal: '{signal}' ({signal_desc}). "
                                "Production servers should return generic errors only."
                            ),
                        )]

        return []

    # =========================================================================
    #  Private helpers
    # =========================================================================

    def _to_path(self, endpoint: str) -> str:
        return endpoint.replace(self.base_url, "") or "/"

    def _gql_post(self, path: str, query: str):
        return self.http.post(path, json={"query": query})

    def _is_gql_response(self, r) -> bool:
        if r is None or r.status_code not in (200, 400):
            return False
        try:
            body = r.json()
            return isinstance(body, dict) and ("data" in body or "errors" in body)
        except Exception:
            return False

    def _is_introspection_response(self, r) -> bool:
        if not self._is_gql_response(r):
            return False
        try:
            body = self._parse_gql(r)
            return bool(
                body.get("data", {}).get("__schema")
                or body.get("data", {}).get("__type")
            )
        except Exception:
            return False

    def _has_data(self, r, key: str) -> bool:
        if not self._is_gql_response(r):
            return False
        try:
            return bool(r.json().get("data", {}).get(key))
        except Exception:
            return False

    def _parse_gql(self, r) -> dict:
        if r is None:
            return {}
        try:
            return r.json()
        except Exception:
            return {}

    def _resolve_endpoints(self, endpoints: list[str]) -> list[str]:
        keywords = ("graphql", "gql", "query", "graph")
        matched  = [
            ep for ep in endpoints
            if any(kw in ep.lower() for kw in keywords)
        ]
        if not matched:
            logger.debug("[GraphQL] No GQL endpoints — probing common paths")
            return [f"{self.base_url}{p}" for p in GRAPHQL_ENDPOINTS]
        return matched

    def _build_idor_candidates(self) -> list[tuple[str, str, str]]:
        """
        Build (resource_name, arg_name, query_template) candidates for IDOR.

        Priority:
          1. Real queries with id-like single arguments from SchemaState
          2. Hardcoded heuristic list
        """
        candidates: list[tuple[str, str, str]] = []

        for q in self._schema_state.get_query_fields():
            name    = q.get("name", "")
            args    = q.get("args", [])
            id_args = [a for a in args if "id" in a.lower()]

            if not id_args or len(args) != 1:
                continue

            arg_name = id_args[0]
            tpl      = f"query {{ {name}({arg_name}: %d) {{ id }} }}"
            candidates.append((name, arg_name, tpl))

        if candidates:
            return candidates

        if self._schema_state.status == SchemaStatus.BLOCKED:
            logger.info(
                "    [INFO] GQL-S5 IDOR — schema unavailable. "
                "Using hardcoded resource names — may miss non-standard queries."
            )

        return [
            ("user",    "id", "query { user(id: %d) { id email } }"),
            ("post",    "id", "query { post(id: %d) { id title } }"),
            ("order",   "id", "query { order(id: %d) { id total } }"),
            ("account", "id", "query { account(id: %d) { id } }"),
            ("product", "id", "query { product(id: %d) { id name } }"),
        ]

    def _build_deep_query(self, depth: int) -> str:
        inner = "name"
        for _ in range(depth - 1):
            inner = f"fields {{ name type {{ {inner} }} }}"
        return f"{{ __schema {{ types {{ {inner} }} }} }}"


# -----------------------------------------------------------------------------
#  Module-level accessor for --list-tests
# -----------------------------------------------------------------------------

def get_gql_tests() -> list[dict]:
    """
    Return all GraphQL tests with implementation status.
    Used by: apisec scan --list-tests
    """
    implemented = set(GraphQLScanner._TEST_REGISTRY.keys())
    return [
        {**entry, "name": key, "implemented": key in implemented}
        for key, entry in _vulndb.all_tests
    ]