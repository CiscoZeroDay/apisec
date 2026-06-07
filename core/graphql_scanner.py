# core/graphql_scanner.py
"""
GraphQLScanner — Automated GraphQL vulnerability detection.

Architecture:
  - Vulnerability metadata lives in data/graphql_vulns.json — never hardcoded.
  - This file contains only detection logic.
  - _vuln() is the single ScanResult factory — all 14 fields always populated.
  - SchemaState tracks introspection availability across all tests.

Schema availability matrix:
  ┌──────────────────────────┬─────────────────────────────────────────────┐
  │ Test                     │ Behavior when schema unavailable            │
  ├──────────────────────────┼─────────────────────────────────────────────┤
  │ GQL-S1 introspection     │ Probes live — logs if blocked               │
  │ GQL-S2 bypass            │ Only runs when S1 is blocked                │
  │                          │ → tries GET, newline, fragment, clairvoyance│
  │ GQL-S3 fields            │ Skipped with INFO log — needs schema        │
  │ GQL-S4 auth              │ Falls back to hardcoded mutation names      │
  │ GQL-S5 idor              │ Falls back to hardcoded query names         │
  │ GQL-S6 csrf              │ Always runs — schema-independent            │
  │ GQL-S9 batch             │ Always runs — schema-independent            │
  │ GQL-S10 alias            │ Always runs — schema-independent            │
  │ GQL-S11 depth            │ Always runs — schema-independent            │
  │ GQL-S13 error            │ Always runs — schema-independent            │
  └──────────────────────────┴─────────────────────────────────────────────┘

Schema sources (priority order):
  1. AVAILABLE_FROM_DISCOVERY    : schema pre-fetched during API discovery
  2. AVAILABLE_FROM_SCAN         : live introspection during scan
  3. AVAILABLE_FROM_BYPASS       : bypass technique (GET/newline/fragment)
  4. AVAILABLE_FROM_CLAIRVOYANCE : reconstructed via field suggestions

Tests implemented  : GQL-S1 S2 S3 S4 S5 S6 S9 S10 S11 S13  (10/13)
Tests planned      : GQL-S7 (sqli) S8 (nosqli) S12 (subscription)
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from enum import Enum, auto
from typing import Optional

from core.models    import ScanResult
from core.requester import Requester
from logger.logger  import logger


# -----------------------------------------------------------------------------
#  Paths
# -----------------------------------------------------------------------------

_VULNS_FILE   = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "data", "graphql_vulns.json",
)
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_WL_DIR       = os.path.join(_PROJECT_ROOT, "wordlists", "graphql_wordlist", "10k")
_WL_DIR_1K    = os.path.join(_PROJECT_ROOT, "wordlists", "graphql_wordlist", "1k")
_FIELD_WL     = os.path.join(_WL_DIR, "fieldWordlist-10k.txt")


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

BYPASS_NEWLINE_PROBE  = "{ __schema\n{ queryType { name } } }"
BYPASS_FRAGMENT_PROBE = (
    "query { ...F } "
    "fragment F on Query { __schema { queryType { name } } }"
)

CSRF_SAFE_PROBE = "{ __typename }"

_CLAIRVOYANCE_TIMEOUT = 300   # 5 minutes max for schema reconstruction


# -----------------------------------------------------------------------------
#  Wordlist loader
# -----------------------------------------------------------------------------

def _load_wordlist(filename: str, fallback: list[str]) -> list[str]:
    for directory in (_WL_DIR, _WL_DIR_1K):
        path = os.path.join(directory, filename)
        if os.path.isfile(path):
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    words = [line.strip() for line in f if line.strip()]
                if words:
                    logger.debug(f"[wordlist] Loaded {len(words)} entries from {path}")
                    return words
            except OSError as e:
                logger.warning(f"[wordlist] Cannot read {path}: {e}")
    logger.debug(
        f"[wordlist] {filename} not found — "
        f"using built-in fallback ({len(fallback)} entries)"
    )
    return fallback


# -----------------------------------------------------------------------------
#  Wordlists
# -----------------------------------------------------------------------------

_SENSITIVE_FIELDS_FALLBACK: list[str] = [
    "password", "passwd", "secret", "token", "apikey", "api_key",
    "privatekey", "private_key", "ssn", "creditcard", "credit_card",
    "cvv", "pin", "otp", "hash", "salt", "signature", "bearer",
    "auth", "credential", "key", "access", "refresh", "session",
    "private", "master", "admin", "root",
]

# SENSITIVE_FIELDS — static schema analysis only (no HTTP requests).
# Loading 10k words is fine here — it is a keyword comparison against
# field names already retrieved from the schema. Zero HTTP requests.
SENSITIVE_FIELDS: list[str] = _load_wordlist(
    "fieldWordlist-10k.txt",
    _SENSITIVE_FIELDS_FALLBACK,
)

_DANGEROUS_MUTATIONS_FALLBACK: list[str] = [
    "deleteUser", "deleteAccount", "promoteUser", "setRole",
    "updateRole", "grantAdmin", "revokeUser", "createAdmin",
    "resetPassword", "disableUser", "enableUser", "updatePermissions",
    "changePassword", "transferOwnership", "deleteOrganization",
    "removeUser", "banUser", "elevatePrivilege", "setAdmin",
    "updatePassword", "createUser", "destroyAccount",
]

# DANGEROUS_MUTATIONS — fallback for GQL-S4 when schema is unavailable.
#
# Design decision: intentionally NOT loaded from the 10k wordlist.
#
# GQL-S4 logic:
#   - Schema available (introspection or bypass succeeded):
#       → uses real mutation names from schema → this list is NEVER used
#   - Schema unavailable (all bypasses + clairvoyance failed):
#       → uses this list as fallback → ~22 targeted entries = ~22 HTTP requests
#
# Loading mutationFieldWordlist-10k.txt here would fire 10 000 HTTP requests
# even when the schema is available — defeating the entire purpose of
# schema-driven scanning. The 10k wordlist is reserved for Clairvoyance
# (passed as a subprocess argument, not iterated as HTTP probes).
DANGEROUS_MUTATIONS: list[str] = _DANGEROUS_MUTATIONS_FALLBACK

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

BUILTIN_SCALARS: set[str] = {
    "String", "Int", "Float", "Boolean", "ID",
}

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
#  SchemaStatus
# -----------------------------------------------------------------------------

class SchemaStatus(Enum):
    AVAILABLE_FROM_DISCOVERY    = auto()
    AVAILABLE_FROM_SCAN         = auto()
    AVAILABLE_FROM_BYPASS       = auto()
    AVAILABLE_FROM_CLAIRVOYANCE = auto()
    BLOCKED                     = auto()
    UNKNOWN                     = auto()


@dataclass
class SchemaState:
    """Tracks schema availability across all test methods in a scan session."""

    status:     SchemaStatus = SchemaStatus.UNKNOWN
    raw:        Optional[dict] = None
    gql_schema: Optional[dict] = None

    @property
    def available(self) -> bool:
        return self.raw is not None

    @property
    def source_label(self) -> str:
        return {
            SchemaStatus.AVAILABLE_FROM_DISCOVERY:    "discovery",
            SchemaStatus.AVAILABLE_FROM_SCAN:         "live scan",
            SchemaStatus.AVAILABLE_FROM_BYPASS:       "bypass (GQL-S2)",
            SchemaStatus.AVAILABLE_FROM_CLAIRVOYANCE: "clairvoyance (no introspection)",
            SchemaStatus.BLOCKED:                     "blocked",
            SchemaStatus.UNKNOWN:                     "unknown",
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
            logger.debug(f"[vulndb] graphql — {len(self._db) - 1} entries loaded")
        except FileNotFoundError:
            logger.warning(f"[vulndb] {_VULNS_FILE} not found")
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
    confidence: Optional[str] = None,
) -> ScanResult:
    """
    Build a fully-populated ScanResult from the knowledge base.

    Args:
        name       : Key in graphql_vulns.json
        endpoint   : Full endpoint URL
        method     : HTTP method used
        evidence   : Runtime evidence (what was observed)
        payload    : Payload that triggered the finding
        parameter  : Affected parameter name
        extra_desc : Additional context appended to description
        confidence : Override vulnDB confidence (use "MEDIUM" for Clairvoyance)
    """
    meta        = _vulndb.get(name)
    description = meta.get("description", f"Vulnerability detected: {name}")
    if extra_desc:
        description = f"{description} {extra_desc}"
    return ScanResult(
        vuln_id     = meta.get("id",          f"GQL-{name.upper()[:4]}"),
        vuln_type   = meta.get("label",        name),
        severity    = meta.get("severity",     "MEDIUM"),
        confidence  = confidence or meta.get("confidence", "MEDIUM"),
        owasp       = meta.get("owasp",        "API8:2023"),
        cwe         = meta.get("cwe",          "CWE-200"),
        endpoint    = endpoint,
        method      = method,
        parameter   = parameter,
        payload     = payload,
        evidence    = evidence,
        description = description,
        solution    = meta.get("solution",    "See OWASP GraphQL Security Cheat Sheet."),
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

    Includes Clairvoyance integration for schema reconstruction when
    introspection is disabled.
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
        self.base_url      = base_url.rstrip("/")
        self.http          = Requester(self.base_url, timeout=timeout)
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
        path = self._to_path(endpoint)

        if self._schema_state.status == SchemaStatus.AVAILABLE_FROM_DISCOVERY:
            real_types  = [
                t for t in self._schema_state.get_types()
                if t.get("name")
                and not t["name"].startswith("__")
                and t["name"] not in BUILTIN_SCALARS
            ]
            types_count = len(real_types)

            # Resolve the real HTTP method used during discovery.
            # discovery.py stores the method in schema["method"] e.g.
            # "bypass_newline_get" -> GET, "post" -> POST.
            disc_method = ""
            if isinstance(self._schema_state.gql_schema, dict):
                disc_method = self._schema_state.gql_schema.get("method", "").lower()

            if "get" in disc_method:
                real_method  = "GET"
                real_payload = f"GET {path}?query={INTROSPECTION_PROBE}"
            else:
                real_method  = "POST"
                real_payload = INTROSPECTION_PROBE

            logger.info(f"    [VULN] GQL-S1 Introspection exposed → {endpoint}")
            return [_vuln(
                name     = "introspection",
                endpoint = endpoint,
                method   = real_method,
                payload  = real_payload,
                evidence = (
                    f"Introspection active — {types_count} user-defined types exposed "
                    f"(schema pre-fetched during discovery via {disc_method or 'unknown'})"
                ),
            )]

        r = self._gql_post(path, INTROSPECTION_PROBE)

        if not self._is_gql_response(r):
            logger.info(
                f"    [INFO] GQL-S1 — endpoint not reachable or not GraphQL: {endpoint}"
            )
            return []

        body = self._parse_gql(r)

        if not body.get("data", {}).get("__schema"):
            self._schema_state.status = SchemaStatus.BLOCKED
            logger.info(
                f"    [INFO] GQL-S1 — introspection disabled on {endpoint}. "
                "GQL-S2 bypass will be attempted next."
            )
            return []

        r_full = self._gql_post(path, INTROSPECTION_QUERY)
        if self._is_gql_response(r_full):
            full = self._parse_gql(r_full)
            if full and full.get("data", {}).get("__schema"):
                self._schema_state.raw    = full
                self._schema_state.status = SchemaStatus.AVAILABLE_FROM_SCAN

        real_types  = [
            t for t in self._schema_state.get_types()
            if t.get("name")
            and not t["name"].startswith("__")
            and t["name"] not in BUILTIN_SCALARS
        ]
        types_count = len(real_types)
        logger.info(f"    [VULN] GQL-S1 Introspection exposed → {endpoint}")
        return [_vuln(
            name     = "introspection",
            endpoint = endpoint,
            method   = "POST",
            payload  = INTROSPECTION_PROBE,
            evidence = f"Introspection active — {types_count} user-defined types exposed",
        )]

    # =========================================================================
    #  GQL-S2 — Introspection bypass + Clairvoyance
    # =========================================================================

    def _test_introspection_bypass(self, endpoint: str) -> list[ScanResult]:
        """
        Attempt to retrieve the schema when standard introspection is blocked.

        Techniques (in order):
          1. GET ?query=         — bypasses POST-only filters
          2. Newline injection   — bypasses naive string matching
          3. Fragment spreading  — bypasses keyword-based WAF rules
          4. Clairvoyance        — field suggestion enumeration (last resort)
        """
        if self._schema_state.available:
            logger.debug(
                "[GQL-S2] Skipped — schema already available "
                f"({self._schema_state.source_label})"
            )
            return []

        if self._schema_state.status == SchemaStatus.UNKNOWN:
            logger.debug("[GQL-S2] Skipped — run GQL-S1 first.")
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

        # All traditional bypasses failed — try Clairvoyance
        if self._run_clairvoyance(endpoint):
            real_types = [
                t for t in self._schema_state.get_types()
                if t.get("name") and not t["name"].startswith("__")
            ]
            logger.info(
                f"    [VULN] GQL-S2 Schema via Clairvoyance → {endpoint} | "
                f"{len(real_types)} types reconstructed"
            )
            return [_vuln(
                name       = "bypass",
                endpoint   = endpoint,
                method     = "POST",
                payload    = "clairvoyance field-suggestion enumeration",
                evidence   = (
                    f"Schema reconstructed without introspection — "
                    f"{len(real_types)} types discovered via field suggestions."
                ),
                extra_desc = (
                    "Clairvoyance exploits 'Did you mean X?' error messages "
                    "to reconstruct the schema. "
                    "Disable field suggestions in production."
                ),
            )]

        logger.info(
            f"    [INFO] GQL-S2 — all bypass techniques and clairvoyance failed "
            f"on {endpoint}. Schema-dependent tests will be skipped."
        )
        return []

    # =========================================================================
    #  GQL-S3 — Sensitive field exposure
    # =========================================================================

    def _test_field_exposure(self, endpoint: str) -> list[ScanResult]:
        path = self._to_path(endpoint)

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
                    "Introspection blocked and bypass/clairvoyance failed. "
                    "Tip: use --token if introspection requires authentication."
                )
            else:
                logger.info(
                    "    [INFO] GQL-S3 Field Exposure — skipped. Schema unavailable."
                )
            return []

        found: list[str] = []
        for gql_type in self._schema_state.get_types():
            if not isinstance(gql_type, dict):
                continue
            type_name = gql_type.get("name", "")
            if type_name.startswith("__"):
                continue
            for f in (gql_type.get("fields") or []):
                fname = (f.get("name") or "").lower()
                for keyword in SENSITIVE_FIELDS:
                    if keyword in fname:
                        found.append(f"{type_name}.{f.get('name')}")
                        break

        if not found:
            return []

        is_clairvoyance = (
            self._schema_state.status == SchemaStatus.AVAILABLE_FROM_CLAIRVOYANCE
        )
        confidence = "MEDIUM" if is_clairvoyance else "HIGH"
        clairvoyance_note = (
            " ⚠ Schema from Clairvoyance — manual verification required."
            if is_clairvoyance else ""
        )

        evidence = f"Sensitive fields in schema: {', '.join(found[:8])}"
        if len(found) > 8:
            evidence += f" (+{len(found) - 8} more)"
        if clairvoyance_note:
            evidence += f" |{clairvoyance_note}"

        logger.info(
            f"    [VULN] GQL-S3 Field Exposure → {endpoint} | "
            f"{len(found)} field(s) | source: {self._schema_state.source_label} | "
            f"confidence: {confidence}"
        )
        return [_vuln(
            name       = "fields",
            endpoint   = endpoint,
            method     = "POST",
            payload    = f"Introspection analysis ({self._schema_state.source_label})",
            evidence   = evidence,
            parameter  = ", ".join(found[:3]),
            confidence = confidence,
            extra_desc = (
                f"Found {len(found)} sensitive field(s): "
                f"{', '.join(found[:5])}{'...' if len(found) > 5 else ''}."
                + clairvoyance_note
            ),
        )]

    # =========================================================================
    #  GQL-S4 — Broken authentication on mutations
    # =========================================================================

    def _test_broken_auth(self, endpoint: str) -> list[ScanResult]:
        """
        Test dangerous mutations without an auth token.

        Flow:
          1. Schema available → use real mutation names from schema
             (exact names — no guessing, no wordlist)
          2. Schema unavailable → use DANGEROUS_MUTATIONS (~22 hardcoded names)

        The 10k mutationFieldWordlist is NOT used here.
        It would fire 10 000 HTTP requests even when schema is available.
        When schema is available (the common case after GQL-S1/S2), the
        hardcoded fallback is never reached.
        """
        path        = self._to_path(endpoint)
        schema_muts = self._schema_state.get_mutation_names()

        # Fix 1 — If schema is available and has no mutations, skip immediately.
        # No point testing mutations that don't exist — prevents false positives
        # on read-only APIs (queries only, no mutations defined in schema).
        if self._schema_state.available and not schema_muts:
            logger.info(
                "    [INFO] GQL-S4 Broken Auth — skipped. "
                "Schema has no mutations defined."
            )
            return []

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

                is_auth_error = (
                    r.status_code in (401, 403)
                    or any(s in body_lower for s in AUTH_ERROR_SIGNALS)
                )
                # Fix 2 — GraphQL servers return HTTP 200 even for field errors.
                # Checking only status_code == 400 misses most "field not found"
                # responses. Check body content regardless of status code.
                is_field_missing = any(s in body_lower for s in FIELD_MISSING_SIGNALS)

                if not is_auth_error and not is_field_missing:
                    source = " (hardcoded)" if using_fallback else " (from schema)"

                    is_clairvoyance = (
                        self._schema_state.status ==
                        SchemaStatus.AVAILABLE_FROM_CLAIRVOYANCE
                    )
                    confidence = "MEDIUM" if is_clairvoyance else "HIGH"
                    clairvoyance_note = (
                        " ⚠ Schema from Clairvoyance — manual verification required."
                        if is_clairvoyance else ""
                    )

                    logger.info(
                        f"    [VULN] GQL-S4 Broken Auth → {endpoint} | "
                        f"mutation: {mutation_name}{source} | confidence: {confidence}"
                    )
                    findings.append(_vuln(
                        name       = "auth",
                        endpoint   = endpoint,
                        method     = "POST",
                        payload    = query.strip(),
                        parameter  = mutation_name,
                        confidence = confidence,
                        evidence   = (
                            f"HTTP {r.status_code} — mutation '{mutation_name}' "
                            "responded without an authentication error"
                            + (f" | {clairvoyance_note}" if clairvoyance_note else "")
                        ),
                        extra_desc = (
                            f"Mutation '{mutation_name}' accessible without auth. "
                            f"Schema source: {self._schema_state.source_label}."
                            + clairvoyance_note
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
        path     = self._to_path(endpoint)
        findings: list[ScanResult] = []

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
    #  Clairvoyance integration
    # =========================================================================

    @staticmethod
    def _check_clairvoyance() -> bool:
        return bool(shutil.which("clairvoyance"))

    def _run_clairvoyance(self, endpoint: str) -> bool:
        """
        Run clairvoyance to reconstruct the GraphQL schema without introspection.

        The fieldWordlist-10k.txt is passed to the clairvoyance subprocess
        as its wordlist argument — it is NOT iterated as HTTP probes by APISec.
        Clairvoyance handles the enumeration internally.

        Returns True if schema was successfully reconstructed.
        Updates self._schema_state on success.
        """
        if not self._check_clairvoyance():
            logger.debug(
                "[gql] clairvoyance not found — "
                "install with: pip install clairvoyance"
            )
            return False

        logger.info(
            f"    [gql] Introspection blocked — launching clairvoyance "
            f"for schema reconstruction -> {endpoint}"
        )

        output_path: Optional[str] = None

        try:
            with tempfile.NamedTemporaryFile(
                mode   = "w",
                suffix = ".json",
                delete = False,
                prefix = "apisec_clairvoyance_",
            ) as tmp:
                output_path = tmp.name

            cmd = [
                "clairvoyance",
                endpoint,
                "-o", output_path,
                "-c", "5",
                "-k",
                "-p", "slow",
            ]

            if os.path.isfile(_FIELD_WL):
                cmd.extend(["-w", _FIELD_WL])
                logger.debug(f"    [gql] clairvoyance wordlist: {_FIELD_WL}")

            auth_header = self.http._session.headers.get("Authorization")
            if auth_header:
                cmd.extend(["-H", f"Authorization: {auth_header}"])

            result = subprocess.run(
                cmd,
                capture_output = True,
                text           = True,
                timeout        = _CLAIRVOYANCE_TIMEOUT,
                encoding       = "utf-8",
                errors         = "replace",
            )

            if result.stderr and result.stderr.strip():
                for line in result.stderr.strip().splitlines()[:5]:
                    logger.debug(f"    [gql] clairvoyance: {line.strip()}")

            if not output_path or not os.path.isfile(output_path):
                logger.debug("    [gql] clairvoyance produced no output file")
                return False

            with open(output_path, "r", encoding="utf-8") as f:
                content = f.read().strip()

            if not content:
                logger.debug("    [gql] clairvoyance output is empty")
                return False

            schema_json = json.loads(content)
            all_types   = (
                schema_json.get("data", {})
                           .get("__schema", {})
                           .get("types", [])
            )
            real_types  = [
                t for t in all_types
                if t.get("name") and not t["name"].startswith("__")
            ]

            if not real_types:
                logger.debug(
                    "    [gql] clairvoyance schema has no real types — "
                    "field suggestions may be disabled on this server"
                )
                return False

            self._schema_state.raw    = schema_json
            self._schema_state.status = SchemaStatus.AVAILABLE_FROM_CLAIRVOYANCE

            logger.info(
                f"    [gql] clairvoyance SUCCESS — "
                f"{len(real_types)} types reconstructed -> {endpoint}"
            )
            return True

        except subprocess.TimeoutExpired:
            logger.warning(
                f"    [gql] clairvoyance timeout ({_CLAIRVOYANCE_TIMEOUT}s) "
                f"-> {endpoint}"
            )
            return False

        except json.JSONDecodeError as e:
            logger.debug(f"    [gql] clairvoyance JSON parse error: {e}")
            return False

        except FileNotFoundError:
            logger.debug("    [gql] clairvoyance binary not found")
            return False

        except Exception as e:
            logger.debug(f"    [gql] clairvoyance error: {e}")
            return False

        finally:
            if output_path:
                try:
                    if os.path.isfile(output_path):
                        os.unlink(output_path)
                except Exception:
                    pass

    # =========================================================================
    #  Private helpers
    # =========================================================================

    def _to_path(self, endpoint: str) -> str:
        return endpoint.replace(self.base_url, "") or "/"

    def _gql_post(self, path: str, query: str):
        """
        Send a GraphQL query — POST first, GET fallback if 405.

        PATCH: Some servers only accept GET requests for GraphQL queries.
        PortSwigger Lab 3: POST /api → 405 Method Not Allowed
                           GET  /api?query=... → 200 OK

        All tests use _gql_post() so GET-only endpoints are handled
        transparently without changing any individual test logic.
        """
        r = self.http.post(path, json={"query": query})

        # GET fallback — POST rejected with 405 (Method Not Allowed)
        if r is None or r.status_code == 405:
            r = self.http.get(path, params={"query": query})

        return r

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
        """
        Return GraphQL-capable endpoints to scan.

        Priority:
          1. Endpoints passed in → always trusted (already confirmed by discovery)
          2. Common path probing → only when endpoints list is empty

        Rationale:
          Discovery already validated these endpoints as GraphQL — no need to
          filter by keyword or replace with hardcoded candidates. Doing so was
          the source of false positives (e.g. /api confirmed as GraphQL but
          filtered out because it doesn't contain 'graphql'/'gql'/'query').
        """
        if endpoints:
            return endpoints

        # No endpoints at all → probe common paths as last resort
        logger.debug("[GraphQL] No endpoints provided — probing common paths")
        return [f"{self.base_url}{p}" for p in GRAPHQL_ENDPOINTS]

    def _build_idor_candidates(self) -> list[tuple[str, str, str]]:
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
                "Using hardcoded resource names."
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
    implemented = set(GraphQLScanner._TEST_REGISTRY.keys())
    return [
        {**entry, "name": key, "implemented": key in implemented}
        for key, entry in _vulndb.all_tests
    ]