# core/graphql_scanner.py
"""
GraphQLScanner — Automated GraphQL vulnerability detection.

Architecture:
  - Vulnerability metadata (description, OWASP, CWE, solution) lives in
    data/graphql_vulns.json — editable without touching this file.
  - This file contains only detection logic.
  - _vuln() is the single factory that builds ScanResult objects from
    the knowledge base, ensuring all 14 fields are always populated.

Tests implemented:
  GQL-S1  introspection  — Introspection exposed
  GQL-S3  fields         — Sensitive field exposure
  GQL-S4  auth           — Broken auth on mutations
  GQL-S5  idor           — IDOR via queries
  GQL-S9  batch          — Batch query attack
  GQL-S10 alias          — Alias attack / rate-limit bypass
  GQL-S11 depth          — Depth attack (DoS)

Tests planned (data/graphql_vulns.json already contains their metadata):
  GQL-S2  bypass         — Introspection bypass
  GQL-S6  csrf           — CSRF via GET / text-plain
  GQL-S7  sqli           — SQL injection in arguments
  GQL-S8  nosqli         — NoSQL injection in arguments
  GQL-S12 subscription   — Subscription abuse
  GQL-S13 error          — Error disclosure
"""

from __future__ import annotations

import json
import os
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
#  GraphQL constants
# -----------------------------------------------------------------------------

GRAPHQL_ENDPOINTS: list[str] = [
    "/graphql", "/api/graphql", "/graphql/v1",
    "/v1/graphql", "/query", "/gql",
]

SENSITIVE_FIELDS: list[str] = [
    "password", "passwd", "secret", "token", "apikey", "api_key",
    "privatekey", "private_key", "ssn", "creditcard", "credit_card",
    "cvv", "pin", "otp", "hash", "salt", "signature", "bearer",
]

DANGEROUS_MUTATIONS: list[str] = [
    "deleteUser", "deleteAccount", "promoteUser", "setRole",
    "updateRole", "grantAdmin", "revokeUser", "createAdmin",
    "resetPassword", "disableUser", "enableUser", "updatePermissions",
    "changePassword", "transferOwnership", "deleteOrganization",
]

INTROSPECTION_PROBE = "{ __schema { queryType { name } } }"

INTROSPECTION_QUERY = """
{
  __schema {
    queryType    { name }
    mutationType { name }
    types {
      name
      kind
      fields(includeDeprecated: true) {
        name
        type { kind name ofType { kind name } }
      }
    }
  }
}
"""

DEPTH_BLOCKED_SIGNALS: list[str] = [
    "max depth", "maxdepth", "query depth", "too deep",
    "complexity", "limit exceeded", "query too complex",
    "depth limit", "max complexity",
]

AUTH_ERROR_SIGNALS: list[str] = [
    "unauthorized", "unauthenticated", "forbidden",
    "not authorized", "access denied", "permission denied",
    "authentication required", "login required", "invalid token",
]

BATCH_BLOCKED_SIGNALS: list[str] = [
    "batch", "too many", "limit", "forbidden",
    "not allowed", "disabled", "batching not supported",
]


# -----------------------------------------------------------------------------
#  Knowledge base loader
# -----------------------------------------------------------------------------

class _VulnDB:
    """
    Loads data/graphql_vulns.json once and exposes per-vulnerability metadata.
    Singleton — the file is read only on first access.
    """
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
            logger.debug(f"[vulndb] Loaded {_VULNS_FILE} — {len(self._db) - 1} entries")
        except FileNotFoundError:
            logger.warning(f"[vulndb] {_VULNS_FILE} not found — metadata fields will be empty.")
            self._db = {}
        except json.JSONDecodeError as e:
            logger.error(f"[vulndb] Malformed {_VULNS_FILE}: {e}")
            self._db = {}

    def get(self, name: str) -> dict:
        return self._db.get(name, {})

    @property
    def all_tests(self) -> list[dict]:
        return [(k, v) for k, v in self._db.items() if not k.startswith("_")]


_vulndb = _VulnDB()


# -----------------------------------------------------------------------------
#  ScanResult factory
# -----------------------------------------------------------------------------

def _vuln(
    name:      str,
    endpoint:  str,
    method:    str,
    evidence:  str,
    payload:   Optional[str] = None,
    parameter: Optional[str] = None,
    extra:     Optional[str] = None,
) -> ScanResult:
    """
    Build a fully-populated ScanResult from the knowledge base.

    Runtime context (endpoint, evidence, payload) comes from the caller.
    All static metadata (description, solution, OWASP, CWE, severity,
    reference) comes from data/graphql_vulns.json.
    """
    meta = _vulndb.get(name)

    description = meta.get("description", f"Vulnerability: {name}")
    if extra:
        description = f"{description} {extra}"

    return ScanResult(
        vuln_id     = meta.get("id",          f"GQL-{name.upper()[:3]}"),
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
        solution    = meta.get("solution",  "See OWASP GraphQL Security Cheat Sheet."),
        reference   = meta.get("reference", "https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html"),
    )


# -----------------------------------------------------------------------------
#  GraphQLScanner
# -----------------------------------------------------------------------------

class GraphQLScanner:
    """
    Tests GraphQL endpoints for security vulnerabilities.

    Schema data pre-fetched during discovery is injected via the constructor
    to avoid redundant introspection requests during the scan phase.

    Usage:
        scanner = GraphQLScanner(
            base_url = "https://api.example.com",
            schema   = discovery_result["schema"],
        )
        results = scanner.scan(endpoints, tests=["introspection", "auth", "idor"])
    """

    _TEST_REGISTRY: dict[str, str] = {
        "introspection": "_test_introspection",
        "fields":        "_test_field_exposure",
        "auth":          "_test_broken_auth",
        "batch":         "_test_batch_attack",
        "alias":         "_test_alias_attack",
        "depth":         "_test_depth_attack",
        "idor":          "_test_idor",
    }

    def __init__(
        self,
        base_url: str,
        timeout:  int            = 5,
        token:    Optional[str]  = None,
        schema:   Optional[dict] = None,
    ) -> None:
        self.base_url    = base_url.rstrip("/")
        self.http        = Requester(self.base_url, timeout=timeout)
        self._schema     = schema.get("raw_introspection") if isinstance(schema, dict) else None
        self._gql_schema = schema

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
        Unknown test names (REST tests passed by main.py) are silently ignored.
        """
        active: dict[str, callable] = {}
        if tests is None:
            active = {n: getattr(self, m) for n, m in self._TEST_REGISTRY.items()}
        else:
            for name in tests:
                if name in self._TEST_REGISTRY:
                    active[name] = getattr(self, self._TEST_REGISTRY[name])

        if not active:
            logger.info("[GraphQL] No applicable tests for this API type.")
            return []

        gql_endpoints = self._resolve_endpoints(endpoints)
        if not gql_endpoints:
            logger.warning("[GraphQL] No GraphQL endpoints found.")
            return []

        logger.info(
            f"[*] GraphQL scan — {len(gql_endpoints)} endpoint(s) — "
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

        if self._schema:
            types_count = len(
                self._schema.get("data", {}).get("__schema", {}).get("types", [])
            )
            logger.info(f"    [VULN] GQL-S1 Introspection exposed -> {endpoint}")
            return [_vuln(
                name     = "introspection",
                endpoint = endpoint,
                method   = "POST",
                payload  = INTROSPECTION_PROBE,
                evidence = f"Introspection active — {types_count} types exposed (schema from discovery)",
            )]

        r_probe = self._gql_post(path, INTROSPECTION_PROBE)
        if not self._is_gql_response(r_probe):
            return []

        body = self._parse_gql(r_probe)
        if not body or "__schema" not in str(body):
            return []

        r_full = self._gql_post(path, INTROSPECTION_QUERY)
        if self._is_gql_response(r_full):
            full = self._parse_gql(r_full)
            if full:
                self._schema = full

        types_count = len(
            (self._schema or {}).get("data", {}).get("__schema", {}).get("types", [])
        )

        logger.info(f"    [VULN] GQL-S1 Introspection exposed -> {endpoint}")
        return [_vuln(
            name     = "introspection",
            endpoint = endpoint,
            method   = "POST",
            payload  = INTROSPECTION_PROBE,
            evidence = f"Introspection active — {types_count} types exposed",
        )]

    # =========================================================================
    #  GQL-S3 — Sensitive field exposure
    # =========================================================================

    def _test_field_exposure(self, endpoint: str) -> list[ScanResult]:
        path = self._to_path(endpoint)

        if not self._schema:
            r = self._gql_post(path, INTROSPECTION_QUERY)
            if not self._is_gql_response(r):
                return []
            self._schema = self._parse_gql(r)

        if not self._schema:
            return []

        types = (
            self._schema.get("data", {}).get("__schema", {}).get("types", [])
        )

        found: list[str] = []
        for gql_type in types:
            if not isinstance(gql_type, dict):
                continue
            type_name = gql_type.get("name", "")
            for field in (gql_type.get("fields") or []):
                fname = (field.get("name") or "").lower()
                for keyword in SENSITIVE_FIELDS:
                    if keyword in fname:
                        found.append(f"{type_name}.{field.get('name')}")
                        break

        if not found:
            return []

        evidence = f"Sensitive fields in schema: {', '.join(found[:8])}"
        if len(found) > 8:
            evidence += f" ... (+{len(found) - 8} more)"

        logger.info(f"    [VULN] GQL-S3 Field Exposure -> {endpoint} | {len(found)} field(s)")
        return [_vuln(
            name      = "fields",
            endpoint  = endpoint,
            method    = "POST",
            payload   = "Introspection — schema field analysis",
            evidence  = evidence,
            parameter = ", ".join(found[:3]),
            extra     = f"Found {len(found)} sensitive field(s): {', '.join(found[:5])}{'...' if len(found) > 5 else ''}.",
        )]

    # =========================================================================
    #  GQL-S4 — Broken authentication on mutations
    # =========================================================================

    def _test_broken_auth(self, endpoint: str) -> list[ScanResult]:
        path             = self._to_path(endpoint)
        mutations        = self._schema_mutations() or DANGEROUS_MUTATIONS
        saved_auth       = self.http._session.headers.get("Authorization")
        findings: list[ScanResult] = []

        self.http.clear_token()

        try:
            for mutation_name in mutations:
                query = f"mutation {{\n  {mutation_name}(id: 1) {{ id }}\n}}"
                r     = self._gql_post(path, query)
                if r is None:
                    continue

                body_lower = (r.text or "").lower()
                is_auth    = (
                    r.status_code in (401, 403)
                    or any(s in body_lower for s in AUTH_ERROR_SIGNALS)
                )
                is_missing = (
                    r.status_code == 400
                    and any(s in body_lower for s in ("cannot query field", "unknown field", "did you mean"))
                )

                if not is_auth and not is_missing and r.status_code < 500:
                    logger.info(f"    [VULN] GQL-S4 Broken Auth -> {endpoint} | {mutation_name}")
                    findings.append(_vuln(
                        name      = "auth",
                        endpoint  = endpoint,
                        method    = "POST",
                        payload   = query.strip(),
                        parameter = mutation_name,
                        evidence  = f"HTTP {r.status_code} — mutation '{mutation_name}' responded without auth error",
                        extra     = f"Accessible mutation: {mutation_name}.",
                    ))
                    break
        finally:
            if saved_auth:
                self.http._session.headers["Authorization"] = saved_auth

        return findings

    # =========================================================================
    #  GQL-S5 — IDOR via queries
    # =========================================================================

    def _test_idor(self, endpoint: str) -> list[ScanResult]:
        path       = self._to_path(endpoint)
        candidates = self._build_idor_queries()

        for resource, query_tpl in candidates:
            r1 = self._gql_post(path, query_tpl % 1)
            if not self._is_gql_data(r1, resource):
                continue

            r2 = self._gql_post(path, query_tpl % 2)
            if not self._is_gql_data(r2, resource):
                continue

            data1 = self._parse_gql(r1).get("data", {}).get(resource)
            data2 = self._parse_gql(r2).get("data", {}).get(resource)

            if data1 and data2 and str(data1) != str(data2):
                logger.info(f"    [VULN] GQL-S5 IDOR -> {endpoint} | query: {resource}")
                return [_vuln(
                    name      = "idor",
                    endpoint  = endpoint,
                    method    = "POST",
                    payload   = query_tpl % 2,
                    parameter = f"{resource}(id)",
                    evidence  = f"query {resource}(id:1) and {resource}(id:2) both return data — no authorization check",
                    extra     = f"Vulnerable query: {resource}.",
                )]

        return []

    # =========================================================================
    #  GQL-S9 — Batch query attack
    # =========================================================================

    def _test_batch_attack(self, endpoint: str) -> list[ScanResult]:
        path       = self._to_path(endpoint)
        batch_size = 50
        batch      = [{"query": "{ __typename }"}] * batch_size

        r = self.http.post(path, json=batch)
        if r is None:
            return []

        body_lower = (r.text or "").lower()
        is_blocked = (
            r.status_code in (400, 429)
            or any(s in body_lower for s in BATCH_BLOCKED_SIGNALS)
        )

        if is_blocked or r.status_code != 200:
            return []

        try:
            parsed = r.json()
        except Exception:
            return []

        if not isinstance(parsed, list) or len(parsed) < 2:
            return []

        logger.info(f"    [VULN] GQL-S9 Batch Attack -> {endpoint} | {len(parsed)} queries processed")
        return [_vuln(
            name     = "batch",
            endpoint = endpoint,
            method   = "POST",
            payload  = f"Array of {batch_size} query objects",
            evidence = f"HTTP 200 — {len(parsed)} responses for a batch of {batch_size} — no limit enforced",
        )]

    # =========================================================================
    #  GQL-S10 — Alias attack
    # =========================================================================

    def _test_alias_attack(self, endpoint: str) -> list[ScanResult]:
        path        = self._to_path(endpoint)
        alias_count = 30
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

        logger.info(f"    [VULN] GQL-S10 Alias Attack -> {endpoint} | {len(data)}/{alias_count} aliases")
        return [_vuln(
            name     = "alias",
            endpoint = endpoint,
            method   = "POST",
            payload  = f"Query with {alias_count} aliases",
            evidence = f"HTTP 200 — {len(data)}/{alias_count} aliases resolved — no alias limit enforced",
        )]

    # =========================================================================
    #  GQL-S11 — Depth attack
    # =========================================================================

    def _test_depth_attack(self, endpoint: str) -> list[ScanResult]:
        path  = self._to_path(endpoint)
        depth = 12
        query = self._build_deep_query(depth)

        r = self._gql_post(path, query)
        if r is None:
            return []

        body_lower = (r.text or "").lower()
        is_blocked = (
            r.status_code in (400, 429)
            or any(s in body_lower for s in DEPTH_BLOCKED_SIGNALS)
        )

        if is_blocked or r.status_code >= 500:
            return []

        logger.info(f"    [VULN] GQL-S11 Depth Attack -> {endpoint} | {depth} levels accepted")
        return [_vuln(
            name     = "depth",
            endpoint = endpoint,
            method   = "POST",
            payload  = f"Nested query — {depth} levels deep",
            evidence = f"HTTP {r.status_code} — query nested {depth} levels accepted without depth-limit error",
        )]

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

    def _is_gql_data(self, r, key: str) -> bool:
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
        matched  = [ep for ep in endpoints if any(kw in ep.lower() for kw in keywords)]
        if not matched:
            return [f"{self.base_url}{p}" for p in GRAPHQL_ENDPOINTS]
        return matched

    def _schema_mutations(self) -> list[str]:
        if not self._schema:
            return []
        schema_data = self._schema.get("data", {}).get("__schema", {})
        mut_type    = (schema_data.get("mutationType") or {}).get("name", "")
        if not mut_type:
            return []
        for t in schema_data.get("types", []):
            if t.get("name") == mut_type:
                return [f.get("name", "") for f in (t.get("fields") or [])]
        return []

    def _build_idor_queries(self) -> list[tuple[str, str]]:
        candidates: list[tuple[str, str]] = []

        if self._gql_schema:
            for q in self._gql_schema.get("queries", []):
                name    = q.get("name", "")
                args    = q.get("args", [])
                id_args = [a for a in args if "id" in a.lower()]
                if len(args) == 1 and id_args:
                    tpl = f"query {{ {name}({id_args[0]}: %d) {{ id }} }}"
                    candidates.append((name, tpl))

        if candidates:
            return candidates

        return [
            ("user",    "query { user(id: %d) { id email name } }"),
            ("post",    "query { post(id: %d) { id title content } }"),
            ("order",   "query { order(id: %d) { id total status } }"),
            ("account", "query { account(id: %d) { id balance } }"),
            ("product", "query { product(id: %d) { id name price } }"),
        ]

    def _build_deep_query(self, depth: int) -> str:
        inner = "name"
        for _ in range(depth - 1):
            inner = f"fields {{ name type {{ {inner} }} }}"
        return f"{{ __schema {{ types {{ {inner} }} }} }}"


# -----------------------------------------------------------------------------
#  Module-level accessor for --list-tests in main.py
# -----------------------------------------------------------------------------

def get_gql_tests() -> list[dict]:
    """
    Return all GraphQL tests from the knowledge base with implementation status.
    Used by: apisec scan --list-tests (when api_type == GraphQL)
    """
    implemented = set(GraphQLScanner._TEST_REGISTRY.keys())
    result      = []

    for key, entry in _vulndb.all_tests:
        result.append({
            **entry,
            "name":        key,
            "implemented": key in implemented,
        })

    return result