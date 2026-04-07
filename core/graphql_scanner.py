# core/scanners/graphql_scanner.py
"""
GraphQLScanner — Détection automatisée de vulnérabilités GraphQL.

Vulnérabilités détectées :
  - Introspection     : schéma exposé publiquement
  - DepthAttack       : requêtes imbriquées → DoS potentiel
  - FieldExposure     : champs sensibles accessibles (password, token, secret)
  - BrokenAuth        : mutations admin sans privilèges
  - BatchAttack       : batching de requêtes non limité
  - AliasAttack       : contournement rate-limit via aliases
  - IDOR              : accès aux ressources d'autres utilisateurs via queries
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Optional

from core.requester import Requester
from logger.logger import logger


# ─────────────────────────────────────────────────────────────────────────────
#  Constantes
# ─────────────────────────────────────────────────────────────────────────────

# Endpoints GraphQL courants
GRAPHQL_ENDPOINTS: list[str] = [
    "/graphql",
    "/api/graphql",
    "/v1/graphql",
    "/query",
    "/gql",
]

# Champs sensibles à rechercher dans le schéma
SENSITIVE_FIELDS: list[str] = [
    "password", "passwd", "secret", "token", "apikey", "api_key",
    "privatekey", "private_key", "ssn", "creditcard", "credit_card",
    "cvv", "pin", "otp", "hash", "salt", "signature",
]

# Mutations potentiellement dangereuses
DANGEROUS_MUTATIONS: list[str] = [
    "deleteUser", "deleteAccount", "promoteUser", "setRole",
    "updateRole", "grantAdmin", "revokeUser", "createAdmin",
    "resetPassword", "disableUser", "enableUser", "updatePermissions",
]

# Requête d'introspection complète
INTROSPECTION_QUERY = """
{
  __schema {
    types {
      name
      kind
      fields {
        name
        type {
          name
          kind
        }
      }
    }
    queryType { name }
    mutationType { name }
  }
}
"""

# Requête d'introspection minimale (test rapide)
INTROSPECTION_PROBE = '{ __schema { queryType { name } } }'


# ─────────────────────────────────────────────────────────────────────────────
#  ScanResult
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class ScanResult:
    """Résultat d'une vulnérabilité GraphQL détectée."""

    vuln_type:   str
    severity:    str            # CRITICAL | HIGH | MEDIUM | LOW
    endpoint:    str
    method:      str
    payload:     Optional[str]
    evidence:    str
    description: str

    def to_dict(self) -> dict:
        return {
            "vuln_type":   self.vuln_type,
            "severity":    self.severity,
            "endpoint":    self.endpoint,
            "method":      self.method,
            "payload":     self.payload,
            "evidence":    self.evidence,
            "description": self.description,
        }

    def __str__(self) -> str:
        return (
            f"[{self.severity}] {self.vuln_type} — {self.endpoint}\n"
            f"  Payload  : {self.payload}\n"
            f"  Evidence : {self.evidence[:120]}"
        )


# ─────────────────────────────────────────────────────────────────────────────
#  GraphQLScanner
# ─────────────────────────────────────────────────────────────────────────────

class GraphQLScanner:
    """
    Teste les endpoints GraphQL pour des vulnérabilités communes.

    Utilisation :
        scanner = GraphQLScanner("https://api.example.com")
        results = scanner.scan(endpoints)
    """

    def __init__(
        self,
        base_url: str,
        timeout: int = 5,
        token: Optional[str] = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.http     = Requester(self.base_url, timeout=timeout)
        self._schema: Optional[dict] = None   # cache du schéma introspection

        if token:
            self.http.set_token(token)

    # =========================================================================
    #  Point d'entrée
    # =========================================================================

    def scan(self, endpoints: list[str], tests: Optional[list[str]] = None) -> list[ScanResult]:
        """
        Lance tous les tests GraphQL sur les endpoints fournis.

        Args:
            endpoints : liste d'URLs complètes (depuis discovery)
            tests     : sous-ensemble de tests à lancer (None = tous)

        Returns:
            Liste de ScanResult.
        """
        ALL_TESTS = {
            "introspection": self._test_introspection,
            "depth":         self._test_depth_attack,
            "fields":        self._test_field_exposure,
            "auth":          self._test_broken_auth,
            "batch":         self._test_batch_attack,
            "alias":         self._test_alias_attack,
            "idor":          self._test_idor,
        }

        active = {k: v for k, v in ALL_TESTS.items()
                  if tests is None or k in tests}

        results: list[ScanResult] = []

        # Filtre les endpoints GraphQL
        gql_endpoints = self._filter_graphql_endpoints(endpoints)

        if not gql_endpoints:
            logger.warning("[GraphQL] Aucun endpoint GraphQL détecté dans la liste fournie.")
            logger.info("[GraphQL] Tentative sur les paths courants...")
            gql_endpoints = [f"{self.base_url}{path}" for path in GRAPHQL_ENDPOINTS]

        logger.info(f"[*] GraphQL scan — {len(gql_endpoints)} endpoint(s) — tests : {list(active.keys())}")

        for endpoint in gql_endpoints:
            logger.debug(f"    [gql] {endpoint}")

            for test_name, test_fn in active.items():
                try:
                    results += test_fn(endpoint)
                except Exception as e:
                    logger.debug(f"    [gql:{test_name}] erreur : {e}")

        logger.info(f"[+] GraphQL scan terminé — {len(results)} vulnérabilité(s) détectée(s)")
        return results

    # =========================================================================
    #  Test 1 — Introspection activée
    # =========================================================================

    def _test_introspection(self, endpoint: str) -> list[ScanResult]:
        """
        Teste si l'introspection GraphQL est activée.
        Une introspection activée expose toute l'architecture de l'API.
        """
        results: list[ScanResult] = []
        path    = self._to_path(endpoint)

        # Probe rapide
        r = self._gql_post(path, INTROSPECTION_PROBE)
        if not self._is_gql_success(r):
            return results

        data = self._parse_gql(r)
        if not data or "__schema" not in str(data):
            return results

        # Introspection complète pour récupérer le schéma
        r_full = self._gql_post(path, INTROSPECTION_QUERY)
        if self._is_gql_success(r_full):
            full_data = self._parse_gql(r_full)
            if full_data:
                self._schema = full_data  # cache pour les autres tests

        types_count = 0
        if self._schema:
            types_count = len(
                self._schema.get("data", {})
                    .get("__schema", {})
                    .get("types", [])
            )

        evidence = f"Introspection active — {types_count} types exposés"
        results.append(ScanResult(
            vuln_type   = "Introspection",
            severity    = "MEDIUM",
            endpoint    = endpoint,
            method      = "POST",
            payload     = INTROSPECTION_PROBE.strip(),
            evidence    = evidence,
            description = (
                "L'introspection GraphQL est activée. Un attaquant peut mapper "
                "l'intégralité du schéma : queries, mutations, types et champs. "
                "Désactiver l'introspection en production."
            ),
        ))
        logger.info(f"    [VULN] Introspection active → {endpoint}")
        return results

    # =========================================================================
    #  Test 2 — Depth Attack (DoS)
    # =========================================================================

    def _test_depth_attack(self, endpoint: str) -> list[ScanResult]:
        """
        Envoie une requête imbriquée sur 10+ niveaux.
        Si le serveur répond 200 sans limite → vulnérable au DoS.
        """
        results: list[ScanResult] = []
        path    = self._to_path(endpoint)

        # Construit une requête imbriquée sur 12 niveaux
        depth   = 12
        query   = self._build_deep_query(depth)

        r = self._gql_post(path, query)

        # Vulnérable si pas de 400/429 et pas d'erreur "max depth"
        if r is None:
            return results

        body = (r.text or "").lower()
        blocked_signals = [
            "max depth", "maxdepth", "query depth", "too deep",
            "complexity", "limit exceeded", "query too complex",
        ]
        is_blocked = any(s in body for s in blocked_signals) or r.status_code in (400, 429)

        if not is_blocked and r.status_code < 500:
            results.append(ScanResult(
                vuln_type   = "DepthAttack",
                severity    = "HIGH",
                endpoint    = endpoint,
                method      = "POST",
                payload     = f"Requête imbriquée {depth} niveaux",
                evidence    = f"HTTP {r.status_code} — aucune limite de profondeur détectée",
                description = (
                    f"L'API accepte des requêtes imbriquées sur {depth} niveaux sans erreur. "
                    "Cela peut provoquer une surcharge serveur (DoS). "
                    "Implémenter une limite de profondeur (query depth limiting)."
                ),
            ))
            logger.info(f"    [VULN] Depth Attack → {endpoint} ({depth} niveaux acceptés)")

        return results

    # =========================================================================
    #  Test 3 — Field Exposure (champs sensibles)
    # =========================================================================

    def _test_field_exposure(self, endpoint: str) -> list[ScanResult]:
        """
        Recherche les champs sensibles dans le schéma récupéré par introspection.
        (password, token, secret, apikey, etc.)
        """
        results: list[ScanResult] = []

        # Nécessite le schéma
        if not self._schema:
            path  = self._to_path(endpoint)
            r     = self._gql_post(path, INTROSPECTION_QUERY)
            if not self._is_gql_success(r):
                return results
            self._schema = self._parse_gql(r)

        if not self._schema:
            return results

        found: list[str] = []
        types = (
            self._schema.get("data", {})
                .get("__schema", {})
                .get("types", [])
        )

        for gql_type in types:
            if not isinstance(gql_type, dict):
                continue
            fields = gql_type.get("fields") or []
            for f in fields:
                fname = (f.get("name") or "").lower()
                for sensitive in SENSITIVE_FIELDS:
                    if sensitive in fname:
                        found.append(f"{gql_type.get('name')}.{f.get('name')}")

        if found:
            evidence = "Champs sensibles : " + ", ".join(found[:10])
            results.append(ScanResult(
                vuln_type   = "FieldExposure",
                severity    = "HIGH",
                endpoint    = endpoint,
                method      = "POST",
                payload     = "Introspection — analyse des champs",
                evidence    = evidence,
                description = (
                    f"Le schéma GraphQL expose {len(found)} champ(s) potentiellement sensible(s) : "
                    f"{', '.join(found[:5])}{'...' if len(found) > 5 else ''}. "
                    "Vérifier que ces champs ne retournent pas de données confidentielles."
                ),
            ))
            logger.info(f"    [VULN] Field Exposure → {endpoint} | {len(found)} champ(s) sensible(s)")

        return results

    # =========================================================================
    #  Test 4 — Broken Auth (mutations dangereuses sans token)
    # =========================================================================

    def _test_broken_auth(self, endpoint: str) -> list[ScanResult]:
        """
        Tente d'exécuter des mutations dangereuses sans token d'authentification.
        Si la réponse n'est pas 401/403 → vulnérabilité d'autorisation.
        """
        results: list[ScanResult] = []
        path    = self._to_path(endpoint)

        # Supprime le token temporairement
        saved_auth = self.http._session.headers.get("Authorization")
        self.http.clear_token()

        for mutation_name in DANGEROUS_MUTATIONS:
            # Mutation minimale pour tester l'accès
            query = f"""
            mutation {{
              {mutation_name}(id: 1) {{
                id
              }}
            }}
            """
            r = self._gql_post(path, query)
            if r is None:
                continue

            body = (r.text or "").lower()

            # Pas bloqué par auth → potentiellement accessible
            auth_errors = [
                "unauthorized", "unauthenticated", "forbidden",
                "not authorized", "access denied", "permission denied",
                "authentication", "login required",
            ]
            is_auth_error = (
                r.status_code in (401, 403)
                or any(e in body for e in auth_errors)
            )

            if not is_auth_error and r.status_code != 404:
                results.append(ScanResult(
                    vuln_type   = "BrokenAuth",
                    severity    = "CRITICAL",
                    endpoint    = endpoint,
                    method      = "POST",
                    payload     = f"mutation {{ {mutation_name}(id: 1) }}",
                    evidence    = f"HTTP {r.status_code} — mutation '{mutation_name}' sans token",
                    description = (
                        f"La mutation '{mutation_name}' est accessible sans authentification. "
                        "Un attaquant peut exécuter des opérations sensibles sans privilèges."
                    ),
                ))
                logger.info(f"    [VULN] Broken Auth → {endpoint} | mutation: {mutation_name}")
                break   # Un résultat par endpoint suffit

        # Restaure le token
        if saved_auth:
            self.http._session.headers["Authorization"] = saved_auth

        return results

    # =========================================================================
    #  Test 5 — Batch Attack
    # =========================================================================

    def _test_batch_attack(self, endpoint: str) -> list[ScanResult]:
        """
        Envoie un batch de 50 requêtes identiques en une seule requête.
        Si le serveur les exécute toutes → pas de protection contre le batching.
        """
        results: list[ScanResult] = []
        path    = self._to_path(endpoint)

        batch_size = 50
        batch = [{"query": "{ __typename }"}] * batch_size

        r = self.http.post(path, json=batch)
        if r is None:
            return results

        body = (r.text or "").lower()
        blocked_signals = ["batch", "too many", "limit", "forbidden", "not allowed"]
        is_blocked = (
            r.status_code in (400, 429)
            or any(s in body for s in blocked_signals)
        )

        if not is_blocked and r.status_code == 200:
            # Vérifie que la réponse est bien un array (batch traité)
            try:
                parsed = r.json()
                if isinstance(parsed, list) and len(parsed) > 1:
                    results.append(ScanResult(
                        vuln_type   = "BatchAttack",
                        severity    = "HIGH",
                        endpoint    = endpoint,
                        method      = "POST",
                        payload     = f"Batch de {batch_size} requêtes",
                        evidence    = f"HTTP 200 — {len(parsed)} réponses retournées",
                        description = (
                            f"L'API traite {batch_size} requêtes en batch sans limite. "
                            "Cela permet de contourner le rate limiting et de surcharger le serveur. "
                            "Désactiver le batching ou limiter le nombre de requêtes par batch."
                        ),
                    ))
                    logger.info(f"    [VULN] Batch Attack → {endpoint} | {len(parsed)} requêtes traitées")
            except Exception:
                pass

        return results

    # =========================================================================
    #  Test 6 — Alias Attack (contournement rate-limit)
    # =========================================================================

    def _test_alias_attack(self, endpoint: str) -> list[ScanResult]:
        """
        Envoie une requête avec 30 aliases pointant vers le même champ.
        Technique pour contourner le rate limiting (1 requête HTTP = 30 opérations).
        """
        results: list[ScanResult] = []
        path    = self._to_path(endpoint)

        alias_count = 30
        aliases = "\n".join(
            f"  q{i}: __typename" for i in range(alias_count)
        )
        query = f"{{ {aliases} }}"

        r = self._gql_post(path, query)
        if r is None:
            return results

        if r.status_code == 200:
            try:
                parsed = r.json()
                data   = parsed.get("data", {})
                if isinstance(data, dict) and len(data) >= alias_count * 0.8:
                    results.append(ScanResult(
                        vuln_type   = "AliasAttack",
                        severity    = "MEDIUM",
                        endpoint    = endpoint,
                        method      = "POST",
                        payload     = f"Requête avec {alias_count} aliases",
                        evidence    = f"HTTP 200 — {len(data)} aliases traités",
                        description = (
                            f"L'API traite {alias_count} aliases dans une seule requête. "
                            "Un attaquant peut multiplier les opérations sans déclencher le rate limiting. "
                            "Implémenter une limite sur le nombre d'aliases par requête."
                        ),
                    ))
                    logger.info(f"    [VULN] Alias Attack → {endpoint} | {len(data)} aliases traités")
            except Exception:
                pass

        return results

    # =========================================================================
    #  Test 7 — IDOR via queries
    # =========================================================================

    def _test_idor(self, endpoint: str) -> list[ScanResult]:
        """
        Teste l'accès aux ressources d'autres utilisateurs via les queries GraphQL.
        Essaie user(id: 1), user(id: 2), etc.
        """
        results: list[ScanResult] = []
        path    = self._to_path(endpoint)

        # Queries courantes avec ID
        idor_queries = [
            ('user',    'query { user(id: %d) { id email name } }'),
            ('post',    'query { post(id: %d) { id title content } }'),
            ('order',   'query { order(id: %d) { id total status } }'),
            ('account', 'query { account(id: %d) { id balance owner } }'),
        ]

        for resource, query_tpl in idor_queries:
            # Test avec ID=1
            r1 = self._gql_post(path, query_tpl % 1)
            if not self._is_gql_success(r1):
                continue

            data1 = self._parse_gql(r1)
            if not data1 or not data1.get("data", {}).get(resource):
                continue

            # Test avec ID=2
            r2 = self._gql_post(path, query_tpl % 2)
            if not self._is_gql_success(r2):
                continue

            data2 = self._parse_gql(r2)
            if not data2 or not data2.get("data", {}).get(resource):
                continue

            # Les deux réponses ont des données différentes → IDOR potentiel
            if str(data1) != str(data2):
                results.append(ScanResult(
                    vuln_type   = "IDOR",
                    severity    = "HIGH",
                    endpoint    = endpoint,
                    method      = "POST",
                    payload     = query_tpl % 2,
                    evidence    = f"query {resource}(id:1) et (id:2) retournent des données différentes",
                    description = (
                        f"La query '{resource}' accepte des IDs arbitraires sans vérification d'autorisation. "
                        "Un utilisateur peut accéder aux données d'autres utilisateurs."
                    ),
                ))
                logger.info(f"    [VULN] IDOR (GraphQL) → {endpoint} | query: {resource}")
                break

        return results

    # =========================================================================
    #  Helpers privés
    # =========================================================================

    def _to_path(self, endpoint: str) -> str:
        return endpoint.replace(self.base_url, "") or "/"

    def _gql_post(self, path: str, query: str):
        """Envoie une requête GraphQL POST."""
        return self.http.post(path, json={"query": query})

    def _is_gql_success(self, r) -> bool:
        """True si la réponse est un JSON GraphQL valide (pas forcément 200)."""
        if r is None:
            return False
        if r.status_code not in (200, 400):
            return False
        try:
            data = r.json()
            return "data" in data or "errors" in data
        except Exception:
            return False

    def _parse_gql(self, r) -> Optional[dict]:
        """Parse la réponse GraphQL en dict."""
        if r is None:
            return None
        try:
            return r.json()
        except Exception:
            return None

    def _filter_graphql_endpoints(self, endpoints: list[str]) -> list[str]:
        """Filtre les endpoints qui ressemblent à du GraphQL."""
        keywords = ["graphql", "gql", "query", "graph"]
        return [
            ep for ep in endpoints
            if any(kw in ep.lower() for kw in keywords)
        ]

    def _build_deep_query(self, depth: int) -> str:
        """Construit une requête GraphQL imbriquée sur `depth` niveaux."""
        # Utilise __schema qui est toujours disponible
        inner = "name"
        for _ in range(depth - 1):
            inner = f"fields {{ name type {{ {inner} }} }}"
        return f"{{ __schema {{ types {{ {inner} }} }} }}"