# core/graphql_schema.py
"""
GraphQLSchema — Récupération du schéma GraphQL.

Deux stratégies, dans l'ordre :
  1. Introspection complète  — si elle est activée sur le serveur
  2. Oracle (clairvoyance)   — si l'introspection est bloquée :
       envoie des noms de champs invalides et lit les suggestions
       "Did you mean X?" dans les messages d'erreur GraphQL

Résultat : un dict `GraphQLSchemaResult` utilisable par GraphQLScanner
et sérialisable dans endpoints.json.

Structure de sortie :
  {
    "endpoint":       "https://api.example.com/graphql",
    "method":         "introspection" | "oracle" | "none",
    "queries":        [{"name": "user", "args": ["id", "email"]}, ...],
    "mutations":      [{"name": "createUser", "args": ["input"]}, ...],
    "types":          ["User", "Post", "Order", ...],
    "raw_introspection": { ... } | None   # réponse brute si dispo
  }
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
]

# Requête d'introspection complète
# Standard full introspection query — compatible with GraphQL Voyager,
# Nathan Randal visualizer, and all GraphQL tooling.
# Includes type information on fields and args so visual tools can
# resolve relationships between types without errors.
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

# Probe rapide pour vérifier si l'introspection répond
_INTROSPECTION_PROBE = "{ __schema { queryType { name } } }"

# Champs internes GraphQL à ignorer dans le schéma
_BUILTIN_PREFIXES = ("__",)

# Wordlists embarquées (chemin relatif depuis la racine du projet)
_WL_QUERIES    = "wordlists/gql-queries-1k.txt"
_WL_MUTATIONS  = "wordlists/gql-mutations-1k.txt"
_WL_ORACLE     = "wordlists/gql-oracle.txt"

# Regex pour extraire les suggestions GraphQL ("Did you mean X?")
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
    """Un champ (query ou mutation) avec ses arguments."""
    name: str
    args: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"name": self.name, "args": self.args}


@dataclass
class GraphQLSchemaResult:
    """Résultat complet de la récupération du schéma."""

    endpoint:          str
    method:            str                    # "introspection" | "oracle" | "none"
    queries:           list[FieldInfo]        = field(default_factory=list)
    mutations:         list[FieldInfo]        = field(default_factory=list)
    types:             list[str]              = field(default_factory=list)
    raw_introspection: Optional[dict]         = None

    # ── Accesseurs pratiques ──────────────────────────────────────────────────

    @property
    def query_names(self) -> list[str]:
        return [q.name for q in self.queries]

    @property
    def mutation_names(self) -> list[str]:
        return [m.name for m in self.mutations]

    @property
    def has_schema(self) -> bool:
        return bool(self.queries or self.mutations or self.types)

    # ── Sérialisation JSON ────────────────────────────────────────────────────

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

    Utilisation :
        fetcher = GraphQLSchemaFetcher("https://api.example.com", token="...")
        result  = fetcher.fetch()           # tente introspection puis oracle
        result  = fetcher.fetch(endpoint="/api/graphql")   # endpoint explicite
    """

    def __init__(
        self,
        base_url: str,
        timeout:  int = 5,
        token:    Optional[str] = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.http     = Requester(self.base_url, timeout=timeout)

        if token:
            self.http.set_token(token)

    # =========================================================================
    #  Point d'entrée public
    # =========================================================================

    def fetch(self, endpoint: Optional[str] = None) -> GraphQLSchemaResult:
        """
        Tente de récupérer le schéma GraphQL.

        Ordre :
          1. Si endpoint fourni → tente introspection sur cet endpoint
          2. Sinon → sonde les endpoints courants
          3. Si introspection bloquée → oracle (clairvoyance)

        Returns:
            GraphQLSchemaResult (method="none" si rien trouvé)
        """
        logger.info("[*] GraphQL schema fetch — démarrage")

        # Endpoints à sonder
        candidates = [endpoint] if endpoint else [
            f"{self.base_url}{p}" for p in GRAPHQL_ENDPOINTS
        ]

        # ── Stratégie 1 : Introspection ───────────────────────────────────────
        for ep in candidates:
            result = self._try_introspection(ep)
            if result is not None:
                logger.info(f"[+] Schéma récupéré par introspection — {ep}")
                logger.info(f"    queries: {len(result.queries)} | mutations: {len(result.mutations)} | types: {len(result.types)}")
                return result

        logger.info("[*] Introspection bloquée — tentative oracle (clairvoyance)")

        # ── Stratégie 2 : Oracle (clairvoyance) ──────────────────────────────
        for ep in candidates:
            result = self._try_oracle(ep)
            if result is not None and result.has_schema:
                logger.info(f"[+] Schéma partiel via oracle — {ep}")
                logger.info(f"    queries: {len(result.queries)} | mutations: {len(result.mutations)}")
                return result

        logger.warning("[!] Schéma GraphQL non récupérable (introspection off, oracle sans résultat)")
        return GraphQLSchemaResult(
            endpoint = candidates[0] if candidates else self.base_url,
            method   = "none",
        )

    # =========================================================================
    #  Stratégie 1 — Introspection complète
    # =========================================================================

    def _try_introspection(self, endpoint: str) -> Optional[GraphQLSchemaResult]:
        """
        Tente l'introspection sur un endpoint.
        Retourne None si l'introspection est bloquée ou l'endpoint inexistant.
        """
        path = self._to_path(endpoint)

        # Probe rapide avant la requête complète
        r_probe = self.http.post(path, json={"query": _INTROSPECTION_PROBE})
        if not self._is_gql_response(r_probe):
            return None

        # Introspection complète
        r = self.http.post(path, json={"query": _INTROSPECTION_QUERY})
        if not self._is_gql_response(r):
            return None

        try:
            body = r.json()
        except Exception:
            return None

        schema_data = body.get("data", {}).get("__schema")
        if not schema_data:
            return None

        return self._parse_introspection(endpoint, body)

    def _parse_introspection(self, endpoint: str, raw: dict) -> GraphQLSchemaResult:
        """Parse la réponse d'introspection en GraphQLSchemaResult."""

        schema      = raw.get("data", {}).get("__schema", {})
        query_type  = (schema.get("queryType")    or {}).get("name", "Query")
        mut_type    = (schema.get("mutationType") or {}).get("name", "Mutation")
        all_types   = schema.get("types", [])

        queries:   list[FieldInfo] = []
        mutations: list[FieldInfo] = []
        type_names: list[str]      = []

        for t in all_types:
            name = t.get("name", "")

            # Ignorer les types internes (__Schema, __Type…)
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
            method            = "introspection",
            queries           = queries,
            mutations         = mutations,
            types             = type_names,
            raw_introspection = raw,
        )

    # =========================================================================
    #  Stratégie 2 — Oracle / Clairvoyance
    # =========================================================================

    def _try_oracle(self, endpoint: str) -> Optional[GraphQLSchemaResult]:
        """
        Bruteforce les champs disponibles via les suggestions d'erreur GraphQL.

        Principe (clairvoyance) :
          - Envoie { <mot_invalide> } → GraphQL répond parfois
            "Cannot query field 'X'. Did you mean 'user'?"
          - On extrait les suggestions pour découvrir les champs réels.
        """
        path = self._to_path(endpoint)

        # Vérifier que l'endpoint répond au GraphQL
        r_check = self.http.post(path, json={"query": "{ __typename }"})
        if not self._is_gql_response(r_check):
            return None

        # Charger la wordlist oracle
        words = self._load_wordlist(_WL_ORACLE)
        if not words:
            # Fallback : utiliser les wordlists queries + mutations
            words = self._load_wordlist(_WL_QUERIES) + self._load_wordlist(_WL_MUTATIONS)

        if not words:
            logger.warning("[oracle] Aucune wordlist disponible")
            return None

        logger.info(f"[*] Oracle — {len(words)} mots → {endpoint}")

        discovered_queries:   set[str] = set()
        discovered_mutations: set[str] = set()

        # ── Phase 1 : découverte des queries ─────────────────────────────────
        query_words = self._load_wordlist(_WL_QUERIES) or words[:500]
        for word in query_words:
            suggestions = self._probe_field(path, word, context="query")
            discovered_queries.update(suggestions)

        # ── Phase 2 : découverte des mutations ───────────────────────────────
        mutation_words = self._load_wordlist(_WL_MUTATIONS) or words[:500]
        for word in mutation_words:
            suggestions = self._probe_field(path, word, context="mutation")
            discovered_mutations.update(suggestions)

        if not discovered_queries and not discovered_mutations:
            logger.info("[oracle] Aucune suggestion reçue — serveur ne révèle pas ses champs")
            return GraphQLSchemaResult(endpoint=endpoint, method="oracle")

        queries   = [FieldInfo(name=q) for q in sorted(discovered_queries)]
        mutations = [FieldInfo(name=m) for m in sorted(discovered_mutations)]

        return GraphQLSchemaResult(
            endpoint  = endpoint,
            method    = "oracle",
            queries   = queries,
            mutations = mutations,
        )

    def _probe_field(self, path: str, word: str, context: str = "query") -> set[str]:
        """
        Envoie un champ invalide et extrait les suggestions de l'erreur.

        Args:
            path    : chemin de l'endpoint GraphQL
            word    : mot à envoyer (ex: "usr" → suggère "user")
            context : "query" ou "mutation"

        Returns:
            set de champs suggérés par le serveur
        """
        if context == "mutation":
            query = f"mutation {{ {word} }}"
        else:
            query = f"{{ {word} }}"

        r = self.http.post(path, json={"query": query})
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
        """Extrait les noms suggérés depuis un message d'erreur GraphQL."""
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
                    # "Did you mean 'a', 'b', 'c'"
                    for word in re.findall(r"[_0-9A-Za-z]+", gd["multi"]):
                        found.add(word)
                if "last"  in gd and gd["last"]:
                    found.add(gd["last"])

        return found

    # =========================================================================
    #  Helpers
    # =========================================================================

    def _to_path(self, endpoint: str) -> str:
        """Convertit une URL absolue en chemin relatif."""
        return endpoint.replace(self.base_url, "") or "/"

    def _is_gql_response(self, r) -> bool:
        """True si la réponse ressemble à une réponse GraphQL valide."""
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
        """
        Charge une wordlist depuis un chemin relatif à la racine du projet.
        Retourne [] si le fichier n'existe pas.
        """
        # Résolution depuis le répertoire du fichier courant (core/)
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
    base_url:        str,
    timeout:         int = 5,
    token:           Optional[str] = None,
    known_endpoint:  Optional[str] = None,
) -> GraphQLSchemaResult:
    """
    Point d'entrée simple pour discovery.py.

    Args:
        base_url       : URL de base de l'API
        timeout        : timeout HTTP
        token          : token d'auth optionnel
        known_endpoint : endpoint GraphQL déjà découvert (depuis _score_graphql)

    Returns:
        GraphQLSchemaResult sérialisable en JSON
    """
    fetcher = GraphQLSchemaFetcher(base_url, timeout=timeout, token=token)
    return fetcher.fetch(endpoint=known_endpoint)