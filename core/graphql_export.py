# core/graphql_export.py
"""
GraphQL Schema Exporter

Converts a GraphQL schema (stored in endpoints.json after discovery) into
formats ready to paste into visual tools without any extra manipulation:

  - Voyager JSON  : introspection payload accepted by GraphQL Voyager
  - Nathan JSON   : introspection payload for Nathan Randal visualizer
  - SDL           : Schema Definition Language

Fixes applied:
  1. _export_nathan() strips directives — Nathan Randal rejects them
  2. _normalize_type_names() capitalizes query/mutation type names
     Some servers return "query"/"mutation" (lowercase) which breaks
     Voyager and Nathan Randal — both expect "Query"/"Mutation"
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Optional

from logger.logger import logger


# -----------------------------------------------------------------------------
#  Result dataclass
# -----------------------------------------------------------------------------

@dataclass
class ExportResult:
    """Holds the paths of generated export files."""

    voyager_path: Optional[str] = None
    nathan_path:  Optional[str] = None
    sdl_path:     Optional[str] = None
    fmt:          str           = "both"

    @property
    def files(self) -> list[str]:
        return [p for p in (self.voyager_path, self.nathan_path, self.sdl_path) if p]

    def __str__(self) -> str:
        lines = []
        if self.voyager_path:
            lines.append(
                f"  Voyager JSON : {self.voyager_path}\n"
                "    → graphql-kit.com/graphql-voyager\n"
                "      Change Schema → Introspection → paste"
            )
        if self.nathan_path:
            lines.append(
                f"  Nathan JSON  : {self.nathan_path}\n"
                "    → nathanrandal.com/graphql-visualizer\n"
                "      paste directly"
            )
        if self.sdl_path:
            lines.append(
                f"  SDL          : {self.sdl_path}\n"
                "    → graphql-kit.com/graphql-voyager\n"
                "      Change Schema → SDL → paste"
            )
        return "\n".join(lines)


# -----------------------------------------------------------------------------
#  GraphQLSchemaExporter
# -----------------------------------------------------------------------------

class GraphQLSchemaExporter:
    """
    Converts a schema dict (from endpoints.json → schema) into
    Voyager-ready JSON and/or SDL.
    """

    def __init__(self, schema_dict: dict) -> None:
        if not isinstance(schema_dict, dict):
            raise ValueError("schema_dict must be a dict (endpoints.json → schema)")
        self._schema = schema_dict

    # -------------------------------------------------------------------------
    #  Public API
    # -------------------------------------------------------------------------

    def export(
        self,
        output_dir: str = ".",
        fmt:        str = "both",
    ) -> ExportResult:
        os.makedirs(output_dir, exist_ok=True)
        result = ExportResult(fmt=fmt)

        if fmt in ("voyager", "both"):
            path = self._export_voyager(output_dir)
            if path:
                result.voyager_path = path

            path = self._export_nathan(output_dir)
            if path:
                result.nathan_path = path

        if fmt in ("sdl", "both"):
            path = self._export_sdl(output_dir)
            if path:
                result.sdl_path = path

        return result

    # -------------------------------------------------------------------------
    #  Fix 1 — Normalize type names
    # -------------------------------------------------------------------------

    def _normalize_schema(self, schema_obj: dict) -> dict:
        """
        Normalize a __schema object for compatibility with Voyager and Nathan Randal.

        Problems fixed:
          1. Some servers return queryType.name = "query" (lowercase).
             Voyager and Nathan Randal expect "Query" (PascalCase).
             Same for mutationType → "Mutation", subscriptionType → "Subscription".

          2. The type definitions themselves may also use lowercase names.
             We rename them to match the normalized type references.

        Returns a normalized copy — does not mutate the original.
        """
        import copy
        schema = copy.deepcopy(schema_obj)

        # Build a rename map: lowercase → PascalCase
        rename_map: dict[str, str] = {}

        for key, pascal in [
            ("queryType",        "Query"),
            ("mutationType",     "Mutation"),
            ("subscriptionType", "Subscription"),
        ]:
            type_ref = schema.get(key)
            if isinstance(type_ref, dict) and type_ref.get("name"):
                original = type_ref["name"]
                if original and original != pascal and original.lower() == pascal.lower():
                    rename_map[original] = pascal
                    schema[key]["name"]  = pascal
                    logger.debug(
                        f"[export] Normalized {key}.name: "
                        f"'{original}' → '{pascal}'"
                    )

        # Rename matching types in the types list
        if rename_map:
            for t in schema.get("types", []):
                if isinstance(t, dict) and t.get("name") in rename_map:
                    t["name"] = rename_map[t["name"]]

        return schema

    # -------------------------------------------------------------------------
    #  Fix 2 — Strip directives for Nathan Randal
    # -------------------------------------------------------------------------

    def _strip_directives(self, schema_obj: dict) -> dict:
        """
        Remove the 'directives' key from a __schema object.

        Nathan Randal's visualizer does not handle the directives array and
        throws a JSON.parse error when it is present. Directives are not
        needed for visualization — they are internal GraphQL machinery.

        Returns a shallow copy with 'directives' removed.
        """
        return {k: v for k, v in schema_obj.items() if k != "directives"}

    # -------------------------------------------------------------------------
    #  Voyager JSON export
    # -------------------------------------------------------------------------

    def _export_voyager(self, output_dir: str) -> Optional[str]:
        """
        Write the introspection payload for GraphQL Voyager.
        Format: {"data": {"__schema": {...}}}
        Applies type name normalization.
        """
        raw = self._schema.get("raw_introspection")

        if raw and isinstance(raw, dict) and "data" in raw:
            schema_obj = raw["data"].get("__schema", {})
        elif raw and isinstance(raw, dict) and "__schema" in raw:
            schema_obj = raw["__schema"]
        else:
            reconstructed = self._reconstruct_introspection()
            schema_obj = reconstructed.get("data", {}).get("__schema", {})

        # Apply normalization
        schema_obj = self._normalize_schema(schema_obj)
        payload    = {"data": {"__schema": schema_obj}}

        path = os.path.join(output_dir, "schema_voyager.json")
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2, ensure_ascii=False)
            logger.info(f"[export] Voyager JSON → {path}")
            return path
        except OSError as e:
            logger.error(f"[export] Cannot write {path}: {e}")
            return None

    # -------------------------------------------------------------------------
    #  Nathan Randal export
    # -------------------------------------------------------------------------

    def _export_nathan(self, output_dir: str) -> Optional[str]:
        """
        Write the introspection payload for Nathan Randal visualizer.
        Format: {"__schema": {...}}

        Fixes applied:
          - Strips 'directives' (Nathan Randal rejects them → JSON.parse error)
          - Normalizes type names (query → Query, mutation → Mutation)
        """
        raw = self._schema.get("raw_introspection")

        if raw and isinstance(raw, dict) and "data" in raw:
            schema_obj = raw["data"].get("__schema", {})
        elif raw and isinstance(raw, dict) and "__schema" in raw:
            schema_obj = raw["__schema"]
        else:
            reconstructed = self._reconstruct_introspection()
            schema_obj = reconstructed.get("data", {}).get("__schema", {})

        if not schema_obj:
            return None

        # Fix 1 — normalize type names (query → Query, mutation → Mutation)
        schema_obj = self._normalize_schema(schema_obj)

        # Fix 2 — strip directives (Nathan Randal rejects them)
        schema_obj = self._strip_directives(schema_obj)

        payload = {"__schema": schema_obj}

        path = os.path.join(output_dir, "schema_nathan.json")
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2, ensure_ascii=False)
            logger.info(f"[export] Nathan JSON → {path}")
            return path
        except OSError as e:
            logger.error(f"[export] Cannot write {path}: {e}")
            return None

    # -------------------------------------------------------------------------
    #  SDL export
    # -------------------------------------------------------------------------

    def _export_sdl(self, output_dir: str) -> Optional[str]:
        sdl = self._build_sdl()
        if not sdl.strip():
            logger.warning("[export] SDL: empty schema — nothing to export")
            return None

        path = os.path.join(output_dir, "schema.graphql")
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(sdl)
            logger.info(f"[export] SDL → {path}")
            return path
        except OSError as e:
            logger.error(f"[export] Cannot write {path}: {e}")
            return None

    def _build_sdl(self) -> str:
        raw = self._schema.get("raw_introspection")
        if raw:
            return self._sdl_from_introspection(raw)
        return self._sdl_from_parsed()

    def _sdl_from_introspection(self, raw: dict) -> str:
        lines: list[str] = [
            "# GraphQL Schema — generated by APISec",
            "# Source: introspection",
            "",
        ]

        schema_data = (
            raw.get("data", {}).get("__schema")
            or raw.get("__schema")
            or {}
        )
        all_types = schema_data.get("types", [])

        skip_prefixes = ("__",)
        skip_scalars  = {"String", "Int", "Float", "Boolean", "ID"}

        for t in all_types:
            name = t.get("name", "")
            kind = t.get("kind", "")

            if any(name.startswith(p) for p in skip_prefixes):
                continue
            if name in skip_scalars:
                continue

            fields = t.get("fields") or []
            ev     = t.get("enumValues") or []

            if kind == "OBJECT" and fields:
                lines.append(f"type {name} {{")
                for field in fields:
                    fname = field.get("name", "")
                    fargs = field.get("args", []) or []
                    ftype = self._resolve_field_type(field)

                    if fargs:
                        arg_str = ", ".join(
                            f"{a['name']}: {self._resolve_arg_type(a)}"
                            for a in fargs
                        )
                        lines.append(f"  {fname}({arg_str}): {ftype}")
                    else:
                        lines.append(f"  {fname}: {ftype}")
                lines.append("}")
                lines.append("")

            elif kind == "ENUM" and ev:
                lines.append(f"enum {name} {{")
                for val in ev:
                    lines.append(f"  {val.get('name', '')}")
                lines.append("}")
                lines.append("")

            elif kind == "INPUT_OBJECT":
                input_fields = t.get("inputFields") or []
                if input_fields:
                    lines.append(f"input {name} {{")
                    for field in input_fields:
                        fname = field.get("name", "")
                        ftype = self._resolve_field_type(field)
                        lines.append(f"  {fname}: {ftype}")
                    lines.append("}")
                    lines.append("")

            elif kind == "SCALAR" and name not in skip_scalars:
                lines.append(f"scalar {name}")
                lines.append("")

            elif kind == "INTERFACE" and fields:
                lines.append(f"interface {name} {{")
                for field in fields:
                    fname = field.get("name", "")
                    ftype = self._resolve_field_type(field)
                    lines.append(f"  {fname}: {ftype}")
                lines.append("}")
                lines.append("")

        return "\n".join(lines)

    def _sdl_from_parsed(self) -> str:
        queries   = self._schema.get("queries",   [])
        mutations = self._schema.get("mutations", [])
        types     = self._schema.get("types",     [])

        lines: list[str] = [
            "# GraphQL Schema — generated by APISec",
            "# Source: oracle (partial schema — field types unavailable)",
            "",
        ]

        if queries:
            lines.append("type Query {")
            for q in queries:
                args = q.get("args", [])
                if args:
                    arg_str = ", ".join(f"{a}: String" for a in args)
                    lines.append(f"  {q['name']}({arg_str}): String")
                else:
                    lines.append(f"  {q['name']}: String")
            lines.append("}")
            lines.append("")

        if mutations:
            lines.append("type Mutation {")
            for m in mutations:
                args = m.get("args", [])
                if args:
                    arg_str = ", ".join(f"{a}: String" for a in args)
                    lines.append(f"  {m['name']}({arg_str}): String")
                else:
                    lines.append(f"  {m['name']}: String")
            lines.append("}")
            lines.append("")

        skip = {"Query", "Mutation", "Boolean", "Int", "String", "Float", "ID"}
        for t in types:
            if t not in skip and not t.startswith("__"):
                lines.append(f"type {t} {{")
                lines.append("  # fields unavailable — schema discovered via oracle")
                lines.append("}")
                lines.append("")

        return "\n".join(lines)

    # -------------------------------------------------------------------------
    #  Reconstruction helper (oracle fallback)
    # -------------------------------------------------------------------------

    def _reconstruct_introspection(self) -> dict:
        queries   = self._schema.get("queries",   [])
        mutations = self._schema.get("mutations", [])
        types     = self._schema.get("types",     [])

        query_fields = [
            {
                "name":               q["name"],
                "args":               [{"name": a} for a in q.get("args", [])],
                "isDeprecated":       False,
                "deprecationReason":  None,
            }
            for q in queries
        ]
        mutation_fields = [
            {
                "name":               m["name"],
                "args":               [{"name": a} for a in m.get("args", [])],
                "isDeprecated":       False,
                "deprecationReason":  None,
            }
            for m in mutations
        ]

        all_types = []

        if query_fields:
            all_types.append({
                "kind":          "OBJECT",
                "name":          "Query",
                "fields":        query_fields,
                "inputFields":   None,
                "interfaces":    [],
                "enumValues":    None,
                "possibleTypes": None,
            })

        if mutation_fields:
            all_types.append({
                "kind":          "OBJECT",
                "name":          "Mutation",
                "fields":        mutation_fields,
                "inputFields":   None,
                "interfaces":    [],
                "enumValues":    None,
                "possibleTypes": None,
            })

        for type_name in types:
            if type_name not in ("Query", "Mutation") and not type_name.startswith("__"):
                all_types.append({
                    "kind":          "OBJECT",
                    "name":          type_name,
                    "fields":        [],
                    "inputFields":   None,
                    "interfaces":    [],
                    "enumValues":    None,
                    "possibleTypes": None,
                })

        return {
            "data": {
                "__schema": {
                    "queryType":        {"name": "Query"}    if query_fields    else None,
                    "mutationType":     {"name": "Mutation"} if mutation_fields else None,
                    "subscriptionType": None,
                    "types":            all_types,
                    "directives":       [],
                }
            }
        }

    # -------------------------------------------------------------------------
    #  Type resolution helpers
    # -------------------------------------------------------------------------

    def _resolve_field_type(self, field: dict) -> str:
        type_ref = field.get("type")
        if not type_ref:
            return "String"
        return self._unwrap_type(type_ref)

    def _resolve_arg_type(self, arg: dict) -> str:
        type_ref = arg.get("type")
        if not type_ref:
            return "String"
        return self._unwrap_type(type_ref)

    def _unwrap_type(self, type_ref: dict, suffix: str = "") -> str:
        if not isinstance(type_ref, dict):
            return "String"

        kind    = type_ref.get("kind", "")
        name    = type_ref.get("name")
        of_type = type_ref.get("ofType")

        if kind == "NON_NULL":
            inner = self._unwrap_type(of_type) if of_type else "String"
            return f"{inner}!{suffix}"

        if kind == "LIST":
            inner = self._unwrap_type(of_type) if of_type else "String"
            return f"[{inner}]{suffix}"

        return name or "String"


# -----------------------------------------------------------------------------
#  Convenience function
# -----------------------------------------------------------------------------

def export_schema(
    endpoints_json_path: str,
    output_dir:          str = ".",
    fmt:                 str = "both",
) -> Optional[ExportResult]:
    try:
        with open(endpoints_json_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        logger.error(f"[export] Cannot read '{endpoints_json_path}': {e}")
        return None

    api_type = data.get("api_type", "")
    if api_type != "GraphQL":
        logger.error(
            f"[export] '{endpoints_json_path}' is not a GraphQL discovery result "
            f"(api_type: '{api_type}')"
        )
        return None

    schema = data.get("schema")
    if not schema:
        logger.error(
            f"[export] No schema found in '{endpoints_json_path}'. "
            "Re-run discovery to fetch the schema."
        )
        return None

    exporter = GraphQLSchemaExporter(schema)
    return exporter.export(output_dir=output_dir, fmt=fmt)