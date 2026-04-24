# core/graphql_export.py
"""
GraphQL Schema Exporter

Converts a GraphQL schema (stored in endpoints.json after discovery) into
formats ready to paste into visual tools without any extra manipulation:

  - Voyager JSON  : introspection payload accepted by GraphQL Voyager
                    (graphql-kit.com/graphql-voyager → Change Schema → Introspection)
  - SDL           : Schema Definition Language accepted by GraphQL Voyager (SDL tab),
                    Nathan Randal's visualizer, and most GraphQL IDEs

Usage (programmatic):
    exporter = GraphQLSchemaExporter(schema_dict)
    exporter.export(output_dir=".", fmt="both")

Usage (CLI):
    apisec schema --input endpoints.json --format both --output-dir ./schema_export
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

    voyager_path: Optional[str] = None   # {"data": {"__schema": ...}} for GraphQL Voyager
    nathan_path:  Optional[str] = None   # {"__schema": ...} for Nathan Randal
    sdl_path:     Optional[str] = None   # SDL .graphql file
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

    Args:
        schema_dict : the 'schema' value from endpoints.json
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
        """
        Generate export files.

        Args:
            output_dir : directory where files are written
            fmt        : "voyager" | "sdl" | "both"

        Returns:
            ExportResult with paths of generated files
        """
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
    #  Voyager JSON export
    # -------------------------------------------------------------------------

    def _export_voyager(self, output_dir: str) -> Optional[str]:
        """
        Write the introspection payload in the exact format GraphQL Voyager expects.

        Voyager expects the raw introspection response:
            { "data": { "__schema": { ... } } }

        If raw_introspection is available (from fetch), use it directly.
        Otherwise, reconstruct a minimal introspection from the parsed schema.
        """
        raw = self._schema.get("raw_introspection")

        if raw and isinstance(raw, dict) and "data" in raw:
            # Perfect — use the original introspection response as-is
            payload = raw
            logger.debug("[export] Voyager: using original raw_introspection")

        elif raw and isinstance(raw, dict) and "__schema" in raw:
            # Wrap in data envelope if missing
            payload = {"data": raw}
            logger.debug("[export] Voyager: wrapping __schema in data envelope")

        else:
            # Reconstruct from parsed schema fields
            logger.debug("[export] Voyager: reconstructing introspection from parsed schema")
            payload = self._reconstruct_introspection()

        path = os.path.join(output_dir, "schema_voyager.json")
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2, ensure_ascii=False)
            logger.info(f"[export] Voyager JSON → {path}")
            return path
        except OSError as e:
            logger.error(f"[export] Cannot write {path}: {e}")
            return None

    def _reconstruct_introspection(self) -> dict:
        """
        Build a minimal introspection payload from the parsed schema fields.
        Used as fallback when raw_introspection is not available (oracle method).
        """
        queries   = self._schema.get("queries",   [])
        mutations = self._schema.get("mutations", [])
        types     = self._schema.get("types",     [])

        # Build Query type fields
        query_fields = [
            {
                "name": q["name"],
                "args": [{"name": a} for a in q.get("args", [])],
                "isDeprecated": False,
                "deprecationReason": None,
            }
            for q in queries
        ]

        # Build Mutation type fields
        mutation_fields = [
            {
                "name": m["name"],
                "args": [{"name": a} for a in m.get("args", [])],
                "isDeprecated": False,
                "deprecationReason": None,
            }
            for m in mutations
        ]

        # Build types list
        all_types = []

        if query_fields:
            all_types.append({
                "kind":   "OBJECT",
                "name":   "Query",
                "fields": query_fields,
                "inputFields":   None,
                "interfaces":    [],
                "enumValues":    None,
                "possibleTypes": None,
            })

        if mutation_fields:
            all_types.append({
                "kind":   "OBJECT",
                "name":   "Mutation",
                "fields": mutation_fields,
                "inputFields":   None,
                "interfaces":    [],
                "enumValues":    None,
                "possibleTypes": None,
            })

        # Add known scalar types
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
    #  Nathan Randal export
    # -------------------------------------------------------------------------

    def _export_nathan(self, output_dir: str) -> Optional[str]:
        """
        Write the introspection payload in the exact format Nathan Randal expects.

        Nathan Randal visualizer (nathanrandal.com/graphql-visualizer) expects
        the __schema object directly — without the "data" envelope:
            { "__schema": { ... } }
        """
        raw = self._schema.get("raw_introspection")

        if raw and isinstance(raw, dict) and "data" in raw:
            # Strip the "data" wrapper — Nathan wants {"__schema": ...} directly
            schema_obj = raw["data"].get("__schema")
        elif raw and isinstance(raw, dict) and "__schema" in raw:
            schema_obj = raw["__schema"]
        else:
            # Reconstruct and unwrap
            reconstructed = self._reconstruct_introspection()
            schema_obj = reconstructed.get("data", {}).get("__schema")

        if not schema_obj:
            return None

        payload = {"__schema": schema_obj}

        path = os.path.join(output_dir, "schema_nathan.json")
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2, ensure_ascii=False)
            return path
        except OSError as e:
            return None

    # -------------------------------------------------------------------------
    #  SDL export
    # -------------------------------------------------------------------------

    def _export_sdl(self, output_dir: str) -> Optional[str]:
        """
        Generate a Schema Definition Language (.graphql) file.

        SDL is human-readable and accepted by:
          - GraphQL Voyager (SDL tab)
          - Nathan Randal's visualizer
          - GraphQL Playground / Insomnia / Postman
        """
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
        """
        Build SDL from the parsed schema.

        Priority:
          1. Build from raw_introspection types (most complete)
          2. Fall back to parsed queries/mutations/types
        """
        raw = self._schema.get("raw_introspection")

        if raw:
            return self._sdl_from_introspection(raw)

        return self._sdl_from_parsed()

    def _sdl_from_introspection(self, raw: dict) -> str:
        """Convert raw introspection response to SDL."""
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

        # Skip built-in introspection types
        skip_prefixes = ("__",)
        skip_scalars  = {"String", "Int", "Float", "Boolean", "ID"}

        for t in all_types:
            name = t.get("name", "")
            kind = t.get("kind", "")

            if any(name.startswith(p) for p in skip_prefixes):
                continue
            if name in skip_scalars:
                continue

            fields  = t.get("fields") or []
            ev      = t.get("enumValues") or []

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
        """
        Build a minimal SDL from the parsed schema fields.
        Used when raw_introspection is not available (oracle method).
        """
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

        # Known types (no field details in oracle mode)
        skip = {"Query", "Mutation", "Boolean", "Int", "String", "Float", "ID"}
        for t in types:
            if t not in skip and not t.startswith("__"):
                lines.append(f"type {t} {{")
                lines.append("  # fields unavailable — schema discovered via oracle")
                lines.append("}")
                lines.append("")

        return "\n".join(lines)

    # -------------------------------------------------------------------------
    #  Type resolution helpers
    # -------------------------------------------------------------------------

    def _resolve_field_type(self, field: dict) -> str:
        """
        Resolve the SDL type string for a field or input value.
        GraphQL wraps types in NON_NULL and LIST wrappers.
        """
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
        """
        Recursively unwrap NON_NULL / LIST wrappers and return SDL type string.

        Examples:
          NON_NULL(String)     → "String!"
          LIST(NON_NULL(Int))  → "[Int!]"
          NON_NULL(LIST(User)) → "[User]!"
        """
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

        # Scalar / Object / Enum / Interface — leaf type
        return name or "String"


# -----------------------------------------------------------------------------
#  Convenience function — used by main.py
# -----------------------------------------------------------------------------

def export_schema(
    endpoints_json_path: str,
    output_dir:          str  = ".",
    fmt:                 str  = "both",
) -> Optional[ExportResult]:
    """
    Load endpoints.json and export the GraphQL schema.

    Args:
        endpoints_json_path : path to endpoints.json
        output_dir          : where to write the output files
        fmt                 : "voyager" | "sdl" | "both"

    Returns:
        ExportResult, or None if the file has no GraphQL schema
    """
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