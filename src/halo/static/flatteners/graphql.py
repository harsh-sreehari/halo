from __future__ import annotations

import re
from collections.abc import Sequence
from typing import Any

from halo.static.graph import RouteNode


class GraphQLFlattener:
    """
    Parses GraphQL SDL schemas (.graphql) and resolver maps to expand
    root operations (Query, Mutation) into virtual route endpoints.
    """

    @classmethod
    def parse_schema_and_resolvers(
        cls,
        schema_str: str,
        resolvers: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        """
        Parse a GraphQL SDL schema and optional resolver map into virtual route endpoints.

        Args:
            schema_str: GraphQL Schema Definition Language (SDL) text
            resolvers: Resolver dictionary (nested, dotted, or flat)

        Returns:
            List of endpoint dictionaries (e.g. 'GRAPHQL: Query.getInvoice').
        """
        # 1. Clean schema: strip block comments/strings and line comments
        cleaned = cls._clean_schema(schema_str)

        # 2. Identify root type names for query and mutation
        query_type, mutation_type = cls._find_root_types(cleaned)

        # 3. Find and parse type definitions matching root types
        endpoints: list[dict[str, Any]] = []

        # Find all type / extend type blocks
        type_pattern = re.compile(
            r"(?:type|extend\s+type)\s+([A-Za-z0-9_]+)[^{]*\{([^}]+)\}",
            re.MULTILINE,
        )

        for match in type_pattern.finditer(cleaned):
            type_name = match.group(1)
            body = match.group(2)

            op_type = None
            if type_name == query_type:
                op_type = "Query"
            elif type_name == mutation_type:
                op_type = "Mutation"

            if op_type is None:
                continue

            fields = cls._parse_fields(body)
            for field in fields:
                field_name = field["name"]
                full_name = f"{type_name}.{field_name}"
                virtual_endpoint = f"GRAPHQL: {full_name}"

                handler_name, handler_obj = cls._resolve_handler(
                    resolvers, type_name, op_type, field_name
                )

                endpoint = {
                    "type": op_type,
                    "root_type": type_name,
                    "operation_type": op_type,
                    "field": field_name,
                    "name": full_name,
                    "path": virtual_endpoint,
                    "virtual_endpoint": virtual_endpoint,
                    "method": "POST",
                    "arguments": field["arguments"],
                    "argument_names": list(field["arguments"].keys()),
                    "return_type": field["return_type"],
                    "handler": handler_obj,
                    "handler_name": handler_name,
                }
                endpoints.append(endpoint)

        return endpoints

    @classmethod
    def _clean_schema(cls, schema_str: str) -> str:
        # Strip block strings: """ ... """
        cleaned = re.sub(r'"""[\s\S]*?"""', "", schema_str)
        # Strip line comments: # ...
        cleaned = re.sub(r"#[^\n]*", "", cleaned)
        return cleaned

    @classmethod
    def _find_root_types(cls, schema_str: str) -> tuple[str, str]:
        """Find custom query and mutation root types or default to Query and Mutation."""
        query_type = "Query"
        mutation_type = "Mutation"

        schema_match = re.search(r"\bschema\s*\{([^}]+)\}", schema_str)
        if schema_match:
            body = schema_match.group(1)
            qm = re.search(r"\bquery\s*:\s*([A-Za-z0-9_]+)", body)
            if qm:
                query_type = qm.group(1)
            mm = re.search(r"\bmutation\s*:\s*([A-Za-z0-9_]+)", body)
            if mm:
                mutation_type = mm.group(1)

        return query_type, mutation_type

    @classmethod
    def _parse_fields(cls, body: str) -> list[dict[str, Any]]:
        """Parse field declarations inside a type body."""
        fields: list[dict[str, Any]] = []

        field_pattern = re.compile(
            r"([A-Za-z0-9_]+)"  # field name
            r"(?:\s*\(\s*([^)]*?)\s*\))?"  # optional arguments in (...)
            r"\s*:\s*"  # colon
            r"([A-Za-z0-9_\[\]!]+)"  # return type
        )

        for match in field_pattern.finditer(body):
            name = match.group(1)
            args_str = match.group(2)
            return_type = match.group(3)

            arguments: dict[str, str] = {}
            if args_str:
                # Parse arguments: argName: Type or argName: Type = Default
                arg_pattern = re.compile(
                    r"([A-Za-z0-9_]+)\s*:\s*([A-Za-z0-9_\[\]!]+)"
                )
                for arg_match in arg_pattern.finditer(args_str):
                    arguments[arg_match.group(1)] = arg_match.group(2)

            fields.append({
                "name": name,
                "arguments": arguments,
                "return_type": return_type,
            })

        return fields

    @classmethod
    def _resolve_handler(
        cls,
        resolvers: dict[str, Any] | None,
        type_name: str,
        op_type: str,
        field_name: str,
    ) -> tuple[str, Any]:
        """Find matching resolver by nested, dotted, or flat name."""
        if not resolvers:
            return f"{type_name}.{field_name}", None

        handler_obj = None

        # 1. Nested: resolvers[type_name][field_name] or resolvers[op_type][field_name]
        for key in (type_name, op_type):
            if key in resolvers:
                bucket = resolvers[key]
                if isinstance(bucket, dict) and field_name in bucket:
                    handler_obj = bucket[field_name]
                    break
                elif hasattr(bucket, field_name):
                    handler_obj = getattr(bucket, field_name)
                    break

        # 2. Dotted: resolvers[f"{type_name}.{field_name}"] or resolvers[f"{op_type}.{field_name}"]
        if handler_obj is None:
            for key in (f"{type_name}.{field_name}", f"{op_type}.{field_name}"):
                if key in resolvers:
                    handler_obj = resolvers[key]
                    break

        # 3. Flat: resolvers[field_name]
        if handler_obj is None and field_name in resolvers:
            handler_obj = resolvers[field_name]

        if handler_obj is not None:
            if callable(handler_obj):
                name = getattr(
                    handler_obj,
                    "__name__",
                    str(handler_obj),
                )
            elif isinstance(handler_obj, str):
                name = handler_obj
            else:
                name = str(handler_obj)
            return name, handler_obj

        return f"{type_name}.{field_name}", None

    @classmethod
    def to_route_nodes(
        cls,
        endpoints: Sequence[dict[str, Any]],
        file_path: str = "",
    ) -> list[RouteNode]:
        """Convert GraphQL virtual endpoints to CKG RouteNode instances."""
        nodes: list[RouteNode] = []
        for ep in endpoints:
            node_id = f"route:graphql:{ep['name']}"
            nodes.append(
                RouteNode(
                    id=node_id,
                    method=ep.get("method", "POST"),
                    path=ep["path"],
                    file_path=file_path,
                )
            )
        return nodes
