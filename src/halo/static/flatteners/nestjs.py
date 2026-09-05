from __future__ import annotations

import re
import warnings
from collections.abc import Sequence
from typing import Any

from halo.static.graph import RouteNode

try:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        import tree_sitter_languages
        _TS_PARSER = tree_sitter_languages.get_parser("typescript")
except (ImportError, Exception):  # noqa: BLE001
    _TS_PARSER = None


class NestJSFlattener:
    """
    Flattens NestJS controller prefix decorators and route decorators
    (@Controller, @Get, @Post, @Put, @Delete, @Patch, etc.) into normalized URIs.
    """

    SUPPORTED_HTTP_METHODS: frozenset[str] = frozenset({
        "GET",
        "POST",
        "PUT",
        "DELETE",
        "PATCH",
        "OPTIONS",
        "HEAD",
        "ALL",
    })

    @classmethod
    def compose_prefix(cls, controller_prefix: str, action_path: str = "") -> str:
        """
        Compose a class-level controller prefix and an action route path into a normalized URI.
        Converts Express/NestJS parameter syntax (:param) to standard OpenAPI curly braces ({param}).

        Examples:
            - ("api/v1/invoices", ":id") -> "/api/v1/invoices/{id}"
            - ("api/v1/invoices", "") -> "/api/v1/invoices"
            - ("", ":id") -> "/{id}"
            - ("", "") -> "/"
        """
        prefix = (controller_prefix or "").strip()
        action = (action_path or "").strip()

        # Clean consecutive slashes
        prefix = re.sub(r"/+", "/", prefix).strip("/")
        action = re.sub(r"/+", "/", action).strip("/")

        if prefix and action:
            combined = f"/{prefix}/{action}"
        elif prefix:
            combined = f"/{prefix}"
        elif action:
            combined = f"/{action}"
        else:
            combined = "/"

        # Convert :param to {param}
        # Handles :param and :param(regex)
        combined = re.sub(r":([a-zA-Z_][a-zA-Z0-9_]*)(?:\([^)]+\))?", r"{\1}", combined)
        return combined

    @classmethod
    def extract_routes(cls, code: str, file_path: str = "") -> list[dict[str, Any]]:
        """
        Extract route declarations from NestJS TypeScript/JavaScript code.
        Finds @Controller('...') classes and @Get/@Post/@Put/@Delete methods,
        composing them into normalized route definitions.
        """
        if _TS_PARSER is not None:
            try:
                tree_routes = cls._extract_routes_tree_sitter(code, file_path)
                if tree_routes:
                    return tree_routes
            except Exception:  # noqa: BLE001, S110
                pass

        return cls._extract_routes_regex(code, file_path)

    @classmethod
    def _extract_routes_tree_sitter(cls, code: str, file_path: str) -> list[dict[str, Any]]:
        code_bytes = code.encode("utf-8")
        tree = _TS_PARSER.parse(code_bytes)
        routes: list[dict[str, Any]] = []

        def strip_quotes(text: str) -> str:
            text = text.strip()
            if (text.startswith("'") and text.endswith("'")) or (
                text.startswith('"') and text.endswith('"')
            ) or (text.startswith("`") and text.endswith("`")):
                return text[1:-1]
            return text

        def parse_decorator(dec_node: Any) -> tuple[str, str]:
            """Returns (decorator_name, argument_string)."""
            for child in dec_node.children:
                if child.type == "call_expression":
                    fn_node = child.child_by_field_name("function")
                    args_node = child.child_by_field_name("arguments")
                    dec_name = fn_node.text.decode() if fn_node else ""
                    arg_str = ""
                    if args_node:
                        for arg_child in args_node.children:
                            if arg_child.type in ("string", "template_string"):
                                arg_str = strip_quotes(arg_child.text.decode())
                                break
                    return dec_name, arg_str
                elif child.type == "identifier":
                    return child.text.decode(), ""
            return "", ""

        def process_class(
            class_node: Any, controller_prefix: str, controller_name: str
        ) -> None:
            body_node = class_node.child_by_field_name("body")
            if not body_node:
                return

            pending_decorators: list[tuple[str, str, int]] = []
            for child in body_node.children:
                if child.type == "decorator":
                    name, arg = parse_decorator(child)
                    line = child.start_point[0] + 1
                    pending_decorators.append((name, arg, line))
                elif child.type == "method_definition":
                    prop = child.child_by_field_name("name")
                    method_name = prop.text.decode() if prop else ""
                    line = child.start_point[0] + 1

                    for dec_name, dec_arg, dec_line in pending_decorators:
                        dec_upper = dec_name.upper()
                        if dec_upper in cls.SUPPORTED_HTTP_METHODS:
                            composed = cls.compose_prefix(controller_prefix, dec_arg)
                            routes.append({
                                "method": dec_upper,
                                "path": composed,
                                "action_path": dec_arg,
                                "controller_prefix": controller_prefix,
                                "handler_name": method_name,
                                "controller": controller_name,
                                "file_path": file_path,
                                "line_number": dec_line or line,
                            })
                    pending_decorators = []

        def walk(node: Any) -> None:
            if node.type in ("class_declaration", "export_statement"):
                # Check for @Controller decorator
                controller_prefix: str | None = None
                controller_name: str = ""
                class_node = (
                    node
                    if node.type == "class_declaration"
                    else node.child_by_field_name("declaration")
                )

                # Look for decorators on node or class_node
                decorators = [c for c in node.children if c.type == "decorator"]
                if class_node and class_node != node:
                    decorators.extend([c for c in class_node.children if c.type == "decorator"])

                for dec in decorators:
                    name, arg = parse_decorator(dec)
                    if name.lower() == "controller":
                        controller_prefix = arg
                        break

                if controller_prefix is not None and class_node:
                    name_node = class_node.child_by_field_name("name")
                    if name_node:
                        controller_name = name_node.text.decode()
                    process_class(class_node, controller_prefix, controller_name)

            for child in node.children:
                walk(child)

        walk(tree.root_node)
        return routes

    @classmethod
    def _extract_routes_regex(cls, code: str, file_path: str) -> list[dict[str, Any]]:
        routes: list[dict[str, Any]] = []

        # Find controller classes: @Controller('prefix') class ControllerName { ... }
        # Matches @Controller() or @Controller('...') with class body
        ctrl_pattern = re.compile(
            r"@Controller\s*\(\s*(?:['\"`](.*?)['\"`])?\s*\)\s*(?:export\s+)?class\s+([A-Za-z0-9_]+)\s*\{",
            re.MULTILINE,
        )

        method_pattern = re.compile(
            r"@(Get|Post|Put|Delete|Patch|Options|Head|All)\s*\(\s*(?:['\"`](.*?)['\"`])?\s*\)\s*"
            r"(?:@[A-Za-z0-9_]+\s*\([^)]*\)\s*)*"
            r"(?:(?:async\s+)?([A-Za-z0-9_]+)\s*\()",
            re.MULTILINE,
        )

        for ctrl_match in ctrl_pattern.finditer(code):
            ctrl_prefix = ctrl_match.group(1) or ""
            ctrl_name = ctrl_match.group(2)
            ctrl_start = ctrl_match.end()

            # Find matching closing brace for class body
            brace_count = 1
            idx = ctrl_start
            while idx < len(code) and brace_count > 0:
                if code[idx] == "{":
                    brace_count += 1
                elif code[idx] == "}":
                    brace_count -= 1
                idx += 1
            class_body = code[ctrl_start:idx]

            for m_match in method_pattern.finditer(class_body):
                http_method = m_match.group(1).upper()
                action_path = m_match.group(2) or ""
                handler_name = m_match.group(3)
                composed = cls.compose_prefix(ctrl_prefix, action_path)

                # Estimate line number
                char_offset = ctrl_start + m_match.start()
                line_number = code[:char_offset].count("\n") + 1

                routes.append({
                    "method": http_method,
                    "path": composed,
                    "action_path": action_path,
                    "controller_prefix": ctrl_prefix,
                    "handler_name": handler_name,
                    "controller": ctrl_name,
                    "file_path": file_path,
                    "line_number": line_number,
                })

        return routes

    @classmethod
    def to_route_nodes(
        cls,
        routes: Sequence[dict[str, Any]],
        file_path: str = "",
    ) -> list[RouteNode]:
        """Convert extracted route dictionaries to CKG RouteNode instances."""
        nodes: list[RouteNode] = []
        for r in routes:
            node_id = f"route:nestjs:{r['method']}:{r['path']}"
            nodes.append(
                RouteNode(
                    id=node_id,
                    method=r["method"],
                    path=r["path"],
                    file_path=r.get("file_path", file_path),
                    line_number=r.get("line_number", 0),
                )
            )
        return nodes
