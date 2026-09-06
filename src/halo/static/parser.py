from __future__ import annotations

import re
import warnings
from pathlib import Path
from typing import Any, ClassVar

import tree_sitter_languages
from pydantic import BaseModel, ConfigDict, Field
from tree_sitter import Node, Tree


def normalize_route_path(path: str) -> tuple[str, dict[str, str]]:
    """
    Normalizes parameterized route paths across frameworks and extracts parameter constraints.

    Examples:
        - /items/{id:int} -> (/items/{id}, {"id": "int"})
        - /users/{user_id:uuid} -> (/users/{user_id}, {"user_id": "uuid"})
        - /items/{id:[0-9]+} -> (/items/{id}, {"id": "[0-9]+"})
        - /products/<int:prod_id> -> (/products/{prod_id}, {"prod_id": "int"})
        - /categories/<cat_name> -> (/categories/{cat_name}, {})
        - /invoices/:id -> (/invoices/:id, {})
        - /invoices/:id([0-9]+) -> (/invoices/:id, {"id": "[0-9]+"})
    """
    constraints: dict[str, str] = {}
    normalized = path

    # 1. FastAPI / Starlette / OpenAPI style: {param:constraint}
    def replace_brace(match: re.Match) -> str:
        param = match.group(1)
        constraint = match.group(2)
        constraints[param] = constraint
        return f"{{{param}}}"

    normalized = re.sub(r"\{([a-zA-Z_][a-zA-Z0-9_]*):([^}]+)\}", replace_brace, normalized)

    # 2. Flask style with type converter: <int:param>, <string:param>, <uuid:param>, <path:param>
    def replace_flask_typed(match: re.Match) -> str:
        constraint = match.group(1)
        param = match.group(2)
        constraints[param] = constraint
        return f"{{{param}}}"

    normalized = re.sub(r"<([a-zA-Z_][a-zA-Z0-9_]*):([a-zA-Z_][a-zA-Z0-9_]*)>", replace_flask_typed, normalized)

    # 3. Flask style untyped: <param>
    normalized = re.sub(r"<([a-zA-Z_][a-zA-Z0-9_]*)>", r"{\1}", normalized)

    # 4. Express regex parameter constraint: :id([0-9]+)
    def replace_express_regex(match: re.Match) -> str:
        param = match.group(1)
        constraint = match.group(2)
        constraints[param] = constraint
        return f":{param}"

    normalized = re.sub(r":([a-zA-Z_][a-zA-Z0-9_]*)\(([^)]+)\)", replace_express_regex, normalized)

    return normalized, constraints


def to_standard_path(path: str) -> str:
    """Convert framework-specific path parameters (e.g. Express :id) to standard OpenAPI {id} format."""
    # Convert Express :id to {id}
    return re.sub(r":([a-zA-Z_][a-zA-Z0-9_]*)", r"{\1}", path)


class RouteDefinition(BaseModel):
    model_config = ConfigDict(extra="allow")

    method: str
    path: str
    handler_name: str
    middleware: list[str] = Field(default_factory=list)
    param_constraints: dict[str, str] = Field(default_factory=dict)
    file_path: str = ""
    line_number: int = 0
    raw_path: str = ""
    normalized_path: str = ""
    extra: dict[str, Any] = Field(default_factory=dict)

    def __init__(self, **data: Any) -> None:
        if "path" in data and "raw_path" not in data:
            data["raw_path"] = data["path"]
        super().__init__(**data)
        if not self.normalized_path:
            self.normalized_path = to_standard_path(self.path)


class HandlerDefinition(BaseModel):
    model_config = ConfigDict(extra="allow")

    name: str
    signature: str = ""
    line_span: tuple[int, int] = (0, 0)
    arguments: list[str] = Field(default_factory=list)
    file_path: str = ""
    docstring: str = ""
    is_async: bool = False
    class_name: str = ""


class ASTParseResult(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    tree: Tree
    language: str
    file_path: str
    code: str

    @property
    def root_node(self) -> Node:
        return self.tree.root_node


class CodeParser:
    """
    Multi-language AST parser wrapping tree_sitter_languages with SCM query execution,
    route extraction, and handler cataloging for Python, JS/TS, and PHP.
    """

    EXT_TO_LANG: ClassVar[dict[str, str]] = {
        ".py": "python",
        ".pyi": "python",
        ".js": "javascript",
        ".jsx": "javascript",
        ".mjs": "javascript",
        ".cjs": "javascript",
        ".ts": "typescript",
        ".tsx": "typescript",
        ".mts": "typescript",
        ".cts": "typescript",
        ".php": "php",
        ".phtml": "php",
    }

    def __init__(self, queries_dir: Path | str | None = None) -> None:
        if queries_dir is None:
            self.queries_dir = Path(__file__).parent / "queries"
        else:
            self.queries_dir = Path(queries_dir)

        self._query_cache: dict[tuple[str, str], Any] = {}

    def _detect_language(self, file_path: str) -> str:
        ext = Path(file_path).suffix.lower()
        lang = self.EXT_TO_LANG.get(ext)
        if not lang:
            raise ValueError(f"Unsupported or unrecognized file extension '{ext}' for file '{file_path}'")
        return lang

    def parse_file(
        self,
        file_path: str,
        code: str | None = None,
        language: str | None = None,
    ) -> ASTParseResult:
        """Parse source code bytes into a Tree-sitter Tree."""
        if code is None:
            code = Path(file_path).read_text(encoding="utf-8", errors="replace")

        if language is None:
            language = self._detect_language(file_path)

        with warnings.catch_warnings():
            warnings.simplefilter("ignore", FutureWarning)
            parser = tree_sitter_languages.get_parser(language)
        source_bytes = code.encode("utf-8")
        tree = parser.parse(source_bytes)

        return ASTParseResult(
            tree=tree,
            language=language,
            file_path=str(file_path),
            code=code,
        )

    def execute_query(
        self,
        tree: Tree,
        language: str,
        query_scm: str,
    ) -> list[tuple[Node, str]]:
        """
        Execute an SCM query against a Tree-sitter Tree and return (Node, capture_name) pairs.
        `query_scm` may be a query string or a path/filename to an SCM file.
        """
        scm_text: str
        is_file = False
        if not ("\n" in query_scm or query_scm.strip().startswith("(") or query_scm.strip().startswith(";")):
            base_name = query_scm.removesuffix(".scm")
            candidates = [
                self.queries_dir / f"{base_name}.scm",
                Path(query_scm),
            ]
            if base_name in ("typescript", "typescript.scm"):
                candidates.append(self.queries_dir / "javascript.scm")

            found_path: Path | None = None
            for cand in candidates:
                if cand.is_file():
                    found_path = cand
                    break

            if found_path:
                scm_text = found_path.read_text(encoding="utf-8")
                is_file = True
            else:
                scm_text = query_scm
        else:
            scm_text = query_scm

        cache_key = (language, scm_text if not is_file else query_scm)
        if cache_key not in self._query_cache:
            # Silence deprecated Language(path, name) warning from tree_sitter_languages
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", FutureWarning)
                lang = tree_sitter_languages.get_language(language)
            self._query_cache[cache_key] = lang.query(scm_text)

        compiled_query = self._query_cache[cache_key]
        return compiled_query.captures(tree.root_node)

    def extract_routes(
        self,
        file_path: str,
        code: str | None = None,
        language: str | None = None,
    ) -> list[RouteDefinition]:
        """Extract all route definitions from a source file."""
        parse_result = self.parse_file(file_path, code=code, language=language)
        lang = parse_result.language
        tree = parse_result.tree
        code_bytes = parse_result.code.encode("utf-8")

        if lang == "python":
            routes = self._extract_python_routes(tree, code_bytes, parse_result.file_path)
        elif lang in ("javascript", "typescript"):
            routes = self._extract_js_routes(tree, code_bytes, parse_result.file_path)
        elif lang == "php":
            routes = self._extract_php_routes(tree, code_bytes, parse_result.file_path)
        else:
            routes = []
        return self._deduplicate_routes(routes)

    def _deduplicate_routes(self, routes: list[RouteDefinition]) -> list[RouteDefinition]:
        """Deduplicate routes by (method, normalized_path) and aggregate chained middlewares."""
        merged: dict[tuple[str, str], RouteDefinition] = {}
        for r in routes:
            raw = (r.path or "").strip()
            if " " in raw or ">" in raw or raw.startswith("."):
                continue
            key = (r.method.upper(), r.normalized_path or r.path)
            if key not in merged:
                merged[key] = r
                continue

            existing = merged[key]
            combined_mw = list(existing.middleware)

            is_existing_guard = any(
                t in existing.handler_name.lower()
                for t in (
                    "deny",
                    "auth",
                    "guard",
                    "role",
                    "check",
                    "valid",
                    "perm",
                    "reject",
                    "block",
                    "forbidden",
                )
            ) or existing.handler_name.endswith("()")

            is_r_guard = any(
                t in r.handler_name.lower()
                for t in (
                    "deny",
                    "auth",
                    "guard",
                    "role",
                    "check",
                    "valid",
                    "perm",
                    "reject",
                    "block",
                    "forbidden",
                )
            ) or r.handler_name.endswith("()")

            if (
                existing.handler_name
                and (is_existing_guard or r.handler_name)
                and existing.handler_name not in combined_mw
                and existing.handler_name != r.handler_name
            ):
                combined_mw.append(existing.handler_name)

            for mw in r.middleware:
                if mw not in combined_mw:
                    combined_mw.append(mw)

            new_handler = existing.handler_name
            if is_existing_guard and r.handler_name and not is_r_guard or not existing.handler_name and r.handler_name:
                new_handler = r.handler_name
            elif r.handler_name and is_r_guard and r.handler_name not in combined_mw:
                combined_mw.append(r.handler_name)

            existing.middleware = combined_mw
            existing.handler_name = new_handler
            if r.param_constraints:
                existing.param_constraints.update(r.param_constraints)

        return list(merged.values())

    def extract_handlers(
        self,
        file_path: str,
        code: str | None = None,
        language: str | None = None,
    ) -> list[HandlerDefinition]:
        """Extract all function and class method handlers from a source file."""
        parse_result = self.parse_file(file_path, code=code, language=language)
        lang = parse_result.language
        tree = parse_result.tree
        code_bytes = parse_result.code.encode("utf-8")

        if lang == "python":
            return self._extract_python_handlers(tree, code_bytes, parse_result.file_path)
        elif lang in ("javascript", "typescript"):
            return self._extract_js_handlers(tree, code_bytes, parse_result.file_path)
        elif lang == "php":
            return self._extract_php_handlers(tree, code_bytes, parse_result.file_path)
        else:
            return []

    # -------------------------------------------------------------------------
    # Python Route & Handler Extraction
    # -------------------------------------------------------------------------

    def _extract_python_routes(
        self, tree: Tree, code_bytes: bytes, file_path: str
    ) -> list[RouteDefinition]:
        routes: list[RouteDefinition] = []

        def walk(node: Node) -> None:
            if node.type == "decorated_definition":
                fn_node = None
                decorators: list[Node] = []
                for child in node.children:
                    if child.type == "decorator":
                        decorators.append(child)
                    elif child.type == "function_definition":
                        fn_node = child

                if fn_node and decorators:
                    fn_name_node = fn_node.child_by_field_name("name")
                    handler_name = fn_name_node.text.decode() if fn_name_node else ""

                    # Extract parameter dependencies (e.g. Depends(auth))
                    fn_middlewares = self._extract_python_fn_dependencies(fn_node, code_bytes)

                    for dec in decorators:
                        extracted = self._parse_python_decorator(
                            dec, handler_name, fn_middlewares, code_bytes, file_path
                        )
                        routes.extend(extracted)

            for child in node.children:
                walk(child)

        walk(tree.root_node)
        return routes

    def _parse_python_decorator(
        self,
        dec: Node,
        handler_name: str,
        fn_middlewares: list[str],
        code_bytes: bytes,
        file_path: str,
    ) -> list[RouteDefinition]:
        routes: list[RouteDefinition] = []
        call_node = None
        for child in dec.children:
            if child.type == "call":
                call_node = child
                break

        if not call_node:
            return routes

        fn_expr = call_node.child_by_field_name("function")
        if not fn_expr or fn_expr.type != "attribute":
            return routes

        attr_node = fn_expr.child_by_field_name("attribute")
        method_name = attr_node.text.decode() if attr_node else ""
        router_node = fn_expr.child_by_field_name("object")
        router_var = router_node.text.decode() if router_node else ""

        args_node = call_node.child_by_field_name("arguments")
        if not args_node:
            return routes

        raw_path = ""
        flask_methods: list[str] = []
        dec_middlewares: list[str] = list(fn_middlewares)

        # Parse arguments
        for arg in args_node.children:
            if arg.type in ("(", ")", ","):
                continue
            if arg.type == "string" and not raw_path:
                raw_path = self._strip_quotes(arg.text.decode())
            elif arg.type == "keyword_argument":
                kw_name = arg.child_by_field_name("name")
                kw_val = arg.child_by_field_name("value")
                if kw_name and kw_val:
                    kw_key = kw_name.text.decode()
                    if kw_key in ("path", "rule") and not raw_path:
                        raw_path = self._strip_quotes(kw_val.text.decode())
                    elif kw_key == "methods" and kw_val.type == "list":
                        for item in kw_val.children:
                            if item.type == "string":
                                flask_methods.append(self._strip_quotes(item.text.decode()).upper())
                    elif kw_key == "dependencies" and kw_val.type == "list":
                        for item in kw_val.children:
                            if item.type == "call":
                                dep_fn = item.child_by_field_name("function")
                                if dep_fn and dep_fn.text.decode() == "Depends":
                                    dep_args = item.child_by_field_name("arguments")
                                    if dep_args:
                                        for da in dep_args.children:
                                            if da.type == "identifier":
                                                dec_middlewares.append(da.text.decode())

        if not raw_path:
            return routes

        norm_path, constraints = normalize_route_path(raw_path)
        line_num = dec.start_point[0] + 1

        std_methods = {"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"}
        m_upper = method_name.upper()

        if m_upper in std_methods:
            routes.append(
                RouteDefinition(
                    method=m_upper,
                    path=norm_path,
                    raw_path=raw_path,
                    handler_name=handler_name,
                    middleware=dec_middlewares,
                    param_constraints=constraints,
                    file_path=file_path,
                    line_number=line_num,
                    extra={"router": router_var},
                )
            )
        elif method_name in ("route", "add_url_rule"):
            methods = flask_methods if flask_methods else ["GET"]
            for m in methods:
                routes.append(
                    RouteDefinition(
                        method=m,
                        path=norm_path,
                        raw_path=raw_path,
                        handler_name=handler_name,
                        middleware=dec_middlewares,
                        param_constraints=constraints,
                        file_path=file_path,
                        line_number=line_num,
                        extra={"router": router_var},
                    )
                )

        return routes

    def _extract_python_fn_dependencies(self, fn_node: Node, code_bytes: bytes) -> list[str]:
        deps: list[str] = []
        params_node = fn_node.child_by_field_name("parameters")
        if not params_node:
            return deps

        for p in params_node.children:
            if p.type == "typed_default_parameter":
                val = p.child_by_field_name("value")
                if val and val.type == "call":
                    fn = val.child_by_field_name("function")
                    if fn and fn.text.decode() == "Depends":
                        args = val.child_by_field_name("arguments")
                        if args:
                            for a in args.children:
                                if a.type == "identifier":
                                    deps.append(a.text.decode())
        return deps

    def _extract_python_handlers(
        self, tree: Tree, code_bytes: bytes, file_path: str
    ) -> list[HandlerDefinition]:
        handlers: list[HandlerDefinition] = []

        def walk(node: Node, class_name: str = "") -> None:
            if node.type == "class_definition":
                cname_node = node.child_by_field_name("name")
                cname = cname_node.text.decode() if cname_node else ""
                body = node.child_by_field_name("body")
                if body:
                    for child in body.children:
                        walk(child, class_name=cname)
                return

            if node.type == "function_definition":
                name_node = node.child_by_field_name("name")
                fn_name = name_node.text.decode() if name_node else ""
                full_name = f"{class_name}.{fn_name}" if class_name else fn_name

                params_node = node.child_by_field_name("parameters")
                sig = params_node.text.decode() if params_node else "()"
                args: list[str] = []
                if params_node:
                    for p in params_node.children:
                        if p.type in ("(", ")", ","):
                            continue
                        if p.type == "identifier":
                            args.append(p.text.decode())
                            continue
                        p_name = p.child_by_field_name("name")
                        if not p_name:
                            for c in p.children:
                                if c.type == "identifier":
                                    p_name = c
                                    break
                        if p_name:
                            args.append(p_name.text.decode())

                line_span = (node.start_point[0] + 1, node.end_point[0] + 1)
                is_async = (
                    any(c.type == "async" for c in node.children)
                    or code_bytes[node.start_byte:node.end_byte].startswith(b"async")
                )

                # Extract docstring if present
                docstring = ""
                body = node.child_by_field_name("body")
                if body and body.children:
                    first_stmt = body.children[0]
                    if first_stmt.type == "expression_statement" and first_stmt.children:
                        cand = first_stmt.children[0]
                        if cand.type == "string":
                            docstring = self._strip_docstring(cand.text.decode())

                handlers.append(
                    HandlerDefinition(
                        name=full_name,
                        signature=sig,
                        line_span=line_span,
                        arguments=args,
                        file_path=file_path,
                        docstring=docstring,
                        is_async=is_async,
                        class_name=class_name,
                    )
                )

            for child in node.children:
                walk(child, class_name=class_name)

        walk(tree.root_node)
        return handlers

    # -------------------------------------------------------------------------
    # JavaScript / TypeScript Route & Handler Extraction
    # -------------------------------------------------------------------------

    def _extract_js_routes(
        self, tree: Tree, code_bytes: bytes, file_path: str
    ) -> list[RouteDefinition]:
        routes: list[RouteDefinition] = []
        std_methods = {"get", "post", "put", "delete", "patch", "options", "head", "all", "use"}

        def walk(node: Node) -> None:
            if node.type == "call_expression":
                fn_node = node.child_by_field_name("function")
                if fn_node and fn_node.type == "member_expression":
                    prop = fn_node.child_by_field_name("property")
                    method_str = prop.text.decode() if prop else ""

                    if method_str.lower() in std_methods:
                        obj = fn_node.child_by_field_name("object")
                        router_var = obj.text.decode() if obj else ""

                        args_node = node.child_by_field_name("arguments")
                        if args_node:
                            # Check if chained from router.route('/path')
                            chained_path = self._unwrap_chained_js_route(obj)

                            extracted = self._parse_js_route_args(
                                args_node,
                                method_str.upper(),
                                router_var,
                                file_path,
                                node.start_point[0] + 1,
                                default_path=chained_path,
                            )
                            if extracted:
                                routes.append(extracted)

            for child in node.children:
                walk(child)

        walk(tree.root_node)
        return routes

    def _unwrap_chained_js_route(self, obj_node: Node | None) -> str:
        if not obj_node or obj_node.type != "call_expression":
            return ""
        fn = obj_node.child_by_field_name("function")
        if fn and fn.type == "member_expression":
            prop = fn.child_by_field_name("property")
            if prop and prop.text.decode() == "route":
                args = obj_node.child_by_field_name("arguments")
                if args:
                    for a in args.children:
                        if a.type in ("string", "template_string"):
                            return self._strip_quotes(a.text.decode())
            # Recursive check if chained further: e.g. router.route(...).get(...)
            inner_obj = fn.child_by_field_name("object")
            return self._unwrap_chained_js_route(inner_obj)
        return ""

    def _parse_js_route_args(
        self,
        args_node: Node,
        method: str,
        router_var: str,
        file_path: str,
        line_num: int,
        default_path: str = "",
    ) -> RouteDefinition | None:
        raw_path = default_path
        arg_nodes: list[Node] = []

        for c in args_node.children:
            if c.type in ("(", ")", ","):
                continue
            if not raw_path and c.type in ("string", "template_string"):
                raw_path = self._strip_quotes(c.text.decode())
            else:
                arg_nodes.append(c)

        if not raw_path:
            return None

        middlewares: list[str] = []
        handler_name = ""

        if arg_nodes:
            # Last argument is handler
            handler_node = arg_nodes[-1]
            handler_name = self._node_to_expression_str(handler_node)

            # All prior arguments are middlewares
            for mw_node in arg_nodes[:-1]:
                if mw_node.type == "array":
                    for item in mw_node.children:
                        if item.type not in ("[", "]", ","):
                            middlewares.append(self._node_to_expression_str(item))
                else:
                    middlewares.append(self._node_to_expression_str(mw_node))

        norm_path, constraints = normalize_route_path(raw_path)

        return RouteDefinition(
            method=method,
            path=raw_path,
            raw_path=raw_path,
            normalized_path=to_standard_path(norm_path),
            handler_name=handler_name,
            middleware=middlewares,
            param_constraints=constraints,
            file_path=file_path,
            line_number=line_num,
            extra={"router": router_var},
        )

    def _extract_js_handlers(
        self, tree: Tree, code_bytes: bytes, file_path: str
    ) -> list[HandlerDefinition]:
        handlers: list[HandlerDefinition] = []

        def walk(node: Node, class_name: str = "") -> None:
            # Class declaration
            if node.type == "class_declaration":
                cname_node = node.child_by_field_name("name")
                cname = cname_node.text.decode() if cname_node else ""
                body = node.child_by_field_name("body")
                if body:
                    for child in body.children:
                        walk(child, class_name=cname)
                return

            # Function declaration: function foo(...) { ... }
            if node.type == "function_declaration":
                name_node = node.child_by_field_name("name")
                fn_name = name_node.text.decode() if name_node else ""
                params_node = node.child_by_field_name("parameters")
                sig = params_node.text.decode() if params_node else "()"
                args = self._extract_js_param_names(params_node)
                is_async = (
                    any(c.type == "async" for c in node.children)
                    or code_bytes[node.start_byte:node.end_byte].startswith(b"async")
                )
                handlers.append(
                    HandlerDefinition(
                        name=fn_name,
                        signature=sig,
                        line_span=(node.start_point[0] + 1, node.end_point[0] + 1),
                        arguments=args,
                        file_path=file_path,
                        is_async=is_async,
                    )
                )

            # Method definition in class: show(req, res) { ... }
            elif node.type == "method_definition":
                name_node = node.child_by_field_name("name")
                method_name = name_node.text.decode() if name_node else ""
                full_name = f"{class_name}.{method_name}" if class_name else method_name
                params_node = node.child_by_field_name("parameters")
                sig = params_node.text.decode() if params_node else "()"
                args = self._extract_js_param_names(params_node)
                is_async = (
                    any(c.type == "async" for c in node.children)
                    or code_bytes[node.start_byte:node.end_byte].startswith(b"async")
                )
                handlers.append(
                    HandlerDefinition(
                        name=full_name,
                        signature=sig,
                        line_span=(node.start_point[0] + 1, node.end_point[0] + 1),
                        arguments=args,
                        file_path=file_path,
                        is_async=is_async,
                        class_name=class_name,
                    )
                )

            # Variable declarator: const handler = (req, res) => ...
            elif node.type == "variable_declarator":
                val = node.child_by_field_name("value")
                if val and val.type in ("arrow_function", "function"):
                    name_node = node.child_by_field_name("name")
                    fn_name = name_node.text.decode() if name_node else ""
                    params_node = val.child_by_field_name("parameters")
                    sig = params_node.text.decode() if params_node else "()"
                    args = self._extract_js_param_names(params_node)
                    is_async = (
                        any(c.type == "async" for c in val.children)
                        or code_bytes[val.start_byte:val.end_byte].startswith(b"async")
                    )
                    handlers.append(
                        HandlerDefinition(
                            name=fn_name,
                            signature=sig,
                            line_span=(node.start_point[0] + 1, node.end_point[0] + 1),
                            arguments=args,
                            file_path=file_path,
                            is_async=is_async,
                        )
                    )

            for child in node.children:
                walk(child, class_name=class_name)

        walk(tree.root_node)
        return handlers

    def _extract_js_param_names(self, params_node: Node | None) -> list[str]:
        args: list[str] = []
        if not params_node:
            return args

        for p in params_node.children:
            if p.type in ("(", ")", ","):
                continue
            if p.type in ("identifier", "property_identifier"):
                args.append(p.text.decode())
                continue

            name_node = p.child_by_field_name("name") or p.child_by_field_name("pattern")
            if not name_node:
                for c in p.children:
                    if c.type in ("identifier", "property_identifier"):
                        name_node = c
                        break
            if name_node:
                if name_node.type in ("identifier", "property_identifier"):
                    args.append(name_node.text.decode())
                else:
                    for c in name_node.children:
                        if c.type in ("identifier", "property_identifier"):
                            args.append(c.text.decode())
                            break
        return args

    # -------------------------------------------------------------------------
    # PHP Laravel Route & Handler Extraction
    # -------------------------------------------------------------------------

    def _extract_php_routes(
        self, tree: Tree, code_bytes: bytes, file_path: str
    ) -> list[RouteDefinition]:
        routes: list[RouteDefinition] = []

        def walk(node: Node) -> None:
            if node.type == "scoped_call_expression":
                scope_node = node.child_by_field_name("scope")
                name_node = node.child_by_field_name("name")
                scope_str = scope_node.text.decode() if scope_node else ""
                method_str = name_node.text.decode() if name_node else ""

                if scope_str == "Route":
                    args_node = node.child_by_field_name("arguments")
                    if args_node:
                        route = self._parse_laravel_route(
                            node, method_str, args_node, code_bytes, file_path
                        )
                        if route:
                            routes.append(route)

            for child in node.children:
                walk(child)

        walk(tree.root_node)
        return routes

    def _parse_laravel_route(
        self,
        call_node: Node,
        method_name: str,
        args_node: Node,
        code_bytes: bytes,
        file_path: str,
    ) -> RouteDefinition | None:
        args: list[Node] = []
        for c in args_node.children:
            if c.type in ("(", ")", ","):
                continue
            if c.type == "argument":
                args.append(c)

        if not args:
            return None

        raw_path = self._strip_quotes(args[0].text.decode())
        handler_name = ""
        if len(args) > 1:
            handler_name = self._parse_php_action_handler(args[1])

        # Traverse parent chain for chained middleware and constraints (->where, ->middleware)
        middlewares: list[str] = []
        constraints: dict[str, str] = {}
        curr = call_node.parent
        while curr and curr.type == "member_call_expression":
            member_name_node = curr.child_by_field_name("name")
            member_args_node = curr.child_by_field_name("arguments")
            if member_name_node and member_args_node:
                member_name = member_name_node.text.decode()
                arg_list = [
                    self._strip_quotes(a.text.decode())
                    for a in member_args_node.children
                    if a.type == "argument"
                ]
                if member_name == "middleware":
                    middlewares.extend(arg_list)
                elif member_name == "where" and len(arg_list) >= 2:
                    constraints[arg_list[0]] = arg_list[1]
                elif member_name == "whereNumber" and arg_list:
                    constraints[arg_list[0]] = r"\d+"
                elif member_name == "whereUuid" and arg_list:
                    constraints[arg_list[0]] = "uuid"

            curr = curr.parent

        norm_path, path_constraints = normalize_route_path(raw_path)
        constraints.update(path_constraints)

        m_upper = method_name.upper()
        if m_upper == "RESOURCE":
            http_method = "RESOURCE"
        elif m_upper == "APIRESOURCE":
            http_method = "API_RESOURCE"
        else:
            http_method = m_upper

        return RouteDefinition(
            method=http_method,
            path=norm_path,
            raw_path=raw_path,
            normalized_path=to_standard_path(norm_path),
            handler_name=handler_name,
            middleware=middlewares,
            param_constraints=constraints,
            file_path=file_path,
            line_number=call_node.start_point[0] + 1,
            extra={"scope": "Route"},
        )

    def _parse_php_action_handler(self, arg_node: Node) -> str:
        text = self._strip_quotes(arg_node.text.decode())
        # Case 1: string or encapsed_string e.g. 'InvoiceController@store' or "InvoiceController@store"
        if arg_node.children and arg_node.children[0].type in ("string", "encapsed_string"):
            return self._strip_quotes(text)

        # Case 2: array [InvoiceController::class, 'show']
        for child in arg_node.children:
            if child.type == "array_creation_expression":
                elements = [
                    self._strip_quotes(e.text.decode())
                    for e in child.children
                    if e.type == "array_element_initializer"
                ]
                if elements:
                    cleaned_elements = [
                        self._strip_quotes(e.replace("::class", "")) for e in elements
                    ]
                    if len(cleaned_elements) == 2:
                        return f"{cleaned_elements[0]}@{cleaned_elements[1]}"
                    return f"[{', '.join(cleaned_elements)}]"

        # Case 3: class constant e.g. OrderController::class
        if "::class" in text:
            return self._strip_quotes(text.replace("::class", "")).strip()

        return self._strip_quotes(text)

    def _extract_php_handlers(
        self, tree: Tree, code_bytes: bytes, file_path: str
    ) -> list[HandlerDefinition]:
        handlers: list[HandlerDefinition] = []

        def walk(node: Node, class_name: str = "") -> None:
            if node.type == "class_declaration":
                cname_node = node.child_by_field_name("name")
                cname = cname_node.text.decode() if cname_node else ""
                body = node.child_by_field_name("body")
                if body:
                    for child in body.children:
                        walk(child, class_name=cname)
                return

            if node.type in ("function_definition", "method_declaration"):
                name_node = node.child_by_field_name("name")
                fn_name = name_node.text.decode() if name_node else ""
                full_name = f"{class_name}::{fn_name}" if class_name else fn_name

                params_node = node.child_by_field_name("parameters")
                sig = params_node.text.decode() if params_node else "()"
                args: list[str] = []
                if params_node:
                    for p in params_node.children:
                        if p.type in ("simple_parameter", "variadic_parameter"):
                            var_node = p.child_by_field_name("name")
                            if var_node:
                                var_str = var_node.text.decode().lstrip("$")
                                args.append(var_str)

                handlers.append(
                    HandlerDefinition(
                        name=full_name,
                        signature=sig,
                        line_span=(node.start_point[0] + 1, node.end_point[0] + 1),
                        arguments=args,
                        file_path=file_path,
                        class_name=class_name,
                    )
                )

            for child in node.children:
                walk(child, class_name=class_name)

        walk(tree.root_node)
        return handlers

    # -------------------------------------------------------------------------
    # Utility Helpers
    # -------------------------------------------------------------------------

    @staticmethod
    def _strip_quotes(s: str) -> str:
        s = s.strip()
        if (
            (s.startswith('"') and s.endswith('"'))
            or (s.startswith("'") and s.endswith("'"))
            or (s.startswith("`") and s.endswith("`"))
        ):
            return s[1:-1]
        return s

    @staticmethod
    def _strip_docstring(s: str) -> str:
        s = s.strip()
        for quote in ('"""', "'''", '"', "'"):
            if s.startswith(quote) and s.endswith(quote) and len(s) >= 2 * len(quote):
                return s[len(quote) : -len(quote)].strip()
        return s

    @staticmethod
    def _node_to_expression_str(node: Node) -> str:
        if node.type in ("identifier", "property_identifier", "member_expression"):
            return node.text.decode()
        elif node.type in ("arrow_function", "function"):
            name = node.child_by_field_name("name")
            return name.text.decode() if name else "<anonymous>"
        return node.text.decode().strip()
