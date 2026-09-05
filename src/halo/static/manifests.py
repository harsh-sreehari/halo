from __future__ import annotations

import ast
import json
import logging
import re
import tomllib
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


def strip_json_comments(text: str) -> str:
    """
    Strip line comments (//) and block comments (/* ... */) and trailing commas
    from JSON/JSONC text without breaking string literals.
    """
    def replacer(match: re.Match[str]) -> str:
        if match.group(1) is not None:
            return match.group(1)
        return ""

    pattern = re.compile(r'("(?:\\.|[^"\\])*")|//[^\r\n]*|/\*.*?\*/', re.DOTALL)
    cleaned = pattern.sub(replacer, text)
    # Strip trailing commas before closing braces or brackets
    cleaned = re.sub(r",(?=\s*[\}\]])", "", cleaned)
    return cleaned


class ExportSymbolIndex(dict[str, Any]):
    """
    Two-pass Pass 1 export symbol table.
    Inherits from dict so it can be indexed by file_path or by symbol_name,
    or traversed as a mapping of {file_path: {symbol_name: symbol_info}}.
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._symbols_map: dict[str, dict[str, Any]] = {}
        self._all_symbols_list: dict[str, list[dict[str, Any]]] = {}

    def register_file_exports(self, file_path: str, exports: dict[str, dict[str, Any]]) -> None:
        self[file_path] = exports
        for sym_name, sym_info in exports.items():
            self._symbols_map[sym_name] = sym_info
            self._all_symbols_list.setdefault(sym_name, []).append(sym_info)

    @property
    def by_file(self) -> dict[str, dict[str, Any]]:
        return dict(self)

    @property
    def by_symbol(self) -> dict[str, dict[str, Any]]:
        return dict(self._symbols_map)

    def get_symbol(self, name: str) -> dict[str, Any] | None:
        return self._symbols_map.get(name)

    def get_symbols_by_name(self, name: str) -> list[dict[str, Any]]:
        return self._all_symbols_list.get(name, [])

    def __getitem__(self, key: str) -> Any:
        if super().__contains__(key):
            return super().__getitem__(key)
        try:
            resolved_key = str(Path(key).resolve())
            if super().__contains__(resolved_key):
                return super().__getitem__(resolved_key)
        except (TypeError, ValueError):
            pass
        if key in self._symbols_map:
            return self._symbols_map[key]
        raise KeyError(key)

    def __contains__(self, key: object) -> bool:
        if super().__contains__(key):
            return True
        if isinstance(key, (str, Path)):
            try:
                resolved_key = str(Path(key).resolve())
                if super().__contains__(resolved_key):
                    return True
            except (TypeError, ValueError):
                pass
            if str(key) in self._symbols_map:
                return True
        return False

    def get(self, key: str, default: Any = None) -> Any:
        try:
            return self[key]
        except KeyError:
            return default


class ManifestResolver:
    """
    Resolves project manifests (tsconfig.json, jsconfig.json, composer.json,
    package.json, pyproject.toml), path aliases, and module import paths.
    Also builds the Pass 1 export symbol index.
    """

    EXTENSIONS: tuple[str, ...] = (
        ".ts",
        ".tsx",
        ".js",
        ".jsx",
        ".mjs",
        ".cjs",
        ".py",
        ".php",
    )

    INDEX_FILES: tuple[str, ...] = (
        "index.ts",
        "index.tsx",
        "index.js",
        "index.jsx",
        "index.mjs",
        "index.cjs",
        "__init__.py",
        "index.php",
    )

    def __init__(self, repo_path: str | Path = "") -> None:
        self.repo_path: Path = Path(repo_path).resolve() if repo_path else Path.cwd().resolve()
        self._aliases: dict[str, str] | None = None
        self._base_urls: list[Path] = []

    def _probe_path(self, target: Path) -> Path | None:
        """
        Probe a filesystem target with standard extensions and index files.
        """
        if target.is_file():
            return target.resolve()

        # If it has a modern JS extension imported in TypeScript ESM, check .ts / .tsx
        if target.suffix == ".js":
            ts_cand = target.with_suffix(".ts")
            if ts_cand.is_file():
                return ts_cand.resolve()
            tsx_cand = target.with_suffix(".tsx")
            if tsx_cand.is_file():
                return tsx_cand.resolve()
        elif target.suffix == ".mjs":
            mts_cand = target.with_suffix(".mts")
            if mts_cand.is_file():
                return mts_cand.resolve()

        # Probe with extension appended (e.g. invoice.service -> invoice.service.ts)
        target_name = target.name
        for ext in self.EXTENSIONS:
            appended = target.parent / f"{target_name}{ext}"
            if appended.is_file():
                return appended.resolve()
            if target.suffix:
                replaced = target.with_suffix(ext)
                if replaced.is_file():
                    return replaced.resolve()

        # Probe directory index files
        if target.is_dir() or not target.suffix:
            for index_name in self.INDEX_FILES:
                idx_cand = target / index_name
                if idx_cand.is_file():
                    return idx_cand.resolve()

        return None

    def resolve_path_aliases(
        self_or_repo: Any,
        repo_path: str | Path | None = None,
    ) -> dict[str, str]:
        """
        Parse tsconfig.json, jsconfig.json, composer.json, package.json, and
        pyproject.toml from the project to extract path aliases and PSR-4 namespaces.
        """
        if not isinstance(self_or_repo, ManifestResolver):
            root = Path(self_or_repo).resolve() if self_or_repo else Path.cwd().resolve()
            return ManifestResolver(root).resolve_path_aliases()

        self = self_or_repo
        root = Path(repo_path).resolve() if repo_path else self.repo_path
        if self._aliases is not None and root == self.repo_path:
            return self._aliases

        aliases: dict[str, str] = {}
        base_urls: list[Path] = []

        # 1. Parse tsconfig.json & jsconfig.json
        for config_name in ("tsconfig.json", "jsconfig.json"):
            config_file = root / config_name
            if config_file.is_file():
                try:
                    raw_text = config_file.read_text(encoding="utf-8", errors="replace")
                    cleaned_json = strip_json_comments(raw_text)
                    data = json.loads(cleaned_json)
                    compiler_opts = data.get("compilerOptions", {})

                    base_url_str = compiler_opts.get("baseUrl", ".")
                    base_url_dir = (config_file.parent / base_url_str).resolve()
                    base_urls.append(base_url_dir)

                    paths = compiler_opts.get("paths", {})
                    for alias_key, target_list in paths.items():
                        if isinstance(target_list, list) and target_list:
                            target = target_list[0]
                        elif isinstance(target_list, str):
                            target = target_list
                        else:
                            continue

                        # Resolve target relative to base_url_dir
                        has_wildcard = "*" in target
                        clean_target = target.replace("*", "")
                        resolved_dir = (base_url_dir / clean_target).resolve()
                        try:
                            rel_to_root = resolved_dir.relative_to(root).as_posix()
                        except ValueError:
                            rel_to_root = resolved_dir.as_posix()

                        if has_wildcard:
                            normalized_target = (
                                f"{rel_to_root}/*" if not rel_to_root.endswith("/") else f"{rel_to_root}*"
                            )
                        else:
                            normalized_target = rel_to_root

                        aliases[alias_key] = normalized_target
                except (json.JSONDecodeError, OSError) as exc:
                    logger.debug("Failed to parse %s: %s", config_file, exc)

        # 2. Parse composer.json (PSR-4 autoloading)
        composer_file = root / "composer.json"
        if composer_file.is_file():
            try:
                raw_text = composer_file.read_text(encoding="utf-8", errors="replace")
                data = json.loads(raw_text)
                autoload_psr4 = data.get("autoload", {}).get("psr-4", {})
                autoload_dev_psr4 = data.get("autoload-dev", {}).get("psr-4", {})

                combined_psr4 = {**autoload_psr4, **autoload_dev_psr4}
                for ns, dir_target in combined_psr4.items():
                    if isinstance(dir_target, list) and dir_target:
                        dir_target = dir_target[0]
                    resolved_dir = (composer_file.parent / dir_target).resolve()
                    try:
                        rel_to_root = resolved_dir.relative_to(root).as_posix()
                    except ValueError:
                        rel_to_root = resolved_dir.as_posix()
                    if not rel_to_root.endswith("/"):
                        rel_to_root += "/"
                    aliases[ns] = rel_to_root
            except (json.JSONDecodeError, OSError) as exc:
                logger.debug("Failed to parse composer.json: %s", exc)

        # 3. Parse package.json (imports & _moduleAliases)
        package_file = root / "package.json"
        if package_file.is_file():
            try:
                raw_text = package_file.read_text(encoding="utf-8", errors="replace")
                data = json.loads(raw_text)
                # Node subpath imports
                pkg_imports = data.get("imports", {})
                for alias_key, target in pkg_imports.items():
                    if isinstance(target, dict):
                        target = target.get("default", next(iter(target.values())) if target else "")
                    if isinstance(target, str):
                        clean_target = target.removeprefix("./")
                        aliases[alias_key] = clean_target

                # _moduleAliases
                module_aliases = data.get("_moduleAliases", {})
                for alias_key, target in module_aliases.items():
                    if isinstance(target, str):
                        clean_target = target.removeprefix("./")
                        aliases[alias_key] = clean_target
            except (json.JSONDecodeError, OSError) as exc:
                logger.debug("Failed to parse package.json: %s", exc)

        # 4. Parse pyproject.toml
        pyproject_file = root / "pyproject.toml"
        if pyproject_file.is_file():
            try:
                raw_text = pyproject_file.read_text(encoding="utf-8", errors="replace")
                data = tomllib.loads(raw_text)

                # tool.pytest.ini_options.pythonpath
                pythonpaths = (
                    data.get("tool", {}).get("pytest", {}).get("ini_options", {}).get("pythonpath", [])
                )
                for p in pythonpaths:
                    base_urls.append((root / p).resolve())

                # tool.poetry.packages
                poetry_packages = data.get("tool", {}).get("poetry", {}).get("packages", [])
                for pkg_spec in poetry_packages:
                    inc = pkg_spec.get("include")
                    frm = pkg_spec.get("from", "")
                    if inc:
                        target = f"{frm}/{inc}" if frm else inc
                        aliases[inc] = target
                        aliases[f"{inc}/*"] = f"{target}/*"

                # project.name
                proj_name = data.get("project", {}).get("name")
                if proj_name:
                    clean_name = proj_name.replace("-", "_")
                    if (root / "src" / clean_name).is_dir():
                        aliases[clean_name] = f"src/{clean_name}"
            except (tomllib.TOMLDecodeError, OSError) as exc:
                logger.debug("Failed to parse pyproject.toml: %s", exc)

        self._aliases = aliases
        self._base_urls = base_urls
        return aliases

    def resolve_import(
        self_or_source: Any,
        import_source_or_file: str | Path,
        current_file_or_repo: str | Path | None = None,
        repo_path: str | Path | None = None,
    ) -> str | None:
        """
        Resolve an import source to an absolute filesystem path.
        Handles relative imports, path aliases (tsconfig/composer/package.json/pyproject.toml),
        and baseUrl / pythonpath search roots with extension probing.
        """
        if not isinstance(self_or_source, ManifestResolver):
            import_source = str(self_or_source)
            current_file = import_source_or_file
            effective_repo = repo_path if repo_path is not None else current_file_or_repo
            if effective_repo is None:
                effective_repo = Path(current_file).resolve().parent
            return ManifestResolver(effective_repo).resolve_import(import_source, current_file)

        self = self_or_source
        import_source = str(import_source_or_file)
        current_file = current_file_or_repo if current_file_or_repo is not None else ""
        root = Path(repo_path).resolve() if repo_path else self.repo_path

        # 1. Relative imports
        if import_source.startswith("."):
            curr_dir = Path(current_file).resolve().parent
            if import_source.startswith(("./", "../")):
                target = (curr_dir / import_source).resolve()
            else:
                # Python relative import e.g. .models or ..utils
                dots = len(import_source) - len(import_source.lstrip("."))
                sub = import_source[dots:].replace(".", "/")
                base = curr_dir
                for _ in range(dots - 1):
                    base = base.parent
                target = (base / sub).resolve()

            found = self._probe_path(target)
            return str(found) if found else None

        # 2. Alias resolution
        aliases = self.resolve_path_aliases(root)

        # 2a. PSR-4 PHP namespace resolution
        normalized_import_bs = import_source.replace("/", "\\")
        for alias_key, target_dir in sorted(
            aliases.items(), key=lambda item: len(item[0]), reverse=True
        ):
            if "\\" in alias_key or "\\" in import_source:
                norm_alias = alias_key.replace("/", "\\")
                if not norm_alias.endswith("\\"):
                    norm_alias_prefix = norm_alias + "\\"
                else:
                    norm_alias_prefix = norm_alias

                if normalized_import_bs.startswith(norm_alias_prefix):
                    remainder = normalized_import_bs[len(norm_alias_prefix) :].replace("\\", "/")
                    target = (root / target_dir / remainder).resolve()
                    found = self._probe_path(target)
                    if found:
                        return str(found)

        # 2b. Wildcard aliases (e.g. @services/* -> src/services/*)
        for alias_key, target_pattern in sorted(
            aliases.items(), key=lambda item: len(item[0]), reverse=True
        ):
            if "*" in alias_key and "*" in target_pattern:
                prefix, suffix = alias_key.split("*", 1)
                if import_source.startswith(prefix) and (
                    not suffix or import_source.endswith(suffix)
                ):
                    wildcard_val = import_source[
                        len(prefix) : len(import_source) - len(suffix) if suffix else None
                    ]
                    target_subpath = target_pattern.replace("*", wildcard_val)
                    target = (root / target_subpath).resolve()
                    found = self._probe_path(target)
                    if found:
                        return str(found)

        # 2c. Exact alias match
        if import_source in aliases:
            target_path = aliases[import_source]
            target = (root / target_path).resolve()
            found = self._probe_path(target)
            if found:
                return str(found)

        # 2d. Subpath alias prefix match (e.g. @shared/config -> src/shared/config)
        for alias_key, target_dir in sorted(
            aliases.items(), key=lambda item: len(item[0]), reverse=True
        ):
            if not alias_key.endswith("*") and not alias_key.endswith("\\"):
                clean_alias = alias_key.rstrip("/")
                prefix = f"{clean_alias}/"
                if import_source.startswith(prefix):
                    remainder = import_source[len(prefix) :]
                    target = (root / target_dir / remainder).resolve()
                    found = self._probe_path(target)
                    if found:
                        return str(found)

        # 3. BaseUrl / Search Roots / Python Modules
        candidate_roots: list[Path] = []
        if self._base_urls:
            candidate_roots.extend(self._base_urls)
        # Standard roots
        if (root / "src").is_dir():
            candidate_roots.append((root / "src").resolve())
        candidate_roots.append(root)

        # Direct search with import_source
        for search_root in candidate_roots:
            target = (search_root / import_source).resolve()
            found = self._probe_path(target)
            if found:
                return str(found)

        # Python dot notation search (e.g. inventory.models -> inventory/models.py)
        if "." in import_source:
            python_subpath = import_source.replace(".", "/")
            for search_root in candidate_roots:
                target = (search_root / python_subpath).resolve()
                found = self._probe_path(target)
                if found:
                    return str(found)

        return None

    def build_export_symbol_index(
        self_or_repo: Any = None,
        repo_path: str | Path | None = None,
    ) -> ExportSymbolIndex:
        """
        Traverse ASTs and source files across the repository to catalog
        all exported classes, functions, and handler signatures (Pass 1 export table).
        """
        if not isinstance(self_or_repo, ManifestResolver):
            target_repo = self_or_repo if self_or_repo is not None else repo_path
            root = Path(target_repo).resolve() if target_repo else Path.cwd().resolve()
            return ManifestResolver(root).build_export_symbol_index()

        self = self_or_repo
        root = Path(repo_path).resolve() if repo_path else self.repo_path

        index = ExportSymbolIndex()
        ignored_dirs = {
            ".git",
            "node_modules",
            "vendor",
            ".venv",
            "venv",
            "__pycache__",
            "dist",
            "build",
            ".pytest_cache",
            ".superpowers",
            ".worktrees",
        }

        for path in root.rglob("*"):
            if not path.is_file():
                continue
            if any(part in ignored_dirs for part in path.parts):
                continue

            ext = path.suffix.lower()
            if ext not in self.EXTENSIONS:
                continue

            try:
                code = path.read_text(encoding="utf-8", errors="replace")
            except OSError as exc:
                logger.debug("Failed to read %s: %s", path, exc)
                continue

            file_abs = str(path.resolve())
            exports: dict[str, dict[str, Any]] = {}

            if ext == ".py":
                exports = self._extract_python_exports(path, code)
            elif ext in (".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"):
                exports = self._extract_js_ts_exports(path, code)
            elif ext == ".php":
                exports = self._extract_php_exports(path, code)

            if exports:
                index.register_file_exports(file_abs, exports)

        return index

    def _extract_python_exports(self, file_path: Path, code: str) -> dict[str, dict[str, Any]]:
        exports: dict[str, dict[str, Any]] = {}
        try:
            tree = ast.parse(code, filename=str(file_path))
            for node in tree.body:
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    if not node.name.startswith("_"):
                        exports[node.name] = {
                            "name": node.name,
                            "kind": "function",
                            "line": node.lineno,
                            "file_path": str(file_path.resolve()),
                            "signature": f"def {node.name}(...)",
                        }
                elif isinstance(node, ast.ClassDef) and not node.name.startswith("_"):
                    exports[node.name] = {
                        "name": node.name,
                        "kind": "class",
                        "line": node.lineno,
                        "file_path": str(file_path.resolve()),
                        "signature": f"class {node.name}",
                    }
        except (SyntaxError, ValueError):
            for line_no, line in enumerate(code.splitlines(), start=1):
                stripped = line.strip()
                m_func = re.match(r"^(?:async\s+)?def\s+([A-Za-z0-9_]+)", stripped)
                if m_func and not m_func.group(1).startswith("_"):
                    name = m_func.group(1)
                    exports[name] = {
                        "name": name,
                        "kind": "function",
                        "line": line_no,
                        "file_path": str(file_path.resolve()),
                        "signature": stripped,
                    }
                m_class = re.match(r"^class\s+([A-Za-z0-9_]+)", stripped)
                if m_class and not m_class.group(1).startswith("_"):
                    name = m_class.group(1)
                    exports[name] = {
                        "name": name,
                        "kind": "class",
                        "line": line_no,
                        "file_path": str(file_path.resolve()),
                        "signature": stripped,
                    }
        return exports

    def _extract_js_ts_exports(self, file_path: Path, code: str) -> dict[str, dict[str, Any]]:
        exports: dict[str, dict[str, Any]] = {}
        for line_no, line in enumerate(code.splitlines(), start=1):
            stripped = line.strip()
            # 1. export (default) class
            m = re.search(r"export\s+(?:default\s+)?class\s+([A-Za-z0-9_$]+)", stripped)
            if m:
                name = m.group(1)
                exports[name] = {
                    "name": name,
                    "kind": "class",
                    "line": line_no,
                    "file_path": str(file_path.resolve()),
                    "signature": stripped,
                }
                continue

            # 2. export interface / type / enum
            m = re.search(r"export\s+(?:default\s+)?(interface|type|enum)\s+([A-Za-z0-9_$]+)", stripped)
            if m:
                kind, name = m.group(1), m.group(2)
                exports[name] = {
                    "name": name,
                    "kind": kind,
                    "line": line_no,
                    "file_path": str(file_path.resolve()),
                    "signature": stripped,
                }
                continue

            # 3. export (async) function
            m = re.search(
                r"export\s+(?:default\s+)?(?:async\s+)?function\s*([A-Za-z0-9_$]+)?", stripped
            )
            if m and m.group(1):
                name = m.group(1)
                exports[name] = {
                    "name": name,
                    "kind": "function",
                    "line": line_no,
                    "file_path": str(file_path.resolve()),
                    "signature": stripped,
                }
                continue

            # 4. export const/let/var
            m = re.search(r"export\s+(?:const|let|var)\s+([A-Za-z0-9_$]+)", stripped)
            if m:
                name = m.group(1)
                kind = "function" if "=>" in stripped or "function" in stripped else "variable"
                exports[name] = {
                    "name": name,
                    "kind": kind,
                    "line": line_no,
                    "file_path": str(file_path.resolve()),
                    "signature": stripped,
                }
                continue

            # 5. export { a, b as c }
            m = re.search(r"export\s*\{\s*([^}]+)\s*\}", stripped)
            if m:
                for item in m.group(1).split(","):
                    item = item.strip()
                    if not item:
                        continue
                    name = item.split(" as ", 1)[-1].strip() if " as " in item else item
                    if name:
                        exports[name] = {
                            "name": name,
                            "kind": "export",
                            "line": line_no,
                            "file_path": str(file_path.resolve()),
                            "signature": stripped,
                        }
                continue

            # 6. module.exports or exports.foo
            m = re.search(r"(?:module\.)?exports\.([A-Za-z0-9_$]+)\s*=", stripped)
            if m:
                name = m.group(1)
                exports[name] = {
                    "name": name,
                    "kind": "variable",
                    "line": line_no,
                    "file_path": str(file_path.resolve()),
                    "signature": stripped,
                }
                continue

            m = re.search(r"module\.exports\s*=\s*\{\s*([^}]+)\s*\}", stripped)
            if m:
                for item in m.group(1).split(","):
                    name = item.strip().split(":")[0].strip()
                    if name and re.match(r"^[A-Za-z0-9_$]+$", name):
                        exports[name] = {
                            "name": name,
                            "kind": "export",
                            "line": line_no,
                            "file_path": str(file_path.resolve()),
                            "signature": stripped,
                        }

        return exports

    def _extract_php_exports(self, file_path: Path, code: str) -> dict[str, dict[str, Any]]:
        exports: dict[str, dict[str, Any]] = {}
        namespace = ""
        for line_no, line in enumerate(code.splitlines(), start=1):
            stripped = line.strip()
            m_ns = re.search(r"namespace\s+([A-Za-z0-9_\\]+)\s*;", stripped)
            if m_ns:
                namespace = m_ns.group(1).rstrip("\\")

            m_cls = re.search(
                r"(?:final\s+|abstract\s+)?(class|interface|trait|enum)\s+([A-Za-z0-9_]+)", stripped
            )
            if m_cls:
                kind, name = m_cls.group(1), m_cls.group(2)
                exports[name] = {
                    "name": name,
                    "kind": kind,
                    "line": line_no,
                    "file_path": str(file_path.resolve()),
                    "signature": stripped,
                    "namespace": namespace,
                }
                if namespace:
                    fqn = f"{namespace}\\{name}"
                    exports[fqn] = {
                        "name": fqn,
                        "kind": kind,
                        "line": line_no,
                        "file_path": str(file_path.resolve()),
                        "signature": stripped,
                        "namespace": namespace,
                    }
                continue

            m_fn = re.search(r"function\s+([A-Za-z0-9_]+)\s*\(", stripped)
            if m_fn:
                name = m_fn.group(1)
                exports[name] = {
                    "name": name,
                    "kind": "function",
                    "line": line_no,
                    "file_path": str(file_path.resolve()),
                    "signature": stripped,
                    "namespace": namespace,
                }
                if namespace:
                    fqn = f"{namespace}\\{name}"
                    exports[fqn] = {
                        "name": fqn,
                        "kind": "function",
                        "line": line_no,
                        "file_path": str(file_path.resolve()),
                        "signature": stripped,
                        "namespace": namespace,
                    }

        return exports
