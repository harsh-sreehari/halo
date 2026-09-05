import json
import tempfile
from pathlib import Path

from halo.static.manifests import ManifestResolver


def test_tsconfig_alias_resolution():
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        tsconfig = {
            "compilerOptions": {
                "baseUrl": ".",
                "paths": {
                    "@services/*": ["src/services/*"],
                    "@controllers/*": ["src/controllers/*"],
                },
            }
        }
        (root / "tsconfig.json").write_text(json.dumps(tsconfig))
        (root / "src" / "services").mkdir(parents=True)
        (root / "src" / "services" / "invoice.ts").write_text("export class InvoiceService {}")

        resolver = ManifestResolver(root)
        resolved = resolver.resolve_import("@services/invoice", str(root / "src" / "routes.ts"))
        assert resolved is not None
        assert resolved.endswith("src/services/invoice.ts")
        assert Path(resolved).exists()


def test_tsconfig_with_comments_and_trailing_commas():
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        # JSON with comments and trailing comma
        tsconfig_content = """{
            // TypeScript compiler options
            "compilerOptions": {
                "baseUrl": "./", /* base directory */
                "paths": {
                    "@components/*": ["src/components/*"],
                },
            },
        }"""
        (root / "tsconfig.json").write_text(tsconfig_content)
        (root / "src" / "components").mkdir(parents=True)
        (root / "src" / "components" / "Button.tsx").write_text("export const Button = () => null;")

        resolver = ManifestResolver(root)
        resolved = resolver.resolve_import(
            "@components/Button", str(root / "src" / "App.tsx")
        )
        assert resolved is not None
        assert resolved.endswith("src/components/Button.tsx")


def test_composer_psr4_autoload_resolution():
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        composer = {
            "autoload": {
                "psr-4": {
                    "App\\": "app/",
                    "Database\\Factories\\": "database/factories/",
                }
            },
            "autoload-dev": {
                "psr-4": {
                    "Tests\\": "tests/",
                }
            },
        }
        (root / "composer.json").write_text(json.dumps(composer))
        (root / "app" / "Services").mkdir(parents=True)
        (root / "app" / "Services" / "InvoiceService.php").write_text(
            "<?php\nnamespace App\\Services;\nclass InvoiceService {}\n"
        )

        resolver = ManifestResolver(root)
        aliases = resolver.resolve_path_aliases()
        assert "App\\" in aliases

        # Test resolution using PSR-4 namespace backslashes
        resolved_bs = resolver.resolve_import(
            "App\\Services\\InvoiceService", str(root / "routes" / "web.php")
        )
        assert resolved_bs is not None
        assert resolved_bs.endswith("app/Services/InvoiceService.php")

        # Test resolution using forward slashes
        resolved_fs = resolver.resolve_import(
            "App/Services/InvoiceService", str(root / "routes" / "web.php")
        )
        assert resolved_fs is not None
        assert resolved_fs.endswith("app/Services/InvoiceService.php")


def test_package_json_imports_and_aliases():
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        pkg = {
            "name": "ecommerce-api",
            "imports": {
                "#models/*": "./src/models/*",
            },
            "_moduleAliases": {
                "@shared": "src/shared",
            },
        }
        (root / "package.json").write_text(json.dumps(pkg))
        (root / "src" / "models").mkdir(parents=True)
        (root / "src" / "models" / "User.js").write_text("class User {}; module.exports = { User };")
        (root / "src" / "shared").mkdir(parents=True)
        (root / "src" / "shared" / "config.mjs").write_text("export const config = {};")

        resolver = ManifestResolver(root)
        aliases = resolver.resolve_path_aliases()
        assert "#models/*" in aliases
        assert "@shared" in aliases

        resolved_subpath = resolver.resolve_import(
            "#models/User", str(root / "src" / "index.js")
        )
        assert resolved_subpath is not None
        assert resolved_subpath.endswith("src/models/User.js")

        resolved_alias = resolver.resolve_import(
            "@shared/config", str(root / "src" / "index.js")
        )
        assert resolved_alias is not None
        assert resolved_alias.endswith("src/shared/config.mjs")


def test_pyproject_toml_module_resolution():
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        pyproject_content = """[project]
name = "inventory-service"
version = "0.1.0"

[tool.pytest.ini_options]
pythonpath = ["src"]
"""
        (root / "pyproject.toml").write_text(pyproject_content)
        (root / "src" / "inventory").mkdir(parents=True)
        (root / "src" / "inventory" / "models.py").write_text("class Item: pass\n")

        resolver = ManifestResolver(root)
        resolved = resolver.resolve_import(
            "inventory.models", str(root / "tests" / "test_models.py")
        )
        assert resolved is not None
        assert resolved.endswith("src/inventory/models.py")


def test_relative_imports_and_extension_probing():
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        src_dir = root / "src"
        src_dir.mkdir(parents=True)

        (src_dir / "utils.ts").write_text("export function helper() {}")
        (src_dir / "routes.ts").write_text("import { helper } from './utils';")

        components_dir = src_dir / "components"
        components_dir.mkdir(parents=True)
        (components_dir / "index.ts").write_text("export * from './Button';")
        (components_dir / "Button.tsx").write_text("export const Button = null;")

        resolver = ManifestResolver(root)

        # 1. Relative import resolving .ts
        resolved_utils = resolver.resolve_import("./utils", str(src_dir / "routes.ts"))
        assert resolved_utils is not None
        assert resolved_utils.endswith("src/utils.ts")

        # 2. Directory index probing (./components -> ./components/index.ts)
        resolved_dir = resolver.resolve_import("./components", str(src_dir / "routes.ts"))
        assert resolved_dir is not None
        assert resolved_dir.endswith("src/components/index.ts")

        # 3. Parent relative import
        sub_dir = src_dir / "nested" / "deep"
        sub_dir.mkdir(parents=True)
        (sub_dir / "consumer.ts").write_text("import { helper } from '../../utils';")
        resolved_parent = resolver.resolve_import("../../utils", str(sub_dir / "consumer.ts"))
        assert resolved_parent is not None
        assert resolved_parent.endswith("src/utils.ts")

        # 4. Third-party library import should return None
        resolved_external = resolver.resolve_import("express", str(src_dir / "routes.ts"))
        assert resolved_external is None

        # 5. Non-existent relative file should return None
        resolved_missing = resolver.resolve_import("./non_existent", str(src_dir / "routes.ts"))
        assert resolved_missing is None


def test_build_export_symbol_index():
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)

        # TypeScript file
        ts_dir = root / "src" / "services"
        ts_dir.mkdir(parents=True)
        ts_file = ts_dir / "invoice.ts"
        ts_file.write_text(
            """
export class InvoiceService {
    process() {}
}

export async function calculateTotal(items: any[]): Promise<number> {
    return 0;
}

export const TAX_RATE = 0.08;
"""
        )

        # Python file
        py_dir = root / "src" / "handlers"
        py_dir.mkdir(parents=True)
        py_file = py_dir / "order_handler.py"
        py_file.write_text(
            """
class OrderHandler:
    pass

async def handle_checkout(request):
    return {"status": "ok"}
"""
        )

        # PHP file
        php_dir = root / "app" / "Controllers"
        php_dir.mkdir(parents=True)
        php_file = php_dir / "UserController.php"
        php_file.write_text(
            """<?php
namespace App\\Controllers;

class UserController {
    public function show($id) {}
}

function helper_function() {}
"""
        )

        resolver = ManifestResolver(root)
        index = resolver.build_export_symbol_index()

        # Check TypeScript exports
        assert str(ts_file.resolve()) in index
        ts_exports = index[str(ts_file.resolve())]
        assert "InvoiceService" in ts_exports
        assert ts_exports["InvoiceService"]["kind"] == "class"
        assert "calculateTotal" in ts_exports
        assert ts_exports["calculateTotal"]["kind"] == "function"
        assert "TAX_RATE" in ts_exports

        # Check Python exports
        assert str(py_file.resolve()) in index
        py_exports = index[str(py_file.resolve())]
        assert "OrderHandler" in py_exports
        assert py_exports["OrderHandler"]["kind"] == "class"
        assert "handle_checkout" in py_exports
        assert py_exports["handle_checkout"]["kind"] == "function"

        # Check PHP exports
        assert str(php_file.resolve()) in index
        php_exports = index[str(php_file.resolve())]
        assert "UserController" in php_exports
        assert php_exports["UserController"]["kind"] == "class"

        # Check by-symbol access / membership
        assert "InvoiceService" in index
        assert "OrderHandler" in index
        assert "UserController" in index


def test_class_method_interface():
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        tsconfig = {
            "compilerOptions": {
                "baseUrl": ".",
                "paths": {
                    "@lib/*": ["src/lib/*"],
                },
            }
        }
        (root / "tsconfig.json").write_text(json.dumps(tsconfig))
        (root / "src" / "lib").mkdir(parents=True)
        (root / "src" / "lib" / "math.ts").write_text("export function add(a, b) { return a + b; }")

        # Call as classmethods passing repo_path
        aliases = ManifestResolver.resolve_path_aliases(root)
        assert "@lib/*" in aliases

        resolved = ManifestResolver.resolve_import(
            "@lib/math", str(root / "src" / "index.ts"), repo_path=root
        )
        assert resolved is not None
        assert resolved.endswith("src/lib/math.ts")

        index = ManifestResolver.build_export_symbol_index(root)
        assert "add" in index
