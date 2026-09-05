from __future__ import annotations

import tempfile
from pathlib import Path

from halo.static.parser import (
    ASTParseResult,
    CodeParser,
    HandlerDefinition,
    RouteDefinition,
    normalize_route_path,
)


def test_python_fastapi_route_extraction():
    code = """
from fastapi import FastAPI, Depends

app = FastAPI()

@app.get("/api/v1/invoices/{id}")
async def get_invoice(id: int):
    return {"id": id}
"""
    parser = CodeParser()
    routes = parser.extract_routes("main.py", code, language="python")
    assert len(routes) == 1
    assert isinstance(routes[0], RouteDefinition)
    assert routes[0].method == "GET"
    assert routes[0].path == "/api/v1/invoices/{id}"
    assert routes[0].handler_name == "get_invoice"


def test_javascript_express_route_extraction():
    code = """
const express = require('express');
const router = express.Router();

router.get('/invoices/:id', authMiddleware, getInvoiceHandler);
"""
    parser = CodeParser()
    routes = parser.extract_routes("routes.js", code, language="javascript")
    assert len(routes) == 1
    assert routes[0].method == "GET"
    assert routes[0].path == "/invoices/:id"
    assert routes[0].handler_name == "getInvoiceHandler"
    assert "authMiddleware" in routes[0].middleware


def test_php_laravel_route_extraction():
    code = """<?php
use App\\Http\\Controllers\\InvoiceController;
use App\\Http\\Controllers\\OrderController;
use Illuminate\\Support\\Facades\\Route;

Route::get('/invoices/{id}', [InvoiceController::class, 'show']);
Route::post('/invoices', 'InvoiceController@store');
Route::resource('orders', OrderController::class);
Route::get('/admin/dashboard', 'AdminController@index')->middleware('auth');
"""
    parser = CodeParser()
    routes = parser.extract_routes("routes/web.php", code, language="php")
    assert len(routes) == 4

    # Route 1: get with array action
    assert routes[0].method == "GET"
    assert routes[0].path == "/invoices/{id}"
    assert "InvoiceController" in routes[0].handler_name
    assert "show" in routes[0].handler_name

    # Route 2: post with string action
    assert routes[1].method == "POST"
    assert routes[1].path == "/invoices"
    assert routes[1].handler_name == "InvoiceController@store"

    # Route 3: resource
    assert routes[2].method == "RESOURCE"
    assert routes[2].path == "orders"
    assert "OrderController" in routes[2].handler_name

    # Route 4: chained middleware
    assert routes[3].method == "GET"
    assert routes[3].path == "/admin/dashboard"
    assert "auth" in routes[3].middleware


def test_python_handler_extraction():
    code = """
def calculate_tax(amount: float, rate: float = 0.2) -> float:
    '''Calculate total tax for an invoice.'''
    return amount * rate

class InvoiceService:
    async def process_invoice(self, invoice_id: str) -> bool:
        return True
"""
    parser = CodeParser()
    handlers = parser.extract_handlers("service.py", code, language="python")
    assert len(handlers) == 2

    # Top level function
    h0 = handlers[0]
    assert isinstance(h0, HandlerDefinition)
    assert h0.name == "calculate_tax"
    assert "amount" in h0.arguments
    assert "rate" in h0.arguments
    assert h0.is_async is False
    assert h0.line_span[0] > 0
    assert "Calculate total tax" in h0.docstring

    # Class method
    h1 = handlers[1]
    assert h1.name == "InvoiceService.process_invoice"
    assert "self" in h1.arguments
    assert "invoice_id" in h1.arguments
    assert h1.is_async is True


def test_javascript_typescript_handler_extraction():
    code = """
function topLevelFunc(req, res) {
    res.send('ok');
}

const arrowHandler = async (id, status) => {
    return { id, status };
};

class UserController {
    async getUser(req, res) {
        return res.json({});
    }
}
"""
    parser = CodeParser()
    handlers = parser.extract_handlers("controller.ts", code, language="typescript")
    assert len(handlers) == 3

    names = [h.name for h in handlers]
    assert "topLevelFunc" in names
    assert "arrowHandler" in names
    assert "UserController.getUser" in names or "getUser" in names

    arrow = next(h for h in handlers if h.name == "arrowHandler")
    assert "id" in arrow.arguments
    assert "status" in arrow.arguments
    assert arrow.is_async is True


def test_php_handler_extraction():
    code = """<?php
function calculateDiscount($total, $percent) {
    return $total * ($percent / 100);
}

class OrderManager {
    public function cancelOrder($orderId, $reason) {
        return false;
    }
}
"""
    parser = CodeParser()
    handlers = parser.extract_handlers("manager.php", code, language="php")
    assert len(handlers) == 2

    fn = next(h for h in handlers if h.name == "calculateDiscount")
    assert "total" in fn.arguments
    assert "percent" in fn.arguments

    method = next(h for h in handlers if "cancelOrder" in h.name)
    assert "orderId" in method.arguments
    assert "reason" in method.arguments


def test_path_normalization_and_parameter_constraints():
    # FastAPI path with type constraint
    p1, c1 = normalize_route_path("/items/{id:int}")
    assert p1 == "/items/{id}"
    assert c1 == {"id": "int"}

    # FastAPI path with regex / uuid constraint
    p2, c2 = normalize_route_path("/users/{user_id:uuid}")
    assert p2 == "/users/{user_id}"
    assert c2 == {"user_id": "uuid"}

    p3, c3 = normalize_route_path("/items/{id:[0-9]+}")
    assert p3 == "/items/{id}"
    assert c3 == {"id": "[0-9]+"}

    # Flask path style <type:param>
    p4, c4 = normalize_route_path("/products/<int:prod_id>")
    assert p4 == "/products/{prod_id}"
    assert c4 == {"prod_id": "int"}

    # Flask untyped parameter <param>
    p5, c5 = normalize_route_path("/categories/<cat_name>")
    assert p5 == "/categories/{cat_name}"
    assert c5 == {}

    # Express path parameter :id
    p6, c6 = normalize_route_path("/invoices/:id")
    assert p6 == "/invoices/:id"
    assert c6 == {}

    # Integration test through extract_routes
    code = """
from fastapi import FastAPI
app = FastAPI()

@app.get("/items/{id:int}")
def get_item(id: int):
    pass
"""
    parser = CodeParser()
    routes = parser.extract_routes("main.py", code, language="python")
    assert len(routes) == 1
    assert routes[0].path == "/items/{id}"
    assert routes[0].param_constraints == {"id": "int"}


def test_flask_multi_method_routes():
    code = """
from flask import Flask
app = Flask(__name__)

@app.route("/api/v1/items", methods=["GET", "POST"])
def items():
    return "ok"
"""
    parser = CodeParser()
    routes = parser.extract_routes("app.py", code, language="python")
    assert len(routes) == 2
    methods = {r.method for r in routes}
    assert methods == {"GET", "POST"}
    for r in routes:
        assert r.path == "/api/v1/items"
        assert r.handler_name == "items"


def test_execute_query_direct():
    code = "def sample_function(x, y): pass"
    parser = CodeParser()
    parse_result = parser.parse_file("test.py", code=code, language="python")
    assert isinstance(parse_result, ASTParseResult)
    assert parse_result.tree is not None

    query = "(function_definition name: (identifier) @name)"
    captures = parser.execute_query(parse_result.tree, "python", query)
    assert len(captures) == 1
    node, capture_name = captures[0]
    assert capture_name == "name"
    assert code[node.start_byte:node.end_byte] == "sample_function"


def test_parse_file_from_disk_with_extension_probing():
    with tempfile.TemporaryDirectory() as tmpdir:
        py_file = Path(tmpdir) / "app.py"
        py_file.write_text("def ping(): return 'pong'")

        parser = CodeParser()
        res = parser.parse_file(str(py_file))
        assert res.language == "python"
        assert res.file_path == str(py_file)
        assert "ping" in res.code


def test_all_authored_scm_queries():
    parser = CodeParser()

    # 1. python.scm
    py_code = """
@app.get("/items")
def list_items():
    pass
"""
    py_tree = parser.parse_file("app.py", code=py_code, language="python").tree
    py_caps = parser.execute_query(py_tree, "python", "python.scm")
    assert any(name == "route" for _, name in py_caps)

    # 2. javascript.scm against JavaScript
    js_code = """
class AppController {}
router.get('/users', authMw, getUser);
"""
    js_tree = parser.parse_file("app.js", code=js_code, language="javascript").tree
    js_caps = parser.execute_query(js_tree, "javascript", "javascript.scm")
    assert any(name == "route" for _, name in js_caps)
    assert any(name == "class" for _, name in js_caps)

    # 3. javascript.scm against TypeScript (verifying type_identifier / class_declaration)
    ts_code = """
class TsController {}
router.get('/ts-items', getTsItems);
"""
    ts_tree = parser.parse_file("app.ts", code=ts_code, language="typescript").tree
    ts_caps = parser.execute_query(ts_tree, "typescript", "javascript.scm")
    assert any(name == "route" for _, name in ts_caps)
    assert any(name == "class" for _, name in ts_caps)

    # 4. typescript.scm and alias "typescript" against TypeScript
    ts_caps_alias = parser.execute_query(ts_tree, "typescript", "typescript")
    assert any(name == "route" for _, name in ts_caps_alias)

    # 5. php.scm
    php_code = """<?php
class Controller {}
Route::get('/orders', 'OrderController@index');
"""
    php_tree = parser.parse_file("routes.php", code=php_code, language="php").tree
    php_caps = parser.execute_query(php_tree, "php", "php.scm")
    assert any(name == "route" for _, name in php_caps)


def test_php_double_quoted_action_handler():
    code = '''<?php
Route::get("/invoices", "InvoiceController@show");
Route::post("/orders", ["App\\Controllers\\OrderController", "store"]);
'''
    parser = CodeParser()
    routes = parser.extract_routes("routes.php", code, language="php")
    assert len(routes) == 2
    assert routes[0].path == "/invoices"
    assert routes[0].handler_name == "InvoiceController@show"
    assert '"' not in routes[0].handler_name

    assert routes[1].path == "/orders"
    assert routes[1].handler_name == "App\\Controllers\\OrderController@store"
    assert '"' not in routes[1].handler_name


def test_js_ts_template_literal_routes():
    code = """
router.get(`/invoices/:id`, authMiddleware, getInvoiceHandler);
router.route(`/api/v1/orders`).post(createOrderHandler);
"""
    parser = CodeParser()
    routes = parser.extract_routes("routes.ts", code, language="typescript")
    assert len(routes) == 2
    assert routes[0].path == "/invoices/:id"
    assert routes[0].handler_name == "getInvoiceHandler"
    assert routes[0].middleware == ["authMiddleware"]

    assert routes[1].path == "/api/v1/orders"
    assert routes[1].method == "POST"
    assert routes[1].handler_name == "createOrderHandler"

