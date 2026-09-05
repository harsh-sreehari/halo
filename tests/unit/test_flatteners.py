from __future__ import annotations

import json

from halo.static.export import export_ckg_to_cytoscape
from halo.static.flatteners.graphql import GraphQLFlattener
from halo.static.flatteners.laravel import LaravelFlattener
from halo.static.flatteners.nestjs import NestJSFlattener
from halo.static.graph import (
    CodeKnowledgeGraph,
    EdgeType,
    HandlerNode,
    MiddlewareNode,
    RouteNode,
    SinkNode,
)

# -----------------------------------------------------------------------------
# Brief Baseline Tests
# -----------------------------------------------------------------------------


def test_laravel_resource_expansion():
    routes = LaravelFlattener.expand_resource("orders", "OrderController")
    assert len(routes) == 7
    methods = {r["method"] for r in routes}
    assert "GET" in methods
    assert "POST" in methods
    assert "DELETE" in methods


def test_nestjs_prefix_composition():
    composed = NestJSFlattener.compose_prefix("api/v1/invoices", ":id")
    assert composed == "/api/v1/invoices/{id}"


def test_cytoscape_export():
    ckg = CodeKnowledgeGraph()
    ckg.add_node(RouteNode(id="r1", method="GET", path="/test", file_path="t.py", line_number=1))
    cyto = export_ckg_to_cytoscape(ckg)
    assert "elements" in cyto
    assert len(cyto["elements"]["nodes"]) == 1


# -----------------------------------------------------------------------------
# Laravel Flattener Extended Tests
# -----------------------------------------------------------------------------


def test_laravel_all_seven_routes_and_paths():
    routes = LaravelFlattener.expand_resource("orders", "OrderController")
    route_map = {r["action"]: r for r in routes}

    assert set(route_map.keys()) == {
        "index",
        "create",
        "store",
        "show",
        "edit",
        "update",
        "destroy",
    }

    assert route_map["index"]["method"] == "GET"
    assert route_map["index"]["path"] == "/orders"
    assert route_map["index"]["handler"] == "OrderController@index"

    assert route_map["create"]["method"] == "GET"
    assert route_map["create"]["path"] == "/orders/create"
    assert route_map["create"]["handler"] == "OrderController@create"

    assert route_map["store"]["method"] == "POST"
    assert route_map["store"]["path"] == "/orders"
    assert route_map["store"]["handler"] == "OrderController@store"

    assert route_map["show"]["method"] == "GET"
    assert route_map["show"]["path"] == "/orders/{id}"
    assert route_map["show"]["handler"] == "OrderController@show"

    assert route_map["edit"]["method"] == "GET"
    assert route_map["edit"]["path"] == "/orders/{id}/edit"
    assert route_map["edit"]["handler"] == "OrderController@edit"

    assert "PUT" in route_map["update"]["method"]
    assert route_map["update"]["path"] == "/orders/{id}"
    assert route_map["update"]["handler"] == "OrderController@update"

    assert route_map["destroy"]["method"] == "DELETE"
    assert route_map["destroy"]["path"] == "/orders/{id}"
    assert route_map["destroy"]["handler"] == "OrderController@destroy"


def test_laravel_resource_slash_normalization():
    routes = LaravelFlattener.expand_resource("/api/v1/users/", "UserController")
    paths = {r["path"] for r in routes}
    assert "/api/v1/users" in paths
    assert "/api/v1/users/create" in paths
    assert "/api/v1/users/{id}" in paths


def test_laravel_only_filter():
    routes = LaravelFlattener.expand_resource(
        "orders", "OrderController", only=["index", "show"]
    )
    assert len(routes) == 2
    actions = {r["action"] for r in routes}
    assert actions == {"index", "show"}


def test_laravel_except_filter():
    routes = LaravelFlattener.expand_resource(
        "orders", "OrderController", except_actions=["create", "edit"]
    )
    assert len(routes) == 5
    actions = {r["action"] for r in routes}
    assert "create" not in actions
    assert "edit" not in actions
    assert "index" in actions
    assert "store" in actions
    assert "show" in actions
    assert "update" in actions
    assert "destroy" in actions


def test_laravel_api_resource_expansion():
    routes = LaravelFlattener.expand_api_resource("products", "ProductController")
    assert len(routes) == 5
    actions = {r["action"] for r in routes}
    assert actions == {"index", "store", "show", "update", "destroy"}


def test_laravel_to_route_nodes():
    routes = LaravelFlattener.expand_resource("orders", "OrderController")
    nodes = LaravelFlattener.to_route_nodes(routes, file_path="routes/web.php")
    assert len(nodes) == 7
    assert all(isinstance(n, RouteNode) for n in nodes)
    assert all(n.file_path == "routes/web.php" for n in nodes)


# -----------------------------------------------------------------------------
# NestJS Flattener Extended Tests
# -----------------------------------------------------------------------------


def test_nestjs_compose_prefix_edge_cases():
    # Empty controller prefix
    assert NestJSFlattener.compose_prefix("", ":id") == "/{id}"
    # Empty action path
    assert NestJSFlattener.compose_prefix("users", "") == "/users"
    # Both empty
    assert NestJSFlattener.compose_prefix("", "") == "/"
    # Multiple slashes
    assert NestJSFlattener.compose_prefix("/api/v1///invoices/", "/:id/") == "/api/v1/invoices/{id}"
    # Multiple path parameters
    assert (
        NestJSFlattener.compose_prefix("api/orgs/:orgId", "teams/:teamId/members")
        == "/api/orgs/{orgId}/teams/{teamId}/members"
    )


def test_nestjs_extract_routes_from_typescript():
    ts_code = """
    import { Controller, Get, Post, Put, Delete, Patch, Param, Body } from '@nestjs/common';

    @Controller('api/v1/invoices')
    export class InvoicesController {
        @Get()
        findAll() {
            return [];
        }

        @Get(':id')
        findOne(@Param('id') id: string) {
            return { id };
        }

        @Post()
        create(@Body() body: any) {
            return body;
        }

        @Put(':id')
        update(@Param('id') id: string, @Body() body: any) {
            return body;
        }

        @Delete(':id')
        remove(@Param('id') id: string) {
            return true;
        }

        @Patch(':id/status')
        updateStatus(@Param('id') id: string) {
            return true;
        }
    }
    """
    routes = NestJSFlattener.extract_routes(ts_code, file_path="src/invoices.controller.ts")
    assert len(routes) == 6

    route_by_handler = {r["handler_name"]: r for r in routes}
    assert route_by_handler["findAll"]["method"] == "GET"
    assert route_by_handler["findAll"]["path"] == "/api/v1/invoices"
    assert route_by_handler["findAll"]["controller"] == "InvoicesController"

    assert route_by_handler["findOne"]["method"] == "GET"
    assert route_by_handler["findOne"]["path"] == "/api/v1/invoices/{id}"

    assert route_by_handler["create"]["method"] == "POST"
    assert route_by_handler["create"]["path"] == "/api/v1/invoices"

    assert route_by_handler["update"]["method"] == "PUT"
    assert route_by_handler["update"]["path"] == "/api/v1/invoices/{id}"

    assert route_by_handler["remove"]["method"] == "DELETE"
    assert route_by_handler["remove"]["path"] == "/api/v1/invoices/{id}"

    assert route_by_handler["updateStatus"]["method"] == "PATCH"
    assert route_by_handler["updateStatus"]["path"] == "/api/v1/invoices/{id}/status"


def test_nestjs_controller_default_prefix():
    ts_code = """
    @Controller()
    export class RootController {
        @Get('health')
        getHealth() {
            return { status: 'ok' };
        }
    }
    """
    routes = NestJSFlattener.extract_routes(ts_code)
    assert len(routes) == 1
    assert routes[0]["path"] == "/health"
    assert routes[0]["method"] == "GET"


# -----------------------------------------------------------------------------
# GraphQL Flattener Extended Tests
# -----------------------------------------------------------------------------


def test_graphql_parse_schema_and_virtual_endpoints():
    schema = """
    type Query {
        getInvoice(id: ID!): Invoice
        listInvoices(limit: Int = 10, offset: Int): [Invoice!]!
        me: User
    }

    type Mutation {
        createInvoice(amount: Float!, recipient: String!): Invoice
        deleteInvoice(id: ID!): Boolean
    }
    """
    endpoints = GraphQLFlattener.parse_schema_and_resolvers(schema)
    assert len(endpoints) == 5

    ep_by_name = {ep["name"]: ep for ep in endpoints}
    assert "Query.getInvoice" in ep_by_name
    assert "Query.listInvoices" in ep_by_name
    assert "Query.me" in ep_by_name
    assert "Mutation.createInvoice" in ep_by_name
    assert "Mutation.deleteInvoice" in ep_by_name

    # Check virtual route endpoint format
    assert ep_by_name["Query.getInvoice"]["path"] == "GRAPHQL: Query.getInvoice"
    assert ep_by_name["Query.getInvoice"]["virtual_endpoint"] == "GRAPHQL: Query.getInvoice"
    assert ep_by_name["Query.getInvoice"]["operation_type"] == "Query"
    assert "id" in ep_by_name["Query.getInvoice"]["arguments"]

    assert ep_by_name["Mutation.createInvoice"]["path"] == "GRAPHQL: Mutation.createInvoice"
    assert ep_by_name["Mutation.createInvoice"]["operation_type"] == "Mutation"
    assert ep_by_name["Mutation.createInvoice"]["method"] == "POST"


def test_graphql_with_resolver_mapping():
    schema = """
    type Query {
        getInvoice(id: ID!): Invoice
    }
    type Mutation {
        createInvoice(amount: Float!): Invoice
    }
    """

    def resolve_invoice():
        pass

    resolvers = {
        "Query": {
            "getInvoice": resolve_invoice,
        },
        "Mutation.createInvoice": "app.resolvers.create_invoice_handler",
    }

    endpoints = GraphQLFlattener.parse_schema_and_resolvers(schema, resolvers=resolvers)
    ep_by_name = {ep["name"]: ep for ep in endpoints}

    assert ep_by_name["Query.getInvoice"]["handler_name"] == "resolve_invoice"
    assert ep_by_name["Mutation.createInvoice"]["handler_name"] == "app.resolvers.create_invoice_handler"


def test_graphql_custom_schema_root():
    schema = """
    schema {
        query: RootQuery
        mutation: RootMutation
    }

    type RootQuery {
        account(id: ID!): Account
    }

    type RootMutation {
        updateAccount(id: ID!, name: String): Account
    }
    """
    endpoints = GraphQLFlattener.parse_schema_and_resolvers(schema)
    assert len(endpoints) == 2
    ep_by_name = {ep["name"]: ep for ep in endpoints}
    assert "RootQuery.account" in ep_by_name
    assert ep_by_name["RootQuery.account"]["path"] == "GRAPHQL: RootQuery.account"
    assert ep_by_name["RootQuery.account"]["operation_type"] == "Query"
    assert ep_by_name["RootMutation.updateAccount"]["operation_type"] == "Mutation"


# -----------------------------------------------------------------------------
# Cytoscape Export Extended Tests
# -----------------------------------------------------------------------------


def test_cytoscape_export_complete_graph():
    ckg = CodeKnowledgeGraph()

    route = RouteNode(
        id="route_1",
        method="GET",
        path="/api/v1/invoices/{id}",
        param_constraints={"id": r"\d+"},
        file_path="src/routes.py",
        line_number=10,
    )
    handler = HandlerNode(
        id="handler_1",
        name="get_invoice",
        signature="async def get_invoice(id: str)",
        line_span=(20, 35),
        arguments=["id"],
        file_path="src/controller.py",
        line_number=20,
    )
    sink = SinkNode(
        id="sink_1",
        operation="READ",
        entity="Invoice",
        query_params=["id"],
        file_path="src/service.py",
        line_number=50,
    )
    guard = MiddlewareNode(
        id="guard_1",
        name="authMiddleware",
        type="AUTHN",
        guard_params={"role": "admin"},
        is_auth_guard=True,
        file_path="src/auth.py",
        line_number=5,
    )

    ckg.add_node(route)
    ckg.add_node(handler)
    ckg.add_node(sink)
    ckg.add_node(guard)

    ckg.add_edge(route.id, guard.id, EdgeType.PROTECTED_BY)
    ckg.add_edge(route.id, handler.id, EdgeType.ROUTES_TO)
    ckg.add_edge(handler.id, sink.id, EdgeType.CALLS)

    cyto = export_ckg_to_cytoscape(ckg)

    assert "elements" in cyto
    elements = cyto["elements"]
    assert len(elements["nodes"]) == 4
    assert len(elements["edges"]) == 3

    # Check node structure
    node_map = {n["data"]["id"]: n["data"] for n in elements["nodes"]}
    assert "route_1" in node_map
    assert node_map["route_1"]["node_type"] == "ROUTE"
    assert node_map["route_1"]["method"] == "GET"
    assert node_map["route_1"]["path"] == "/api/v1/invoices/{id}"
    assert node_map["route_1"]["param_constraints"] == {"id": r"\d+"}

    assert node_map["guard_1"]["node_type"] == "MIDDLEWARE"
    assert node_map["guard_1"]["is_auth_guard"] is True

    # Check edge structure
    edge_pairs = {(e["data"]["source"], e["data"]["target"], e["data"]["edge_type"]) for e in elements["edges"]}
    assert ("route_1", "guard_1", "PROTECTED_BY") in edge_pairs
    assert ("route_1", "handler_1", "ROUTES_TO") in edge_pairs
    assert ("handler_1", "sink_1", "CALLS") in edge_pairs

    # Check that export is valid JSON
    serialized = json.dumps(cyto)
    assert serialized is not None
    deserialized = json.loads(serialized)
    assert len(deserialized["elements"]["nodes"]) == 4


def test_cytoscape_export_empty_graph():
    ckg = CodeKnowledgeGraph()
    cyto = export_ckg_to_cytoscape(ckg)
    assert cyto == {"elements": {"nodes": [], "edges": []}}
