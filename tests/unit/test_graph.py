from halo.static.graph import (
    CodeKnowledgeGraph,
    EdgeType,
    EntityNode,
    HandlerNode,
    MiddlewareNode,
    NodeType,
    RouteNode,
    SinkNode,
    ValidationSchemaNode,
)


def test_ckg_construction_and_traversal():
    ckg = CodeKnowledgeGraph()
    route = RouteNode(
        id="route_1",
        method="GET",
        path="/api/v1/invoices/{id}",
        file_path="routes.py",
        line_number=10,
    )
    handler = HandlerNode(
        id="handler_1",
        name="get_invoice",
        file_path="controller.py",
        line_number=20,
    )
    sink = SinkNode(
        id="sink_1",
        operation="READ",
        entity="Invoice",
        query_params=["id"],
        file_path="service.py",
        line_number=35,
    )

    ckg.add_node(route)
    ckg.add_node(handler)
    ckg.add_node(sink)
    ckg.add_edge(route.id, handler.id, EdgeType.ROUTES_TO)
    ckg.add_edge(handler.id, sink.id, EdgeType.CALLS)

    trace = ckg.get_route_trace("route_1")
    assert len(trace["nodes"]) == 3
    sinks = ckg.find_candidate_sinks("route_1")
    assert len(sinks) == 1
    assert sinks[0].entity == "Invoice"


def test_all_six_node_types_and_edge_types():
    route = RouteNode(
        id="r_1",
        method="POST",
        path="/api/v1/users",
        param_constraints={"id": r"\d+"},
        file_path="routes.py",
        line_number=5,
    )
    assert route.node_type == NodeType.ROUTE
    assert route.method == "POST"

    middleware = MiddlewareNode(
        id="mw_1",
        name="authMiddleware",
        type="AUTHN",
        guard_params={"role": "admin"},
        is_auth_guard=True,
        file_path="auth.py",
        line_number=12,
    )
    assert middleware.node_type == NodeType.MIDDLEWARE
    assert middleware.is_auth_guard is True

    handler = HandlerNode(
        id="h_1",
        name="create_user",
        signature="async def create_user(data: UserDTO)",
        line_span=(25, 45),
        arguments=["data"],
        file_path="controllers.py",
        line_number=25,
    )
    assert handler.node_type == NodeType.HANDLER
    assert handler.arguments == ["data"]

    schema = ValidationSchemaNode(
        id="vs_1",
        name="UserDTO",
        schema_type="Pydantic",
        allowed_fields=["username", "email"],
        stripped_fields=["role"],
        strict=True,
        file_path="schemas.py",
        line_number=8,
    )
    assert schema.node_type == NodeType.VALIDATION_SCHEMA
    assert schema.strict is True

    entity = EntityNode(
        id="ent_1",
        name="users",
        primary_key="id",
        columns=["id", "username", "email", "created_at"],
        file_path="models.py",
        line_number=1,
    )
    assert entity.node_type == NodeType.ENTITY
    assert entity.primary_key == "id"

    sink = SinkNode(
        id="snk_1",
        operation="CREATE",
        entity="users",
        query_params=["username", "email"],
        filters=[],
        file_path="repository.py",
        line_number=50,
    )
    assert sink.node_type == NodeType.SINK
    assert sink.operation == "CREATE"

    assert EdgeType.ROUTES_TO == "ROUTES_TO"
    assert EdgeType.PROTECTED_BY == "PROTECTED_BY"
    assert EdgeType.FILTERED_BY == "FILTERED_BY"
    assert EdgeType.CALLS == "CALLS"
    assert EdgeType.READS_FROM == "READS_FROM"
    assert EdgeType.WRITES_TO == "WRITES_TO"


def test_traversal_halts_at_authorization_guards():
    ckg = CodeKnowledgeGraph()

    route = RouteNode(id="r_sec", method="GET", path="/secure/data", file_path="r.py")
    handler = HandlerNode(id="h_sec", name="get_secure_data", file_path="c.py")
    guard = MiddlewareNode(id="guard_1", name="isOwner", type="AUTHZ", is_auth_guard=True)
    sink = SinkNode(id="sink_sec", operation="READ", entity="Secret", query_params=["id"])

    ckg.add_node(route)
    ckg.add_node(handler)
    ckg.add_node(guard)
    ckg.add_node(sink)

    ckg.add_edge(route.id, handler.id, EdgeType.ROUTES_TO)
    ckg.add_edge(handler.id, guard.id, EdgeType.CALLS)
    ckg.add_edge(guard.id, sink.id, EdgeType.CALLS)

    # Traversal should halt when explicit authorization guard is reached;
    # protected sink behind guard is NOT reachable as candidate sink
    sinks = ckg.find_candidate_sinks("r_sec")
    assert len(sinks) == 0

    trace = ckg.get_route_trace("r_sec")
    # Trace includes route, handler, and the guard where it halted
    trace_ids = [n.id for n in trace["nodes"]]
    assert "r_sec" in trace_ids
    assert "h_sec" in trace_ids
    assert "guard_1" in trace_ids
    assert "sink_sec" not in trace_ids


def test_traversal_depth_limit():
    ckg = CodeKnowledgeGraph()
    route = RouteNode(id="r_deep", method="GET", path="/deep", file_path="r.py")
    ckg.add_node(route)

    prev_id = route.id
    # Create chain of 7 nodes: route -> h1 -> h2 -> h3 -> h4 -> h5 -> h6 -> sink
    for i in range(1, 7):
        hid = f"h_{i}"
        ckg.add_node(HandlerNode(id=hid, name=f"handler_{i}", file_path="c.py"))
        ckg.add_edge(prev_id, hid, EdgeType.CALLS if prev_id != route.id else EdgeType.ROUTES_TO)
        prev_id = hid

    sink = SinkNode(id="sink_deep", operation="READ", entity="DeepData")
    ckg.add_node(sink)
    ckg.add_edge(prev_id, sink.id, EdgeType.CALLS)

    # Default max_depth is 5 hops from route
    # Hop 0: r_deep
    # Hop 1: h_1
    # Hop 2: h_2
    # Hop 3: h_3
    # Hop 4: h_4
    # Hop 5: h_5
    # h_6 is hop 6, sink is hop 7 (out of reach)
    sinks = ckg.find_candidate_sinks("r_deep", max_depth=5)
    assert len(sinks) == 0

    # With max_depth=7, sink should be reached
    sinks_7 = ckg.find_candidate_sinks("r_deep", max_depth=7)
    assert len(sinks_7) == 1
    assert sinks_7[0].id == "sink_deep"


def test_traversal_cycle_handling():
    ckg = CodeKnowledgeGraph()
    route = RouteNode(id="r_cycle", method="GET", path="/cycle", file_path="r.py")
    h1 = HandlerNode(id="h_cycle1", name="step1", file_path="c.py")
    h2 = HandlerNode(id="h_cycle2", name="step2", file_path="c.py")
    sink = SinkNode(id="sink_cycle", operation="READ", entity="CycleData")

    ckg.add_node(route)
    ckg.add_node(h1)
    ckg.add_node(h2)
    ckg.add_node(sink)

    ckg.add_edge(route.id, h1.id, EdgeType.ROUTES_TO)
    ckg.add_edge(h1.id, h2.id, EdgeType.CALLS)
    ckg.add_edge(h2.id, h1.id, EdgeType.CALLS)  # Cycle!
    ckg.add_edge(h2.id, sink.id, EdgeType.CALLS)

    # Cycle should not cause infinite loop or duplicate entries
    trace = ckg.get_route_trace("r_cycle")
    trace_ids = [n.id for n in trace["nodes"]]
    assert len(trace_ids) == len(set(trace_ids))
    assert "sink_cycle" in trace_ids

    sinks = ckg.find_candidate_sinks("r_cycle")
    assert len(sinks) == 1
    assert sinks[0].id == "sink_cycle"


def test_nonexistent_route_query():
    ckg = CodeKnowledgeGraph()
    trace = ckg.get_route_trace("unknown_route")
    assert trace["nodes"] == []
    assert trace["edges"] == []
    sinks = ckg.find_candidate_sinks("unknown_route")
    assert sinks == []


def test_handler_name_authorization_heuristic():
    ckg = CodeKnowledgeGraph()
    # Business logic handler with "authorize" in its name, but NOT a guard
    route_pay = RouteNode(id="r_pay", method="POST", path="/pay", file_path="r.py")
    handler_pay = HandlerNode(id="h_pay", name="authorize_payment", file_path="c.py")
    sink_pay = SinkNode(id="s_pay", operation="CREATE", entity="Payment")

    ckg.add_node(route_pay)
    ckg.add_node(handler_pay)
    ckg.add_node(sink_pay)
    ckg.add_edge(route_pay.id, handler_pay.id, EdgeType.ROUTES_TO)
    ckg.add_edge(handler_pay.id, sink_pay.id, EdgeType.CALLS)

    # authorize_payment should NOT be treated as an authorization guard
    sinks = ckg.find_candidate_sinks("r_pay")
    assert len(sinks) == 1
    assert sinks[0].id == "s_pay"

    # Now test an actual guard handler like check_authorization
    route_chk = RouteNode(id="r_chk", method="GET", path="/secret", file_path="r.py")
    handler_guard = HandlerNode(id="h_guard", name="check_authorization", file_path="c.py")
    sink_secret = SinkNode(id="s_secret", operation="READ", entity="Secret")

    ckg.add_node(route_chk)
    ckg.add_node(handler_guard)
    ckg.add_node(sink_secret)
    ckg.add_edge(route_chk.id, handler_guard.id, EdgeType.ROUTES_TO)
    ckg.add_edge(handler_guard.id, sink_secret.id, EdgeType.CALLS)

    sinks_chk = ckg.find_candidate_sinks("r_chk")
    assert len(sinks_chk) == 0


def test_route_level_protected_by_guard():
    ckg = CodeKnowledgeGraph()
    route = RouteNode(id="r_admin", method="GET", path="/admin/users", file_path="r.py")
    guard_mw = MiddlewareNode(id="mw_authz", name="adminGuard", type="AUTHZ")
    handler = HandlerNode(id="h_users", name="get_users", file_path="c.py")
    sink = SinkNode(id="s_users", operation="READ", entity="User")

    ckg.add_node(route)
    ckg.add_node(guard_mw)
    ckg.add_node(handler)
    ckg.add_node(sink)

    ckg.add_edge(route.id, guard_mw.id, EdgeType.PROTECTED_BY)
    ckg.add_edge(route.id, handler.id, EdgeType.ROUTES_TO)
    ckg.add_edge(handler.id, sink.id, EdgeType.CALLS)

    assert ckg.is_route_guarded("r_admin") is True
    # By default exclude_guarded=True, should return empty list
    assert ckg.find_candidate_sinks("r_admin") == []
    # If exclude_guarded=False, sink is still reachable
    sinks_included = ckg.find_candidate_sinks("r_admin", exclude_guarded=False)
    assert len(sinks_included) == 1
    assert sinks_included[0].id == "s_users"

    # Non-guard middleware (e.g. RATE_LIMIT) does NOT guard the route
    route2 = RouteNode(id="r_public", method="GET", path="/public", file_path="r.py")
    rate_mw = MiddlewareNode(id="mw_rate", name="rateLimiter", type="RATE_LIMIT")
    handler2 = HandlerNode(id="h_pub", name="get_public", file_path="c.py")
    sink2 = SinkNode(id="s_pub", operation="READ", entity="PublicData")

    ckg.add_node(route2)
    ckg.add_node(rate_mw)
    ckg.add_node(handler2)
    ckg.add_node(sink2)

    ckg.add_edge(route2.id, rate_mw.id, EdgeType.PROTECTED_BY)
    ckg.add_edge(route2.id, handler2.id, EdgeType.ROUTES_TO)
    ckg.add_edge(handler2.id, sink2.id, EdgeType.CALLS)

    assert ckg.is_route_guarded("r_public") is False
    assert len(ckg.find_candidate_sinks("r_public")) == 1

