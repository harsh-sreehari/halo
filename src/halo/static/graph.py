from __future__ import annotations

from collections import deque
from enum import Enum
from typing import Any

import networkx as nx
from pydantic import BaseModel, ConfigDict, Field


class NodeType(str, Enum):
    ROUTE = "ROUTE"
    MIDDLEWARE = "MIDDLEWARE"
    HANDLER = "HANDLER"
    VALIDATION_SCHEMA = "VALIDATION_SCHEMA"
    ENTITY = "ENTITY"
    SINK = "SINK"


class EdgeType(str, Enum):
    ROUTES_TO = "ROUTES_TO"
    PROTECTED_BY = "PROTECTED_BY"
    FILTERED_BY = "FILTERED_BY"
    CALLS = "CALLS"
    READS_FROM = "READS_FROM"
    WRITES_TO = "WRITES_TO"


class BaseNode(BaseModel):
    model_config = ConfigDict(extra="allow")

    id: str
    node_type: NodeType
    file_path: str = ""
    line_number: int = 0


class RouteNode(BaseNode):
    node_type: NodeType = NodeType.ROUTE
    method: str
    path: str
    param_constraints: dict[str, str] = Field(default_factory=dict)


class MiddlewareNode(BaseNode):
    node_type: NodeType = NodeType.MIDDLEWARE
    name: str
    type: str = "AUTHN"
    guard_params: dict[str, Any] = Field(default_factory=dict)
    is_auth_guard: bool = False

    def __init__(self, **data: Any) -> None:
        if "middleware_type" in data and "type" not in data:
            data["type"] = data.pop("middleware_type")
        super().__init__(**data)

    @property
    def middleware_type(self) -> str:
        return self.type


class HandlerNode(BaseNode):
    node_type: NodeType = NodeType.HANDLER
    name: str
    signature: str = ""
    line_span: tuple[int, int] = (0, 0)
    arguments: list[str] = Field(default_factory=list)


class ValidationSchemaNode(BaseNode):
    node_type: NodeType = NodeType.VALIDATION_SCHEMA
    name: str = ""
    schema_type: str = ""
    allowed_fields: list[str] = Field(default_factory=list)
    stripped_fields: list[str] = Field(default_factory=list)
    strict: bool = True
    strictness_flags: dict[str, Any] = Field(default_factory=dict)


class EntityNode(BaseNode):
    node_type: NodeType = NodeType.ENTITY
    name: str
    primary_key: str = "id"
    columns: list[str] = Field(default_factory=list)


class SinkNode(BaseNode):
    node_type: NodeType = NodeType.SINK
    operation: str
    entity: str
    query_params: list[str] = Field(default_factory=list)
    filters: list[str] = Field(default_factory=list)


def is_authorization_guard(node: BaseNode | None) -> bool:
    """Determine whether a CKG node represents an explicit authorization guard."""
    if node is None:
        return False
    if getattr(node, "is_auth_guard", False):
        return True
    if isinstance(node, MiddlewareNode):
        if str(node.type).upper() == "AUTHZ":
            return True
        name_lower = node.name.lower()
        if any(
            token in name_lower
            for token in ("isowner", "hasrole", "has_role", "is_owner", "check_permission", "rbac", "authoriz")
        ):
            return True
    elif isinstance(node, HandlerNode):
        name_lower = node.name.lower()
        guard_patterns = (
            "check_authoriz",
            "is_authoriz",
            "verify_authoriz",
            "require_authoriz",
            "has_role",
            "hasrole",
            "has_permission",
            "haspermission",
            "is_owner",
            "isowner",
            "ensure_access",
            "assert_perm",
            "check_permission",
            "require_permission",
            "verify_permission",
        )
        if any(token in name_lower for token in guard_patterns):
            return True
    return False


class CodeKnowledgeGraph:
    """Manages the Code Knowledge Graph (CKG) using a NetworkX DiGraph."""

    def __init__(self) -> None:
        self.graph: nx.DiGraph = nx.DiGraph()
        self._nodes: dict[str, BaseNode] = {}

    @property
    def nodes(self) -> dict[str, BaseNode]:
        return self._nodes

    def __len__(self) -> int:
        return len(self._nodes)

    def __contains__(self, node_id: str) -> bool:
        return node_id in self._nodes

    def add_node(self, node: BaseNode) -> None:
        """Add a typed node to the CKG."""
        self._nodes[node.id] = node
        attrs = node.model_dump()
        attrs["data"] = node
        self.graph.add_node(node.id, **attrs)

    def get_node(self, node_id: str) -> BaseNode | None:
        """Retrieve a node by its ID."""
        return self._nodes.get(node_id)

    def add_edge(
        self,
        source_id: str,
        target_id: str,
        edge_type: EdgeType | str,
        **attributes: Any,
    ) -> None:
        """Add a directed typed edge between two nodes in the CKG."""
        edge_type_val = edge_type.value if isinstance(edge_type, EdgeType) else str(edge_type)
        self.graph.add_edge(source_id, target_id, edge_type=edge_type_val, **attributes)

    def get_route_trace(self, route_id: str, max_depth: int = 5) -> dict[str, Any]:
        """
        Traverse the graph from a RouteNode up to max_depth hops.
        Halts when a SinkNode is reached or an explicit authorization guard is encountered.
        """
        if route_id not in self.graph:
            return {"route_id": route_id, "nodes": [], "edges": []}

        queue: deque[tuple[str, int]] = deque([(route_id, 0)])
        visited_nodes: set[str] = {route_id}
        ordered_nodes: list[BaseNode] = []
        ordered_edges: list[dict[str, Any]] = []

        while queue:
            curr_id, curr_depth = queue.popleft()
            curr_node = self.get_node(curr_id)
            if curr_node is not None:
                ordered_nodes.append(curr_node)

            # Traversal halting criteria
            if curr_id != route_id:
                # Halt if SinkNode is reached
                if isinstance(curr_node, SinkNode):
                    continue
                # Halt if explicit authorization guard is encountered
                if is_authorization_guard(curr_node):
                    continue
                # Halt if depth limit reached
                if curr_depth >= max_depth:
                    continue

            for successor_id in self.graph.successors(curr_id):
                edge_attrs = self.graph.get_edge_data(curr_id, successor_id) or {}
                ordered_edges.append({
                    "source": curr_id,
                    "target": successor_id,
                    **edge_attrs,
                })
                if successor_id not in visited_nodes:
                    visited_nodes.add(successor_id)
                    queue.append((successor_id, curr_depth + 1))

        return {
            "route_id": route_id,
            "nodes": ordered_nodes,
            "edges": ordered_edges,
        }

    def is_route_guarded(self, route_id: str) -> bool:
        """
        Check whether a route is protected by an explicit authorization guard
        via a PROTECTED_BY edge or an explicit guard flag.
        """
        route_node = self.get_node(route_id)
        if route_node is None:
            return False
        if getattr(route_node, "is_auth_guard", False):
            return True
        for succ_id in self.graph.successors(route_id):
            edge_data = self.graph.get_edge_data(route_id, succ_id) or {}
            edge_type = edge_data.get("edge_type")
            if edge_type in (EdgeType.PROTECTED_BY, EdgeType.PROTECTED_BY.value):
                succ_node = self.get_node(succ_id)
                if is_authorization_guard(succ_node):
                    return True
        return False

    def find_candidate_sinks(
        self,
        route_id: str,
        max_depth: int = 5,
        exclude_guarded: bool = True,
    ) -> list[SinkNode]:
        """
        Find all reachable data sinks from a route within max_depth hops
        that are not blocked by authorization guards.

        If exclude_guarded is True and the route is protected by an authorization
        guard via a PROTECTED_BY edge, returns an empty list.
        """
        if exclude_guarded and self.is_route_guarded(route_id):
            return []

        trace = self.get_route_trace(route_id, max_depth=max_depth)
        sinks: list[SinkNode] = []
        seen_sink_ids: set[str] = set()
        for node in trace["nodes"]:
            if isinstance(node, SinkNode) and (node.id not in seen_sink_ids):
                seen_sink_ids.add(node.id)
                sinks.append(node)
        return sinks

    def get_nodes_by_type(self, node_type: NodeType) -> list[BaseNode]:
        """Retrieve all nodes matching a specific NodeType."""
        return [node for node in self._nodes.values() if node.node_type == node_type]
