"""Deterministic Candidate Pruner: Eliminates safe paths and flags suspect business logic flaw candidates."""

from __future__ import annotations

import logging
import re
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from halo.intent.extractor import BusinessPolicyMatrix
from halo.static.graph import (
    CodeKnowledgeGraph,
    EdgeType,
    HandlerNode,
    MiddlewareNode,
    NodeType,
    RouteNode,
    SinkNode,
    ValidationSchemaNode,
    is_authorization_guard,
)

logger = logging.getLogger(__name__)

SENSITIVE_FIELDS: set[str] = {
    "role",
    "roles",
    "is_admin",
    "admin",
    "is_staff",
    "is_superuser",
    "permissions",
    "permission",
    "balance",
    "credit",
    "credits",
    "verified",
    "email_verified",
    "is_verified",
    "tenant_id",
    "owner_id",
    "user_id",
    "group_id",
    "status",
    "tier",
    "plan",
    "quota",
}

RACE_KEYWORDS: set[str] = {
    "balance",
    "transfer",
    "withdraw",
    "deposit",
    "credit",
    "debit",
    "redeem",
    "coupon",
    "discount",
    "voucher",
    "stock",
    "inventory",
    "reserve",
    "checkout",
    "points",
    "vote",
    "like",
    "counter",
    "quota",
    "limit",
    "ticket",
    "wallet",
}

ADMIN_PATH_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"^/api/(?:v\d+/)?admin(?:/|$)", re.IGNORECASE),
    re.compile(r"^/admin(?:/|$)", re.IGNORECASE),
    re.compile(r"^/api/(?:v\d+/)?manage(?:/|$)", re.IGNORECASE),
    re.compile(r"^/manage(?:/|$)", re.IGNORECASE),
    re.compile(r"^/api/(?:v\d+/)?internal(?:/|$)", re.IGNORECASE),
    re.compile(r"^/internal(?:/|$)", re.IGNORECASE),
    re.compile(r"^/api/(?:v\d+/)?super(?:/|$)", re.IGNORECASE),
    re.compile(r"^/ops(?:/|$)", re.IGNORECASE),
    re.compile(r"^/sys(?:/|$)", re.IGNORECASE),
]

PRIVILEGED_ROLES: set[str] = {
    "superadmin",
    "root",
    "owner",
    "admin",
    "administrator",
    "manager",
    "staff",
    "moderator",
    "ops",
    "internal",
}

UNPRIVILEGED_ROLES: set[str] = {
    "user",
    "users",
    "customer",
    "customers",
    "member",
    "members",
    "guest",
    "guests",
    "anonymous",
    "public",
    "client",
    "clients",
}

WORKFLOW_ACTIONS: set[str] = {
    "ship",
    "fulfill",
    "refund",
    "payout",
    "approve",
    "publish",
    "complete",
    "cancel",
    "void",
    "checkout",
    "finalize",
    "dispatch",
}


class SuspectCandidate(BaseModel):
    """A prioritized suspect route and data sink candidate flagged for dynamic testing."""

    model_config = ConfigDict(extra="allow")

    route: RouteNode
    sink: SinkNode | None = None
    candidate_flaws: list[str] = Field(
        default_factory=list,
        description="Candidate flaw types (e.g. BOLA, BFLA, RACE, WORKFLOW, MASS_ASSIGNMENT)",
    )
    reasoning: str = Field(
        default="",
        description="Detailed static reasoning justifying why this route is suspect",
    )


class CandidatePruner:
    """Deterministically prunes safe execution paths to prevent LLM token waste."""

    def prune_candidates(
        self,
        ckg: CodeKnowledgeGraph,
        policies: BusinessPolicyMatrix | None = None,
    ) -> list[SuspectCandidate]:
        """Filter out safe paths and classify remaining suspect candidates.

        Eliminates 90%+ safe paths based on deterministic structural properties:
        - Safe read-only routes without path parameters or query filters are discarded from BOLA analysis.
        - Routes wrapped by strict validation schemas without sensitive fields are discarded from Mass Assignment.
        - Simple read-then-write paths without conditional threshold comparisons or race-sensitive counters are discarded from Race Condition analysis.
        - Routes guarded by verified authorization middleware are marked safe or skipped.
        """
        suspects: list[SuspectCandidate] = []
        routes: list[RouteNode] = [
            n for n in ckg.get_nodes_by_type(NodeType.ROUTE) if isinstance(n, RouteNode)
        ]

        for route in routes:
            # 1. Rule 4: Routes guarded by verified authorization middleware are marked safe or skipped
            if self._is_route_guarded(ckg, route.id):
                continue

            # Route trace and candidate sinks
            trace = ckg.get_route_trace(route.id)
            trace_nodes = trace.get("nodes", [])
            sinks = ckg.find_candidate_sinks(route.id, exclude_guarded=True)

            flaws: list[str] = []
            reasons: list[str] = []

            # 2. Rule 1: Evaluate BOLA (Broken Object Level Authorization)
            bola_candidate, bola_reason = self._evaluate_bola(route, sinks)
            if bola_candidate:
                flaws.append("BOLA")
                reasons.append(bola_reason)

            # 3. Rule 2: Evaluate MASS_ASSIGNMENT
            mass_assign_candidate, mass_assign_reason = self._evaluate_mass_assignment(
                ckg, route, trace_nodes
            )
            if mass_assign_candidate:
                flaws.append("MASS_ASSIGNMENT")
                reasons.append(mass_assign_reason)

            # 4. Rule 3: Evaluate RACE (Race Condition / Concurrency)
            race_candidate, race_reason = self._evaluate_race_condition(route, trace_nodes, sinks)
            if race_candidate:
                flaws.append("RACE")
                reasons.append(race_reason)

            # 5. Evaluate BFLA (Broken Function Level Authorization)
            bfla_candidate, bfla_reason = self._evaluate_bfla(route, trace_nodes, policies)
            if bfla_candidate:
                flaws.append("BFLA")
                reasons.append(bfla_reason)

            # 6. Evaluate WORKFLOW (State Machine / Invariant Bypass)
            workflow_candidate, workflow_reason = self._evaluate_workflow(
                route, sinks, policies
            )
            if workflow_candidate:
                flaws.append("WORKFLOW")
                reasons.append(workflow_reason)

            # If no flaws identified, the route is pruned as safe
            if not flaws:
                continue

            # Deduplicate flaws preserving order
            unique_flaws = list(dict.fromkeys(flaws))
            full_reasoning = "; ".join(reasons)

            if sinks:
                for sink in sinks:
                    suspects.append(
                        SuspectCandidate(
                            route=route,
                            sink=sink,
                            candidate_flaws=unique_flaws,
                            reasoning=full_reasoning,
                        )
                    )
            else:
                suspects.append(
                    SuspectCandidate(
                        route=route,
                        sink=None,
                        candidate_flaws=unique_flaws,
                        reasoning=full_reasoning,
                    )
                )

        return suspects

    def _is_route_guarded(self, ckg: CodeKnowledgeGraph, route_id: str) -> bool:
        """Check whether the route is guarded by verified authorization middleware."""
        if ckg.is_route_guarded(route_id):
            return True

        # Check direct middleware successors via PROTECTED_BY
        for succ_id in ckg.graph.successors(route_id):
            edge_data = ckg.graph.get_edge_data(route_id, succ_id) or {}
            edge_type = edge_data.get("edge_type")
            succ_node = ckg.get_node(succ_id)
            if is_authorization_guard(succ_node):
                return True
            if (
                edge_type in (EdgeType.PROTECTED_BY, EdgeType.PROTECTED_BY.value)
                and isinstance(succ_node, MiddlewareNode)
                and (str(succ_node.type).upper() == "AUTHZ" or getattr(succ_node, "is_auth_guard", False))
            ):
                return True

        return False

    def _has_path_parameters(self, route: RouteNode) -> bool:
        """Determine if a route contains variable path parameters."""
        if bool(route.param_constraints):
            return True
        path = route.path
        return "{" in path or ":" in path or "<" in path

    def _evaluate_bola(
        self,
        route: RouteNode,
        sinks: list[SinkNode],
    ) -> tuple[bool, str]:
        """Evaluate route for Broken Object Level Authorization (BOLA)."""
        method = route.method.upper()
        has_params = self._has_path_parameters(route)
        has_sink_filters = any(
            (len(s.query_params) > 0 or len(s.filters) > 0) for s in sinks
        )

        # Rule: Safe read-only routes without path parameters or query filters are discarded
        if method in ("GET", "HEAD"):
            if not has_params and not has_sink_filters:
                return False, ""
            # Parameterized or filtered read-only route
            entity_names = [s.entity for s in sinks if s.entity]
            entity_str = ", ".join(entity_names) if entity_names else "resource"
            return (
                True,
                f"Parameterized GET route '{route.path}' accesses {entity_str} without verified ownership guard",
            )

        # For mutations, parameterized ID accesses are also BOLA targets
        if method in ("PUT", "DELETE", "PATCH") and has_params:
            return (
                True,
                f"Parameterized mutation route '{route.path}' accesses resource by ID without authorization check",
            )

        return False, ""

    def _evaluate_mass_assignment(
        self,
        ckg: CodeKnowledgeGraph,
        route: RouteNode,
        trace_nodes: list[Any],
    ) -> tuple[bool, str]:
        """Evaluate route for Mass Assignment vulnerabilities."""
        method = route.method.upper()
        # Mass assignment only targets mutations
        if method not in ("POST", "PUT", "PATCH"):
            return False, ""

        # Locate validation schemas attached to route or handler
        schemas: list[ValidationSchemaNode] = []
        for node in trace_nodes:
            if isinstance(node, ValidationSchemaNode):
                schemas.append(node)

        for succ_id in ckg.graph.successors(route.id):
            succ_node = ckg.get_node(succ_id)
            if isinstance(succ_node, ValidationSchemaNode) and succ_node not in schemas:
                schemas.append(succ_node)

        # If no validation schema is present, the route is unprotected against mass assignment
        if not schemas:
            return (
                True,
                f"Mutation route '{route.path}' has no validation schema attached",
            )

        # Check all associated schemas
        for schema in schemas:
            # If schema is not strict, extra arbitrary fields are permitted
            if not schema.strict:
                return (
                    True,
                    f"Mutation route '{route.path}' is guarded by non-strict schema '{schema.name}'",
                )

            # Check for sensitive fields in allowed_fields
            allowed_lower = {f.lower() for f in schema.allowed_fields}
            leaked_sensitive = allowed_lower.intersection(SENSITIVE_FIELDS)
            if leaked_sensitive:
                fields_str = ", ".join(sorted(leaked_sensitive))
                return (
                    True,
                    f"Strict schema '{schema.name}' allows sensitive fields: {fields_str}",
                )

        # Wrapped by strict schema without sensitive fields -> discarded
        return False, ""

    def _evaluate_race_condition(
        self,
        route: RouteNode,
        trace_nodes: list[Any],
        sinks: list[SinkNode],
    ) -> tuple[bool, str]:
        """Evaluate route for Concurrency / Race Condition flaws."""
        method = route.method.upper()
        if method not in ("POST", "PUT", "PATCH", "DELETE"):
            return False, ""

        # Collect text tokens across route path, handlers, sinks, and params
        tokens: set[str] = set()
        path_segments = re.findall(r"[a-zA-Z0-9_]+", route.path.lower())
        tokens.update(path_segments)

        for node in trace_nodes:
            if isinstance(node, HandlerNode):
                tokens.update(re.findall(r"[a-zA-Z0-9_]+", node.name.lower()))

        for sink in sinks:
            tokens.update(re.findall(r"[a-zA-Z0-9_]+", sink.entity.lower()))
            for qp in sink.query_params:
                tokens.update(re.findall(r"[a-zA-Z0-9_]+", qp.lower()))

        matched_keywords = {
            t
            for t in tokens
            if t in RACE_KEYWORDS or (t.endswith("s") and t[:-1] in RACE_KEYWORDS)
        }
        if matched_keywords:
            kw_str = ", ".join(sorted(matched_keywords))
            return (
                True,
                f"Mutation route '{route.path}' touches race-sensitive business logic ({kw_str})",
            )

        # Simple read-then-write paths without counters/thresholds are discarded
        return False, ""

    def _evaluate_bfla(
        self,
        route: RouteNode,
        trace_nodes: list[Any],
        policies: BusinessPolicyMatrix | None,
    ) -> tuple[bool, str]:
        """Evaluate route for Broken Function Level Authorization (BFLA)."""
        path = route.path
        is_admin_path = any(p.match(path) for p in ADMIN_PATH_PATTERNS)

        is_admin_handler = False
        for node in trace_nodes:
            if isinstance(node, HandlerNode):
                name_lower = node.name.lower()
                if any(k in name_lower for k in ("admin", "superuser", "manage_user", "purge", "elevate")):
                    is_admin_handler = True
                    break

        if is_admin_path or is_admin_handler:
            return (
                True,
                f"Privileged route '{route.path}' lacks verified role-based authorization guard",
            )

        # Check role hierarchy from policies (strictly targeting privileged roles)
        if policies and policies.role_hierarchy:
            top_roles = [
                r
                for r in policies.role_hierarchy
                if r.lower() in PRIVILEGED_ROLES and r.lower() not in UNPRIVILEGED_ROLES
            ]
            for role in top_roles:
                role_clean = role.lower()
                # Strict path boundary match (e.g. /admin/..., /api/v1/superadmin/..., not /users or /user/profile)
                role_pattern = re.compile(
                    rf"(?:^|/)(?:api/(?:v\d+/)?)?{re.escape(role_clean)}(?:/|$)",
                    re.IGNORECASE,
                )
                if role_pattern.search(path):
                    return (
                        True,
                        f"Privileged route '{route.path}' for role '{role}' lacks explicit auth guard",
                    )

        return False, ""

    def _evaluate_workflow(
        self,
        route: RouteNode,
        sinks: list[SinkNode],
        policies: BusinessPolicyMatrix | None,
    ) -> tuple[bool, str]:
        """Evaluate route for Broken Workflow / State Invariant Bypass."""
        method = route.method.upper()
        # 1. State machine workflow transitions are strictly mutations (POST, PUT, PATCH, DELETE)
        # Static read-only routes (GET, HEAD, OPTIONS) cannot trigger state transitions
        if method not in ("POST", "PUT", "PATCH", "DELETE"):
            return False, ""

        path_lower = route.path.lower()
        path_segments = set(re.findall(r"[a-zA-Z0-9_]+", path_lower))

        # Match against predefined transition actions
        matched_actions = path_segments.intersection(WORKFLOW_ACTIONS)
        if matched_actions:
            action_str = ", ".join(sorted(matched_actions))
            return (
                True,
                f"State transition endpoint '{route.path}' ({action_str}) requires state invariant verification",
            )

        # 2. Match transition verbs from policy state invariants
        if policies and policies.state_invariants:
            for inv in policies.state_invariants:
                inv_lower = inv.lower()
                inv_tokens = set(re.findall(r"[a-zA-Z0-9_]+", inv_lower))
                # Only match transition action verbs, never generic entity nouns (like 'order', 'user')
                relevant_actions = inv_tokens.intersection(WORKFLOW_ACTIONS).union({
                    "pay",
                    "paid",
                    "capture",
                    "authorize",
                    "reject",
                    "close",
                    "reopen",
                    "transfer",
                    "activate",
                    "deactivate",
                    "promote",
                    "demote",
                    "release",
                })
                matched_inv_actions = path_segments.intersection(relevant_actions)
                if matched_inv_actions:
                    act_str = ", ".join(sorted(matched_inv_actions))
                    return (
                        True,
                        f"Route '{route.path}' triggers state transition '{act_str}' tied to invariant: '{inv}'",
                    )

        return False, ""
