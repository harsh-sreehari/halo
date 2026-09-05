from __future__ import annotations

from collections.abc import Iterable, Sequence
from typing import Any

from halo.static.graph import RouteNode


class LaravelFlattener:
    """
    Expands Laravel macro route definitions (Route::resource, Route::apiResource)
    into standard REST endpoints.
    """

    # 7 standard REST actions in Laravel resource controllers
    RESOURCE_ACTIONS: tuple[dict[str, str], ...] = (
        {"action": "index", "method": "GET", "path_suffix": ""},
        {"action": "create", "method": "GET", "path_suffix": "/create"},
        {"action": "store", "method": "POST", "path_suffix": ""},
        {"action": "show", "method": "GET", "path_suffix": "/{{{param}}}"},
        {"action": "edit", "method": "GET", "path_suffix": "/{{{param}}}/edit"},
        {"action": "update", "method": "PUT/PATCH", "path_suffix": "/{{{param}}}"},
        {"action": "destroy", "method": "DELETE", "path_suffix": "/{{{param}}}"},
    )

    @classmethod
    def expand_resource(
        cls,
        resource_name: str,
        controller: str,
        only: Iterable[str] | None = None,
        except_actions: Iterable[str] | None = None,
        param_name: str = "id",
        **kwargs: Any,
    ) -> list[dict[str, Any]]:
        """
        Expand a Laravel Route::resource macro into its 7 standard REST endpoints:
        - index: GET /resource
        - create: GET /resource/create
        - store: POST /resource
        - show: GET /resource/{id}
        - edit: GET /resource/{id}/edit
        - update: PUT/PATCH /resource/{id}
        - destroy: DELETE /resource/{id}

        Args:
            resource_name: Resource URI name (e.g. 'orders' or 'api/v1/invoices')
            controller: Controller class name (e.g. 'OrderController')
            only: Whitelist of action names to generate
            except_actions: Blacklist of action names to omit
            param_name: Route parameter name, default 'id'

        Returns:
            List of endpoint dictionaries containing action, method, path, handler, and controller.
        """
        clean_resource = resource_name.strip("/")
        base_path = f"/{clean_resource}" if clean_resource else ""

        # Normalize filter sets
        only_set = set(only) if only is not None else None
        # Handle kwargs 'except' alias if passed
        if except_actions is None and kwargs.get("except"):
            except_actions = kwargs["except"]
        except_set = set(except_actions) if except_actions is not None else set()

        routes: list[dict[str, Any]] = []

        for item in cls.RESOURCE_ACTIONS:
            action = item["action"]

            if only_set is not None and action not in only_set:
                continue
            if action in except_set:
                continue

            suffix = item["path_suffix"].format(param=param_name)
            path = f"{base_path}{suffix}"
            if not path.startswith("/"):
                path = f"/{path}"

            route = {
                "action": action,
                "name": f"{clean_resource}.{action}" if clean_resource else action,
                "method": item["method"],
                "path": path,
                "handler": f"{controller}@{action}",
                "handler_name": f"{controller}@{action}",
                "controller": controller,
            }
            routes.append(route)

        return routes

    @classmethod
    def expand_api_resource(
        cls,
        resource_name: str,
        controller: str,
        only: Iterable[str] | None = None,
        except_actions: Iterable[str] | None = None,
        param_name: str = "id",
        **kwargs: Any,
    ) -> list[dict[str, Any]]:
        """
        Expand a Laravel Route::apiResource macro, which excludes 'create' and 'edit'
        HTML form actions and returns 5 REST endpoints (index, store, show, update, destroy).
        """
        api_except = set(except_actions) if except_actions is not None else set()
        if kwargs.get("except"):
            api_except.update(kwargs["except"])
        api_except.update({"create", "edit"})

        return cls.expand_resource(
            resource_name=resource_name,
            controller=controller,
            only=only,
            except_actions=api_except,
            param_name=param_name,
            **kwargs,
        )

    @classmethod
    def to_route_nodes(
        cls,
        routes: Sequence[dict[str, Any]],
        file_path: str = "",
        line_number: int = 0,
    ) -> list[RouteNode]:
        """Convert flattened route dictionaries to CKG RouteNode instances."""
        nodes: list[RouteNode] = []
        for r in routes:
            node_id = f"route:laravel:{r['method']}:{r['path']}"
            nodes.append(
                RouteNode(
                    id=node_id,
                    method=r["method"],
                    path=r["path"],
                    file_path=file_path,
                    line_number=line_number,
                )
            )
        return nodes
