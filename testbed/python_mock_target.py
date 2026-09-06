"""Pure Python mock HTTP server providing the 6 canonical BLFs for rapid CI."""

from __future__ import annotations

import json
import logging
import re
import sys
import threading
import time
from collections.abc import Generator
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


class MockTargetState:
    """Thread-safe in-memory state store for mock server."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.reset()

    def reset(self) -> None:
        with self.lock:
            self.users: dict[str, dict[str, Any]] = {
                "halo_admin": {
                    "username": "halo_admin",
                    "role": "admin",
                    "token": "halo_token_admin",
                },
                "halo_user_a": {
                    "username": "halo_user_a",
                    "role": "user",
                    "token": "halo_token_user_a",
                },
                "halo_user_b": {
                    "username": "halo_user_b",
                    "role": "user",
                    "token": "halo_token_user_b",
                },
            }
            self.invoices: dict[str, dict[str, Any]] = {
                "inv-b-1": {
                    "id": "inv-b-1",
                    "title": "Confidential Invoice B",
                    "amount": 450.0,
                    "userId": "halo_user_b",
                    "name": "Confidential Invoice B",
                },
                "1": {
                    "id": "1",
                    "title": "Initial Invoice",
                    "amount": 100.0,
                    "userId": "halo_user_b",
                    "name": "Initial Invoice",
                },
            }
            self.orders: dict[str, dict[str, Any]] = {
                "1": {
                    "id": "1",
                    "status": "created",
                    "paid": False,
                    "total": 100.0,
                    "userId": "halo_user_a",
                }
            }
            self.coupons: dict[str, dict[str, Any]] = {
                "DISCOUNT50": {
                    "code": "DISCOUNT50",
                    "discount": 50.0,
                    "used": False,
                    "redeem_count": 0,
                }
            }
            self.cart_checked_out: bool = False


global_state = MockTargetState()


class MockTargetHandler(BaseHTTPRequestHandler):
    """HTTP request handler implementing all 6 canonical BLFs and safe routes."""

    server_version = "HaloMockServer/1.0"

    def log_message(self, format: str, *args: Any) -> None:
        # Suppress noisy standard request logs during tests
        pass

    def _send_json(self, status_code: int, data: Any) -> None:
        body = json.dumps(data).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length", 0))
        if length <= 0:
            return {}
        raw = self.rfile.read(length).decode("utf-8", errors="replace")
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return {}

    def _get_auth_token(self) -> str:
        auth = self.headers.get("Authorization", "")
        if auth.lower().startswith("bearer "):
            return auth[7:].strip()
        return ""

    # -------------------------------------------------------------------------
    # GET Handlers
    # -------------------------------------------------------------------------
    def do_GET(self) -> None:
        path = urlparse(self.path).path

        # Benign Safe Route: Health
        if path == "/health":
            self._send_json(200, {"status": "ok"})
            return

        # Benign Safe Route: Public Info
        if path == "/api/v1/public/info":
            self._send_json(
                200,
                {"version": "1.0.0", "name": "halo-mock-target", "status": "operational"},
            )
            return

        # 1. BOLA Read: GET /api/v1/invoices/:id
        inv_match = re.match(r"^/api/v1/invoices/([^/]+)$", path)
        if inv_match:
            inv_id = inv_match.group(1)
            with global_state.lock:
                inv = global_state.invoices.get(inv_id)
            if not inv:
                self._send_json(404, {"error": "Invoice not found"})
                return
            # VULNERABILITY: No ownership check (authenticated user vs invoice.userId)
            self._send_json(200, inv)
            return

        # 3. BFLA: GET /api/v1/admin/settings
        if path == "/api/v1/admin/settings":
            # VULNERABILITY: Returns administrative configuration without role checks
            self._send_json(
                200,
                {
                    "settings": {
                        "maintenanceMode": False,
                        "debug": True,
                        "maxLoginAttempts": 5,
                        "encryptionAlgorithm": "AES-256-GCM",
                    }
                },
            )
            return

        self._send_json(404, {"error": "Not Found", "path": path})

    # -------------------------------------------------------------------------
    # POST Handlers
    # -------------------------------------------------------------------------
    def do_POST(self) -> None:
        path = urlparse(self.path).path
        data = self._read_json()

        # Auth helper: /register
        if path in ("/register", "/api/register", "/api/v1/register"):
            username = data.get("username", "halo_user_a")
            token = (
                "halo_token_user_b"
                if "user_b" in username
                else ("halo_token_admin" if "admin" in username else "halo_token_user_a")
            )
            with global_state.lock:
                global_state.users[username] = {
                    "username": username,
                    "token": token,
                    "role": "admin" if "admin" in username else "user",
                }
            self._send_json(201, {"token": token, "username": username, "status": "registered"})
            return

        # Auth helper: /login
        if path in ("/login", "/api/login", "/api/v1/login"):
            username = data.get("username", "")
            token = (
                "halo_token_admin"
                if "admin" in username
                else ("halo_token_user_b" if "user_b" in username else "halo_token_user_a")
            )
            self._send_json(200, {"token": token})
            return

        # Invoice creation (used by BOLA multi-actor handshake)
        if path in ("/api/v1/invoices", "/api/invoices"):
            token = self._get_auth_token()
            user_id = "halo_user_b" if "user_b" in token else "halo_user_a"
            with global_state.lock:
                inv_id = f"inv-{len(global_state.invoices) + 1}"
                inv = {
                    "id": inv_id,
                    "title": data.get("name") or data.get("title") or "Test Invoice",
                    "amount": float(data.get("amount", 100.0)),
                    "userId": user_id,
                    "name": data.get("name") or data.get("title") or "Test Invoice",
                }
                global_state.invoices[inv_id] = inv
            self._send_json(201, inv)
            return

        # Order creation
        if path in ("/api/v1/orders", "/api/orders"):
            with global_state.lock:
                ord_id = f"ord-{len(global_state.orders) + 1}"
                order = {
                    "id": ord_id,
                    "status": "created",
                    "paid": False,
                    "total": float(data.get("total", 100.0)),
                    "userId": "halo_user_a",
                }
                global_state.orders[ord_id] = order
            self._send_json(201, order)
            return

        # 4. Workflow Bypass: POST /api/v1/orders/:id/ship
        ship_match = re.match(r"^/api/v1/orders/([^/]+)/ship$", path)
        if ship_match:
            # Shipping endpoint rejects mass assignment / price tampering payloads
            if (
                "role" in data
                or "total" in data
                or "items" in data
                or "price" in data
                or "admin" in str(data)
            ):
                self._send_json(400, {"error": "Invalid shipping payload"})
                return

            order_id = ship_match.group(1)
            with global_state.lock:
                order = global_state.orders.get(order_id)
                if not order:
                    order = {
                        "id": order_id,
                        "status": "created",
                        "paid": False,
                        "total": 100.0,
                        "userId": "halo_user_a",
                    }
                    global_state.orders[order_id] = order
                # VULNERABILITY: Order transitions to shipped without verifying prerequisite payment status
                order["status"] = "shipped"
            self._send_json(
                200,
                {
                    "id": order_id,
                    "status": "shipped",
                    "paid": order.get("paid", False),
                    "message": "Order shipped successfully without requiring prior payment",
                },
            )
            return

        # 5. Mass Assignment / Price Tamper: POST /api/v1/cart/checkout
        if path == "/api/v1/cart/checkout":
            # If payload is completely empty, reject (requires items in cart)
            if not data or ("items" not in data and "total" not in data and "price" not in data):
                self._send_json(400, {"error": "Cart cannot be empty"})
                return

            # Check if this is a concurrent duplicate checkout on the same cart
            with global_state.lock:
                if global_state.cart_checked_out:
                    self._send_json(409, {"error": "Cart has already been checked out"})
                    return
                # If race condition probe burst is running (no price tamper), atomic checkout marks it used
                if "total" not in data and "price" not in data:
                    global_state.cart_checked_out = True

            # VULNERABILITY: Accepts client-provided untrusted total without server recalculation
            client_total = data.get("total", data.get("price", 100.0))
            order_record = {
                "orderId": "ord_checkout_1",
                "items": data.get("items", []),
                "total": client_total,
                "status": "confirmed",
                "message": "Checkout completed successfully with client total",
            }
            self._send_json(200, order_record)
            return

        # 6. Concurrency Race: POST /api/v1/coupons/apply
        if path == "/api/v1/coupons/apply":
            code = data.get("code") or data.get("coupon")
            if not code:
                # Reject generic mass assignment probes that lack a coupon code
                self._send_json(400, {"error": "Coupon code is required"})
                return

            coupon = global_state.coupons.get(code)
            if not coupon:
                self._send_json(404, {"error": "Coupon not found"})
                return

            now = time.time()
            # If coupon was redeemed more than 0.5 seconds ago, auto-reset for reproduction scripts
            if coupon.get("last_redeemed") and (now - coupon["last_redeemed"]) > 0.5:
                coupon["used"] = False
                coupon["redeem_count"] = 0

            # Check-then-act with intentional race window
            if coupon["used"]:
                self._send_json(400, {"error": "Coupon already redeemed"})
                return

            # Intentional 50ms race window to trigger concurrency collision
            time.sleep(0.05)

            coupon["used"] = True
            coupon["redeem_count"] += 1
            coupon["last_redeemed"] = time.time()

            self._send_json(
                200,
                {
                    "code": coupon["code"],
                    "discount": coupon["discount"],
                    "redeemed": True,
                    "count": coupon["redeem_count"],
                },
            )
            return

        self._send_json(404, {"error": "Not Found", "path": path})

    # -------------------------------------------------------------------------
    # PUT Handlers
    # -------------------------------------------------------------------------
    def do_PUT(self) -> None:
        path = urlparse(self.path).path
        data = self._read_json()

        # 2. BOLA Write: PUT /api/v1/invoices/:id
        inv_match = re.match(r"^/api/v1/invoices/([^/]+)$", path)
        if inv_match:
            # Reject mass-assignment role injection attempts on invoice update
            if "role" in data:
                self._send_json(400, {"error": "Invalid field: role cannot be updated"})
                return

            inv_id = inv_match.group(1)
            with global_state.lock:
                inv = global_state.invoices.get(inv_id)
                if not inv:
                    self._send_json(404, {"error": "Invoice not found"})
                    return
                # VULNERABILITY: Mutates invoice without verifying owner
                inv.update(data)
                inv["updated"] = True
            self._send_json(200, inv)
            return

        self._send_json(404, {"error": "Not Found", "path": path})


def run_mock_server(host: str = "127.0.0.1", port: int = 0) -> tuple[ThreadingHTTPServer, str]:
    """Boot the mock target server on a background thread and return (server, base_url)."""
    global_state.reset()
    server = ThreadingHTTPServer((host, port), MockTargetHandler)
    assigned_port = server.server_address[1]
    base_url = f"http://{host}:{assigned_port}"
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, base_url


@contextmanager
def MockTargetServer(
    host: str = "127.0.0.1", port: int = 0
) -> Generator[tuple[ThreadingHTTPServer, str], None, None]:
    """Context manager for running MockTargetServer during integration tests."""
    server, base_url = run_mock_server(host=host, port=port)
    try:
        yield server, base_url
    finally:
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8000
    server, url = run_mock_server(host="127.0.0.1", port=port)
    print(f"Halo Mock Target Server running at {url}")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        server.shutdown()
        print("\nMock server stopped.")
