"""Unit tests for DAST core modules: SandboxManager, SessionVault, CSRFHarvester, and PayloadSynthesizer."""

import json
from pathlib import Path

import httpx
import pytest

from halo.dast.csrf import CSRFHarvester
from halo.dast.sandbox import SafeModeViolationError, SandboxManager
from halo.dast.synthesizer import PayloadSynthesizer
from halo.dast.vault import IdentityPersona, PersonaType, SessionVault
from halo.llm.provider import MockLLMProvider
from halo.static.graph import ValidationSchemaNode


def test_csrf_token_harvesting():
    harvester = CSRFHarvester()
    headers = httpx.Headers({"set-cookie": "XSRF-TOKEN=secret_csrf_val; Path=/"})
    token = harvester.extract_from_headers(headers)
    assert token == "secret_csrf_val"
    req_headers = {}
    harvester.inject_csrf(req_headers, token)
    assert req_headers["X-CSRF-Token"] == "secret_csrf_val"


def test_csrf_harvesting_from_html_meta_and_body():
    harvester = CSRFHarvester()

    # Meta tag with csrf-token
    html_meta = '<html><head><meta name="csrf-token" content="meta_token_123"></head></html>'
    token = harvester.extract_from_html(html_meta)
    assert token == "meta_token_123"

    # Meta tag with _csrf
    html_csrf = '<html><head><meta name="_csrf" content="meta_token_456"></head></html>'
    assert harvester.extract_from_html(html_csrf) == "meta_token_456"

    # Hidden form input
    html_input = '<form><input type="hidden" name="_csrf" value="input_token_789" /></form>'
    assert harvester.extract_from_html(html_input) == "input_token_789"

    # Response with meta tag and header injection
    resp = httpx.Response(200, headers={"content-type": "text/html"}, text=html_meta)
    extracted = harvester.extract_token(resp)
    assert extracted == "meta_token_123"

    target_headers = {}
    harvester.inject_headers(target_headers, extracted)
    assert target_headers["X-CSRF-Token"] == "meta_token_123"


def test_payload_synthesizer():
    mock_llm = MockLLMProvider(default_response='{"amount": 100, "currency": "USD"}')
    synth = PayloadSynthesizer(mock_llm)
    payload = synth.generate_payload(schema_info={"fields": ["amount", "currency"]})
    assert payload["amount"] == 100


def test_payload_synthesizer_with_markdown_fences():
    mock_llm = MockLLMProvider(
        default_response='```json\n{"name": "test_item", "price": 49.99, "is_active": true}\n```'
    )
    synth = PayloadSynthesizer(mock_llm)
    payload = synth.generate_payload(schema_info={"fields": ["name", "price", "is_active"]})
    assert payload["name"] == "test_item"
    assert payload["price"] == 49.99
    assert payload["is_active"] is True


def test_payload_synthesizer_deterministic_fallback():
    # No LLM provider -> deterministic generator
    synth = PayloadSynthesizer(llm_provider=None)
    schema_node = ValidationSchemaNode(
        id="schema_1",
        name="CreateUserSchema",
        schema_type="zod",
        allowed_fields=["id", "email", "amount", "currency", "status", "is_admin"],
    )
    payload = synth.synthesize_payload(schema_node)
    assert "@" in payload["email"]
    assert isinstance(payload["amount"], (int, float))
    assert payload["currency"] == "USD"
    assert payload["is_admin"] is True
    assert len(payload["id"]) >= 8


def test_session_vault_persona_management():
    vault = SessionVault()
    vault.set_token(PersonaType.USER_A, "token_user_a")
    vault.set_token(PersonaType.USER_B, "token_user_b")
    vault.set_token(PersonaType.ADMIN, "token_admin")

    persona_a = vault.get_persona(PersonaType.USER_A)
    assert isinstance(persona_a, IdentityPersona)
    assert persona_a.token == "token_user_a"
    assert persona_a.username == "halo_user_a"
    assert "Authorization" in persona_a.headers
    assert persona_a.headers["Authorization"] == "Bearer token_user_a"

    client_b = vault.get_session(PersonaType.USER_B)
    assert isinstance(client_b, httpx.Client)
    assert client_b.headers["Authorization"] == "Bearer token_user_b"


def test_session_vault_automated_registration_hierarchy():
    # Mock transport supporting /api/register
    registered_users = {}

    def handler(request: httpx.Request):
        if request.method == "POST" and request.url.path in ("/register", "/api/register"):
            body = json.loads(request.content)
            username = body.get("username")
            registered_users[username] = body
            return httpx.Response(201, json={"token": f"token_for_{username}", "status": "created"})
        return httpx.Response(404)

    client = httpx.Client(transport=httpx.MockTransport(handler), base_url="http://testapp")
    vault = SessionVault()
    personas = vault.provision_personas(target_url="http://testapp", client=client)

    assert personas[PersonaType.USER_A].token == "token_for_halo_user_a"
    assert personas[PersonaType.USER_B].token == "token_for_halo_user_b"
    assert "halo_user_a" in registered_users
    assert "halo_user_b" in registered_users


def test_session_vault_seed_file_fallback(tmp_path: Path):
    seed_file = tmp_path / "seeds.sql"
    seed_file.write_text(
        "INSERT INTO users (username, email, password_hash, role) VALUES "
        "('seed_admin', 'admin@halo.test', 'hash123', 'admin'), "
        "('seed_user_a', 'user_a@halo.test', 'hash456', 'user'), "
        "('seed_user_b', 'user_b@halo.test', 'hash789', 'user');"
    )

    vault = SessionVault()
    # Mock registration failure to trigger seed fallback
    def failing_handler(request: httpx.Request):
        return httpx.Response(404)

    client = httpx.Client(transport=httpx.MockTransport(failing_handler), base_url="http://testapp")
    personas = vault.provision_personas(target_url="http://testapp", seed_data=seed_file, client=client)

    assert personas[PersonaType.USER_A].username == "seed_user_a"
    assert personas[PersonaType.USER_B].username == "seed_user_b"
    assert personas[PersonaType.ADMIN].username == "seed_admin"


def test_session_vault_heartbeat_and_refresh():
    call_counts = {"me": 0, "login": 0}

    def handler(request: httpx.Request):
        auth = request.headers.get("Authorization", "")
        if request.url.path == "/api/me":
            call_counts["me"] += 1
            if auth == "Bearer expired_token":
                return httpx.Response(401, json={"error": "token_expired"})
            return httpx.Response(200, json={"user": "halo_user_a"})
        elif request.url.path == "/api/login":
            call_counts["login"] += 1
            return httpx.Response(200, json={"token": "refreshed_token_123"})
        return httpx.Response(404)

    client = httpx.Client(transport=httpx.MockTransport(handler), base_url="http://testapp")
    vault = SessionVault()
    vault.set_token(PersonaType.USER_A, "expired_token")

    # Heartbeat detects 401 and refreshes token via login
    refreshed = vault.send_heartbeat(
        persona=PersonaType.USER_A,
        target_url="http://testapp",
        client=client,
        ping_endpoint="/api/me",
        login_endpoint="/api/login",
    )
    assert refreshed is True
    assert vault.get_persona(PersonaType.USER_A).token == "refreshed_token_123"


def test_sandbox_manager_readiness_polling(monkeypatch):
    mgr = SandboxManager()

    # Simulate readiness returning 200 after 2 attempts
    attempts = [0]

    def mock_check(url: str, readiness_path: str = "/health") -> bool:
        attempts[0] += 1
        return attempts[0] >= 2

    monkeypatch.setattr(mgr, "_check_endpoint", mock_check)
    ready = mgr.wait_for_readiness("http://localhost:8080", timeout=2.0, poll_interval=0.01)
    assert ready is True
    assert attempts[0] >= 2


def test_sandbox_manager_safe_mode_guardrails():
    mgr = SandboxManager(safe_mode=True)

    # Local target is allowed
    assert mgr.is_remote_target("http://localhost:3000") is False
    assert mgr.is_remote_target("http://127.0.0.1:8080") is False
    assert mgr.is_remote_target("http://api.production.internal") is True

    # Remote target with safe mode
    remote_url = "https://api.example.com"

    # GET is safe (read-only)
    allowed, _ = mgr.check_safe_mode_guardrails(remote_url, method="GET", path="/users/123")
    assert allowed is True

    # Synthetic identity mutating synthetic entity is allowed
    allowed, _ = mgr.check_safe_mode_guardrails(
        remote_url,
        method="POST",
        path="/invoices",
        identity="halo_user_a",
        resource_owner="halo_user_a",
    )
    assert allowed is True

    # Foreign identity or non-synthetic user mutating remote entity is blocked
    allowed, reason = mgr.check_safe_mode_guardrails(
        remote_url,
        method="DELETE",
        path="/invoices/foreign_inv_999",
        identity="admin_real",
        resource_owner="victim_real_user",
    )
    assert allowed is False
    assert "destructive" in reason.lower() or "safe mode" in reason.lower()

    with pytest.raises(SafeModeViolationError):
        mgr.enforce_safe_mode(
            remote_url,
            method="DELETE",
            path="/users/1",
            identity="unauthorized_actor",
            resource_owner="victim_user",
        )


def test_csrf_harvester_edge_cases():
    harvester = CSRFHarvester()

    # Empty / none cases
    assert harvester.extract_from_headers({}) is None
    assert harvester.extract_from_html("") is None

    headers = {"Authorization": "Bearer token"}
    harvester.inject_csrf(headers, token=None)
    assert "X-CSRF-Token" not in headers

    # Custom header name
    harvester.inject_csrf(headers, token="my_token", header_name="X-XSRF-Header")
    assert headers["X-XSRF-Header"] == "my_token"


def test_payload_synthesizer_llm_failure_and_partial_response():
    # LLM returns invalid JSON -> graceful fallback
    bad_llm = MockLLMProvider(default_response="I am sorry, I cannot generate JSON for you.")
    synth = PayloadSynthesizer(bad_llm)
    payload = synth.generate_payload(schema_info={"fields": ["email", "amount"]})
    assert "@" in payload["email"]
    assert payload["amount"] == 100

    # LLM returns partial fields -> missing fields filled by fallback
    partial_llm = MockLLMProvider(default_response='{"amount": 50}')
    synth2 = PayloadSynthesizer(partial_llm)
    payload2 = synth2.generate_payload(schema_info={"fields": ["amount", "currency", "id"]})
    assert payload2["amount"] == 50
    assert payload2["currency"] == "USD"
    assert len(payload2["id"]) >= 8


def test_payload_synthesizer_field_heuristics():
    synth = PayloadSynthesizer()
    assert "@" in synth.generate_field_value("contact_email")
    assert synth.generate_field_value("invoice_amount") == 100
    assert synth.generate_field_value("item_quantity") == 10
    assert synth.generate_field_value("is_verified") is True
    assert synth.generate_field_value("order_status") == "active"
    assert synth.generate_field_value("user_role") == "user"
    assert "https://" in synth.generate_field_value("callback_url")
    assert synth.generate_field_value("phone_number") == "+15551234567"
    assert "T" in synth.generate_field_value("created_at")


def test_session_vault_record_request_heartbeat(monkeypatch):
    vault = SessionVault()
    heartbeat_calls = []

    def mock_heartbeat(persona, target_url=None, client=None):
        heartbeat_calls.append(persona)
        return True

    monkeypatch.setattr(vault, "send_heartbeat", mock_heartbeat)

    for _ in range(9):
        vault.record_request(PersonaType.USER_A)
    assert len(heartbeat_calls) == 0

    # 10th request triggers heartbeat
    vault.record_request(PersonaType.USER_A)
    assert len(heartbeat_calls) == 1
    assert heartbeat_calls[0] == PersonaType.USER_A


def test_session_vault_json_seed_parsing():
    vault = SessionVault()
    seed_json = json.dumps([
        {"username": "json_admin", "email": "admin@json.test", "role": "admin"},
        {"username": "json_user1", "email": "user1@json.test", "role": "user"},
        {"username": "json_user2", "email": "user2@json.test", "role": "user"},
    ])
    vault._parse_and_apply_seeds(seed_json)
    assert vault.get_persona(PersonaType.ADMIN).username == "json_admin"
    assert vault.get_persona(PersonaType.USER_A).username == "json_user1"
    assert vault.get_persona(PersonaType.USER_B).username == "json_user2"


def test_session_vault_persona_type_parsing():
    assert PersonaType.from_str("user_a") == PersonaType.USER_A
    assert PersonaType.from_str("attacker") == PersonaType.USER_A
    assert PersonaType.from_str("victim") == PersonaType.USER_B
    assert PersonaType.from_str("admin") == PersonaType.ADMIN
    with pytest.raises(ValueError):
        PersonaType.from_str("unknown_role")


def test_sandbox_manager_lifecycle_and_disabled_safe_mode():
    # Safe mode disabled
    mgr = SandboxManager(safe_mode=False)
    allowed, reason = mgr.check_safe_mode_guardrails("https://remote.api", method="DELETE")
    assert allowed is True
    assert "disabled" in reason.lower()

    # Lifecycle status
    assert mgr.status == "idle"
    assert mgr.is_running is False
    assert mgr.stop() is True


def test_session_vault_reauthentication_syncs_client_headers():
    def handler(request: httpx.Request):
        auth = request.headers.get("Authorization", "")
        if request.url.path == "/api/me":
            if auth == "Bearer expired_tok":
                return httpx.Response(401)
            return httpx.Response(200)
        elif request.url.path == "/api/login":
            return httpx.Response(200, json={"token": "fresh_tok_999"})
        return httpx.Response(404)

    client = httpx.Client(transport=httpx.MockTransport(handler), base_url="http://testapp")
    vault = SessionVault()
    vault.set_token(PersonaType.USER_A, "expired_tok")
    cached_client = vault.get_session(PersonaType.USER_A)
    assert cached_client.headers["Authorization"] == "Bearer expired_tok"

    refreshed = vault.send_heartbeat(
        persona=PersonaType.USER_A,
        client=client,
        ping_endpoint="/api/me",
        login_endpoint="/api/login",
    )
    assert refreshed is True
    assert client.headers["Authorization"] == "Bearer fresh_tok_999"
    assert cached_client.headers["Authorization"] == "Bearer fresh_tok_999"


def test_sandbox_readiness_probe_fallback_on_5xx(monkeypatch):
    mgr = SandboxManager()

    def mock_get(url: str, timeout: float = 2.0):
        if url.endswith("/health"):
            return httpx.Response(500)
        return httpx.Response(200)

    monkeypatch.setattr(httpx, "get", mock_get)
    assert mgr._check_endpoint("http://localhost:8000", readiness_path="/health") is True


def test_csrf_harvester_plain_dict_case_insensitivity():
    harvester = CSRFHarvester()

    # Title-case Set-Cookie
    headers_title = {"Set-Cookie": "XSRF-TOKEN=title_csrf_val; Path=/"}
    assert harvester.extract_from_headers(headers_title) == "title_csrf_val"

    # Uppercase SET-COOKIE
    headers_upper = {"SET-COOKIE": "csrf_token=upper_csrf_val; Path=/"}
    assert harvester.extract_from_headers(headers_upper) == "upper_csrf_val"

    # List of cookies in plain dict
    headers_list = {"set-cookie": ["session=123", "XSRF-TOKEN=list_csrf_val; Path=/"]}
    assert harvester.extract_from_headers(headers_list) == "list_csrf_val"


