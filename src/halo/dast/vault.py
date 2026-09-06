"""Multi-identity session vault with automated registration, seed parsing, and session heartbeat."""

from __future__ import annotations

import json
import logging
import os
import re
from enum import Enum
from pathlib import Path
from typing import Any

import httpx
from pydantic import BaseModel, ConfigDict, Field

from halo.dast.csrf import CSRFHarvester

logger = logging.getLogger(__name__)


class PersonaType(str, Enum):
    """Supported test persona identities."""

    USER_A = "USER_A"
    USER_B = "USER_B"
    ADMIN = "ADMIN"

    @classmethod
    def from_str(cls, value: str | PersonaType) -> PersonaType:
        if isinstance(value, cls):
            return value
        val_str = str(value).strip().upper()
        if val_str in ("USER_A", "A", "ATTACKER", "HALO_USER_A"):
            return cls.USER_A
        if val_str in ("USER_B", "B", "VICTIM", "HALO_USER_B"):
            return cls.USER_B
        if val_str in ("ADMIN", "ADMINISTRATOR", "HALO_ADMIN"):
            return cls.ADMIN
        for member in cls:
            if member.value == val_str:
                return member
        raise ValueError(f"Unknown PersonaType: {value}")


class IdentityPersona(BaseModel):
    """Represents an authenticated or synthetic test identity with active credentials."""

    model_config = ConfigDict(extra="allow")

    persona_type: PersonaType
    username: str
    email: str
    password: str
    token: str | None = None
    headers: dict[str, str] = Field(default_factory=dict)
    cookies: dict[str, str] = Field(default_factory=dict)

    def set_token(self, token: str, token_type: str = "Bearer") -> None:
        """Assign authentication token and configure Authorization header."""
        self.token = token
        auth_val = f"{token_type} {token}".strip() if token_type else token
        self.headers["Authorization"] = auth_val


class SessionVault:
    """Manages multi-persona authentication, auto-registration hierarchy, and session heartbeat."""

    def __init__(self) -> None:
        self.personas: dict[PersonaType, IdentityPersona] = {
            PersonaType.USER_A: IdentityPersona(
                persona_type=PersonaType.USER_A,
                username="halo_user_a",
                email="halo_user_a@example.com",
                password="HaloUserA_123!",
            ),
            PersonaType.USER_B: IdentityPersona(
                persona_type=PersonaType.USER_B,
                username="halo_user_b",
                email="halo_user_b@example.com",
                password="HaloUserB_123!",
            ),
            PersonaType.ADMIN: IdentityPersona(
                persona_type=PersonaType.ADMIN,
                username="halo_admin",
                email="halo_admin@example.com",
                password="HaloAdmin_123!",
            ),
        }
        self.request_counts: dict[PersonaType, int] = {
            p: 0 for p in PersonaType
        }
        self._clients: dict[PersonaType, httpx.Client] = {}

    def get_persona(self, persona: PersonaType | str) -> IdentityPersona:
        """Retrieve the identity persona object."""
        ptype = PersonaType.from_str(persona)
        return self.personas[ptype]

    def set_token(
        self,
        persona: PersonaType | str,
        token: str,
        token_type: str = "Bearer",
    ) -> None:
        """Manually configure an authorization token for a persona."""
        ptype = PersonaType.from_str(persona)
        self.personas[ptype].set_token(token, token_type)
        if ptype in self._clients:
            self._clients[ptype].headers.update(self.personas[ptype].headers)

    def set_credentials(
        self,
        persona: PersonaType | str,
        username: str | None = None,
        password: str | None = None,
        email: str | None = None,
    ) -> None:
        """Update persona credentials."""
        p = self.get_persona(persona)
        if username:
            p.username = username
        if password:
            p.password = password
        if email:
            p.email = email

    def get_headers(self, persona: PersonaType | str) -> dict[str, str]:
        """Get copy of active headers for persona."""
        return dict(self.get_persona(persona).headers)

    def get_session(
        self,
        persona: PersonaType | str,
        base_url: str = "",
    ) -> httpx.Client:
        """Obtain an HTTP client configured with persona credentials, headers, and cookies."""
        ptype = PersonaType.from_str(persona)
        p = self.personas[ptype]

        client = httpx.Client(
            base_url=base_url,
            headers=dict(p.headers),
            cookies=dict(p.cookies),
            timeout=15.0,
        )
        self._clients[ptype] = client
        return client

    def provision_personas(
        self,
        target_url: str,
        seed_data: str | Path | dict[str, Any] | None = None,
        client: httpx.Client | None = None,
        repo_path: str | Path | None = None,
    ) -> dict[PersonaType, IdentityPersona]:
        """Provisions personas using registration hierarchy: /register -> seed files -> manual fallback."""
        http_client = client or httpx.Client(base_url=target_url, timeout=10.0)

        # Hierarchy Step 1: Automated Registration
        reg_success = self._attempt_auto_registration(http_client)

        # Hierarchy Step 2: Seed file parsing fallback if registration not fully successful
        target_seed = seed_data
        if target_seed is None and repo_path is not None:
            rpath = Path(repo_path)
            for candidate_rel in (
                "prisma/seed.ts",
                "seed.ts",
                "seeds/seed.ts",
                "prisma/seed.js",
                "seed.json",
                "seeds.sql",
            ):
                cand = rpath / candidate_rel
                if cand.is_file():
                    target_seed = cand
                    break

        if not reg_success and target_seed is not None:
            self._parse_and_apply_seeds(target_seed, http_client)

        return self.personas

    def _attempt_auto_registration(self, client: httpx.Client) -> bool:
        """Attempt to register User_A and User_B against registration endpoints."""
        endpoints = [
            "/register",
            "/api/register",
            "/api/v1/register",
            "/signup",
            "/api/signup",
            "/api/v1/signup",
            "/auth/register",
            "/api/Users",
            "/api/Users/",
        ]

        login_endpoints = [
            "/login",
            "/api/login",
            "/api/v1/login",
            "/rest/user/login",
            "/auth/login",
        ]

        success_count = 0
        personas_to_register = [self.personas[PersonaType.USER_A], self.personas[PersonaType.USER_B]]

        for persona in personas_to_register:
            registered = False
            for endpoint in endpoints:
                payload = {
                    "username": persona.username,
                    "email": persona.email,
                    "password": persona.password,
                    "name": persona.username,
                }
                try:
                    resp = client.post(endpoint, json=payload)
                    ct = resp.headers.get("content-type", "").lower()
                    is_json = "json" in ct
                    if resp.status_code in (200, 201) and is_json:
                        token = self._extract_token_from_response(resp)
                        if token:
                            persona.set_token(token)
                        if hasattr(resp, "cookies"):
                            for k, v in resp.cookies.items():
                                persona.cookies[k] = v
                        registered = True
                        break
                    elif resp.status_code in (400, 409) and is_json:
                        registered = True
                        break
                except httpx.HTTPError as err:
                    logger.debug("Registration probe error on %s: %s", endpoint, err)

            # If registered or existing, authenticate via login endpoints if token not yet set
            if not persona.token:
                for log_ep in login_endpoints:
                    try:
                        login_payload = {
                            "email": persona.email,
                            "username": persona.username,
                            "password": persona.password,
                        }
                        resp_log = client.post(log_ep, json=login_payload)
                        ct_log = resp_log.headers.get("content-type", "").lower()
                        if resp_log.status_code in (200, 201) and "json" in ct_log:
                            token = self._extract_token_from_response(resp_log)
                            if token:
                                persona.set_token(token)
                            if hasattr(resp_log, "cookies"):
                                for k, v in resp_log.cookies.items():
                                    persona.cookies[k] = v
                            registered = True
                            break
                    except httpx.HTTPError:
                        pass

            if registered:
                success_count += 1

        # Check / provision Admin persona if unauthenticated
        admin_persona = self.personas[PersonaType.ADMIN]
        if not admin_persona.token:
            env_admin = os.getenv("HALO_ADMIN_CREDS") or os.getenv("HALO_AUTH_CREDS")
            admin_candidates = []
            if env_admin and ":" in env_admin:
                u, p = env_admin.split(":", 1)
                admin_candidates.append((u.strip(), p.strip()))
            admin_candidates.extend([
                ("admin", "admin"),
                ("admin", "admin123"),
                ("admin@example.com", "admin123"),
                ("admin@example.com", "Admin123!"),
                ("administrator", "administrator"),
                (admin_persona.email, admin_persona.password),
            ])
            for email_cand, pass_cand in admin_candidates:
                for log_ep in login_endpoints:
                    try:
                        resp_admin = client.post(
                            log_ep,
                            json={"email": email_cand, "password": pass_cand},
                        )
                        ct_admin = resp_admin.headers.get("content-type", "").lower()
                        if resp_admin.status_code in (200, 201) and "json" in ct_admin:
                            token = self._extract_token_from_response(resp_admin)
                            if token:
                                admin_persona.set_token(token)
                                admin_persona.email = email_cand
                                admin_persona.password = pass_cand
                                break
                    except httpx.HTTPError:
                        pass
                if admin_persona.token:
                    break

        return success_count >= 2

    def _extract_token_from_response(self, response: httpx.Response) -> str | None:
        """Extract bearer/JWT token from response body or headers."""
        try:
            data = response.json()
            if isinstance(data, dict):
                for key in ("token", "access_token", "jwt", "id_token", "session_token"):
                    if key in data and isinstance(data[key], str):
                        return data[key]
                # Check nested data or authentication object
                for container_key in ("data", "authentication"):
                    if container_key in data and isinstance(data[container_key], dict):
                        for key in ("token", "access_token", "jwt", "id_token", "session_token"):
                            if key in data[container_key] and isinstance(data[container_key][key], str):
                                return data[container_key][key]
        except (json.JSONDecodeError, ValueError, KeyError):
            logger.debug("Could not parse JSON token from response")

        # Check Authorization header in response
        auth_header = response.headers.get("authorization", "")
        if auth_header.lower().startswith("bearer "):
            return auth_header[7:].strip()

        return None

    def _parse_and_apply_seeds(
        self,
        seed_data: str | Path | dict[str, Any],
        client: httpx.Client | None = None,
    ) -> None:
        """Extract credentials from SQL, TypeScript, JSON seed files and configure personas."""
        content = ""
        if isinstance(seed_data, Path) or (isinstance(seed_data, str) and "\n" not in seed_data and Path(seed_data).is_file()):
            try:
                content = Path(seed_data).read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError) as err:
                logger.warning("Could not read seed file %s: %s", seed_data, err)
                return
        elif isinstance(seed_data, str):
            content = seed_data
        elif isinstance(seed_data, dict):
            content = json.dumps(seed_data)

        parsed_creds: list[dict[str, str]] = []

        # 1. SQL Seed parsing: INSERT INTO users ... VALUES (...)
        sql_rows = re.findall(
            r"""\((?:[^()]*?['"][a-zA-Z0-9_\-\.]+['"][^()]*?)+\)""", content
        )
        for row in sql_rows:
            # Extract quoted strings
            tokens = re.findall(r"""['"]([^'"]+)['"]""", row)
            if len(tokens) >= 2:
                cred = {"username": "", "email": "", "role": "user"}
                for t in tokens:
                    if "@" in t:
                        cred["email"] = t
                    elif t.lower() in ("admin", "administrator"):
                        cred["role"] = "admin"
                    elif not cred["username"] and len(t) >= 3 and not t.startswith("hash"):
                        cred["username"] = t
                if cred["username"] or cred["email"]:
                    parsed_creds.append(cred)

        # 2. JSON / TS parsing: "username": "admin", "email": ...
        if not parsed_creds:
            json_matches = re.finditer(
                r"""\{[^{}]*?(?:username|email)['"]?\s*:\s*['"]([^'"]+)['"][^{}]*?\}""",
                content,
            )
            for m in json_matches:
                block = m.group(0)
                u_m = re.search(r"""(?:username|user)['"]?\s*:\s*['"]([^'"]+)['"]""", block)
                e_m = re.search(r"""(?:email)['"]?\s*:\s*['"]([^'"]+)['"]""", block)
                r_m = re.search(r"""(?:role)['"]?\s*:\s*['"]([^'"]+)['"]""", block)
                cred = {
                    "username": u_m.group(1) if u_m else "",
                    "email": e_m.group(1) if e_m else "",
                    "role": r_m.group(1) if r_m else "user",
                }
                if cred["username"] or cred["email"]:
                    parsed_creds.append(cred)

        # Assign parsed credentials to personas
        admins = [c for c in parsed_creds if c.get("role") == "admin"]
        standard_users = [c for c in parsed_creds if c.get("role") != "admin"]

        if admins:
            self.set_credentials(
                PersonaType.ADMIN,
                username=admins[0].get("username") or "admin",
                email=admins[0].get("email") or "admin@test.local",
            )
        if len(standard_users) >= 1:
            self.set_credentials(
                PersonaType.USER_A,
                username=standard_users[0].get("username") or "user_a",
                email=standard_users[0].get("email") or "user_a@test.local",
            )
        if len(standard_users) >= 2:
            self.set_credentials(
                PersonaType.USER_B,
                username=standard_users[1].get("username") or "user_b",
                email=standard_users[1].get("email") or "user_b@test.local",
            )

    def record_request(
        self,
        persona: PersonaType | str,
        client: httpx.Client | None = None,
        target_url: str = "",
    ) -> bool:
        """Increment request count and trigger periodic session heartbeat every 10 requests."""
        ptype = PersonaType.from_str(persona)
        self.request_counts[ptype] += 1
        if self.request_counts[ptype] % 10 == 0:
            return self.send_heartbeat(ptype, target_url=target_url, client=client)
        return True

    def record_response(self, persona: PersonaType | str, response: httpx.Response) -> None:
        """Record response cookies, auth headers, and harvest anti-CSRF tokens."""
        ptype = PersonaType.from_str(persona)
        harvester = CSRFHarvester()
        csrf_token = harvester.extract_token(response)
        p = self.personas[ptype]
        for k, v in response.cookies.items():
            p.cookies[k] = v
        if csrf_token:
            p.headers["X-XSRF-TOKEN"] = csrf_token
            p.headers["X-CSRF-TOKEN"] = csrf_token

    def send_heartbeat(
        self,
        persona: PersonaType | str,
        target_url: str | None = None,
        client: httpx.Client | None = None,
        ping_endpoint: str = "/api/me",
        login_endpoint: str = "/api/login",
    ) -> bool:
        """Send lightweight ping; automatically refresh/re-authenticate if token expired (401)."""
        ptype = PersonaType.from_str(persona)
        p = self.personas[ptype]
        http_client = client or self._clients.get(ptype) or httpx.Client(base_url=target_url or "", timeout=5.0)

        # 1. Send lightweight ping
        headers = dict(p.headers)
        try:
            resp = http_client.get(ping_endpoint, headers=headers)
            if resp.status_code == 200:
                return True

            if resp.status_code in (401, 403):
                # Token expired or invalid, attempt re-authentication
                logger.info("Session expired for %s (status %d). Attempting re-authentication.", ptype, resp.status_code)
                return self._reauthenticate(p, http_client, login_endpoint)
        except httpx.HTTPError as err:
            logger.debug("Heartbeat ping failed for %s: %s", ptype, err)

        return False

    def _reauthenticate(
        self,
        persona: IdentityPersona,
        client: httpx.Client,
        login_endpoint: str = "/api/login",
    ) -> bool:
        """Attempt to re-authenticate persona via login endpoint."""
        payload = {
            "username": persona.username,
            "password": persona.password,
            "email": persona.email,
        }
        try:
            resp = client.post(login_endpoint, json=payload)
            if resp.status_code in (200, 201):
                token = self._extract_token_from_response(resp)
                if token:
                    persona.set_token(token)
                    if hasattr(client, "headers"):
                        client.headers.update(persona.headers)
                    if persona.persona_type in self._clients:
                        self._clients[persona.persona_type].headers.update(persona.headers)
                    return True
        except httpx.HTTPError as err:
            logger.warning("Re-authentication failed for %s: %s", persona.persona_type, err)

        return False
