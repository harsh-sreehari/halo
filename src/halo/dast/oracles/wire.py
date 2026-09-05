"""Layer 1 Deterministic Wire Oracle for token leakage and state mutation verification."""

from __future__ import annotations

import json
import logging
from typing import Any, Self

logger = logging.getLogger(__name__)

DEFAULT_PUBLIC_FIELDS: frozenset[str] = frozenset(
    {
        "username",
        "user_name",
        "avatar",
        "avatar_url",
        "id",
        "_id",
        "created_at",
        "updated_at",
        "timestamp",
        "display_name",
        "displayname",
        "name",
        "public_name",
        "first_name",
        "last_name",
        "slug",
        "type",
        "__typename",
    }
)

DEFAULT_SENSITIVE_PATTERNS: frozenset[str] = frozenset(
    {
        "password",
        "password_hash",
        "email",
        "ssn",
        "billing_address",
        "billing",
        "api_key",
        "apikey",
        "secret",
        "secret_key",
        "token",
        "private_token",
        "phone",
        "phone_number",
        "credit_card",
        "card_number",
        "cvv",
        "auth_token",
        "access_token",
        "refresh_token",
        "bearer_token",
        "private_key",
    }
)

DEFAULT_TRANSIENT_FIELDS: frozenset[str] = frozenset(
    {
        "updated_at",
        "updatedat",
        "last_updated",
        "timestamp",
        "created_at",
        "createdat",
        "etag",
        "_etag",
        "request_id",
        "requestid",
        "trace_id",
        "traceid",
        "client_ip",
        "access_time",
    }
)


class StateMutationResult(tuple):
    """Result of state mutation verification.

    Functions as a 2-tuple (mutated, modified_fields), with boolean evaluation
    and property accessors for ergonomic consumption.
    """

    def __new__(cls, mutated: bool, modified_fields: list[str]) -> Self:
        return super().__new__(cls, (mutated, list(modified_fields)))

    @property
    def mutated(self) -> bool:
        return self[0]

    @property
    def modified_fields(self) -> list[str]:
        return self[1]

    def __bool__(self) -> bool:
        return bool(self[0])

    def __eq__(self, other: object) -> bool:
        if isinstance(other, bool):
            return self[0] == other
        return super().__eq__(other)


def _flatten_leaves(obj: Any, prefix: str = "") -> list[tuple[str, str, Any]]:
    """Recursively extracts (full_path, leaf_key, value) from nested dicts and lists."""
    results: list[tuple[str, str, Any]] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            path = f"{prefix}.{k}" if prefix else str(k)
            if isinstance(v, (dict, list)):
                results.extend(_flatten_leaves(v, path))
            else:
                results.append((path, str(k), v))
    elif isinstance(obj, list):
        for idx, item in enumerate(obj):
            path = f"{prefix}[{idx}]"
            if isinstance(item, (dict, list)):
                results.extend(_flatten_leaves(item, path))
            else:
                results.append((path, str(idx), item))
    return results


class WireOracle:
    """Layer 1 Deterministic Wire Oracle.

    Verifies security invariants using deterministic wire-level observables:
    1. Sensitive Token Leakage: Detects unauthorized exposure of private victim tokens
       while strictly excluding public profile fields.
    2. State Mutation Read-Back: Verifies whether an unauthorized state change persisted
       by comparing baseline and post-attack state reads.
    """

    def __init__(
        self,
        excluded_fields: set[str] | None = None,
        sensitive_patterns: set[str] | None = None,
        transient_fields: set[str] | None = None,
    ) -> None:
        self.excluded_fields = (
            {f.lower() for f in excluded_fields}
            if excluded_fields is not None
            else set(DEFAULT_PUBLIC_FIELDS)
        )
        self.sensitive_patterns = (
            {p.lower() for p in sensitive_patterns}
            if sensitive_patterns is not None
            else set(DEFAULT_SENSITIVE_PATTERNS)
        )
        self.transient_fields = (
            {t.lower() for t in transient_fields}
            if transient_fields is not None
            else set(DEFAULT_TRANSIENT_FIELDS)
        )

    def _is_public_field(self, field_name: str) -> bool:
        name = field_name.lower().strip()
        if name in self.excluded_fields:
            return True
        # Only split on dot path notation, never on underscores
        last_seg = name.split(".")[-1].strip()
        return last_seg in self.excluded_fields

    def _is_transient_field(self, field_name: str) -> bool:
        name = field_name.lower().strip()
        if name in self.transient_fields:
            return True
        last_seg = name.split(".")[-1].strip()
        return last_seg in self.transient_fields

    def check_token_leakage(
        self,
        victim_sensitive_data: dict[str, Any],
        attacker_response_body: dict[str, Any] | list[Any] | str,
    ) -> tuple[bool, list[str]]:
        """Checks if private victim fields appear in attacker response.

        Public profile fields (username, avatar, id, created_at, display_name) are
        strictly excluded. Returns (is_leaked, leaked_tokens).
        """
        leaked_tokens: list[str] = []
        victim_leaves = _flatten_leaves(victim_sensitive_data)

        # Distinguish structured JSON from unparseable raw text/HTML
        attacker_dict: dict[str, Any] | None = None
        raw_text_only: str | None = None

        if isinstance(attacker_response_body, dict):
            attacker_dict = attacker_response_body
        elif isinstance(attacker_response_body, (list, tuple)):
            attacker_dict = {"_items": list(attacker_response_body)}
        elif isinstance(attacker_response_body, str):
            try:
                parsed = json.loads(attacker_response_body)
                if isinstance(parsed, dict):
                    attacker_dict = parsed
                elif isinstance(parsed, list):
                    attacker_dict = {"_items": parsed}
                else:
                    raw_text_only = attacker_response_body
            except (json.JSONDecodeError, ValueError):
                raw_text_only = attacker_response_body

        for _path, leaf_key, val in victim_leaves:
            # Exclude public fields
            if self._is_public_field(leaf_key):
                continue

            # Ignore empty or trivial values, but preserve numeric 0
            if (
                val is None
                or val == ""
                or (isinstance(val, bool) and not val)
                or val == []
                or val == {}
            ):
                continue

            str_val = str(val)
            val_leaked = False

            # Check structured attacker leaves when JSON parsed successfully
            if attacker_dict is not None:
                attacker_leaves = _flatten_leaves(attacker_dict)
                for _att_path, att_key, att_val in attacker_leaves:
                    # Skip matching within public profile fields
                    if self._is_public_field(att_key):
                        continue
                    if att_val == val:
                        val_leaked = True
                        break
                    if isinstance(att_val, str) and len(str_val) >= 3 and str_val in att_val:
                        val_leaked = True
                        break
            # Only run raw string search when response is unparseable text/HTML
            elif raw_text_only is not None and len(str_val) >= 3 and str_val in raw_text_only:
                val_leaked = True

            if val_leaked and leaf_key not in leaked_tokens:
                leaked_tokens.append(leaf_key)

        return (len(leaked_tokens) > 0, leaked_tokens)

    def check_state_mutation(
        self,
        baseline_read: dict[str, Any],
        attacker_mutation_res: dict[str, Any],
        victim_verify_read: dict[str, Any],
    ) -> StateMutationResult:
        """Confirms User_A's unauthorized mutation is verified in a subsequent User_B read.

        Compares field modifications against baseline, filtering transient fields and
        verifying against attacker mutation response. Returns StateMutationResult.
        """
        # 1. Check if attacker mutation explicitly failed or was rejected on the wire
        if isinstance(attacker_mutation_res, dict):
            status = attacker_mutation_res.get("status")
            if isinstance(status, int) and (status >= 400 or status < 200):
                return StateMutationResult(False, [])
            if attacker_mutation_res.get("success") is False:
                return StateMutationResult(False, [])
            if "error" in attacker_mutation_res and not attacker_mutation_res.get("success"):
                return StateMutationResult(False, [])

        modified_fields: list[str] = []

        # 2. Check for resource deletion
        if baseline_read and (
            not victim_verify_read
            or victim_verify_read.get("status") in (404, "not_found", "deleted")
            or victim_verify_read.get("error") in ("Not Found", "Resource not found")
        ):
            modified_fields.extend(
                k
                for k in baseline_read
                if not self._is_public_field(k) and not self._is_transient_field(k)
            )
            if not modified_fields:
                modified_fields.append("__deleted__")
            return StateMutationResult(True, modified_fields)

        # 3. Compare baseline against victim verify read, skipping transient fields
        for k, v in baseline_read.items():
            if self._is_transient_field(k):
                continue
            if k in victim_verify_read:
                if victim_verify_read[k] != v:
                    modified_fields.append(k)
            else:
                modified_fields.append(k)

        for k in victim_verify_read:
            if self._is_transient_field(k):
                continue
            if k not in baseline_read:
                modified_fields.append(k)

        # 4. Verify against attacker_mutation_res when specific mutation payload provided
        if modified_fields and isinstance(attacker_mutation_res, dict):
            attacker_payload_fields = [
                k
                for k in attacker_mutation_res
                if not self._is_transient_field(k)
                and k not in ("id", "_id", "status", "success", "message", "ok", "deleted")
            ]
            if attacker_payload_fields:
                matched = [f for f in modified_fields if f in attacker_payload_fields]
                if matched:
                    return StateMutationResult(True, matched)
                return StateMutationResult(False, [])

        mutated = len(modified_fields) > 0
        return StateMutationResult(mutated, modified_fields)
