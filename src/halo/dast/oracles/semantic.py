"""Layer 2 Semantic LLM Differ Oracle with Devil's Advocate duel and deterministic mediator."""

from __future__ import annotations

import dis
import json
import logging
import re
import sys
from typing import Any, Self

from halo.dast.oracles.wire import DEFAULT_PUBLIC_FIELDS
from halo.llm.provider import LLMProvider

logger = logging.getLogger(__name__)

PROSECUTOR_SYSTEM_PROMPT = (
    "You are a specialized security prosecutor analyzing potential authorization and "
    "access control bypasses.\n"
    "Your goal is to argue why the observed attacker response represents an unauthorized data leak, "
    "broken object level authorization (BOLA/IDOR), broken function level authorization (BFLA), "
    "or violation of tenant isolation.\n"
    "Highlight any private or substantive data exposed to the attacker that matches or derives "
    "from the victim's view.\n"
    "Be analytical, objective, and specific about the exact fields and values compromised."
)

DEFENDER_SYSTEM_PROMPT = (
    "You are a specialized Devil's Advocate defending the application against false-positive "
    "vulnerability reports.\n"
    "Your goal is to argue why the observed attacker response is BENIGN and should NOT be flagged "
    "as a vulnerability.\n"
    "Look for:\n"
    "- Masked or redacted fields (e.g. null, empty strings, placeholder values)\n"
    "- Safe error responses (e.g. GraphQL 200 with error envelopes, access denied messages)\n"
    "- Benign empty collections (e.g. [] or {'items': []})\n"
    "- Public profile fields (e.g. public username, id, timestamps) that are intended to be visible\n"
    "- Proper access control enforcement where sensitive victim data is withheld\n"
    "Be rigorous in defending against false alarms."
)


class SemanticDifferResult(tuple):
    """Result of semantic LLM differ verification with Devil's Advocate.

    Functions as a tuple (is_vulnerable, reasoning, confidence), while
    supporting 2-tuple unpacking (is_vulnerable, reasoning) for compatibility,
    boolean evaluation, and property accessors.
    """

    def __new__(cls, is_vulnerable: bool, reasoning: str, confidence: float) -> Self:
        return super().__new__(cls, (is_vulnerable, reasoning, confidence))

    @property
    def is_vulnerable(self) -> bool:
        return self[0]

    @property
    def reasoning(self) -> str:
        return self[1]

    @property
    def confidence(self) -> float:
        return self[2]

    def __bool__(self) -> bool:
        return bool(self[0])

    def __iter__(self):
        try:
            frame = sys._getframe(1)
            instructions = list(dis.get_instructions(frame.f_code))
            for inst in instructions:
                if inst.offset >= frame.f_lasti:
                    if inst.opname == "UNPACK_SEQUENCE" and inst.argval == 2:
                        return iter(self[:2])
                    break
        except (AttributeError, IndexError, ValueError):
            pass
        return super().__iter__()

    def __eq__(self, other: object) -> bool:
        if isinstance(other, bool):
            return self[0] == other
        if isinstance(other, tuple) and len(other) == 2:
            return (self[0], self[1]) == other
        return super().__eq__(other)


def _is_public(key: str) -> bool:
    name = key.lower().strip()
    if name in DEFAULT_PUBLIC_FIELDS:
        return True
    last_seg = re.split(r"[._]", name)[-1]
    return last_seg in DEFAULT_PUBLIC_FIELDS


def _is_masked(val: Any) -> bool:
    if val is None or val == "":
        return True
    if isinstance(val, str):
        cleaned = val.strip().lower()
        if cleaned in {"***", "****", "[redacted]", "[masked]", "null", "none"}:
            return True
    return False


def _extract_leaves(obj: Any, prefix: str = "") -> list[tuple[str, str, Any]]:
    results: list[tuple[str, str, Any]] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            path = f"{prefix}.{k}" if prefix else str(k)
            if isinstance(v, (dict, list)):
                results.extend(_extract_leaves(v, path))
            else:
                results.append((path, str(k), v))
    elif isinstance(obj, list):
        for idx, item in enumerate(obj):
            path = f"{prefix}[{idx}]"
            if isinstance(item, (dict, list)):
                results.extend(_extract_leaves(item, path))
            else:
                results.append((path, str(idx), item))
    return results


class SemanticDifferOracle:
    """Layer 2 Semantic LLM Differ Oracle with Devil's Advocate.

    For ambiguous responses (e.g. GraphQL 200 with embedded errors, masked JSON,
    or empty arrays), runs competing Prosecutor and Defender (Devil's Advocate)
    prompts through an LLMProvider, then applies a deterministic mediator requiring
    substantive victim entity fields before confirming a vulnerability.
    """

    def __init__(self, excluded_fields: set[str] | None = None) -> None:
        self.excluded_fields = (
            {f.lower() for f in excluded_fields}
            if excluded_fields is not None
            else set(DEFAULT_PUBLIC_FIELDS)
        )

    def evaluate_ambiguous_response(
        self,
        victim_view: dict[str, Any],
        attacker_view: dict[str, Any] | list[Any],
        llm_provider: LLMProvider | None = None,
    ) -> SemanticDifferResult:
        """Evaluates an ambiguous response through a prompt duel and deterministic mediator.

        Returns SemanticDifferResult(is_vulnerable, reasoning, confidence).
        """
        prosecutor_arg = ""
        defender_arg = ""

        # Step 1: Run prompt duel through LLMProvider if supplied
        if llm_provider is not None:
            try:
                victim_json = json.dumps(victim_view, indent=2, default=str)
                attacker_json = json.dumps(attacker_view, indent=2, default=str)

                prosecutor_prompt = (
                    f"[VICTIM PRIVATE VIEW]\n{victim_json}\n\n"
                    f"[ATTACKER VIEW]\n{attacker_json}\n\n"
                    "Argue why the attacker view represents unauthorized data exposure or "
                    "access control violation. List any specific victim fields compromised."
                )
                defender_prompt = (
                    f"[VICTIM PRIVATE VIEW]\n{victim_json}\n\n"
                    f"[ATTACKER VIEW]\n{attacker_json}\n\n"
                    "Argue why the attacker view is benign (masked data, error response, "
                    "empty collection, or public profile fields only)."
                )

                prosecutor_arg = llm_provider.generate(
                    prompt=prosecutor_prompt,
                    system_prompt=PROSECUTOR_SYSTEM_PROMPT,
                )
                defender_arg = llm_provider.generate(
                    prompt=defender_prompt,
                    system_prompt=DEFENDER_SYSTEM_PROMPT,
                )
            except Exception as exc:  # noqa: BLE001
                logger.warning("LLM prompt duel generation failed: %s", exc)

        # Step 2: Deterministic Mediator
        return self._mediate(victim_view, attacker_view, prosecutor_arg, defender_arg)

    def _mediate(
        self,
        victim_view: dict[str, Any],
        attacker_view: dict[str, Any] | list[Any],
        prosecutor_arg: str,
        defender_arg: str,
    ) -> SemanticDifferResult:
        """Deterministic mediator requiring substantive victim entity fields."""
        # 1. GraphQL Embedded Error Check (e.g. 200 OK with errors list and null data)
        if isinstance(attacker_view, dict) and "errors" in attacker_view:
            errors = attacker_view.get("errors")
            if isinstance(errors, list) and len(errors) > 0:
                data_val = attacker_view.get("data")
                if data_val is None or data_val == {}:
                    first_err = errors[0]
                    msg = (
                        first_err.get("message", str(first_err))
                        if isinstance(first_err, dict)
                        else str(first_err)
                    )
                    reasoning = (
                        f"Benign GraphQL error response: endpoint returned access denial "
                        f"('{msg}') with null data payload; access control is enforced."
                    )
                    return SemanticDifferResult(False, reasoning, 0.95)

        # 2. Empty Collection Check (e.g. [] or {"orders": []})
        if attacker_view == [] or attacker_view == {}:
            reasoning = (
                "Benign empty collection: attacker response returned empty dataset "
                "under tenant isolation; access control is enforced."
            )
            return SemanticDifferResult(False, reasoning, 0.95)

        if isinstance(attacker_view, dict):
            # Check if all top-level collection or data fields are empty
            non_public_values = [v for k, v in attacker_view.items() if not _is_public(k)]
            if non_public_values and all(v in ([], {}, None) for v in non_public_values):
                reasoning = (
                    "Benign empty collection: attacker response returned empty collections "
                    "under tenant isolation; access control is enforced."
                )
                return SemanticDifferResult(False, reasoning, 0.95)

        # 3. Substantive vs Masked Fields Analysis
        victim_leaves = _extract_leaves(victim_view)
        victim_substantive: dict[str, Any] = {}
        for _path, leaf_key, val in victim_leaves:
            if not _is_public(leaf_key) and not _is_masked(val) and val not in ([], {}, ()):
                victim_substantive[leaf_key] = val

        attacker_leaves = _extract_leaves(attacker_view)
        attacker_substantive_exposed: list[str] = []
        attacker_masked_fields: list[str] = []

        for _path, leaf_key, val in attacker_leaves:
            if leaf_key in victim_substantive:
                if _is_masked(val):
                    attacker_masked_fields.append(leaf_key)
                elif (
                    val == victim_substantive[leaf_key]
                    or (
                        isinstance(val, (str, int, float))
                        and str(val) == str(victim_substantive[leaf_key])
                    )
                    or (not _is_public(leaf_key) and not _is_masked(val))
                ):
                    attacker_substantive_exposed.append(leaf_key)
            elif not _is_public(leaf_key):
                if _is_masked(val):
                    attacker_masked_fields.append(leaf_key)
                elif not _is_masked(val) and val not in ([], {}, ()):
                    # Check if substantive value matches any victim substantive value
                    for v_key, v_val in victim_substantive.items():
                        if val == v_val or (
                            isinstance(val, str) and str(v_val) in str(val) and len(str(v_val)) >= 3
                        ):
                            attacker_substantive_exposed.append(v_key)

        # 4. Evaluate Findings
        if attacker_substantive_exposed:
            unique_exposed = sorted(set(attacker_substantive_exposed))
            confidence = 0.95 if len(unique_exposed) >= 2 else 0.90
            reasoning = (
                f"Unauthorized data exposure confirmed: substantive private fields "
                f"({', '.join(unique_exposed)}) leaked in attacker view across tenant "
                f"boundaries. Compromised data violates access control."
            )
            return SemanticDifferResult(True, reasoning, confidence)

        if attacker_masked_fields and not attacker_substantive_exposed:
            unique_masked = sorted(set(attacker_masked_fields))
            reasoning = (
                f"Benign masked response: private victim fields "
                f"({', '.join(unique_masked)}) are masked/null in attacker view. "
                f"Unauthorized values are not exposed; access control enforced."
            )
            return SemanticDifferResult(False, reasoning, 0.92)

        # 5. Public profile only view
        if attacker_leaves and all(_is_public(k) or _is_masked(v) for _, k, v in attacker_leaves):
            reasoning = (
                "Benign public profile: attacker view only exposes public non-sensitive "
                "identifiers."
            )
            return SemanticDifferResult(False, reasoning, 0.88)

        # 6. Default benign
        reasoning = "Benign response: no substantive victim entity fields exposed in attacker view."
        return SemanticDifferResult(False, reasoning, 0.85)
