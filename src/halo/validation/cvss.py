"""Deterministic CVSS v3.1 calculator adhering strictly to FIRST CVSS v3.1 specification."""

from __future__ import annotations

import math
from typing import Any, ClassVar


class CVSSCalculator:
    """Computes deterministic CVSS v3.1 base score, qualitative severity, and vector string."""

    # Metric weight tables adhering to CVSS v3.1 specification
    AV_WEIGHTS: ClassVar[dict[str, float]] = {
        "N": 0.85,  # Network
        "A": 0.62,  # Adjacent
        "L": 0.55,  # Local
        "P": 0.20,  # Physical
    }

    AC_WEIGHTS: ClassVar[dict[str, float]] = {
        "L": 0.77,  # Low
        "H": 0.44,  # High
    }

    PR_WEIGHTS: ClassVar[dict[str, dict[str, float]]] = {
        "U": {  # Scope Unchanged
            "N": 0.85,  # None
            "L": 0.62,  # Low
            "H": 0.27,  # High
        },
        "C": {  # Scope Changed
            "N": 0.85,  # None
            "L": 0.68,  # Low
            "H": 0.50,  # High
        },
    }

    UI_WEIGHTS: ClassVar[dict[str, float]] = {
        "N": 0.85,  # None
        "R": 0.62,  # Required
    }

    CIA_WEIGHTS: ClassVar[dict[str, float]] = {
        "N": 0.00,  # None
        "L": 0.22,  # Low
        "H": 0.56,  # High
    }

    @staticmethod
    def roundup(val: float) -> float:
        """FIRST CVSS v3.1 Appendix A Roundup ceiling function to 1 decimal place.

        Defined as the smallest number, specified to one decimal place, that is
        greater than or equal to the input parameter.
        """
        int_val = round(val * 100000)
        if (int_val % 10000) == 0:
            return round(int_val / 100000.0, 1)
        else:
            return round((math.floor(int_val / 10000) + 1) / 10.0, 1)

    @staticmethod
    def get_severity(score: float) -> str:
        """Qualitative Severity Rating Scale:

        - 0.0: NONE
        - 0.1 - 3.9: LOW
        - 4.0 - 6.9: MEDIUM
        - 7.0 - 8.9: HIGH
        - 9.0 - 10.0: CRITICAL
        """
        if score <= 0.0:
            return "NONE"
        elif score <= 3.9:
            return "LOW"
        elif score <= 6.9:
            return "MEDIUM"
        elif score <= 8.9:
            return "HIGH"
        else:
            return "CRITICAL"

    @classmethod
    def _normalize_metric(cls, val: str, valid_keys: set[str], default: str) -> str:
        if not val:
            return default
        cleaned = str(val).strip().upper()
        if cleaned in valid_keys:
            return cleaned
        # Check first letter
        first = cleaned[0]
        if first in valid_keys:
            return first
        return default

    def calculate(
        self,
        attack_vector: str = "N",
        attack_complexity: str = "L",
        privileges_required: str = "L",
        user_interaction: str = "N",
        scope: str = "U",
        confidentiality: str = "H",
        integrity: str = "N",
        availability: str = "N",
        **kwargs: Any,
    ) -> tuple[float, str, str]:
        """Compute CVSS v3.1 base score, severity rating, and vector string.

        Returns:
            (base_score, severity_rating, vector_string)
        """
        # Handle alternate interface: calculate(flaw_type=...) or calculate("BOLA_IDOR", ...)
        if "flaw_type" in kwargs:
            return self.calculate_for_finding(
                flaw_type=kwargs["flaw_type"],
                requires_auth=kwargs.get("requires_auth", privileges_required != "N"),
                scope_changed=kwargs.get("scope_changed", scope == "C"),
                is_write=kwargs.get(
                    "is_write", (integrity == "H") if "integrity" in kwargs else None
                ),
            )

        av_str = str(attack_vector).strip().upper()
        if (
            "_" in av_str
            or av_str
            in {
                "BOLA",
                "IDOR",
                "BOLA_IDOR",
                "BFLA",
                "RACE_CONDITION",
                "WORKFLOW_BYPASS",
                "MASS_ASSIGNMENT",
            }
        ):
            # Positional call was flaw_type
            return self.calculate_for_finding(
                flaw_type=av_str,
                requires_auth=(privileges_required != "N"),
                scope_changed=(scope == "C"),
                is_write=(confidentiality == "H" and attack_complexity == "L"),
            )

        # Normalize metrics
        av = self._normalize_metric(attack_vector, set(self.AV_WEIGHTS.keys()), "N")
        ac = self._normalize_metric(attack_complexity, set(self.AC_WEIGHTS.keys()), "L")
        s = self._normalize_metric(scope, {"U", "C"}, "U")
        pr = self._normalize_metric(privileges_required, set(self.PR_WEIGHTS[s].keys()), "L")
        ui = self._normalize_metric(user_interaction, set(self.UI_WEIGHTS.keys()), "N")
        c = self._normalize_metric(confidentiality, set(self.CIA_WEIGHTS.keys()), "N")
        i = self._normalize_metric(integrity, set(self.CIA_WEIGHTS.keys()), "N")
        a = self._normalize_metric(availability, set(self.CIA_WEIGHTS.keys()), "N")

        # Exploitability Sub-score: 8.22 * AV * AC * PR * UI
        av_w = self.AV_WEIGHTS[av]
        ac_w = self.AC_WEIGHTS[ac]
        pr_w = self.PR_WEIGHTS[s][pr]
        ui_w = self.UI_WEIGHTS[ui]
        exploitability = 8.22 * av_w * ac_w * pr_w * ui_w

        # ISS (Impact Sub-Score): 1 - [(1 - C) * (1 - I) * (1 - A)]
        c_w = self.CIA_WEIGHTS[c]
        i_w = self.CIA_WEIGHTS[i]
        a_w = self.CIA_WEIGHTS[a]
        iss = 1.0 - ((1.0 - c_w) * (1.0 - i_w) * (1.0 - a_w))

        # Impact
        if s == "U":
            impact = 6.42 * iss
        else:
            impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)

        # Base Score
        if impact <= 0.0:
            base_score = 0.0
        else:
            if s == "U":
                base_score = self.roundup(min(impact + exploitability, 10.0))
            else:
                base_score = self.roundup(min(1.08 * (impact + exploitability), 10.0))

        severity = self.get_severity(base_score)
        vector = f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{s}/C:{c}/I:{i}/A:{a}"

        return base_score, severity, vector

    def calculate_for_finding(
        self,
        flaw_type: str,
        requires_auth: bool = True,
        scope_changed: bool = False,
        is_write: bool | None = None,
    ) -> tuple[float, str, str]:
        """Map business logic flaw types to realistic CVSS v3.1 metrics and compute score.

        Mappings:
        - BOLA_IDOR: AV:N, AC:L, PR:L (or N if unauth), UI:N, S:U (or C), C:H, I:H if write else N, A:N
        - BFLA: AV:N, AC:L, PR:L (or N if unauth), UI:N, S:U (or C), C:H, I:H if write else N, A:N
        - RACE_CONDITION: AV:N, AC:H, PR:L (or N if unauth), UI:N, S:U (or C), C:N, I:H, A:N
        - WORKFLOW_BYPASS: AV:N, AC:L, PR:L (or N if unauth), UI:N, S:U (or C), C:N, I:H, A:N
        - MASS_ASSIGNMENT: AV:N, AC:L, PR:L (or N if unauth), UI:N, S:U (or C), C:L, I:H, A:N
        - Default / other: AV:N, AC:L, PR:L (or N if unauth), UI:N, S:U (or C), C:L, I:L, A:N
        """
        norm_type = str(flaw_type or "").strip().upper().replace("-", "_")
        pr = "L" if requires_auth else "N"
        s = "C" if scope_changed else "U"

        is_write_effective = (
            ("BFLA" in norm_type) if is_write is None else is_write
        )

        if "BOLA" in norm_type or "IDOR" in norm_type or "BFLA" in norm_type:
            av, ac, ui = "N", "L", "N"
            c = "H"
            i = "H" if is_write_effective else "N"
            a = "N"
        elif "RACE" in norm_type:
            av, ac, ui = "N", "H", "N"
            c = "N"
            i = "H"
            a = "N"
        elif "WORKFLOW" in norm_type:
            av, ac, ui = "N", "L", "N"
            c = "N"
            i = "H"
            a = "N"
        elif "MASS" in norm_type or "ASSIGNMENT" in norm_type:
            av, ac, ui = "N", "L", "N"
            c = "L"
            i = "H"
            a = "N"
        else:
            av, ac, ui = "N", "L", "N"
            c = "L"
            i = "L"
            a = "N"

        return self.calculate(
            attack_vector=av,
            attack_complexity=ac,
            privileges_required=pr,
            user_interaction=ui,
            scope=s,
            confidentiality=c,
            integrity=i,
            availability=a,
        )
