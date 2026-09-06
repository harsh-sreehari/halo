"""Multi-format reporting engine for Project HALO findings.

Supports JSON, GitHub Security SARIF 2.1.0, Executive Markdown, and Rich Terminal TUI.
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any

from rich import box
from rich.console import Console
from rich.table import Table

from halo.validation.cvss import CVSSCalculator
from halo.validation.models import FindingData, FindingRecord

# Re-export for seamless imports
__all__ = ["FindingData", "FindingRecord", "ReportGenerator"]

# Flaw remediation guidance registry
REMEDIATION_GUIDES: dict[str, str] = {
    "BOLA_IDOR": (
        "Enforce strict object-level authorization by validating that the authenticated principal "
        "possesses legitimate ownership or access permissions for the target resource ID before processing operations."
    ),
    "BFLA": (
        "Implement granular role-based access control (RBAC) and attribute-based access control (ABAC) "
        "guards or middleware on all administrative and privileged endpoints."
    ),
    "RACE_CONDITION": (
        "Implement database transactions with strict isolation levels, atomic mutations (e.g. SELECT ... FOR UPDATE), "
        "or distributed mutexes (e.g. Redis Redlock) to enforce operational atomicity."
    ),
    "WORKFLOW_BYPASS": (
        "Enforce server-side state machine validation verifying that all prerequisite workflow steps "
        "and invariants have been satisfied before permitting state-mutating actions."
    ),
    "MASS_ASSIGNMENT": (
        "Enforce strict input schema filtering using explicit DTO allow-lists (e.g. Pydantic schema or parameter "
        "allowlists) to reject unpermitted privilege or internal state attributes."
    ),
}

DEFAULT_REMEDIATION = (
    "Review authorization boundaries, enforce principle of least privilege, and validate state transitions "
    "server-side for all sensitive endpoints."
)


class ReportGenerator:
    """Delivers deterministic CVSS-enriched security reports across multiple standard formats."""

    _calc = CVSSCalculator()

    @classmethod
    def _ensure_finding_model(cls, finding: FindingRecord | dict[str, Any]) -> FindingRecord:
        if isinstance(finding, FindingRecord):
            return finding
        if isinstance(finding, dict):
            return FindingRecord(**finding)
        raise TypeError(f"Unsupported finding type: {type(finding)}")

    @classmethod
    def _enrich_finding_cvss(cls, record: FindingRecord) -> tuple[float, str, str]:
        """Extract or compute (cvss_score, cvss_severity, cvss_vector) for a finding."""
        score = getattr(record, "cvss_score", None)
        vec = getattr(record, "cvss_vector", None)
        sev = getattr(record, "cvss_severity", None)

        if score is not None and vec is not None and sev is not None:
            return float(score), str(sev), str(vec)

        flaw_type = record.flaw_type or record.rule_id or "UNKNOWN"
        method_str = (record.method or "GET").upper()
        is_write = method_str in {"POST", "PUT", "PATCH", "DELETE"}
        calc_score, calc_sev, calc_vec = cls._calc.calculate_for_finding(
            flaw_type=flaw_type,
            requires_auth=True,
            scope_changed=False,
            is_write=is_write,
        )

        final_score = float(score) if score is not None else calc_score
        final_sev = str(sev) if sev is not None else calc_sev
        final_vec = str(vec) if vec is not None else calc_vec
        return final_score, final_sev, final_vec

    @classmethod
    def export_json(
        cls,
        findings: list[FindingRecord | dict[str, Any]],
        out_path: str | Path,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Export findings to structured JSON with metadata and CVSS metrics."""
        path = Path(out_path)
        path.parent.mkdir(parents=True, exist_ok=True)

        records = [cls._ensure_finding_model(f) for f in findings]
        now_iso = datetime.now(timezone.utc).isoformat()

        findings_data: list[dict[str, Any]] = []
        for r in records:
            score, sev, vec = cls._enrich_finding_cvss(r)
            f_dict = r.model_dump()
            f_dict["cvss_score"] = score
            f_dict["cvss_severity"] = sev
            f_dict["cvss_vector"] = vec
            findings_data.append(f_dict)

        report_dict: dict[str, Any] = {
            "scanner": "Project HALO",
            "version": "0.1.0",
            "timestamp": now_iso,
            "scan_timestamp": now_iso,
            "total_findings": len(records),
            "findings": findings_data,
        }
        if metadata:
            report_dict["metadata"] = metadata

        path.write_text(json.dumps(report_dict, indent=2), encoding="utf-8")
        return report_dict

    @classmethod
    def export_sarif(
        cls, findings: list[FindingRecord | dict[str, Any]], out_path: str | Path
    ) -> dict[str, Any]:
        """Export findings to valid SARIF 2.1.0 format compatible with GitHub Security tab."""
        path = Path(out_path)
        path.parent.mkdir(parents=True, exist_ok=True)

        records = [cls._ensure_finding_model(f) for f in findings]

        # Build distinct rules list
        rules_map: dict[str, dict[str, Any]] = {}
        sarif_results: list[dict[str, Any]] = []

        for r in records:
            rule_id = r.rule_id or r.flaw_type or "HALO-SEC"
            score, sev, vec = cls._enrich_finding_cvss(r)

            # Map severity to SARIF level
            # GitHub code scanning: "error", "warning", "note", "none"
            sev_upper = (r.severity or sev).upper()
            if sev_upper in {"CRITICAL", "HIGH"}:
                level = "error"
            elif sev_upper == "MEDIUM":
                level = "warning"
            else:
                level = "note"

            if rule_id not in rules_map:
                rules_map[rule_id] = {
                    "id": rule_id,
                    "name": rule_id.replace("_", " ").title(),
                    "shortDescription": {
                        "text": f"Business logic vulnerability rule: {rule_id}"
                    },
                    "fullDescription": {
                        "text": (
                            f"Project HALO business logic flaw detection for category {rule_id}."
                        )
                    },
                    "defaultConfiguration": {"level": level},
                    "helpUri": "https://owasp.org/API-Security/",
                    "properties": {
                        "tags": ["security", "business-logic", rule_id.lower()]
                    },
                }

            start_line = max(1, r.line_start or r.line_number or 1)
            end_line = max(start_line, r.line_end or r.line_number or start_line)
            file_uri = r.file_path or "unknown"
            if file_uri.startswith("/") and not file_uri.startswith("//"):
                file_uri = file_uri.lstrip("/")

            description_text = r.description or r.details or f"{rule_id} vulnerability detected on {r.endpoint}"

            result_entry: dict[str, Any] = {
                "ruleId": rule_id,
                "ruleIndex": list(rules_map.keys()).index(rule_id),
                "level": level,
                "message": {"text": description_text},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": file_uri,
                                "uriBaseId": "%SRCROOT%",
                            },
                            "region": {
                                "startLine": start_line,
                                "endLine": end_line,
                            },
                        }
                    }
                ],
                "properties": {
                    "findingId": r.id,
                    "flawType": r.flaw_type,
                    "severity": r.severity,
                    "confidence": r.confidence,
                    "cvssScore": score,
                    "cvssVector": vec,
                    "endpoint": r.endpoint,
                },
            }
            sarif_results.append(result_entry)

        sarif_doc: dict[str, Any] = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "HALO",
                            "semanticVersion": "0.1.0",
                            "informationUri": "https://github.com/halo-security/halo",
                            "rules": list(rules_map.values()),
                        }
                    },
                    "results": sarif_results,
                }
            ],
        }

        path.write_text(json.dumps(sarif_doc, indent=2), encoding="utf-8")
        return sarif_doc

    @classmethod
    def export_markdown(
        cls,
        findings: list[FindingRecord | dict[str, Any]],
        out_path: str | Path,
        metadata: dict[str, Any] | None = None,
    ) -> str:
        """Export findings to an executive audit markdown report."""
        path = Path(out_path)
        path.parent.mkdir(parents=True, exist_ok=True)

        records = [cls._ensure_finding_model(f) for f in findings]
        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        # Aggregate counts by severity
        sev_counts: dict[str, int] = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "INFO": 0,
        }
        for r in records:
            s = (r.severity or "INFO").upper()
            sev_counts[s] = sev_counts.get(s, 0) + 1

        md_lines: list[str] = [
            "# Project HALO - Security Audit Report",
            "",
            f"**Generated:** {now_str}  ",
            f"**Total Findings:** {len(records)}  ",
        ]

        if metadata:
            for k, v in metadata.items():
                md_lines.append(f"**{k.replace('_', ' ').title()}:** {v}  ")

        md_lines.extend(
            [
                "",
                "## Executive Summary",
                "",
                "| Critical | High | Medium | Low | Info |",
                "| :---: | :---: | :---: | :---: | :---: |",
                f"| {sev_counts['CRITICAL']} | {sev_counts['HIGH']} | {sev_counts['MEDIUM']} | {sev_counts['LOW']} | {sev_counts['INFO']} |",
                "",
                "### Findings Overview",
                "",
                "| ID | Severity | Flaw Type | Endpoint | CVSS Score | Location |",
                "|---|---|---|---|---|---|",
            ]
        )

        badge_map = {
            "CRITICAL": "🔴 **CRITICAL**",
            "HIGH": "🟠 **HIGH**",
            "MEDIUM": "🟡 **MEDIUM**",
            "LOW": "🔵 **LOW**",
            "INFO": "⚪ **INFO**",
        }

        finding_details: list[str] = []

        for r in records:
            score, sev, vec = cls._enrich_finding_cvss(r)
            sev_badge = badge_map.get(r.severity.upper(), r.severity)
            loc = f"`{r.file_path}:{r.line_start}`" if r.file_path else "`N/A`"
            endpoint_disp = f"`{r.method} {r.endpoint}`" if r.endpoint else "`N/A`"

            md_lines.append(
                f"| {r.id} | {sev_badge} | {r.flaw_type} | {endpoint_disp} | {score} | {loc} |"
            )

            # Detailed section
            remediation = REMEDIATION_GUIDES.get(r.flaw_type.upper(), DEFAULT_REMEDIATION)
            details_section = [
                f"## {r.id}: {r.flaw_type} on {r.endpoint or r.file_path or 'Target'}",
                "",
                f"- **Severity:** {r.severity.upper()} (CVSS v3.1 Score: **{score}**)",
                f"- **CVSS Vector:** `{vec}`",
                f"- **Endpoint:** `{r.method} {r.endpoint}`",
                f"- **File Location:** `{r.file_path}:{r.line_start}-{r.line_end}`",
                f"- **Confidence:** {r.confidence * 100:.0f}%",
                "",
                "### Description & Evidence",
                "",
                r.details or r.description or "No narrative description provided.",
                "",
                "### Remediation Recommendation",
                "",
                remediation,
                "",
            ]

            if r.reproduction_steps:
                details_section.extend(["### Reproduction Steps", ""])
                for i, step in enumerate(r.reproduction_steps, 1):
                    if isinstance(step, dict):
                        step_desc = step.get("description") or step.get("action") or str(step)
                    else:
                        step_desc = str(step)
                    details_section.append(f"{i}. {step_desc}")
                details_section.append("")

            details_section.append("---")
            finding_details.extend(details_section)

        md_lines.extend(["", "## Detailed Findings", ""])
        md_lines.extend(finding_details)

        full_md = "\n".join(md_lines) + "\n"
        path.write_text(full_md, encoding="utf-8")
        return full_md

    @classmethod
    def render_terminal_summary(
        cls,
        findings: list[FindingRecord | dict[str, Any]],
        console: Console | None = None,
    ) -> Table:
        """Render a colorful rich terminal summary table for CLI output."""
        if console is None:
            console = Console()

        table = Table(
            title="Project HALO - Vulnerability Scan Summary",
            box=box.ROUNDED,
            header_style="bold magenta",
        )
        table.add_column("ID", style="bold cyan", no_wrap=True)
        table.add_column("Severity", justify="center")
        table.add_column("Flaw Type", style="bold")
        table.add_column("CVSS", justify="right")
        table.add_column("Endpoint", style="green")
        table.add_column("Location", style="blue")

        records = [cls._ensure_finding_model(f) for f in findings]

        if not records:
            console.print("[bold green]No vulnerabilities detected.[/bold green]")
            table.add_row("-", "[green]CLEAN[/green]", "None", "0.0", "-", "Clean code base")
            console.print(table)
            return table

        sev_colors = {
            "CRITICAL": "bold red",
            "HIGH": "red",
            "MEDIUM": "yellow",
            "LOW": "blue",
            "INFO": "dim",
        }

        for r in records:
            score, sev, _ = cls._enrich_finding_cvss(r)
            color = sev_colors.get(r.severity.upper(), "white")
            sev_formatted = f"[{color}]{r.severity.upper()}[/{color}]"
            loc = f"{r.file_path}:{r.line_start}" if r.file_path else "-"
            endpoint = f"{r.method} {r.endpoint}" if r.endpoint else "-"

            table.add_row(
                r.id,
                sev_formatted,
                r.flaw_type,
                f"{score:.1f}",
                endpoint,
                loc,
            )

        console.print(table)
        return table
