# HALO: AI-Native Hybrid Application Security Testing (Hybrid-AST)

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python Version](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/)
[![Architecture](https://img.shields.io/badge/Architecture-Deterministic_CKG_%2B_Targeted_LLM-orange.svg)](#key-architecture--core-capabilities)

**HALO** is a developer-centric, AI-native **Hybrid Application Security Testing (Hybrid-AST)** framework engineered to identify, exploit, and remediate complex business logic and access control vulnerabilities that traditional SAST and DAST tools miss.

By uniting a deterministic 6-node **Code Knowledge Graph (CKG)** with targeted LLM reasoning within a strictly budgeted execution envelope, HALO delivers verifiable, zero-false-positive proofs of exploitability along with production-grade AST patches.

---

## Target Vulnerability Classes

Traditional static and dynamic tools inspect syntax patterns or spray generic payloads. HALO models authorization domains, cross-actor relationships, and application state machines to uncover:

* **BOLA / IDOR (Broken Object Level Authorization):** Unauthorized multi-tenant or cross-account entity access and state mutations.
* **BFLA (Broken Function Level Authorization):** Unprivileged role invocation of administrative endpoints, API routes, and hidden functions.
* **Workflow & State Machine Bypasses:** Skipping required verification or checkout steps, tampering with stage transitions, or replaying state mutations.
* **Concurrency & Race Conditions:** Time-of-check to time-of-use (TOCTOU), coupon/credit reuse, and quota overdrafts via synchronized burst probing.
* **Mass Assignment & Parameter Tampering:** Overriding protected fields (`role`, `is_admin`, `balance`) via schema-blind data mappers and ORM bindings.

---

## Key Architecture & Core Capabilities

```
                  ┌────────────────────────────────────────┐
                  │          Source Code / Repo            │
                  └──────────────────┬─────────────────────┘
                                     │
                     Deterministic Multi-Language AST
                    (Tree-sitter: TS/JS, Python, PHP)
                                     │
                                     ▼
                  ┌────────────────────────────────────────┐
                  │       Code Knowledge Graph (CKG)       │
                  │  (Endpoints, DTOs, Handlers, Models)   │
                  └──────────────────┬─────────────────────┘
                                     │
                     Targeted Semantic Intent Analysis
                      (Strict 100k-150k Token Budget)
                                     │
                                     ▼
                  ┌────────────────────────────────────────┐
                  │       Autonomous DAST Validator        │
                  │  (Multi-Actor Handshake: Attacker vs   │
                  │        Victim vs Administrator)        │
                  └──────────────────┬─────────────────────┘
                                     │
                             Active Wire-Level
                              Verification
                                     │
                  ┌──────────────────┴─────────────────────┐
                  ▼                                        ▼
    ┌───────────────────────────┐            ┌───────────────────────────┐
    │ Standalone PoC Generator  │            │ AST-Anchored Remediation  │
    │  (`repro_<id>.py` script) │            │  (Role-Aware Code Patches)│
    └───────────────────────────┘            └───────────────────────────┘
```

1. **Deterministic 6-Node Code Knowledge Graph (CKG):**
   Constructs an explicit graph mapping endpoints, route handlers, DTO validation schemas (Zod, Pydantic, Marshmallow), database query sinks, middleware chains, and auth decorators across JavaScript/TypeScript, Python, and PHP.

2. **Strategic AI Force Multipliers (Strict Token Budgeting):**
   Eliminates wasteful full-code LLM prompting. Reasoning models are targeted exclusively where deterministic rules fall short: extracting business intent from specs/docs, synthesizing valid schema payloads to bypass input validation barriers, and evaluating ambiguous response state mutations with devil's advocate reasoning.

3. **Multi-Actor Autonomous DAST:**
   Executes differential multi-actor handshakes (`User_A` attacker, `User_B` victim, `Admin`) against Docker containers or live URLs with automatic session acquisition, token rotation, and dynamic ID resolution.

4. **Zero-False-Positive Guarantee:**
   Vulnerabilities are never reported based on speculative heuristics. Every finding requires wire-level confirmation via sensitive token leakage or observable state mutation read-backs.

5. **Actionable Deliverables & Self-Repairing PoCs:**
   Every confirmed vulnerability produces:
   * A standalone, self-authenticating Python reproduction script (`repro_<finding_id>.py`).
   * An automated PoC verification and repair loop ensuring the exploit succeeds reliably.
   * An AST-anchored, role-aware remediation code patch.

---

## Installation

### Prerequisites

* Python 3.11+
* [Docker](https://www.docker.com/) (optional, required for container-managed dynamic scans)
* [uv](https://github.com/astral-sh/uv) or `pip`

### Setup

```bash
# Clone the repository
git clone https://github.com/harsh-sreehari/halo.git
cd halo

# Create virtual environment and install dependencies
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

Or using `uv`:

```bash
uv venv
source .venv/bin/activate
uv pip install -e ".[dev]"
```

---

## Configuration

HALO supports multiple LLM providers for intent mining and payload synthesis. Set your environment variables in a `.env` file or export them directly:

```bash
# Provider options: nvidia (default), openai, anthropic, gemini, ollama, mock
export LLM_PROVIDER="nvidia"
export NVIDIA_API_KEY="nvapi-..."

# Or for alternative providers:
# export LLM_PROVIDER="openai"
# export OPENAI_API_KEY="sk-..."
# export GEMINI_API_KEY="..."
# export ANTHROPIC_API_KEY="..."
```

---

## Usage & CLI Reference

HALO exposes an intuitive CLI for full hybrid scans or standalone SAST / DAST phases.

### 1. Full Hybrid Security Audit (`scan`)

Executes the complete end-to-end pipeline: static CKG extraction, intent mining, DAST multi-actor probing, wire verification, and PoC generation.

```bash
# Scan a local repository and automatically run target in Docker
halo scan --repo ./target-app --docker

# Scan against a live running URL with PoC verification enabled
halo scan --repo ./target-app --url http://localhost:3000 --verify-pocs

# Specify custom output directory and LLM token budget
halo scan --repo ./target-app --url http://localhost:8000 --out ./audit-results --token-budget 150000
```

#### Key `scan` Flags:
* `-r, --repo <path>`: Path to target repository (**required**).
* `-u, --url <url>`: Live target URL (e.g. `http://localhost:3000`).
* `-d, --docker`: Automatically discover and manage Docker container lifecycle.
* `--safe-mode / --force-destructive`: Prevent destructive actions on foreign entities (default: `--safe-mode`).
* `-o, --out, --output-dir <path>`: Directory for reports and PoCs (default: `.`).
* `--token-budget <int>`: Max LLM token budget limit (default: `150000`).
* `--llm-provider <provider>`: `nvidia`, `openai`, `gemini`, `anthropic`, `ollama`, or `mock`.
* `--verify-pocs / --no-verify-pocs`: Execute and auto-repair generated PoC scripts against the live target.

### 2. Static Analysis & Knowledge Graph Export (`sast`)

Parses source code into ASTs and exports the structured Code Knowledge Graph (CKG) without network probing.

```bash
halo sast --repo ./target-app --out ckg.json
```

### 3. Autonomous Dynamic Scan (`dast`)

Runs active probes (BOLA, BFLA, Race Condition, Mass Assignment) against a live deployment using repository insights or targeted heuristic endpoints.

```bash
halo dast --url https://staging.example.com --repo ./target-app --verify-pocs
```

---

## Artifacts & Deliverables

After a scan finishes, HALO exports structured deliverables to your output directory:

```
audit-results/
├── ckg.json                         # Serialized Code Knowledge Graph
├── halo_report.json                 # Complete vulnerability report (CVSS, paths, evidence)
├── patches/                         # AST-anchored remediation diffs
│   ├── patch_BOLA_01.diff
│   └── patch_BFLA_02.diff
└── pocs/                            # Standalone, runnable reproduction scripts
    ├── repro_BOLA_01.py
    └── repro_BFLA_02.py
```

### Running a Generated PoC

Every PoC is completely self-contained and reproducible with zero third-party dependencies beyond standard HTTP clients:

```bash
python pocs/repro_BOLA_01.py
```

---

## Development & Testing

Run unit tests and linters:

```bash
# Run unit tests
pytest tests/unit

# Run full test suite including integration tests
pytest

# Code formatting and linting
ruff check .
ruff format .
```

---

## Documentation

* [Technical & Architectural Specification](docs/superpowers/specs/2026-09-05-halo-vulnerability-scanner-design.md)

---

## License

This project is licensed under the Apache 2.0 License. See the [LICENSE](LICENSE) file for details.

