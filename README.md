# Project HALO

**AI-Native Hybrid Application Security Testing (Hybrid-AST) for Business Logic & Access Control Flaws**

Halo is a developer-centric security tool engineered to find and prove complex business logic vulnerabilities that traditional SAST and DAST miss:
- **BOLA / IDOR** (Broken Object Level Authorization)
- **BFLA** (Broken Function Level Authorization)
- **Workflow & State Machine Bypasses** (Skipping checkout steps, replaying state mutations)
- **Concurrency & Race Conditions** (TOCTOU, coupon reuse, quota overdrafts)
- **Mass Assignment & Parameter Tampering**

---

## Key Architecture Highlights

1. **Deterministic 6-Node Code Knowledge Graph (CKG):** Uses Tree-sitter queries and manifest path resolution (`tsconfig.json`, `composer.json`) across JavaScript/TypeScript, Python, and PHP to map endpoints, handlers, DTO validation schemas, and database query sinks.
2. **Strategic AI Force Multipliers (100k–150k Budget):** Targets reasoning models precisely where deterministic rules fail: mining business intent from documentation, synthesizing valid payloads to bypass input validation barriers (Zod/Pydantic), and evaluating complex state responses with devil's advocate prompts.
3. **Autonomous Dynamic Verification (DAST):** Performs multi-actor handshakes (`User_A` attacker, `User_B` victim, `Admin`) against Docker containers or staging URLs.
4. **Zero-False-Positive Guarantee:** Findings are verified at the wire level through sensitive token leakage and state mutation read-backs.
5. **Actionable Deliverables:** Every confirmed vulnerability outputs a self-authenticating standalone Python reproduction script (`repro_<id>.py`) and an AST-anchored, role-aware code replacement block.

---

## Quickstart

```bash
# Clone and install dependencies
git clone https://github.com/halo-sec/halo.git
cd halo
pip install -e ".[dev]"

# Full hybrid scan against a local repository and container
halo scan --repo ./my-app --docker

# Static analysis only (export CKG)
halo sast --repo ./my-app --out ckg.json

# Dynamic scan against a live staging URL
halo dast --url https://staging.example.com --repo ./my-app
```

---

## Documentation

* [Complete Technical & Architectural Specification](docs/superpowers/specs/2026-09-05-halo-vulnerability-scanner-design.md)
