# Descry Roadmap

Descry is built in phases. Each phase ships a working, usable product — not a prototype. The firewall ships first and stays open source. Everything else is built on top of it.

---

## The module map

Descry's long-term goal is the security suite that every organization running AI agents at scale will need. Each module below is a distinct product with a distinct threat model. They share a unified event format and data plane so the dashboard can correlate across them.

| Module | Traditional equivalent | Status |
|---|---|---|
| **Action Firewall** | NGFW / inline packet inspection | **Open source · Alpha** |
| Behavioral Baseline + Anomaly | UEBA | Partially built (baseline store in engine) |
| Memory Store Security | EDR | Planned |
| Context Leakage / DLP | Data Loss Prevention | Planned |
| Agent Identity + Trust | IAM / PAM | Planned |
| Audit / Provable History | SIEM event store | Core ledger open · export tooling open |
| MCP / Tool Chain Integrity | Supply chain security | Planned |
| Prompt Injection Detection | Threat intel / IOC matching | Planned |
| Attack Surface Scanner | Vulnerability management | Planned |
| Compliance / GRC | GRC / audit tooling | Planned |

The Action Firewall is the open-source core — Apache-2.0, no paywalls, no relicensing. All other modules are commercial. The business is built around the engine, not on top of a gimped version of it.

---

## Phase 0 — Action Firewall (current)

**Goal:** A developer can install Descry in one command, hook it into Claude Code / Codex / Cursor, and trust that it will not break their normal workflow while blocking the obvious dangerous stuff.

| What | Status |
|---|---|
| Local evaluation engine (tier-one, asset, drift, behavior, approvals) | Done |
| Safe-default Tier-1 policy pack | Done |
| Claude Code, Codex, Cursor hook normalization | Done |
| Task inference from branch, prompt, recent files, project index | Done |
| Drift / hijack detection (provenance × action class × reversibility) | Done |
| Behavior baseline store + `baseline explain` | Done |
| Scoped TTL approvals (path, action, MCP) | Done |
| Shadow mode (block → allow_with_log before a rule goes live) | Done |
| Corpus precision gate in CI (≥ 0.95 on fixture corpus) | Done |
| Hash-chained JSONL audit log + Merkle checkpoints | Done |
| `descry-verify` standalone chain verifier | Done |
| `descry doctor`, `--fix`, `descry init --all` | Done |
| Seven reproducible launch demos | Done |
| Latency gate: p95 < 50ms in release (enforced in CI) | Done |
| `cargo test --workspace` all green | Done |
| Homebrew tap · tagged v0.1.0 release | **Pending** |

---

## Phase 1 — Firewall hardening

Better precision, richer UX, broader agent support.

- False-positive tuning against real repository corpora
- Richer `require_approval` UX: inline fix suggestion + override phrase
- More Tier-1 rules: Kubernetes destructive ops, GH Actions secret exfil patterns
- Better `descry baseline explain` with escalation context
- ~~Daemon promotion: bearer token auth on `/v1/approve`, Prometheus metrics at `/v1/metrics`~~ **Done (v0.2.0)**
- ~~Structured tracing logs via `DESCRY_LOG` env var~~ **Done (v0.2.0)**
- ~~`TrustLevel` enum replacing free-string trust field~~ **Done (v0.2.0)**
- ~~HMAC-SHA256 keyed scope contract signing~~ **Done (v0.2.0)**
- ~~Machine-local signing key (`~/.descry/signing.key`)~~ **Done (v0.2.0)**
- ~~`globset`-based asset glob precompilation~~ **Done (v0.2.0)**
- ~~Persistent daemon state directory~~ **Done (v0.2.0)**
- Daemon scope-contract cache, 60s policy file watch
- Device identity in audit events (stable, non-PII SHA-256 of hostname+user)
- Redaction manifest in export bundles for compliance-safe sharing

---

## Phase 2 — Behavioral Baseline + Anomaly

The baseline store is already partially built inside the engine. This phase makes it a first-class module:

- Persistent per-triple `(agent, action, target)` familiarity counters
- Statistical drift signal as a standalone risk feed
- `descry baseline explain` with full temporal context (first seen, last seen, rate)
- Escalation detection: same triple repeating at unusual frequency
- Anomaly alerts surfaced to the developer in real time

---

## Phase 3 — Memory Store Security

Scans agent memory stores on write for injected instructions, sensitive data leakage, and silent drift across sessions.

- `.claude/memory/`, `.cursor/rules`, system prompts, custom instructions
- Injection pattern detection in memory entries
- PII and secret pattern matching before persistence
- Session-to-session drift detection (memory growing toward a threat pattern)

---

## Phase 4 — Unified dashboard + team control plane

The revenue layer. All modules report to the same event bus. The dashboard correlates across them.

- Team enrollment and agent fleet inventory
- Fleet-wide policy templates
- Unified security timeline across all modules
- MCP server inventory and signature verification
- Policy sync to all enrolled machines (60s propagation)
- SSO / RBAC / SCIM
- SIEM export (Splunk, Elastic, Datadog)
- Managed audit retention and search
- Compliance reporting (SOC 2, EU AI Act Art. 12)

---

## What will always be free

The Action Firewall. Every crate in the `descry` workspace. Every policy pack published here. Every audit primitive. The standalone verifier. The proof bundle format.

See [OPEN-SOURCE-PROMISE.md](OPEN-SOURCE-PROMISE.md).
