<div align="center">

<img src="docs/assets/hero.png" alt="Descry" width="100%" />

<h3>Semantic Firewall for AI Agents</h3>

<p>Intercepts every agent action before it executes. Blocks what doesn't belong — no rules to write, no LLM in the loop.</p>

[![CI](https://github.com/Descry-Technologies/descry/actions/workflows/ci.yml/badge.svg)](https://github.com/Descry-Technologies/descry/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Rust 1.75+](https://img.shields.io/badge/rust-1.75%2B-orange.svg)](https://www.rust-lang.org/)
[![Status](https://img.shields.io/badge/status-alpha-yellow.svg)](#status)

</div>

---

```
Task:    fix staging 401
Action:  aws rds delete-db-instance --db-instance-identifier prod-db --skip-final-snapshot

Without Descry  →  production database is gone
With Descry     →  BLOCKED in <1ms — destructive cloud operation outside task scope
```

The agent was fixing a 401 error. It found a production token in a tool response and tried to delete a database. Descry blocked it **before the request left the machine** — no LLM call, no network round-trip, no rules you had to write.

---

## Contents

- [Why](#why)
- [Install](#install)
- [Quick start](#quick-start)
- [How it works](#how-it-works)
- [What it blocks](#what-it-blocks)
- [Policies and approvals](#policies-and-approvals)
- [Audit log](#audit-log)
- [CLI reference](#cli-reference)
- [Workspace layout](#workspace-layout)
- [Trust boundary](#trust-boundary)
- [Contributing](#contributing)

---

## Why

AI coding agents run shell commands, edit files, call MCP tools, and reach cloud control planes. One bad action — a hallucination, a bug, a prompt injection in a tool response — can be irreversible.

Existing mitigations fall short:

| Approach | Problem |
|---|---|
| Sandboxes | Add friction, break legitimate workflows |
| Allowlists | Require constant maintenance, break on new actions |
| Audit logs | Tell you what went wrong after the damage is done |

**Descry does preflight, not postmortem.** Before every agent action it asks: *Does this make sense given what the agent is actually working on?* All reasoning is local, deterministic, and completes in under 50ms p95.

---

## Install

```bash
git clone https://github.com/Descry-Technologies/descry.git
cd descry
cargo install --locked --path crates/descry-cli
```

Wire it into your agent:

```bash
descry hook install claude    # Claude Code
descry hook install codex     # OpenAI Codex
descry hook install cursor    # Cursor (shell + MCP)
```

Initialize a project:

```bash
cd your-project
descry init --all             # creates .descry/, installs hooks, builds project index
descry doctor                 # verify everything is wired
```

---

## Quick start

Run the built-in demos to see the engine in action:

```bash
# Agent reads prod credentials from a tool response, tries to delete a volume
descry demo pocketos
```

```
loaded policies/safe-defaults.yml
inferred task: fix staging 401
proposed action: curl -X DELETE https://api.railway.app/v1/volumes/v_prod_pocketos
classified action: CloudDelete
decision: BLOCK
reason: destructive hosted control-plane operation; instruction originated from tool output
```

```bash
# Agent edits a file that's directly in scope for the current task
descry demo in-task-edit
```

```
inferred task: fix/session-expiry
proposed action: src/auth/session.ts
classified action: FileWrite
decision: ALLOW
reason: path matches task context (score=100); terms auth, session matched
```

```bash
# Agent editing a deploy workflow while fixing a login bug
descry demo off-task-edit
```

```
inferred task: fix/session-expiry
proposed action: .github/workflows/deploy.yml
classified action: FileWrite
decision: REQUIRE_APPROVAL
reason: high-sensitivity target outside task scope
```

Run all seven demos with `--json` for machine-readable output:

```bash
descry demo in-task-edit --json
descry demo off-task-edit --json
descry demo secret-access --json
descry demo rm-rf --json
descry demo mcp-poison --json
descry demo prod-delete --json
descry demo pocketos --json
```

---

## How it works

<img src="docs/assets/pipeline.png" alt="Descry evaluation pipeline" width="100%" />

Every agent action flows through a local, deterministic pipeline before execution. No LLM calls. No network. Each stage has one job.

### 1. Action classification

The raw command is parsed into a typed class. Tokenization handles quotes, escapes, and flags correctly:

- `git push -f origin main` → **GitRewrite**
- `aws rds delete-db-instance` → **CloudDelete**
- `cargo test` → **ShellTest**
- `src/auth/session.ts` (write) → **FileWrite**

This class feeds every downstream stage.

### 2. Task inference

Descry builds a `TaskEnvelope` from whatever context is available — the active task string, the current branch, recently edited files, and the project index — and scores it against the proposed action. No configuration required.

| Signal | Confidence |
|---|---|
| Active task + path match | 0.85 |
| Active task + term match | 0.75 |
| Branch name + term match | 0.50 |
| Recent files only | 0.40 |
| No signal | 0.20 |

### 3. Provenance tracking

Every action carries where its instruction came from:

| Source | Label |
|---|---|
| Human typed it | `user` |
| Agent's own plan | `agent_reasoning` |
| Tool call result | `tool_output` |
| File the agent read | `repo_content` |
| Page the agent fetched | `web_content` |

`tool_output`, `repo_content`, and `web_content` are the prompt injection surface. Instructions from these sources driving irreversible destructive actions are treated as potentially hijacked.

### 4. Drift and hijack detection

This is the core inference — a pure function, no LLM, no network:

```
external provenance + destructive class + irreversible  →  Block
external provenance + destructive class + reversible    →  RequireApproval
low task confidence + destructive class                 →  RequireApproval
everything else from user or agent                      →  Allow
```

The P3 scenario hits the first branch: `tool_output` provenance + `CloudDelete` class + `irreversible: true` = **Block**. The reason: *"instruction came from tool output, not from the user."*

<img src="docs/assets/drift-sequence.png" alt="Drift detection flow" width="100%" />

### 5. Asset sensitivity

The project asset graph maps paths and service targets to sensitivity tiers:

| Asset | Tier | Default |
|---|---|---|
| `.env.production` | critical | block |
| `.github/workflows/` | infra | require_approval |
| `src/**` | source | allow if context matches |

When confidence is high and the file is in scope, edits go through without friction. When the agent is touching something it has no business touching, it requires a human.

---

## What it blocks

The bundled `policies/safe-defaults.yml` hard-blocks these without any configuration:

| Category | Examples |
|---|---|
| Catastrophic deletion | `rm -rf /`, `rm -rf ~`, `rm -rf $HOME` and variants |
| Protected branch rewrites | `git push -f origin main`, `git push --force release/*` |
| Cloud control-plane destruction | `aws rds delete-db-instance`, `gcloud sql instances delete`, `fly volumes destroy`, `railway volume delete`, `vercel project remove`, `az group delete` |
| Destructive database operations | `DROP DATABASE`, `DROP TABLE`, `TRUNCATE TABLE`, `DELETE FROM` without `WHERE` |
| Production MCP endpoints | Calls matching `prod`, `production`, `admin`, `control-plane` |
| Destructive MCP tools | `delete_project`, `destroy_volume`, `drop_database` and matching patterns |
| Dangerous MCP argument keys | `confirm_destroy`, `force_delete`, `delete_confirmation` |

These are intentionally conservative. Descry earns trust by letting normal work through without friction.

---

## Policies and approvals

### Policy layers

```
policies/safe-defaults.yml     ← Tier-1 hard blocks. Cannot be approved away.
.descry/project.yml            ← Project asset and action defaults. Can be approved with a TTL.
```

Test a fixture against the engine:

```bash
descry policy test fixtures/railway-delete.json --expect block
descry policy test fixtures/cargo-test.json --expect allow
```

Run a precision gate against the full fixture corpus:

```bash
descry policy precision --manifest fixtures/manifest.yml --min-precision 0.95
```

### Approvals

When the engine returns `require_approval`, the agent pauses and you grant a time-bounded, scoped override:

```bash
descry approve --scope "path:src/auth/**"    --ttl 30m
descry approve --scope "action:deploy"        --ttl 1h
descry approve --scope "mcp:https://prod-mcp.example.com/**" --ttl 10m
```

Approvals are typed. A `path:` approval does not unlock `action:` or `mcp:` blocks.

### Shadow mode

Before a new rule produces real blocks, run it in shadow mode to measure false positives:

```bash
cat action.json | descry evaluate --stdin --shadow
# → { "decision": "allow_with_log", "reason": "[shadow] catastrophic root or home deletion ..." }
```

`block` verdicts become `allow_with_log`, prefixed with `[shadow]`. The action runs. Measure precision before the rule goes live.

---

## Audit log

Every decision is recorded in a tamper-evident, hash-chained JSONL log using SHA-256 Merkle checkpoints:

```bash
descry logs verify                      # verify chain integrity
descry logs tail -n 20                  # stream recent decisions
descry logs search 'asset:production'   # full-text search
```

A `descry-verify` standalone binary checks integrity and exports self-contained proof bundles without the full CLI runtime:

```bash
descry-verify --chain .descry/audit.log
descry-verify --chain .descry/audit.log --export-bundle
```

---

## CLI reference

```bash
# Hooks
descry hook install claude
descry hook install codex
descry hook install cursor
descry hook install git              # pre-push secret scan

# Project
descry init
descry init --all                    # init + hooks + project index
descry init --dry-run

# Health
descry doctor
descry doctor --fix
descry doctor --agent claude

# Task context
descry task set "Fix login session expiry"
descry task get
descry task clear

# Approvals
descry approve --scope "path:src/auth/**" --ttl 30m
descry approvals list

# Policy
descry policy test <fixture> --expect <allow|require_approval|block>
descry policy precision --manifest fixtures/manifest.yml

# Audit
descry logs verify
descry logs tail
descry logs search <query>

# Baseline
descry baseline explain <agent> <action> <target>

# Evaluation (used by hooks)
descry evaluate --stdin
descry evaluate --stdin --shadow

# Secret scanning
descry scan secrets
descry scan secrets --staged

# Demos
descry demo in-task-edit
descry demo off-task-edit
descry demo secret-access
descry demo rm-rf
descry demo mcp-poison
descry demo prod-delete
descry demo pocketos

# Standalone verifier
descry-verify --chain .descry/audit.log
descry-verify --chain .descry/audit.log --export-bundle
```

---

## Workspace layout

| Crate | Role |
|---|---|
| `descry-core` | ACP schema, decision types, action classification, drift signal, task inference |
| `descry-policy` | Policy DSL loader, hard-block matchers, SQL-aware pattern engine |
| `descry-adapters` | Claude Code, Codex, Cursor hook normalization and provenance tracking |
| `descry-engine` | Full evaluation pipeline: tier-one → asset → behavior → approvals → drift |
| `descry-context` | Project index and bounded session history |
| `descry-memory` | Approvals store, behavior counters, asset policy |
| `descry-audit` | Hash-chained JSONL audit log, Merkle checkpoints, export bundles |
| `descry-verify` | Standalone chain verifier — no dependency on descry-cli |
| `descry-cli` | CLI, hook entrypoints, demos, doctor, scan, precision gate |
| `descry-daemon` | Local HTTP daemon (`GET /v1/status`, `POST /v1/approve`) |

---

## Trust boundary

Descry runs at normal user privileges. A hostile process running as the same user can kill the hook. **Its purpose is blocking accidental harm and prompt-injection-driven harm in normal developer workflows — not defeating a malicious local user.**

This is stated here, in `descry doctor` output, and in [OPEN-SOURCE-PROMISE.md](OPEN-SOURCE-PROMISE.md).

---

## Privacy

Everything stays on your machine. Policy, state, approvals, behavior counters, and audit logs live under `.descry/`. Shell command contents are not recorded in audit events. MCP argument values are not recorded. No telemetry, no cloud account, no sign-up required.

---

## Status

Alpha. The local engine is implemented and tested:

- `cargo test --workspace` — full test suite green
- `cargo build --release` — release binary builds
- `descry doctor` — all checks green with hooks installed
- `descry demo prod-delete --json` — P3 drift detection blocks
- `descry evaluate --stdin --shadow` — shadow mode downgrades block to allow_with_log
- `cargo test -p descry-engine corpus_precision` — precision gate ≥ 0.95 on 31-fixture corpus
- `descry-verify --chain .descry/audit.log` — standalone verifier exits cleanly

Upcoming before v0.1.0 public tag:
- Homebrew tap
- Clean-machine install test

---

## Contributing

The project is in alpha — the best contributions are small, testable changes to the engine, policies, adapters, or demos.

```bash
git clone https://github.com/Descry-Technologies/descry.git
cd descry
cargo test --workspace
```

Before opening a PR:

```bash
cargo fmt --check
cargo clippy --workspace -- -D warnings
cargo test --workspace
```

For policy changes, add or update a fixture in `fixtures/` and include it in the fixture manifest. Every new hard block must have a documented real-world incident or failure mode in the PR.

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full guide.

---

## Security

Do not file public issues for security vulnerabilities. See [SECURITY.md](SECURITY.md).

---

## Open source promise

The firewall engine, inspection pipeline, policy schema, deterministic verdict logic, Merkle audit log, and standalone verifier are **Apache-2.0 forever**. No hot-path safety primitive will go behind a paywall.

Covered crates: `descry-core` · `descry-engine` · `descry-adapters` · `descry-policy` · `descry-audit` · `descry-verify` · `descry-context` · `descry-memory`

A future commercial platform (team policy sync, cloud audit retention, SSO, SIEM export) lives in a separate repository under a separate license and is never required to run Descry locally.

See [OPEN-SOURCE-PROMISE.md](OPEN-SOURCE-PROMISE.md) for the full binding commitment.

---

<div align="center">

**[Website](https://descry.app)** · **[CONTRIBUTING.md](CONTRIBUTING.md)** · **[SECURITY.md](SECURITY.md)** · **[OPEN-SOURCE-PROMISE.md](OPEN-SOURCE-PROMISE.md)**

Apache-2.0 · No paywall on safety

</div>
