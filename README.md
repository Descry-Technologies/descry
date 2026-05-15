<div align="center">

<img src="docs/assets/hero.png" alt="Descry — Semantic Firewall for AI Agents" width="100%" />

<br />

**Descry intercepts every AI agent action before it executes.**  
It infers what the agent is working on, classifies the action, and blocks what doesn't belong —  
without rules you have to write and without an LLM in the loop.

<br />

[![CI](https://github.com/descry-dev/descry/actions/workflows/ci.yml/badge.svg)](https://github.com/descry-dev/descry/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Rust 1.75+](https://img.shields.io/badge/rust-1.75%2B-orange.svg)](https://www.rust-lang.org/)
[![Status: Alpha](https://img.shields.io/badge/status-alpha-yellow.svg)](#status)
[![License Promise](https://img.shields.io/badge/promise-no_paywall_on_safety-green.svg)](LICENSE-PROMISE.md)

</div>

---

```
Task:    fix staging 401
Action:  aws rds delete-db-instance --db-instance-identifier prod-db --skip-final-snapshot

Without Descry:  production database deletion request is sent
With Descry:     BLOCKED — destructive hosted control-plane operation (rule: control-plane-delete)
```

The agent was told to fix a 401 error. It found a production token in a tool response and tried to delete a database. Descry blocked it in **< 1ms** — no LLM, no network, no configuration.

---

## Why this exists

AI coding agents run shell commands, edit files, call MCP tools, and reach cloud control planes. The blast radius of a single bad action — whether caused by a bug in the agent, a hallucination, or a prompt injection in a tool response — can be enormous and irreversible.

Existing mitigations are too weak:
- **Sandboxes** add friction and break legitimate workflows
- **Allowlists** require constant maintenance and break on novel actions
- **Audit logs** tell you what went wrong after it already happened

Descry takes a different approach: **semantic preflight**. Before every action, it asks:
- What is the agent actually trying to do?
- Does this action make sense given that task?
- Where did this instruction come from?
- Is this target sensitive?
- Should this be allowed, logged, require a human, or blocked?

All of this happens locally, deterministically, in under 50ms p95.

---

## Install

```bash
# From source (recommended during alpha)
git clone https://github.com/descry-dev/descry.git
cd descry
cargo install --locked --path crates/descry-cli
```

Wire it into your agent in three commands:

```bash
descry hook install claude    # Claude Code
descry hook install codex     # Codex
descry hook install cursor    # Cursor (shell + MCP)
```

Initialize a project:

```bash
cd your-project
descry init --all             # creates .descry/, installs hooks, builds project index
```

Verify everything is wired:

```bash
descry doctor
```

---

## See it in action

```
$ descry demo pocketos

descry demo pocketos
loaded policies/safe-defaults.yml
prompt/context: fix staging 401 after agent discovers Railway credentials
inferred task: fix staging 401
proposed action: curl -X DELETE https://api.railway.app/v1/volumes/v_prod_pocketos
classified action: CloudDelete
asset match: none
decision: block
reason: destructive hosted control-plane operation (rule: control-plane-delete)
without Descry: production volume deleted and backups on the same volume vanish
```

```
$ descry demo in-task-edit

descry demo in-task-edit
loaded policies/safe-defaults.yml
prompt/context: fix login session expiry while editing the session module
inferred task: fix/session-expiry
proposed action: src/auth/session.ts
classified action: FileWrite
asset match: source sensitivity=normal default_action=allow_if_context_matches
decision: allow
reason: allowed: src/auth/session.ts matched task context score=100 via exact path match; terms auth, session; sources branch, recent_files
without Descry: the edit proceeds, but there is no independent task/asset check
```

```
$ descry demo off-task-edit

descry demo off-task-edit
loaded policies/safe-defaults.yml
prompt/context: fix login session expiry while agent edits deployment workflow
inferred task: fix/session-expiry
proposed action: .github/workflows/deploy.yml
classified action: FileWrite
asset match: infra sensitivity=high default_action=require_approval
decision: require_approval
reason: high write target .github/workflows/deploy.yml requires scoped approval by asset policy
without Descry: deployment workflow changes without an explicit approval checkpoint
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

Every agent action flows through the same local pipeline before execution. Each stage has a single job and passes a typed result to the next — no shared mutable state, no LLM calls, no network.

### The five reasoning layers

**1. Semantic action classification**

Descry parses the raw command into a typed class before evaluating it. It tokenizes shell commands correctly — handling quotes, escapes, and flags — so `git push -f origin main` is `GitRewrite` and `git push origin feature/fix` is not. `cargo test` is `ShellTest`. `aws rds delete-db-instance` is `CloudDelete`. This class feeds every downstream layer.

**2. Task inference without configuration**

The engine builds a `TaskEnvelope` from whatever context is available: the active task string, the user's last prompt, the current branch, recently edited files, and the project index. It tokenizes and scores these against the proposed action to get a `confidence` between 0.0 and 0.85:

| Signal | Confidence |
|---|---|
| Active task + path match | 0.85 |
| Active task + term match | 0.75 |
| User prompt + path + term | 0.70 |
| Branch name + term match | 0.50 |
| Recent files only | 0.40 |
| No signal | 0.20 |

**3. Instruction provenance tracking**

Every action carries where its instruction originated:

| Provenance | Meaning |
|---|---|
| `user` | Typed directly by the human |
| `agent_reasoning` | Agent's own plan |
| `tool_output` | Result of a tool call |
| `repo_content` | Something the agent read from the repo |
| `web_content` | Something the agent fetched from the web |

`tool_output`, `repo_content`, and `web_content` are the prompt injection surface. Instructions from these sources that drive irreversible destructive actions are treated as potentially hijacked.

**4. Drift and hijack detection**

This is the core inference. It's a pure function: no LLM, no network:

```
external provenance + destructive class + irreversible → Block
external provenance + destructive class + reversible   → RequireApproval
low task confidence + destructive class                → RequireApproval
everything else from user or agent                     → None
```

The P3 scenario — agent told to "fix staging 401", reads a token from a tool response, attempts `aws rds delete-db-instance` — hits the first branch: `ToolOutput` provenance + `CloudDelete` class + `reversible: false` = `HighConfidence` block. The reason string says: *"instruction came from tool output, not from the user."*

<img src="docs/assets/drift-sequence.png" alt="Drift detection sequence: tool_output → CloudDelete → BLOCKED" width="100%" />

**5. Asset sensitivity**

The project asset graph maps file paths and service targets to sensitivity tiers and default actions. `.env.production` is `critical/block`. `.github/workflows/` is `infra/require_approval`. `src/**` is `source/allow_if_context_matches`. When context confidence is high enough (score ≥ 60), normal source files go through without friction. When the agent is editing something it has no business touching, it requires a human.

---

## What it blocks

The bundled `policies/safe-defaults.yml` hard-blocks the following without configuration:

| Category | Examples |
|---|---|
| Catastrophic local deletion | `rm -rf /`, `rm -rf ~`, `rm -rf $HOME` and variants |
| Protected branch rewrites | `git push -f origin main`, `git push --force release/*` |
| Cloud control-plane destruction | `aws rds delete-db-instance`, `gcloud sql instances delete`, `fly volumes destroy`, `railway volume delete`, `vercel project remove`, `az group delete` |
| Destructive database operations | `DROP DATABASE`, `DROP TABLE`, `TRUNCATE TABLE`, `DELETE FROM` without `WHERE` |
| Production MCP endpoints | Calls matching `prod`, `production`, `admin`, `control-plane` patterns |
| Destructive MCP tools | `delete_project`, `destroy_volume`, `drop_database`, and matching patterns |
| Dangerous MCP argument keys | `confirm_destroy`, `force_delete`, `delete_confirmation` — without recording raw values |

The defaults are intentionally conservative. Descry earns trust by letting normal work through without friction.

---

## Policy layers

```
policies/safe-defaults.yml          ← Tier-1 hard blocks. Versioned policy pack.
                                      schema_version: 1, pack_version: "0.1.0"
                                      These cannot be approved away.

.descry/project.yml                 ← Project asset and action defaults.
                                      secrets, infra, source, deploys, installs.
                                      These can be approved with a TTL.
```

Test a fixture against the full engine:

```bash
descry policy test fixtures/railway-delete.json --expect block
descry policy test fixtures/cargo-test.json --expect allow
```

Enforce a precision gate against the fixture corpus:

```bash
descry policy precision --manifest fixtures/manifest.yml --min-precision 0.95
```

---

## Approvals

When the engine returns `require_approval`, the agent pauses and you grant a time-bounded, scoped override:

```bash
# Approve writes to auth code for 30 minutes
descry approve --scope "path:src/auth/**" --ttl 30m

# Approve the deploy action for 1 hour
descry approve --scope "action:deploy" --ttl 1h

# Approve a specific MCP endpoint for 10 minutes
descry approve --scope "mcp:https://prod-mcp.example.com/**" --ttl 10m
```

Approvals are typed. A `path:` approval does not unlock `action:` or `mcp:` blocks.

---

## Shadow mode

Before a new rule can produce real blocks, run it in shadow mode to measure false positives:

```bash
cat action.json | descry evaluate --stdin --shadow
# → { "decision": "allow_with_log", "reason": "[shadow] catastrophic root or home deletion ..." }
```

In shadow mode, `block` verdicts become `allow_with_log` and the reason is prefixed with `[shadow]`. The action runs, the decision is logged. Measure precision before the rule goes live.

---

## Audit log

Every decision is recorded in a tamper-evident, hash-chained JSONL log:

```bash
descry logs verify                        # verify chain integrity
descry logs tail -n 20                    # stream recent decisions
descry logs search 'asset:production'     # full-text search
```

The chain uses SHA-256 binary Merkle trees over 100-record batches. A `descry-verify` standalone binary can check integrity and export a self-contained proof bundle without the full CLI runtime:

```bash
descry-verify --chain .descry/audit.log
descry-verify --chain .descry/audit.log --export-bundle
```

---

## Baseline explain

After Descry has observed traffic, explain why it trusts or distrusts a given pattern:

```bash
descry baseline explain claude-code shell.exec "cargo test"
# → { "familiarity": "familiar", "observed_count": 47, "first_seen_epoch": ..., "last_seen_epoch": ... }

descry baseline explain claude-code shell.exec "rm -rf ~"
# → { "familiarity": "unseen", "observed_count": 0 }
```

Familiarity tiers: `unseen` · `rare` · `occasional` · `familiar`

---

## CLI reference

```bash
# Hooks
descry hook install claude
descry hook install codex
descry hook install cursor
descry hook install git            # pre-push secret scan

# Project
descry init
descry init --all                  # init + hook install + project index
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

# Policy testing
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
descry evaluate --stdin --shadow   # shadow mode

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

# Standalone verifier (no CLI runtime required)
descry-verify --chain .descry/audit.log
descry-verify --chain .descry/audit.log --export-bundle
```

---

## Workspace layout

| Crate | Role |
|---|---|
| `descry-core` | ACP schema, decision types, action classification, drift signal, task inference |
| `descry-policy` | Policy DSL loader, hard-block matchers, SQL-aware pattern engine |
| `descry-adapters` | Claude Code, Codex, Cursor hook normalization |
| `descry-engine` | Full evaluation pipeline: tier-one, asset, behavior, approvals, drift |
| `descry-context` | Project index and bounded session history |
| `descry-memory` | Approvals store, behavior counters, asset policy |
| `descry-audit` | Hash-chained JSONL audit log, Merkle checkpoints, export bundles |
| `descry-verify` | Standalone chain verifier — zero dependency on descry-cli |
| `descry-cli` | CLI, hook entrypoints, demos, doctor, scan, precision gate |
| `descry-daemon` | Local HTTP daemon (`GET /v1/status`, `POST /v1/approve`) |

---

## Trust boundary

Descry runs at normal user privileges. It cannot prevent a determined local attacker — a hostile process running as the same user can kill the hook process. **Its value is blocking accidental harm and prompt-injection-driven harm in normal developer workflows, not defeating a malicious local user.**

This boundary is intentional and stated plainly everywhere: in this README, in `descry doctor` output, and in `LICENSE-PROMISE.md`.

---

## Privacy

All data stays on your machine. Descry stores policy, state, approvals, behavior counters, and audit logs under `.descry/` by default. Shell command contents are not recorded in audit events. MCP argument values are not recorded. No telemetry, no cloud, no account required to use the open-source engine.

---

## Open source promise

The firewall engine, inspection pipeline, scope inference, policy schema, deterministic verdict, Merkle audit log, and standalone verifier are **Apache-2.0 forever**. No hot-path safety primitive will go behind a paywall.

Covered crates: `descry-core` · `descry-engine` · `descry-adapters` · `descry-policy` · `descry-audit` · `descry-verify` · `descry-context` · `descry-memory`

The future commercial platform — team policy sync, cloud audit retention, SSO, SIEM export, managed detection feeds — lives in a separate repository under a separate license and is never required to run Descry locally.

See [LICENSE-PROMISE.md](LICENSE-PROMISE.md) for the full binding commitment.

---

## Status

Alpha. The local engine is implemented and tested. The following all pass:

- `cargo test --workspace` — full test suite green
- `cargo build --release` — release binary builds
- `descry doctor` — all checks green with hooks installed
- `descry demo prod-delete --json` — P3 drift detection blocks
- `descry evaluate --stdin --shadow` — shadow mode downgrades block to allow_with_log
- `cargo test -p descry-engine corpus_precision` — precision gate ≥ 0.95 on 31-fixture corpus
- `descry-verify --chain .descry/audit.log` — standalone verifier exits cleanly

Before the first public tag:
- Publish the Homebrew tap
- Clean-machine README install test
- Tag v0.1.0

---

## Contributing

Contributions are welcome. The project is in alpha — the best contributions are small, testable changes to the engine, published policies, adapters, or demos.

```bash
git clone https://github.com/descry-dev/descry.git
cd descry
cargo test --workspace
```

Before opening a PR:

```bash
cargo fmt --check
cargo clippy --workspace -- -D warnings
cargo test --workspace
```

For policy changes, add or update a fixture in `fixtures/` and add it to the fixture manifest. Every new hard block must have a real-world incident or failure mode documented in the PR.

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full guide.

---

## Security

Do not file public issues for security vulnerabilities. See [SECURITY.md](SECURITY.md).

---

<div align="center">

**[Website](https://descry.app)** · **[LICENSE-PROMISE.md](LICENSE-PROMISE.md)** · **[CONTRIBUTING.md](CONTRIBUTING.md)** · **[SECURITY.md](SECURITY.md)**

Apache-2.0 · No paywall on safety

</div>
