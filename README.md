# Descry Guard

[![CI](https://github.com/descry-dev/descry/actions/workflows/ci.yml/badge.svg)](https://github.com/descry-dev/descry/actions/workflows/ci.yml)
[![Website](https://img.shields.io/badge/website-descry.app-111827.svg)](https://descry.app)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.75%2B-orange.svg)](https://www.rust-lang.org/)
[![Status](https://img.shields.io/badge/status-alpha-yellow.svg)](#status)

Descry Guard is a local, open-source action firewall for AI coding agents. It installs into Claude Code, Cursor, and Codex, infers task context from the session and repository, and blocks dangerous or off-context actions before execution.

The open-source repository contains the local engine, policy packs, adapters, CLI, demos, and hash-chained audit primitives. The future commercial platform is separate: team policy sync, cloud audit retention, SSO, SIEM export, and managed detection feeds.

## Why Descry Exists

AI coding agents now run shell commands, edit files, call MCP tools, and touch cloud control planes. Markdown rules are not enough when an agent can find a production token and issue a destructive command in seconds.

Descry Guard gives those actions a deterministic preflight check:

- What is the agent trying to do?
- Does it match the current task?
- Does it touch a sensitive asset?
- Is it a known catastrophic pattern?
- Should it be allowed, logged, require approval, or blocked?

## Status

Alpha. The engine is usable for local demos and policy regression tests, but the public install flow and full v0.1 product surface are still in progress.

V1 public claims are tracked in [docs/V1_LAUNCH_CONTRACT.md](docs/V1_LAUNCH_CONTRACT.md) and [docs/V1_CLAIM_MATRIX.md](docs/V1_CLAIM_MATRIX.md).

Current capabilities:

- Local Rust CLI: `descry`
- Safe-default policy pack for Tier-1 catastrophic actions
- Claude Code, Codex, and Cursor hook normalization
- Codex `apply_patch` path extraction without storing patch contents
- Cursor MCP policy matching by target, tool summary, and safe argument keys
- Typed scoped TTL approvals for paths, actions, and MCP targets
- Project asset and action defaults from `.descry/project.yml`
- Hash-chained local audit log verification
- Hook installation, doctor checks, and `doctor --fix` repair
- Minimal project initialization with `.descry/project.yml`, state, memory, and index generation
- Staged and pre-push secret scanning
- Reproducible launch demos: `in-task-edit`, `off-task-edit`, `secret-access`, `rm-rf`, `mcp-poison`, `prod-delete`, `pocketos`

Alpha limitations:

- published Homebrew tap
- daemon remains an experimental local HTTP route skeleton, not the full hook runtime path

## Quickstart

Release install:

```bash
curl -fsSL https://raw.githubusercontent.com/descry-dev/descry/main/scripts/install.sh | sh
descry init --all
descry demo in-task-edit
```

Installer settings:

```bash
DESCRY_VERSION=0.1.0
DESCRY_INSTALL_MODE=release
DESCRY_INSTALL_DIR=$HOME/.local/bin
```

Source checkout install:

```bash
git clone https://github.com/descry-dev/descry.git
cd descry
DESCRY_INSTALL_MODE=source DESCRY_SOURCE_DIR=$PWD sh scripts/install.sh
descry init --all --dry-run
descry demo in-task-edit
descry demo off-task-edit
```

Or install directly with Cargo from a checkout:

```bash
cargo install --locked --path crates/descry-cli
```

Expected demo shape:

```text
descry demo off-task-edit
loaded policies/safe-defaults.yml
prompt/context: fix login session expiry while agent edits deployment workflow
inferred task: fix/session-expiry
proposed action: .github/workflows/deploy.yml
classified action: FileWrite
asset match: infra sensitivity=high default_action=require_approval
decision: require_approval
reason: high write target .github/workflows/deploy.yml requires scoped approval (asset: infra)
without Descry: deployment workflow changes without an explicit approval checkpoint
```

For a real checkout, run `descry init --all` from the project root. It creates `.descry/project.yml`, `.descry/state/`, `.descry/memory/`, and `.descry/state/project-index.json`, then installs project-local Claude, Codex, Cursor, and Git hooks. Use plain `descry init` when you want project files without hook installation.

## Supported Agents

Descry currently ships hook installers and hook entrypoints for:

- Claude Code: `descry hook install claude`
- Codex: `descry hook install codex`
- Cursor shell execution: `descry hook install cursor`
- Cursor MCP calls: `descry hook cursor before-mcp-execution`

## What It Blocks Today

The bundled `policies/safe-defaults.yml` policy currently blocks:

- Catastrophic `rm -rf` root/home patterns
- Force pushes to protected branches
- Destructive Railway, Fly, Vercel, AWS, GCP, and Azure control-plane commands
- Destructive database operations such as `DROP DATABASE`, `DROP TABLE`, `TRUNCATE TABLE`, and `DELETE FROM ...` without `WHERE`
- Production/admin MCP endpoints
- Destructive MCP tool names
- Dangerous MCP confirmation/destruction argument keys, without recording raw argument values

The defaults are intentionally conservative. Descry should block things that are obviously unsafe before it expands into broader ask/approve behavior.

Policy layers are split on purpose: `policies/safe-defaults.yml` is the versioned hard-block policy pack (`schema_version: 1`, `pack_version: "0.1.0"`), while `.descry/project.yml` owns project asset and action defaults such as secrets, infra, source files, deploys, installs, and MCP writes. `descry policy test` evaluates fixtures through the full local engine by default; use `--hard-block-only` only when testing the policy pack matcher in isolation.

## Context Inference

Descry does not require users to manually set a task for normal operation. Hook calls and demos build an inferred task envelope from branch names, recent files, harness context, project index data, and static asset rules. The engine then combines that task with the classified action and asset match.

Examples:

- `src/auth/session.ts` on branch `fix/session-expiry` maps to normal source work and can be allowed.
- `.github/workflows/deploy.yml` during that same task maps to high-sensitivity infra and requires approval.
- `.env.production` maps to critical secrets and is blocked.

Approvals are typed so broad path approvals do not silently apply to MCP or shell hard blocks. Prefer scopes such as `path:src/auth/**`, `action:deploy`, and `mcp:https://prod-mcp.example.com/**`. Tier-1 shell hard blocks are not generally approvable in V1.

## CLI Surface

Implemented:

```bash
descry demo in-task-edit
descry demo pocketos
descry demo rm-rf
descry demo secret-access
descry demo off-task-edit
descry demo mcp-poison
descry demo prod-delete
descry init
descry init --dry-run
descry init --all
descry context build
descry context show
descry scan secrets
descry scan secrets --staged
descry hook install claude
descry hook install codex
descry hook install cursor
descry hook install git
descry task set "Fix login session expiry"
descry task get
descry task clear
descry approve --scope "path:src/auth/**" --ttl 30m
descry approve --scope "action:deploy" --ttl 30m
descry approve --scope "mcp:https://prod-mcp.example.com/**" --ttl 10m
descry approvals list
descry logs verify
descry logs tail
descry logs search 'asset:production'
descry policy test fixtures/railway-delete.json --expect block
descry doctor
descry doctor --fix
descry doctor --agent git --fix
```

Hook targets:

```bash
descry hook claude pretooluse
descry hook codex pretooluse
descry hook cursor before-shell-execution
descry hook cursor before-mcp-execution
```

Git hook install:

```bash
descry hook install git
```

This writes `.git/hooks/pre-push` and runs `descry scan secrets --staged` before pushes.

## Architecture

```text
agent hook payload
  -> adapter normalizer
  -> Action Context Packet
  -> project/context/task inference
  -> action classifier
  -> shared local evaluation engine
  -> allow / ask / require_approval / block
  -> hash-chained audit record
```

Workspace layout:

```text
crates/descry-core      ACP, decisions, risk types
crates/descry-policy    policy loader and matchers
crates/descry-adapters  Claude, Codex, Cursor normalization
crates/descry-cli       CLI, hooks, approvals, demos
crates/descry-context   project index and bounded session history
crates/descry-audit     tamper-evident JSONL audit chain
crates/descry-memory    approvals, asset policy, behavior counters
crates/descry-daemon    local HTTP route skeleton
policies/               published policy packs
fixtures/               policy regression fixtures
```

## Trust Boundary

Descry Guard runs with normal user privileges. It provides detection, friction, and auditability. It is not a kernel sandbox, and a hostile process running as the same user can disable it.

This boundary is intentional. The product goal is to prevent agent mistakes and policy violations in normal developer workflows, not to contain malware on a compromised machine.

## Local Privacy

Descry stores local policy, state, approvals, behavior counters, and audit logs under `.descry/` by default. Session history stores sanitized targets, action types, decisions, and prompt text when a harness exposes it; MCP argument values and sensitive file contents are not recorded.

No cloud service is required for the open-source engine. Future commercial sync, SSO, and managed retention features are outside this local trust boundary.

## Audit Verification

Decisions can be written as a hash-chained JSONL audit log. Verify an audit log with:

```bash
descry logs verify --path .descry/audit.log
descry logs tail --path .descry/audit.log -n 20
descry logs search 'destructive' --path .descry/audit.log
```

The verifier reports whether the chain is intact or where tampering is detected.

## Open Source Commitment

The engine and published policy packs are Apache-2.0. See [LICENSE](LICENSE) and [LICENSE-PROMISE.md](LICENSE-PROMISE.md).

We will not relicense the local engine or published policy packs into a more restrictive license. Commercial work belongs around the engine: cloud audit, team policy management, SSO/RBAC, SIEM export, and managed detection feeds.

## Development

Run the full local gate:

```bash
cargo fmt --check
cargo clippy --workspace -- -D warnings
cargo test --workspace
```

Build local release artifacts:

```bash
sh scripts/package.sh 0.1.0
sh scripts/homebrew_formula.sh 0.1.0
ls dist/
```

Useful focused tests:

```bash
cargo test -p descry-policy
cargo test -p descry-cli --test policy_test
cargo test -p descry-cli --test cursor_hook
cargo test -p descry-cli --test demo
```

## Security

Please do not file public issues for vulnerabilities. See [SECURITY.md](SECURITY.md).

## Contributing

Contributions are welcome while the project is in alpha. Start with [CONTRIBUTING.md](CONTRIBUTING.md), keep changes small, and include regression fixtures for policy behavior.
