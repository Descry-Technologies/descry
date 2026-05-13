# Descry Guard

[![CI](https://github.com/descry-dev/descry/actions/workflows/ci.yml/badge.svg)](https://github.com/descry-dev/descry/actions/workflows/ci.yml)
[![Website](https://img.shields.io/badge/website-descry.app-111827.svg)](https://descry.app)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.75%2B-orange.svg)](https://www.rust-lang.org/)
[![Status](https://img.shields.io/badge/status-alpha-yellow.svg)](#status)

Descry Guard is a local, open-source action firewall for AI coding agents. It sits between tools like Claude Code, Cursor, and Codex and the actions they are about to take, then blocks known-catastrophic operations before they execute.

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

Current capabilities:

- Local Rust CLI: `descry`
- Safe-default policy pack for Tier-1 catastrophic actions
- Claude Code, Codex, and Cursor hook normalization
- Cursor MCP policy matching by target, tool summary, and safe argument keys
- Scoped TTL approvals
- Hash-chained local audit log verification
- Hook installation and doctor checks
- Reproducible launch demos: `pocketos`, `rm-rf`, `secret-access`, `off-task-edit`, `mcp-poison`, `prod-delete`

Not complete yet:

- `descry init`
- packaged installer / Homebrew tap
- staged secret scanning
- SQL-aware `DELETE FROM ...` without `WHERE`
- polished release artifacts

## Quickstart From Source

Prerequisites:

- Rust stable toolchain
- Git

```bash
git clone https://github.com/descry-dev/descry.git
cd descry
cargo test --workspace
cargo run -p descry-cli -- demo pocketos
```

Expected demo shape:

```text
WITH DESCRY                                      | WITHOUT DESCRY
-------------------------------------------------+---------------------------------------------
task: fix staging 401                            | same task: fix staging 401
agent finds Railway token                        | agent finds Railway token
action: curl DELETE api.railway.app volume       | action: curl DELETE api.railway.app volume
BLOCKED before execution                         | request is sent
production volume remains green                  | production volume deleted
backups remain intact                            | backups on same volume vanish

decision: block
reason: destructive hosted control-plane operation (rule: control-plane-delete)
```

## What It Blocks Today

The bundled `policies/safe-defaults.yml` policy currently blocks:

- Catastrophic `rm -rf` root/home patterns
- Force pushes to protected branches
- Destructive Railway, Fly, Vercel, AWS, GCP, and Azure control-plane commands
- Destructive database operations such as `DROP DATABASE`, `DROP TABLE`, and `TRUNCATE TABLE`
- Production/admin MCP endpoints
- Destructive MCP tool names
- Dangerous MCP confirmation/destruction argument keys, without recording raw argument values

The defaults are intentionally conservative. Descry should block things that are obviously unsafe before it expands into broader ask/approve behavior.

## CLI Surface

Implemented:

```bash
descry demo pocketos
descry demo rm-rf
descry demo secret-access
descry demo off-task-edit
descry demo mcp-poison
descry demo prod-delete
descry hook install claude
descry hook install codex
descry hook install cursor
descry task set "Fix login session expiry"
descry task get
descry task clear
descry approve --scope "src/auth/**" --ttl 30m
descry logs verify
descry policy test fixtures/railway-delete.json --expect block
descry doctor
```

Hook targets:

```bash
descry hook claude pretooluse
descry hook codex pretooluse
descry hook cursor before-shell-execution
descry hook cursor before-mcp-execution
```

## Architecture

```text
agent hook payload
  -> adapter normalizer
  -> Action Context Packet
  -> local policy evaluation
  -> approval layer
  -> allow / ask / require_approval / block
  -> hash-chained audit record
```

Workspace layout:

```text
crates/descry-core      ACP, decisions, risk types
crates/descry-policy    policy loader and matchers
crates/descry-adapters  Claude, Codex, Cursor normalization
crates/descry-cli       CLI, hooks, approvals, demos
crates/descry-audit     tamper-evident JSONL audit chain
crates/descry-memory    approvals, asset policy, behavior counters
crates/descry-daemon    local HTTP route skeleton
policies/               published policy packs
fixtures/               policy regression fixtures
```

## Trust Boundary

Descry Guard runs with normal user privileges. It provides detection, friction, and auditability. It is not a kernel sandbox, and a hostile process running as the same user can disable it.

This boundary is intentional. The product goal is to prevent agent mistakes and policy violations in normal developer workflows, not to contain malware on a compromised machine.

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
