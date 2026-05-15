# Changelog

All notable user-facing changes are documented here. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/). Versioning follows SemVer from v0.1.0.

---

## [Unreleased]

### Changed
- `descry doctor`: Codex and Cursor hook checks now return `ok: true` (skipped) when those tools are not installed, rather than failing on missing config files. If the tool IS installed but the hook is not configured, the check still fails as expected.

---

## [0.1.0] — Pending tag

First public release of the Descry action firewall.

### Engine

- Local deterministic evaluation engine — no LLM, no network, no configuration required for basic operation
- Five-layer evaluation pipeline: tier-one hard blocks → action classification → asset matching → behavior baseline → drift/hijack detection
- Verdicts: `allow`, `allow_with_log`, `require_approval`, `block`
- p95 < 50ms latency gate enforced in CI (release build); p50 < 25ms debug / < 10ms release
- Byte-identical output for identical inputs (determinism property test in CI)

### Policy

- Safe-default Tier-1 policy pack (`policies/safe-defaults.yml`, `schema_version: 1`, `pack_version: "0.1.0"`)
- Blocks: catastrophic `rm -rf` patterns, force-pushes to protected branches, destructive cloud control-plane operations (AWS, GCP, Azure, Railway, Fly, Vercel), destructive database operations (DROP, TRUNCATE, unbounded DELETE), production/admin MCP endpoints, destructive MCP tool names, dangerous MCP argument keys
- SQL-aware `DELETE FROM ...` without `WHERE` detection
- Policy DSL with `command_matches`, `command_regex`, `target_regex`, `summary_regex`, `argument_key_matches`
- Project-level asset and action defaults via `.descry/project.yml`
- `descry policy test <fixture> --expect <verdict>` — full engine evaluation
- `descry policy precision --manifest --min-precision` — corpus precision gate
- Corpus precision integration test: `cargo test -p descry-engine corpus_precision` (31-fixture corpus, ≥ 0.95 precision)

### Action classification

- Typed semantic action classes: `FileRead`, `FileWrite`, `SecretRead`, `ShellTest`, `ShellBuild`, `ShellInstall`, `ShellDelete`, `GitRead`, `GitRewrite`, `DatabaseDestroy`, `CloudDelete`, `Deploy`, `McpRead`, `McpWrite`, `McpDestroy`, `Unknown`
- Shell command tokenizer handling quotes, escapes, and flags
- Git classifier: `reset --hard`, `clean -fd`, `push --force` to protected branches
- Cloud delete classifier: AWS, GCP, Azure, Railway, Fly, Vercel CLI patterns + `curl -X DELETE` to platform APIs
- Database destroy classifier: SQL and MongoDB patterns

### Task inference

- Task envelope built from: active task, user prompt, branch name, recently edited files, project index
- Confidence scoring: 0.20 (no signal) → 0.85 (active task + path match)
- Term and path tokenization — branch `fix/session-expiry` correlates with `src/auth/session.ts`
- Multi-source matching: `ActiveTask`, `UserPrompt`, `Branch`, `RecentFiles`
- Project index built by `descry context build` and enriched on every evaluate call

### Drift and hijack detection

- Instruction provenance tracking: `user`, `agent_reasoning`, `tool_output`, `repo_content`, `web_content`
- Drift signal: `None`, `Suspicious`, `HighConfidence`
- `HighConfidence` block: external provenance + destructive class + irreversible action
- `Suspicious` → `RequireApproval`: external provenance + destructive class, or low task confidence + destructive class
- Reason string includes provenance chain: *"instruction came from tool output, not from the user"*

### Shadow mode

- `descry evaluate --stdin --shadow`: `Block` verdicts downgraded to `AllowWithLog`, reason prefixed with `[shadow]`
- Lets new rules run in observation mode before they produce real friction

### Behavior baseline

- Per-triple `(agent, action, target)` familiarity counters in `.descry/memory/behavior.json`
- Familiarity tiers: `unseen`, `rare`, `occasional`, `familiar`
- `descry baseline explain <agent> <action> <target>` — per-triple explanation JSON

### Approvals

- Typed scoped TTL approvals: `path:`, `action:`, `mcp:` scopes
- `descry approve --scope --ttl` — grant a time-bounded override
- `descry approvals list` — list active approvals
- Scope contracts for source-file writes with context matching
- Approval types are validated: `path:` does not unlock `mcp:` blocks

### Adapters

- Claude Code `PreToolUse` hook normalization
- Codex `PreToolUse` hook: `apply_patch` path extraction without storing patch contents
- Cursor shell `before_shell_execution` hook normalization
- Cursor MCP `before_mcp_execution` hook: target, tool summary, safe argument key matching (raw argument values not recorded)

### Audit

- Hash-chained JSONL audit log with SHA-256 binary Merkle trees over 100-record batches
- `descry logs verify` — verify chain integrity
- `descry logs tail -n <N>` — recent decisions
- `descry logs search <query>` — full-text search with structured metadata
- Export bundle: self-contained JSON proof exportable for compliance

### `descry-verify`

- Standalone binary — zero dependency on `descry-cli`
- `descry-verify --chain <path>` — verify chain, exits 0 on success or 1 on chain not found, never exits 2
- `descry-verify --chain <path> --export-bundle` — export proof bundle

### CLI

- `descry init` / `descry init --all` / `descry init --dry-run`
- `descry hook install claude / codex / cursor / git`
- `descry doctor` / `descry doctor --fix` / `descry doctor --agent <agent>`
- `descry task set / get / clear`
- `descry context build / show`
- `descry scan secrets` / `descry scan secrets --staged`
- `descry evaluate --stdin` / `--shadow` / `--no-context`
- `descry demo in-task-edit / off-task-edit / secret-access / rm-rf / mcp-poison / prod-delete / pocketos` (with `--json`)
- Hook entrypoints: `descry hook claude pretooluse`, `descry hook codex pretooluse`, `descry hook cursor before-shell-execution`, `descry hook cursor before-mcp-execution`
- All demos run with isolated temporary memory — local state cannot affect demo output

### Daemon

- Local HTTP daemon: `GET /v1/status`, `POST /v1/approve`, `POST /v1/evaluate`
- Experimental — not part of the V1 hook runtime

### Build and CI

- `cargo test --workspace` all green
- `cargo build --release` succeeds
- Latency gate: `cargo test -p descry-engine evaluate_latency --release`
- Corpus precision gate: `cargo test -p descry-engine corpus_precision`
- Release artifact packaging: `scripts/package.sh`
- Homebrew formula generation: `scripts/homebrew_formula.sh`
- Source installer: `scripts/install.sh`
