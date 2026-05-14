# Descry Guard V1 Claim Matrix

Status values:

- `implemented`: the repository contains implementation and at least one direct test or verification path.
- `partial`: some implementation exists, but the claim needs qualification or remaining V1 ticket work.
- `planned`: roadmap or execution-plan work, not launch copy unless described as future work.
- `not_v1`: explicitly outside the V1 local open-source launch contract.

Launch copy allowed values:

- `yes`: may be stated as current behavior.
- `qualified`: may be stated only with the limitation in the claim row.
- `roadmap`: may be stated only as future or planned work.
- `no`: must not be stated as V1 behavior.

| Claim | Status | Implementation path | Test path | Launch copy allowed |
|---|---|---|---|---|
| Descry Guard is a local, open-source action firewall for AI coding agents. | implemented | `crates/descry-core`, `crates/descry-policy`, `crates/descry-engine`, `crates/descry-cli`, `policies/safe-defaults.yml` | `cargo test --workspace` | yes |
| Descry installs into Claude Code, Codex, and Cursor. | implemented | `crates/descry-cli/src/commands/hook.rs`, `crates/descry-adapters/src/{claude,codex,cursor}.rs` | `cargo test -p descry-cli --test hook_install --test claude_hook --test codex_hook --test cursor_hook --no-fail-fast` | yes |
| Supported host surfaces are Claude Code PreToolUse, Codex PreToolUse, Cursor shell hook, and Cursor MCP hook. | implemented | `crates/descry-cli/src/commands/hook.rs`, `crates/descry-cli/tests/fixtures/hook_contracts/**` | `cargo test -p descry-cli --test hook_contracts --test claude_hook --test codex_hook --test cursor_hook --no-fail-fast` | yes |
| Descry infers task context from session and repository context without manual task setup for normal use. | implemented | `crates/descry-cli/src/commands/context.rs`, `crates/descry-context/src/lib.rs`, `crates/descry-core/src/runtime.rs` | `cargo test -p descry-cli --test context --test task --test demo --no-fail-fast` | yes |
| Decisions are grounded in inferred task context and codebase context, not just allowlists. | implemented | `crates/descry-engine/src/lib.rs`, `crates/descry-policy/src/matcher.rs`, `crates/descry-context/src/lib.rs` | `cargo test -p descry-cli --test evaluate --test demo --no-fail-fast` | yes |
| Descry blocks dangerous or off-context actions before execution. | implemented | `crates/descry-engine/src/lib.rs`, `crates/descry-policy/src/evaluate.rs`, supported hook commands | `cargo test -p descry-cli --test policy_test --test evaluate --test demo --no-fail-fast` | yes |
| Protected actions include shell commands, file reads, file writes, git operations, secrets, deploys, destructive cloud commands, destructive database commands, and MCP tools. | implemented | `crates/descry-core/src/acp.rs`, `crates/descry-policy/src/matcher.rs`, `policies/safe-defaults.yml` | `cargo test -p descry-policy`; `cargo test -p descry-cli --test evaluate --test policy_test --no-fail-fast` | yes |
| Safe-default policy blocks Tier-1 catastrophic actions. | implemented | `policies/safe-defaults.yml`, `crates/descry-policy/src/evaluate.rs` | `cargo test -p descry-policy`; `cargo run --quiet -p descry-cli -- policy test fixtures/rm-rf-home.json --expect block` | yes |
| Catastrophic `rm -rf` root/home patterns are blocked. | implemented | `policies/safe-defaults.yml` | `cargo run --quiet -p descry-cli -- policy test fixtures/rm-rf-home.json --expect block`; `cargo run --quiet -p descry-cli -- policy test fixtures/rm-rf-slash.json --expect block` | yes |
| Force pushes to protected branches are blocked. | implemented | `policies/safe-defaults.yml` | `cargo run --quiet -p descry-cli -- policy test fixtures/force-push-main.json --expect block`; `cargo run --quiet -p descry-cli -- policy test fixtures/force-push-release.json --expect block` | yes |
| Destructive Railway, Fly, Vercel, AWS, GCP, and Azure control-plane commands are blocked by defaults. | implemented | `policies/safe-defaults.yml`, cloud fixtures under `fixtures/**`, `fixtures/manifest.yml` | `cargo test -p descry-policy --test safe_defaults`; `cargo test -p descry-cli --test policy_test` | yes |
| Destructive database operations such as `DROP`, `TRUNCATE`, and unsafe `DELETE FROM` are blocked. | implemented | `policies/safe-defaults.yml`, `crates/descry-policy/src/matcher.rs` | `cargo run --quiet -p descry-cli -- policy test fixtures/db-drop-database.json --expect block`; `cargo test -p descry-policy` | yes |
| Production/admin MCP endpoints, destructive MCP tool names, and dangerous MCP arguments are blocked without recording raw argument values. | implemented | `crates/descry-adapters/src/cursor.rs`, `crates/descry-policy/src/matcher.rs`, `policies/safe-defaults.yml` | `cargo test -p descry-cli --test cursor_hook --test hook_contracts --no-fail-fast` | yes |
| Codex `apply_patch` path extraction avoids storing patch contents. | implemented | `crates/descry-adapters/src/codex.rs` | `cargo test -p descry-cli --test codex_hook` | yes |
| Typed scoped TTL approvals exist for paths, actions, and MCP targets. | implemented | `crates/descry-cli/src/commands/approve.rs`, `crates/descry-memory/src/lib.rs` | `cargo test -p descry-cli --test approve` | yes |
| Broad path approvals do not silently apply to MCP or shell hard blocks. | implemented | `crates/descry-memory/src/lib.rs`, `crates/descry-engine/src/lib.rs` | `cargo test -p descry-cli --test approve --test evaluate --no-fail-fast` | yes |
| Project asset and action defaults come from `.descry/project.yml`. | implemented | `crates/descry-memory/src/lib.rs`, `crates/descry-cli/src/commands/init.rs` | `cargo test -p descry-policy --test project_policy`; `cargo test -p descry-cli --test init` | yes |
| `descry init` creates `.descry/project.yml`, state, memory, and project index data. | implemented | `crates/descry-cli/src/commands/init.rs`, `crates/descry-cli/src/commands/context.rs` | `cargo test -p descry-cli --test init --test context --no-fail-fast` | yes |
| Hook installation, doctor checks, and `doctor --fix` repair are available. | implemented | `crates/descry-cli/src/commands/hook.rs`, `crates/descry-cli/src/commands/doctor.rs` | `cargo test -p descry-cli --test hook_install --test doctor --no-fail-fast` | yes |
| Staged and pre-push secret scanning is available. | implemented | `crates/descry-cli/src/commands/scan.rs`, git hook install path in `crates/descry-cli/src/commands/hook.rs` | `cargo test -p descry-cli --test scan --test hook_install --no-fail-fast` | yes |
| Hash-chained local audit log verification is available. | implemented | `crates/descry-audit/src/**`, `crates/descry-cli/src/commands/logs.rs` | `cargo test -p descry-audit`; `cargo test -p descry-cli --test logs_verify` | yes |
| `descry logs tail` and `descry logs search` are available. | implemented | `crates/descry-cli/src/commands/logs.rs` | `cargo test -p descry-cli --test logs_verify` | yes |
| Reproducible launch demos exist for `in-task-edit`, `off-task-edit`, `secret-access`, `rm-rf`, `mcp-poison`, `prod-delete`, and `pocketos`. | implemented | `crates/descry-cli/src/commands/demo.rs` | `cargo test -p descry-cli --test demo` | yes |
| `descry demo pocketos`, `descry demo rm-rf`, and `descry demo mcp-poison` are launch demos. | implemented | `crates/descry-cli/src/commands/demo.rs` | `cargo test -p descry-cli --test demo`; `cargo run --quiet -p descry-cli -- demo pocketos --json`; `cargo run --quiet -p descry-cli -- demo rm-rf --json`; `cargo run --quiet -p descry-cli -- demo mcp-poison --json` | yes |
| Source installer exists. | implemented | `scripts/install.sh` | `DESCRY_SOURCE_DIR="$PWD" CARGO_INSTALL_ROOT=/tmp/descry-v1-install sh scripts/install.sh` | yes |
| Release artifact packaging exists. | implemented | `.github/workflows/release.yml`, `scripts/package.sh` | `sh scripts/package.sh 0.1.0` | yes |
| Homebrew formula generation exists. | implemented | `scripts/homebrew_formula.sh` | `sh scripts/homebrew_formula.sh 0.1.0` | yes |
| Published Homebrew tap exists. | planned | release publication work outside this repository tree | Manual release verification after tap publication | roadmap |
| Clean-machine README install is verified outside a development checkout. | planned | final release-gate machine or container | `cargo install --locked --path crates/descry-cli --root /tmp/descry-v1-cargo-root`; `DESCRY_SOURCE_DIR="$PWD" CARGO_INSTALL_ROOT=/tmp/descry-v1-install sh scripts/install.sh` | roadmap |
| Daemon is the V1 runtime path. | not_v1 | `crates/descry-daemon` is currently a local HTTP route skeleton | `rg -n "daemon" README.md ROADMAP.md docs` manual copy review | no |
| Current daemon is experimental and not the full hook runtime path. | implemented | `crates/descry-daemon`, README alpha limitation, ROADMAP boundary | `rg -n "daemon" README.md ROADMAP.md docs` manual copy review | yes |
| MCP gateway proxy exists. | not_v1 | No V1 implementation; explicit launch-contract exclusion | `rg -n "MCP gateway" README.md ROADMAP.md docs` manual copy review | no |
| Cloud platform/team policy sync, SSO/RBAC/SCIM, SIEM export, managed audit retention, org-wide MCP allowlist, and managed detection feeds are future commercial features. | not_v1 | No local repository implementation | Public copy may mention only as future commercial roadmap, not V1 local behavior | roadmap |
| No cloud account is required for the open-source local engine. | implemented | local CLI architecture and absence of cloud dependency in runtime crates | `cargo test --workspace`; manual copy review | yes |
| Analysis happens locally and no cloud service is required. | implemented | local CLI/runtime crates | `cargo test --workspace`; manual copy review | yes |
| Session history stores sanitized targets, action types, decisions, and prompt text when a harness exposes it; MCP argument values and sensitive file contents are not recorded. | implemented | `crates/descry-context/src/lib.rs`, `crates/descry-adapters/src/**`, `crates/descry-audit/src/**` | `cargo test -p descry-cli --test context --test claude_hook --test codex_hook --test cursor_hook --no-fail-fast`; `cargo test -p descry-audit` | yes |
| Descry provides detection, friction, and auditability, not kernel sandbox containment. | implemented | README trust boundary, user-space CLI architecture | Manual copy review | yes |
| The local engine and published policy packs are Apache-2.0 and will not be relicensed into a more restrictive license. | implemented | `LICENSE`, `LICENSE-PROMISE.md` | Manual file review | yes |

## Website Claim Inventory

The public website currently lives outside this repository at `/home/aniol/Documents/Descry/descry-website/src/App.jsx`. DG-V1-000 records its launch-sensitive claims here; DG-V1-170 must align the website text with the final matrix before release.

| Website claim | Matrix row to use | Launch copy allowed |
|---|---|---|
| "Installs into your AI coding agent, infers task context from the session and repository, and blocks dangerous or off-context actions before execution." | install, task inference, pre-execution block rows | yes |
| "Every decision is grounded in inferred task context and your codebase - not just allowlists." | task/codebase context row | yes |
| "Stops dangerous actions before they run." | pre-execution block row | yes |
| "Local-first. No cloud account required." | local/no-cloud rows | yes |
| "Scoped approvals and hash-chained local decision logs." | approvals and audit rows | yes |
| "Descry reads session, branch, recent files, and project index context." | context gathering row | yes |
| "Decisions are enforced before execution, with clear reasons." | supported hooks and host-specific explanation rows in launch contract | yes |
| "Run: descry demo pocketos." | demo rows | yes |
| "What Descry protects" action grid: shell, file edits, git, MCP, deployments, secrets, database, cloud. | protected action classes row | yes |
| "Managed team features are roadmap work" and "Policy sync, SSO, SIEM export, and managed audit retention." | commercial platform row | roadmap |
