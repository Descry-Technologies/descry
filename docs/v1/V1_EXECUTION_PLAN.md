# Descry Guard V1 Execution Plan

Status: planning artifact
Scope: `/home/aniol/Documents/descry-code`
Ignored paths: `descryguard/**`
Last updated: 2026-05-14

This file is the resumable execution plan for turning the current alpha into the
promised Descry Guard V1. It is written for Claude as planner/reviewer and Codex
as implementer. Each ticket is intentionally scoped to about one day of focused
implementation. Do not merge tickets unless a human explicitly changes the
execution model.

## V1 Definition

Descry Guard V1 is launch-ready when a clean user can install one binary, run
project initialization, install hooks for supported coding agents, and receive
correct pre-execution decisions for shell, file, git, secret, deploy, cloud,
database, and MCP actions without manually setting task context for normal use.

The launch contract is:

1. Install into Claude Code, Codex, and Cursor.
2. Intercept shell, file, git, MCP, secret, deploy, cloud, and database actions
   through the supported harness surfaces.
3. Gather context from harness events, repo state, branch, recent files, recent
   commands, static project policy, and bounded session history.
4. Infer a task envelope without requiring manual user input.
5. Classify proposed actions structurally enough that V1 behavior is not raw
   regex only.
6. Match targets against asset sensitivity and action defaults.
7. Decide through one shared runtime path.
8. Keep normal in-context work quiet.
9. Block catastrophic actions decisively.
10. Require approval only for rare high-risk or ambiguous cases.
11. Write tamper-evident local audit records.
12. Explain every intervention in a useful host-specific message.

## Current Baseline

The current code already has:

- Rust workspace with `descry-core`, `descry-policy`, `descry-engine`,
  `descry-context`, `descry-memory`, `descry-audit`, `descry-adapters`,
  `descry-cli`, and `descry-daemon`.
- Safe-default hard blocks.
- Hook normalization/installers for Claude, Codex, and Cursor.
- Project policy defaults.
- Basic task inference from active task, prompt, branch, and recent files.
- Scoped TTL approvals for path/action/MCP plus inert rule/once parsing.
- Hash-chained local audit log.
- Launch demos.
- Passing `cargo test --workspace` as of this planning pass.

Known current gaps are folded into the tickets below. Do not rely on README
claims as implementation truth until ticket DG-V1-170 is complete.

## Resume Protocol

When resuming work:

1. Read this file.
2. Run `git status --short`.
3. Read the active ticket section.
4. Create or update `.claude/plan/<ticket>.md` from the ticket section using
   `/home/aniol/Documents/Descry/product/agentic-coding/plan-template.md`.
5. Set `agents/state.json` only if the existing dogfood loop requires it.
6. Codex implementer must edit only the ticket's allowed paths.
7. Run every acceptance test in the ticket.
8. Update this file only when a ticket is completed, split, or superseded.

Never use `git reset --hard`, never revert unrelated user edits, and never touch
`descryguard/**`.

## Global Gates

Run these after each ticket unless the ticket says otherwise:

```bash
cargo fmt --check
cargo clippy --workspace -- -D warnings
cargo test --workspace
```

Run these before declaring V1:

```bash
cargo install --locked --path crates/descry-cli --root /tmp/descry-v1-cargo-root
DESCRY_SOURCE_DIR="$PWD" CARGO_INSTALL_ROOT=/tmp/descry-v1-install sh scripts/install.sh
cargo test --workspace
```

## Ticket Map

| Ticket | Status | Title | Blocks |
|---|---|---|---|
| DG-V1-000 | complete 2026-05-14 | Freeze launch contract and claim matrix | all |
| DG-V1-010 | complete 2026-05-14 | Make release packages target-correct | DG-V1-020 |
| DG-V1-020 | complete 2026-05-14 | Make installer consume release artifacts | DG-V1-030 |
| DG-V1-030 | complete 2026-05-14 | Make init/doctor/hook install clean-machine reliable | DG-V1-040 |
| DG-V1-040 | complete 2026-05-14 | Introduce shared runtime context spine | DG-V1-050, DG-V1-060, DG-V1-130 |
| DG-V1-050 | complete 2026-05-14 | Enrich adapter outputs with safe harness metadata | DG-V1-060 |
| DG-V1-060 | complete 2026-05-14 | Replace shallow task inference with evidence builder | DG-V1-070 |
| DG-V1-070 | complete 2026-05-14 | Add scored task/action context matching | DG-V1-080 |
| DG-V1-080 | complete 2026-05-14 | Fix multi-target asset evaluation | DG-V1-090 |
| DG-V1-090 | complete 2026-05-14 | Add V1 structural action classifiers | DG-V1-100 |
| DG-V1-100 | complete 2026-05-14 | Stabilize policy DSL and policy test behavior | DG-V1-110 |
| DG-V1-110 | complete 2026-05-14 | Make approvals typed, validated, and actually enforced | DG-V1-120 |
| DG-V1-120 | complete 2026-05-14 | Harden host hook contracts and messages | DG-V1-130 |
| DG-V1-130 | pending | Complete audit/memory semantics | DG-V1-140 |
| DG-V1-140 | pending | Make demos reproducible launch tests | DG-V1-150 |
| DG-V1-150 | pending | Add fixture manifest and false-positive gate | DG-V1-160 |
| DG-V1-160 | pending | Decide daemon V1 surface and enforce parity or hide it | DG-V1-170 |
| DG-V1-170 | pending | Align public docs, README, roadmap, and website | release |

---

# DG-V1-000 - Freeze Launch Contract And Claim Matrix

Purpose: stop implementation drift by making every public claim testable.

## In Scope

- Add a V1 contract document.
- Add a claim matrix that maps each public claim to code, tests, or roadmap.
- Make future public copy edits depend on this matrix.

## Out Of Scope

- No runtime behavior changes.
- No README marketing rewrite beyond pointing to the new contract.

## Allowed Paths

- `docs/v1/**`
- `docs/**`
- `README.md`
- `ROADMAP.md`

## Blocked Paths

- `.git/**`
- `.descry/**`
- `target/**`
- `descryguard/**`
- `crates/**`
- `policies/**`
- `fixtures/**`

## Files

| Path | Action | Why |
|---|---|---|
| `docs/V1_LAUNCH_CONTRACT.md` | create | human-readable source of truth |
| `docs/V1_CLAIM_MATRIX.md` | create | map claims to tests/status |
| `README.md` | modify | link to contract and alpha limitations |
| `ROADMAP.md` | modify | make remaining V1 work explicit |

## Implementation Steps

1. Create `docs/V1_LAUNCH_CONTRACT.md`.
   - Include the 12 launch requirements from this plan.
   - Define supported hosts: Claude Code PreToolUse, Codex PreToolUse, Cursor
     shell hook, Cursor MCP hook.
   - Define supported actions: shell, file read, file write, git, secret,
     deploy, cloud destructive, database destructive, MCP read/write/destroy.
   - Define explicitly unsupported V1 surfaces: SaaS team policy sync, SSO,
     SIEM, broad cloud API proxy, finance workflows, CI/CD enforcement, MCP
     gateway proxy unless DG-V1-160 chooses to ship daemon/proxy support.

2. Create `docs/V1_CLAIM_MATRIX.md`.
   - Table columns: claim, status, implementation path, test path, launch copy
     allowed.
   - Status values: `implemented`, `partial`, `planned`, `not_v1`.
   - Add all README, ROADMAP, and website claims that mention install,
     supported hosts, protected actions, task inference, approvals, audit,
     demos, Homebrew, daemon, MCP, cloud platform, and team features.

3. Update `README.md`.
   - Add a short "V1 Contract" link near the Status section.
   - Do not expand marketing copy in this ticket.

4. Update `ROADMAP.md`.
   - Replace vague `v0.1 Remaining` with exact V1 blockers or a link to the
     claim matrix.

## Acceptance Tests

| # | Command | Expect |
|---:|---|---|
| 1 | `test -f docs/V1_LAUNCH_CONTRACT.md` | exit 0 |
| 2 | `test -f docs/V1_CLAIM_MATRIX.md` | exit 0 |
| 3 | `rg -n "V1_LAUNCH_CONTRACT|V1_CLAIM_MATRIX" README.md ROADMAP.md` | exit 0 |

## Risks

| Risk | Likelihood | Mitigation |
|---|---|---|
| Contract becomes stale | medium | DG-V1-170 must update it after implementation |

---

# DG-V1-010 - Make Release Packages Target-Correct

Purpose: ensure release artifacts actually contain binaries built for the target
named in their archive.

## In Scope

- Target-aware `scripts/package.sh`.
- Release workflow target setup.
- Package smoke test.
- CLI `--version` metadata.

## Out Of Scope

- Installer rewrite.
- Homebrew tap publishing.

## Allowed Paths

- `Cargo.lock`
- `Cargo.toml`
- `crates/descry-cli/src/lib.rs`
- `crates/descry-cli/tests/**`
- `.github/workflows/release.yml`
- `.github/workflows/ci.yml`
- `scripts/package.sh`
- `scripts/homebrew_formula.sh`

## Implementation Steps

1. Set a real workspace package version for V1 pre-release.
   - Use `0.1.0` unless human chooses another value.
   - Add `#[command(name = "descry", version)]` to the Clap root command.
   - Add a CLI test that `descry --version` contains `descry 0.1.0`.

2. Update `scripts/package.sh`.
   - Interpret `DESCRY_PACKAGE_TARGET` as a real Rust target triple.
   - Run `cargo build --locked --release --target "$TARGET" -p descry-cli`.
   - Copy from `target/$TARGET/release/descry`.
   - On Windows later, support `.exe`; for V1 non-Windows, fail clearly if
     target path is missing.
   - Write a per-archive sha256 and append all checksums to `SHA256SUMS`
     instead of overwriting it on every package build.

3. Update `.github/workflows/release.yml`.
   - Add `rustup target add ${{ matrix.target_name }}` before packaging.
   - Run packaged binary `--version` before upload.
   - Add a tag/version check:
     `cargo metadata --no-deps` package version must equal `${GITHUB_REF_NAME#v}`.

4. Update CI.
   - Add a Linux dry-run package job with `DESCRY_PACKAGE_TARGET` set to the
     host target.
   - Run `tar -tzf` and binary `--help` from the extracted archive.

## Acceptance Tests

| # | Command | Expect |
|---:|---|---|
| 1 | `cargo test -p descry-cli -- --version` | exit 0 if test name exists, otherwise use full cli tests |
| 2 | `DESCRY_PACKAGE_TARGET="$(rustc -vV \| awk '/host:/ {print $2}')" DESCRY_DIST_DIR=/tmp/descry-dist sh scripts/package.sh 0.1.0` | exit 0 |
| 3 | `tar -tzf /tmp/descry-dist/descry-0.1.0-$(rustc -vV \| awk '/host:/ {print $2}').tar.gz \| rg '/descry$'` | exit 0 |
| 4 | `cargo fmt --check` | exit 0 |
| 5 | `cargo test --workspace` | exit 0 |

## Risks

| Risk | Likelihood | Mitigation |
|---|---|---|
| Cross-target builds fail for missing linker | medium | CI should test host build first; release matrix may need target-specific runners |

---

# DG-V1-020 - Make Installer Consume Release Artifacts

Purpose: users should not need Rust or Git for normal installation.

## In Scope

- Release tarball install path.
- Checksum verification.
- Source install fallback.
- Isolated installer smoke tests.

## Out Of Scope

- Hook installation.
- Homebrew tap publishing.

## Allowed Paths

- `scripts/install.sh`
- `.github/workflows/ci.yml`
- `README.md`
- `SUPPORT.md`

## Implementation Steps

1. Add OS/arch detection to `scripts/install.sh`.
   - Map `uname -s` and `uname -m` to supported triples:
     `x86_64-unknown-linux-gnu`, `aarch64-apple-darwin`.
   - If unsupported, print supported targets and exit 2.

2. Add release artifact mode.
   - Inputs:
     - `DESCRY_VERSION`, default `latest`.
     - `DESCRY_RELEASE_BASE_URL`, default GitHub releases URL.
     - `DESCRY_INSTALL_DIR`, default `$HOME/.local/bin`.
     - `DESCRY_INSTALL_MODE`, values `release` or `source`.
   - For `release`, download archive and `.sha256`.
   - Verify checksum with `shasum -a 256` or `sha256sum`.
   - Extract and install `descry` with mode `0755`.

3. Preserve source fallback.
   - `DESCRY_INSTALL_MODE=source` keeps current clone/cargo path.
   - `DESCRY_SOURCE_DIR` keeps local checkout install path.
   - Source mode must still honor `CARGO_INSTALL_ROOT`.

4. Add isolated CI smoke.
   - `DESCRY_SOURCE_DIR=$PWD CARGO_INSTALL_ROOT=/tmp/descry-cargo-root sh scripts/install.sh`.
   - Run `/tmp/descry-cargo-root/bin/descry --help`.
   - Do not hit the network in CI source smoke.

5. Update README quickstart.
   - Clearly separate "release install" and "source checkout install".
   - Do not say Homebrew works until DG-V1-170 verifies the tap.

## Acceptance Tests

| # | Command | Expect |
|---:|---|---|
| 1 | `DESCRY_SOURCE_DIR="$PWD" CARGO_INSTALL_ROOT=/tmp/descry-v1-source-root sh scripts/install.sh` | exit 0 |
| 2 | `/tmp/descry-v1-source-root/bin/descry --help` | exit 0 |
| 3 | `rg -n "DESCRY_INSTALL_MODE|DESCRY_VERSION|DESCRY_INSTALL_DIR" scripts/install.sh README.md` | exit 0 |

## Risks

| Risk | Likelihood | Mitigation |
|---|---|---|
| Shell portability issues | medium | keep POSIX sh, avoid bash arrays |

---

# DG-V1-030 - Make Init Doctor Hook Install Clean-Machine Reliable

Purpose: one command path should initialize project state, install hooks, and
repair common launch setup problems.

## In Scope

- `descry init --all`.
- Absolute hook command defaults.
- Agent-scoped doctor.
- Git pre-push doctor checks.
- Worktree-safe git hook path resolution.

## Out Of Scope

- Installer tarball changes.
- Runtime decision behavior.

## Allowed Paths

- `crates/descry-cli/src/lib.rs`
- `crates/descry-cli/src/commands/init.rs`
- `crates/descry-cli/src/commands/hook.rs`
- `crates/descry-cli/src/commands/doctor.rs`
- `crates/descry-cli/tests/init.rs`
- `crates/descry-cli/tests/hook_install.rs`
- `crates/descry-cli/tests/doctor.rs`
- `README.md`

## Implementation Steps

1. Add `InitConfig::install_hooks`.
   - CLI flag: `descry init --all`.
   - Behavior:
     - create `.descry/project.yml`, `.descry/state`, `.descry/memory`;
     - build project index;
     - install Claude, Codex, Cursor, and Git hooks using project-local paths;
     - emit JSON listing each installed/unchanged hook.
   - Keep plain `descry init` project-only for users who want manual hooks.

2. Make hook commands absolute by default.
   - In hook install code, use `std::env::current_exe()` and append subcommand
     arguments.
   - Preserve explicit `--command` override for tests and power users.
   - Ensure JSON settings contain the absolute path when no override is passed.

3. Add project readiness checks before hook install.
   - If `--project` is supplied and `.descry/project.yml` or project index is
     missing, return JSON with `next: "descry init --project <path>"`.
   - `descry init --all` must not hit this failure because it initializes first.

4. Add `--agent`.
   - CLI: `descry doctor --agent claude|codex|cursor|git|all`.
   - Default: `all`.
   - `--fix --agent git` installs only the git hook.
   - `--fix --agent claude` repairs project init only when `--project` is also
     passed, then installs Claude only.

5. Add git hook path resolution.
   - Use `git -C <project> rev-parse --git-path hooks/pre-push`.
   - If git is unavailable, fall back to `<project>/.git/hooks/pre-push` only
     when it is a directory.
   - Add tests for `.git` directory and `.git` file worktree shape if practical.

6. Add doctor git hook check.
   - Check `pre-push` contains the Descry secret scan marker.
   - Include `hook.git.pre_push` in JSON output.

## Acceptance Tests

| # | Command | Expect |
|---:|---|---|
| 1 | `cargo test -p descry-cli --test init --test hook_install --test doctor --no-fail-fast` | exit 0 |
| 2 | `cargo test -p descry-cli -- init_all` | exit 0 once test exists |
| 3 | `cargo fmt --check` | exit 0 |
| 4 | `cargo clippy -p descry-cli -- -D warnings` | exit 0 |

## Risks

| Risk | Likelihood | Mitigation |
|---|---|---|
| Absolute command tests become machine-specific | medium | assert command contains current test binary path prefix or parse JSON flexibly |

---

# DG-V1-040 - Introduce Shared Runtime Context Spine

Purpose: every runtime entrypoint must make decisions through the same path.

## In Scope

- Shared context/evaluation API.
- CLI hook, `evaluate`, and daemon route use the same API.
- Session event append and audit append happen in one place.

## Out Of Scope

- Richer task inference internals.
- New classifiers.
- Policy DSL changes.

## Allowed Paths

- `crates/descry-core/src/runtime.rs`
- `crates/descry-core/src/lib.rs`
- `crates/descry-context/src/lib.rs`
- `crates/descry-engine/src/lib.rs`
- `crates/descry-cli/src/commands/hook.rs`
- `crates/descry-cli/src/commands/evaluate.rs`
- `crates/descry-daemon/src/routes.rs`
- `crates/descry-cli/tests/**`
- `crates/descry-daemon/tests/**`

## Architecture Decision

Create `descry-context` as the owner of enrichment and runtime state, but keep
final decision graph in `descry-engine`. The context spine should produce a
`DecisionInput`; `descry-engine::evaluate` remains the policy decision API.

## Implementation Steps

1. Add `RuntimeContextConfig`.
   - Fields:
     - `project_root: PathBuf`
     - `context_path: PathBuf`
     - `state_dir: PathBuf`
     - `project_index_path: PathBuf`
     - `project_policy_path: PathBuf`
     - `policy_path: PathBuf`
     - `approvals_path: PathBuf`
     - `behavior_path: PathBuf`
     - `audit_path: Option<PathBuf>`
     - `repo_id_hash: String`

2. Move ACP enrichment into `descry-context`.
   - Existing private hook behavior should become public:
     - load project index;
     - set repo and branch when index has them;
     - merge recent file targets into `context.recent_files`;
     - read active manual task from context file;
     - append sanitized session event after decision.

3. Add `evaluate_action`.
   - Input: `ActionContextPacket`, `RuntimeContextConfig`, optional session id.
   - Output: `DecisionOutput` plus enriched `DecisionInput`.
   - It loads policy and project config.
   - It builds task and action.
   - It calls `descry_engine::evaluate`.
   - It appends audit if configured.
   - It appends session/behavior memory.

4. Refactor CLI hook.
   - Hook command only:
     - parse host payload;
     - normalize through adapter;
     - call shared context spine;
     - map decision to host output.
   - Remove duplicate enrichment/audit code from `hook.rs`.

5. Refactor `descry evaluate --stdin`.
   - Add flags for context/state/project/audit.
   - Use the same context spine.
   - Keep pure ACP evaluation available only as `--no-context` if needed.

6. Refactor daemon route.
   - Use the same context spine for ACP requests.
   - If daemon cannot know project root, require `cwd` or project root in
     request; otherwise return 400.

7. Add parity tests.
   - Same dangerous ACP through `evaluate`, daemon, and hook helper gives same
     decision.
   - Same source edit with project index enrichment gives same decision.

## Acceptance Tests

| # | Command | Expect |
|---:|---|---|
| 1 | `cargo test -p descry-cli --test evaluate --test claude_hook --test codex_hook --test cursor_hook --no-fail-fast` | exit 0 |
| 2 | `cargo test -p descry-daemon` | exit 0 |
| 3 | `cargo test -p descry-context` | exit 0 |
| 4 | `cargo test -p descry-engine` | exit 0 |

## Risks

| Risk | Likelihood | Mitigation |
|---|---|---|
| Large refactor destabilizes hooks | high | preserve old tests, add parity tests before deleting old helper behavior |

---

# DG-V1-050 - Enrich Adapter Outputs With Safe Harness Metadata

Purpose: adapters should preserve enough safe context for V1 decisions without
recording secret payloads.

## In Scope

- Claude, Codex, Cursor metadata extraction.
- Safe MCP argument key extraction across hosts.
- Contract fixtures for new shapes.

## Out Of Scope

- Context scoring.
- Policy DSL changes.

## Allowed Paths

- `crates/descry-adapters/src/**`
- `crates/descry-adapters/tests/**`
- `crates/descry-cli/tests/fixtures/hook_contracts/**`
- `crates/descry-cli/tests/hook_contracts.rs`
- `crates/descry-cli/tests/claude_hook.rs`
- `crates/descry-cli/tests/codex_hook.rs`
- `crates/descry-cli/tests/cursor_hook.rs`

## Implementation Steps

1. Define safe extraction helpers.
   - `string_field`
   - `safe_argument_keys`
   - `safe_path_list`
   - `prompt_for_hook`
   - `session_or_turn_id`
   - Keep values out when key names indicate secret/token/password.

2. Claude adapter.
   - For `mcp__*`, derive:
     - `action_type = "mcp.call"`;
     - target from server/tool name if available, otherwise tool name;
     - summary `Claude MCP tool call: <tool>`;
     - safe argument keys from `tool_input`.
   - For `MultiEdit`, capture all file paths if hook payload provides them.
   - Keep file content, old string, new string out of summaries.

3. Codex adapter.
   - Continue `apply_patch` path extraction.
   - Add support for file read/write payloads if Codex hook emits tool names
     beyond `apply_patch`.
   - For MCP-prefixed tools, collect safe argument keys and summary.
   - Preserve `turn_id` or `session_id` in source metadata when runtime types
     exist.

4. Cursor adapter.
   - Add session id fields if present in payload.
   - Keep existing MCP safe key behavior.
   - Ensure command bodies are never stored in session history, only evaluated.

5. Add tests.
   - Claude MCP destructive tool blocks.
   - Codex MCP destructive tool blocks.
   - Claude MultiEdit with `.env.production` and source file uses multi-target.
   - Unknown tool remains `sdk.tool.call` and allows unless policy says
     otherwise.

## Acceptance Tests

| # | Command | Expect |
|---:|---|---|
| 1 | `cargo test -p descry-adapters` | exit 0 |
| 2 | `cargo test -p descry-cli --test hook_contracts --test claude_hook --test codex_hook --test cursor_hook --no-fail-fast` | exit 0 |

## Risks

| Risk | Likelihood | Mitigation |
|---|---|---|
| Host payload schemas differ in the wild | high | unknown fields should be tolerated; fixtures should cover observed variants |

---

# DG-V1-060 - Replace Shallow Task Inference With Evidence Builder

Purpose: make automatic task context real enough to support the launch claim.

## In Scope

- Task envelope builder that uses ACP, project index, project policy, and recent
  session events.
- Evidence fields are real matches, not prefilled likely values.
- Prompt persistence decision implemented consistently.

## Out Of Scope

- LLM judging.
- New public cloud service.

## Allowed Paths

- `crates/descry-core/src/runtime.rs`
- `crates/descry-context/src/lib.rs`
- `crates/descry-engine/src/lib.rs`
- `crates/descry-context/tests/**`
- `crates/descry-engine/tests/**`
- `crates/descry-cli/tests/**`

## Implementation Steps

1. Replace `TaskEnvelope::from_acp` direct use.
   - Keep it as fallback only.
   - Add `TaskEnvelopeBuilder` in `descry-context` or `descry-core`.
   - Inputs: ACP, optional `ProjectIndex`, `ProjectPolicy`, recent events.

2. Generate candidate evidence.
   - Active task terms.
   - Current prompt terms.
   - Branch terms.
   - Recent file paths.
   - Recent prompt terms from session events if storing prompts is chosen.
   - Project index buckets.
   - Asset match from project policy.

3. Populate actual match fields.
   - `matched_paths`: only paths that matched current target by exact,
     same-directory, or source/test counterpart logic.
   - `matched_terms`: only terms found in target path, action summary, or
     project-index bucket.
   - `matched_context_sources`: only sources contributing to the match.
   - `matched_asset`: matched asset id.
   - `matched_policy`: matched action or asset policy id.

4. Set confidence.
   - Manual active task exact path: high.
   - Prompt plus branch plus recent file: medium-high.
   - Branch-only: medium-low.
   - Recent file only: medium-low.
   - Unknown: low.
   - Confidence must never imply approval for critical assets.

5. Store prompt context consistently.
   - If storing prompts: sanitize, bound length, and add privacy tests.
   - If not storing prompts: update README in DG-V1-170.
   - Recommended V1 stance: store sanitized prompt text only when harness
     exposes it, capped at 512 chars, never store shell commands as prompts.

6. Add tests.
   - Branch-only inference.
   - Prompt-only inference.
   - Recent-file inference.
   - Project-index bucket inference.
   - Static asset rule match.
   - Prompt privacy bounds.

## Acceptance Tests

| # | Command | Expect |
|---:|---|---|
| 1 | `cargo test -p descry-context` | exit 0 |
| 2 | `cargo test -p descry-engine -- task` | exit 0 |
| 3 | `cargo test -p descry-cli --test claude_hook --test evaluate --no-fail-fast` | exit 0 |

## Risks

| Risk | Likelihood | Mitigation |
|---|---|---|
| Overmatching allows off-task source edits | medium | require multiple evidence points or threshold for allow |

---

# DG-V1-070 - Add Scored Task And Action Context Matching

Purpose: replace boolean exact/substring matching with explainable scoring.

## In Scope

- `TaskMatch` scorer.
- Threshold-based `allow_if_context_matches`.
- Evidence-rich decision reasons.

## Out Of Scope

- New action classifiers.
- Policy DSL changes.

## Allowed Paths

- `crates/descry-engine/src/lib.rs`
- `crates/descry-core/src/runtime.rs`
- `crates/descry-engine/tests/**`
- `crates/descry-cli/tests/evaluate.rs`

## Implementation Steps

1. Add `TaskMatch`.
   - Fields:
     - `score: u8`
     - `exact_paths: Vec<String>`
     - `near_paths: Vec<String>`
     - `source_test_pairs: Vec<String>`
     - `matched_terms: Vec<String>`
     - `sources: Vec<TaskSource>`
     - `reason: String`

2. Add scoring rules.
   - Exact path: +70.
   - Same directory: +35.
   - Source/test counterpart: +45.
   - Filename stem overlap: +20.
   - Branch token overlap: +15 per useful token, cap 30.
   - Prompt/task token overlap: +10 per useful token, cap 30.
   - Recent file proximity: +20.
   - Sensitive asset mismatch cannot lower risk; score only helps normal assets.

3. Add threshold logic.
   - `allow_if_context_matches` allows normal source writes when score >= 60.
   - Score 35-59 returns `require_approval` for write actions.
   - Score < 35 returns `require_approval`.
   - Critical asset still blocks.
   - High infra asset still requires approval even with high score unless
     explicit policy says otherwise.

4. Include evidence in reasons.
   - Example: `allowed: src/auth/session.ts matched task context score=80 via exact path and branch term session`.
   - Reasons must not contain shell command bodies or secret values.

5. Add tests.
   - `src/auth/session.ts` matches `tests/auth/session.test.ts`.
   - `.github/workflows/deploy.yml` does not match `fix/session-expiry`.
   - `src/billing/invoice.ts` does not match `fix/session-expiry`.
   - Same directory source edit matches.

## Acceptance Tests

| # | Command | Expect |
|---:|---|---|
| 1 | `cargo test -p descry-engine` | exit 0 |
| 2 | `cargo test -p descry-cli --test evaluate` | exit 0 |

## Risks

| Risk | Likelihood | Mitigation |
|---|---|---|
| Scoring becomes too permissive | medium | start conservative; false-positive fixture gate comes later |

---

# DG-V1-080 - Fix Multi-Target Asset Evaluation

Purpose: every file target in a multi-target action must receive its own asset
match and the strictest decision must win.

## In Scope

- Remove legacy asset reuse bug.
- Per-target task/action/asset recomputation.
- Regression tests for mixed secret/source patches.

## Out Of Scope

- New adapter extraction beyond existing multi-target support.

## Allowed Paths

- `crates/descry-engine/src/lib.rs`
- `crates/descry-memory/src/lib.rs`
- `crates/descry-cli/tests/codex_hook.rs`
- `crates/descry-engine/tests/**`
- `fixtures/**`

## Implementation Steps

1. Remove or replace `legacy_asset` reuse.
   - Current bug: first target's legacy asset can be reused for all targets.
   - Store legacy asset policy path in runtime only if still needed.
   - Match legacy and project assets inside the target loop.

2. Recompute per-target fields.
   - `candidate_input.acp.action.target = target`.
   - `candidate_input.action = classify_action(&candidate_input.acp)`.
   - `candidate_input.asset = project_config.match_asset(target)` or legacy
     policy match for that same target.
   - Rebuild or rescore task match for the candidate target.

3. Ensure strongest decision wins.
   - `block` outranks `require_approval`.
   - Higher risk wins on equal decision rank.
   - Include target in reason.

4. Add tests.
   - Patch touches `.env.production` and `src/lib.rs`: block.
   - Patch touches `.github/workflows/deploy.yml` and `src/auth/session.ts`:
     require approval.
   - Patch touches two normal in-task source files: allow.

## Acceptance Tests

| # | Command | Expect |
|---:|---|---|
| 1 | `cargo test -p descry-engine -- multi_target` | exit 0 |
| 2 | `cargo test -p descry-cli --test codex_hook` | exit 0 |
| 3 | `cargo test -p descry-cli --test evaluate` | exit 0 |

## Risks

| Risk | Likelihood | Mitigation |
|---|---|---|
| Legacy asset policy users break | low | keep compatibility by matching legacy path per target |

---

# DG-V1-090 - Add V1 Structural Action Classifiers

Purpose: V1 decisions should understand command structure enough to reduce
regex dependence and improve explainability.

## In Scope

- Shell tokenizer.
- Git classifier.
- SQL destructive classifier.
- Cloud/deploy classifier.
- MCP read/write/destroy classifier improvements.
- Project action defaults expanded.

## Out Of Scope

- Full shell interpreter.
- Full cloud API client.
- LLM classifier.

## Allowed Paths

- `Cargo.toml`
- `Cargo.lock`
- `crates/descry-engine/src/lib.rs`
- `crates/descry-policy/src/**`
- `crates/descry-policy/tests/**`
- `crates/descry-engine/tests/**`
- `fixtures/**`
- `policies/safe-defaults.yml`

## Dependency Guidance

Prefer no new dependency if a small conservative tokenizer is enough. If adding
`sqlparser` or `shlex`, the plan must pin exact versions and update Cargo.lock.
Do not add dependencies only to parse one narrow pattern.

## Implementation Steps

1. Add shell tokenization.
   - Parse quotes enough to split executable/args safely.
   - Do not execute shell expansions.
   - If parsing fails, fall back to conservative substring classifier.

2. Add git classifier.
   - Detect:
     - `git push --force origin main`
     - `git push origin main --force`
     - `git push -f origin release/x`
     - `git reset --hard`
     - `git clean -fdx`
   - Classify protected branch force push as `GitRewrite`.

3. Add SQL classifier.
   - Detect `DROP DATABASE`, `DROP TABLE`, `TRUNCATE`.
   - Detect `DELETE FROM <table>` without `WHERE`.
   - Allow `DELETE FROM <table> WHERE ...`.
   - Cover `psql -c '...'`, `mysql -e '...'`, and raw shell command SQL text.

4. Add cloud/deploy classifier.
   - Railway/Fly/Vercel destructive verbs.
   - AWS RDS/EC2 destructive verbs.
   - GCP SQL/compute delete.
   - Azure group delete.
   - Deploy commands: `vercel --prod`, `npm run deploy`, `fly deploy`,
     `railway up` should classify as `Deploy`, not necessarily block.

5. Add MCP classifier refinements.
   - Tool names containing create/update/write classify `McpWrite`.
   - delete/destroy/drop/purge/remove classify `McpDestroy`.
   - list/get/read classify `McpRead`.
   - Argument key confirmation/destruction can upgrade to destroy.

6. Expand default project actions.
   - Add defaults for `build`, `install`, `git_rewrite`, `mcp_write`.
   - Recommended:
     - build: allow
     - install: allow_with_log or require_approval if package manager writes
       lockfiles outside context
     - git_rewrite: require_approval
     - mcp_write: require_approval

7. Add fixtures/tests.
   - Benign installs/builds.
   - Destructive git.
   - SQL delete with and without where.
   - Deploy require approval.
   - MCP write require approval.

## Acceptance Tests

| # | Command | Expect |
|---:|---|---|
| 1 | `cargo test -p descry-engine` | exit 0 |
| 2 | `cargo test -p descry-policy` | exit 0 |
| 3 | `cargo test -p descry-cli --test policy_test --test evaluate --no-fail-fast` | exit 0 |
| 4 | `cargo clippy --workspace -- -D warnings` | exit 0 |

## Risks

| Risk | Likelihood | Mitigation |
|---|---|---|
| Parser misses shell edge cases | high | hard blocks remain as deterministic regex backstop |

---

# DG-V1-100 - Stabilize Policy DSL And Policy Test Behavior

Purpose: make policy files coherent, versioned, and testable against real engine
behavior.

## In Scope

- Versioned policy schema.
- Coherent default policy surface.
- `descry policy test` routes through engine.
- Loader errors are precise.

## Out Of Scope

- Full Rego compatibility.
- Cloud policy sync.

## Allowed Paths

- `crates/descry-policy/src/**`
- `crates/descry-policy/tests/**`
- `crates/descry-cli/src/commands/policy.rs`
- `crates/descry-cli/src/lib.rs`
- `crates/descry-cli/tests/policy_test.rs`
- `policies/safe-defaults.yml`
- `fixtures/**`
- `README.md`

## Architecture Decision

V1 should use one coherent local policy surface. Hard blocks stay in
`descry-policy`; project asset/action defaults should be loadable from project
policy and mirrored in the shipped default configuration. Avoid promising a
single monolithic policy pack unless the code actually loads it that way.

## Implementation Steps

1. Add schema fields.
   - `schema_version: 1`
   - `pack_version: "0.1.0"`
   - Reject unknown major schema.
   - Preserve `deny_unknown_fields`.

2. Clarify policy types.
   - `Policy`: shipped hard/default pack.
   - `ProjectPolicy`: project asset/action defaults.
   - Document exactly which layer owns hard blocks vs approvals.

3. Add loader validation.
   - Duplicate rule ids fail.
   - Empty rule id fails.
   - Empty reason fails.
   - Invalid regex reports rule id.
   - Unknown fields fail.

4. Update `policy test`.
   - Default behavior should evaluate fixture through full engine with
     safe-default policy and project policy.
   - Add flags:
     - `--policy`
     - `--project`
     - `--approvals`
     - `--behavior`
     - `--hard-block-only` if low-level testing is still needed.

5. Update tests.
   - Existing policy tests still pass.
   - New fixture where hard-block policy says allow but project asset requires
     approval should produce `require_approval` through `policy test`.

## Acceptance Tests

| # | Command | Expect |
|---:|---|---|
| 1 | `cargo test -p descry-policy` | exit 0 |
| 2 | `cargo test -p descry-cli --test policy_test` | exit 0 |
| 3 | `cargo run --quiet -p descry-cli -- policy test fixtures/secret-file-write.json --expect block` | exit 0 |
| 4 | `cargo run --quiet -p descry-cli -- policy test fixtures/infra-file-write.json --expect require-approval` | exit 0 |

## Risks

| Risk | Likelihood | Mitigation |
|---|---|---|
| CLI enum spelling mismatch | medium | lock expected CLI values in tests |

---

# DG-V1-110 - Make Approvals Typed Validated And Actually Enforced

Purpose: approval claims must be true, narrow, and safe.

## In Scope

- Scope validation.
- Rule and one-shot approval enforcement or removal from claims.
- Approval revoke/list improvements.
- Max TTL.

## Out Of Scope

- Cloud approval UI.
- Slack/PagerDuty.

## Allowed Paths

- `crates/descry-memory/src/lib.rs`
- `crates/descry-engine/src/lib.rs`
- `crates/descry-cli/src/commands/approve.rs`
- `crates/descry-cli/src/lib.rs`
- `crates/descry-cli/tests/approve.rs`
- `crates/descry-engine/tests/**`
- `README.md`

## Product Stance

Recommended V1 stance:

- Tier-1 catastrophic hard blocks are not generally approvable.
- MCP production/destructive hard blocks may be approval-overridden only by
  explicit `mcp:` target scopes because Cursor MCP can produce false positives
  on admin-like endpoint names.
- Rule and one-shot approvals should either be fully implemented with
  `approval_mode` or removed from public claims.

If implementing rule/once:

- Add `approval_mode: never|rule|once|mcp` per hard block.
- Default `never`.
- Existing MCP override becomes `approval_mode: mcp`.

## Implementation Steps

1. Add `ApprovalScope` validation.
   - Valid prefixes: `path:`, `action:`, `mcp:`, `rule:`, `once:`.
   - Reject empty pattern.
   - Reject unknown prefixes.
   - Reject whitespace-only scope.
   - Cap TTL to default maximum, recommended 24h for V1.

2. Expose validation to CLI.
   - `descry approve --scope pat:foo --ttl 30m` exits 2.
   - `descry approve --scope path: --ttl 30m` exits 2.
   - Output includes parsed scope kind.

3. Add revoke.
   - CLI: `descry approvals revoke --scope <scope>` or `--id` if approval ids
     are added.
   - If ids are not added, use exact scope match and mark expired by rewriting
     JSONL or appending a tombstone event.

4. Decide rule/once behavior.
   - If implementing:
     - thread matched rule id from policy into decision metadata;
     - compute ACP hash before final decision;
     - apply live `rule:` or `once:` approvals only for rules whose
       `approval_mode` allows it;
     - consume `once:` after use.
   - If not implementing:
     - remove `rule:` and `once:` from README and tests;
     - keep parser only if marked internal/unused.

5. Add `--from-last-block`.
   - Reads latest block audit record.
   - Suggests a narrow scope based on action type:
     - file write: `path:<parent>/**`
     - deploy: `action:deploy`
     - MCP: `mcp:<target>`
   - Does not generate approvals for non-overridable hard blocks.

## Acceptance Tests

| # | Command | Expect |
|---:|---|---|
| 1 | `cargo test -p descry-memory` | exit 0 |
| 2 | `cargo test -p descry-engine -- approval` | exit 0 |
| 3 | `cargo test -p descry-cli --test approve` | exit 0 |
| 4 | `cargo test -p descry-cli --test cursor_hook` | exit 0 |

## Risks

| Risk | Likelihood | Mitigation |
|---|---|---|
| Approval override weakens Tier-1 safety | high | default every hard block to `approval_mode: never` |

---

# DG-V1-120 - Harden Host Hook Contracts And Messages

Purpose: host output must be stable, correct, and useful for every decision
kind.

## In Scope

- Golden output fixtures.
- Host-specific decision mapping.
- Block/approval messages.
- Parse error behavior.

## Out Of Scope

- New host integrations.

## Allowed Paths

- `crates/descry-cli/src/commands/hook.rs`
- `crates/descry-cli/tests/hook_contracts.rs`
- `crates/descry-cli/tests/fixtures/hook_contracts/**`
- `crates/descry-cli/tests/claude_hook.rs`
- `crates/descry-cli/tests/codex_hook.rs`
- `crates/descry-cli/tests/cursor_hook.rs`

## Implementation Steps

1. Define host mapping table in tests and code.
   - Claude:
     - allow -> allow
     - allow_with_log -> allow
     - ask -> ask
     - require_approval -> ask
     - block -> deny
   - Codex:
     - allow -> allow
     - allow_with_log -> allow
     - ask -> deny
     - require_approval -> deny
     - block -> deny
   - Cursor:
     - allow -> allow
     - allow_with_log -> allow
     - ask -> ask
     - require_approval -> ask
     - block -> deny

2. Golden fixtures for each host and decision.
   - Add fixtures for allow, require_approval, block, parse error.
   - If `ask` remains unused, add one synthetic engine output unit test rather
     than fixture.

3. Improve messages.
   - Must include:
     - decision
     - reason
     - matched rule or asset if available
     - suggested approval command when approvable
     - retry guidance for Codex require_approval because Codex cannot ask
   - Must not include:
     - secret file contents
     - raw MCP argument values
     - full shell commands in audit/session history; host message may include
       command because user is at point of execution, but tests should ensure
       secret-looking values are redacted.

4. Parse errors.
   - Machine-readable JSON error on stderr.
   - Exit code 2.
   - Do not allow action on parse failure.

## Acceptance Tests

| # | Command | Expect |
|---:|---|---|
| 1 | `cargo test -p descry-cli --test hook_contracts` | exit 0 |
| 2 | `cargo test -p descry-cli --test claude_hook --test codex_hook --test cursor_hook --no-fail-fast` | exit 0 |

## Risks

| Risk | Likelihood | Mitigation |
|---|---|---|
| Host schema changes upstream | medium | keep parse tolerant but output locked |

---

# DG-V1-130 - Complete Audit And Memory Semantics

Purpose: audit logs should be tamper-evident, useful, and safe to search.

## In Scope

- Verified open before append.
- Sanitized event fields.
- Search uses structured fields.
- Behavior/session memory records prompt context if V1 stance permits.

## Out Of Scope

- Cloud audit retention.
- SIEM export.

## Allowed Paths

- `crates/descry-audit/src/**`
- `crates/descry-audit/tests/**`
- `crates/descry-cli/src/commands/hook.rs`
- `crates/descry-cli/src/commands/logs.rs`
- `crates/descry-cli/tests/logs_verify.rs`
- `crates/descry-context/src/lib.rs`
- `crates/descry-context/tests/**`

## Implementation Steps

1. Add `AuditChain::open_verified`.
   - Calls verifier first.
   - Refuses to append if chain is broken.
   - Empty/missing file is okay.

2. Extend `AuditEvent`.
   - Add optional sanitized fields:
     - `host`
     - `actor`
     - `action_type`
     - `target_fingerprint`
     - `sanitized_target`
     - `asset_id`
     - `session_id_hash`
   - Do not add raw ACP.
   - Keep canonicalization stable.

3. Update hook append path.
   - Use `open_verified`.
   - Hash ACP for integrity.
   - Store sanitized target, not raw secret values.
   - Store matched asset/rule if available.

4. Update `logs search`.
   - Search decision, rule id, reason, action type, asset id, host, sanitized
     target.
   - Do not require full raw JSON grep to find common audit queries.

5. Add tamper append test.
   - Create chain with two records.
   - Mutate first record.
   - Attempt append through hook/audit API.
   - Assert failure.

6. Session memory.
   - Persist sanitized prompt text when policy allows.
   - Never persist shell command bodies.
   - Never persist MCP argument values.

## Acceptance Tests

| # | Command | Expect |
|---:|---|---|
| 1 | `cargo test -p descry-audit` | exit 0 |
| 2 | `cargo test -p descry-cli --test logs_verify --test claude_hook --test cursor_hook --no-fail-fast` | exit 0 |
| 3 | `cargo test -p descry-context` | exit 0 |

## Risks

| Risk | Likelihood | Mitigation |
|---|---|---|
| Audit schema migration breaks existing local logs | low | V1 pre-release can document schema reset; verifier handles older only if necessary |

---

# DG-V1-140 - Make Demos Reproducible Launch Tests

Purpose: demos must be deterministic and launch-critical, not affected by user
runtime state.

## In Scope

- Demo isolated memory.
- Strong assertions for every launch demo.
- Optional JSON output.

## Out Of Scope

- Website visual redesign.

## Allowed Paths

- `crates/descry-cli/src/commands/demo.rs`
- `crates/descry-cli/src/lib.rs`
- `crates/descry-cli/tests/demo.rs`
- `README.md`

## Implementation Steps

1. Isolate demo state.
   - Use a temp directory for approvals and behavior.
   - Do not read `.descry/memory` from the user's checkout.
   - Do not append audit unless demo explicitly asks.

2. Add `--json`.
   - Output fields:
     - `demo`
     - `policy_source`
     - `prompt_context`
     - `inferred_task`
     - `proposed_action`
     - `classified_action`
     - `asset_match`
     - `decision`
     - `reason`
     - `without_descry`
   - Plain text remains default.

3. Strengthen tests.
   - For each demo:
     - expected decision;
     - expected action class;
     - expected reason fragment;
     - no raw secret values;
     - no raw MCP argument values.
   - Add a test where a live approval exists in `.descry/memory` but demo
     result is unchanged.

4. Update README demo section.
   - Say demos are isolated and reproducible.
   - Include `descry demo pocketos` as the primary launch demo.

## Acceptance Tests

| # | Command | Expect |
|---:|---|---|
| 1 | `cargo test -p descry-cli --test demo` | exit 0 |
| 2 | `cargo run --quiet -p descry-cli -- demo pocketos` | exits 0 and prints `decision: block` |
| 3 | `cargo run --quiet -p descry-cli -- demo mcp-poison` | exits 0 and prints `decision: block` |

## Risks

| Risk | Likelihood | Mitigation |
|---|---|---|
| Tempdir dependency missing | low | tempfile is already present in workspace if tests use it |

---

# DG-V1-150 - Add Fixture Manifest And False-Positive Gate

Purpose: V1 must know what it blocks and what it must not block.

## In Scope

- `fixtures/manifest.yml`.
- Shared fixture runner.
- Benign near-miss fixtures.
- CI gate.

## Out Of Scope

- Top 50 open-source repo benchmarking.

## Allowed Paths

- `fixtures/**`
- `crates/descry-policy/tests/**`
- `crates/descry-cli/tests/policy_test.rs`
- `crates/descry-cli/tests/evaluate.rs`
- `.github/workflows/ci.yml`
- `policies/safe-defaults.yml`

## Implementation Steps

1. Add manifest.
   - Fields:
     - `path`
     - `expected_decision`
     - `expected_rule`
     - `category`
     - `negative_of`
     - `notes`
   - Include all existing fixtures.

2. Add dangerous fixtures.
   - Root/home deletion variants.
   - Protected force push variants.
   - Cloud delete variants.
   - DB destroy variants.
   - Secret read/write.
   - MCP production/destructive variants.
   - Mixed multi-target patch.

3. Add benign fixtures.
   - Cargo test.
   - Normal source edit.
   - SQL delete with `WHERE`.
   - Git push to feature branch without force.
   - MCP readonly/list.
   - Deploy script read.
   - Package install if V1 policy allows/logs it.

4. Use manifest in tests.
   - `descry-policy` tests use same manifest for hard-block relevant cases.
   - CLI `policy_test` uses same manifest for full engine cases.
   - Tests assert rule id when expected.

5. CI.
   - Add a named fixture gate job or include in normal tests.
   - The gate fails if any manifest fixture lacks a corresponding file.

## Acceptance Tests

| # | Command | Expect |
|---:|---|---|
| 1 | `test -f fixtures/manifest.yml` | exit 0 |
| 2 | `cargo test -p descry-policy --test safe_defaults` | exit 0 |
| 3 | `cargo test -p descry-cli --test policy_test --test evaluate --no-fail-fast` | exit 0 |

## Risks

| Risk | Likelihood | Mitigation |
|---|---|---|
| Manifest parser adds dependency | low | use existing serde_yml if already present |

---

# DG-V1-160 - Decide Daemon V1 Surface And Enforce Parity Or Hide It

Purpose: current daemon is a skeleton. Either make it real or remove it from V1
claims.

## In Scope

- Product decision: daemon as V1 runtime or experimental internal.
- Code/docs alignment.
- Tests for whichever path is chosen.

## Out Of Scope

- MCP gateway proxy unless explicitly chosen.

## Allowed Paths

- `crates/descry-daemon/src/**`
- `crates/descry-daemon/tests/**`
- `crates/descry-cli/src/commands/daemon.rs`
- `crates/descry-cli/src/lib.rs`
- `README.md`
- `docs/V1_LAUNCH_CONTRACT.md`
- `ROADMAP.md`

## Recommended Decision

For V1, keep hook CLI as the production path and mark daemon experimental unless
there is a concrete host that needs a long-running process. This avoids shipping
a second runtime path before parity is complete.

If daemon stays experimental:

1. Hide or clearly label `descry daemon start`.
2. README says daemon is not part of the launch runtime path.
3. Keep minimal tests to ensure it does not regress catastrophically.

If daemon becomes V1:

1. It must call the same context spine as hooks.
2. It must append audit and session memory.
3. It must reject non-localhost bind.
4. It must support adapter-specific payloads or require enriched ACP with
   project root.
5. It must pass parity tests with CLI hook and evaluate.

## Acceptance Tests

Experimental path:

| # | Command | Expect |
|---:|---|---|
| 1 | `cargo test -p descry-daemon` | exit 0 |
| 2 | `rg -n "experimental|not part of the V1 runtime" README.md docs/V1_LAUNCH_CONTRACT.md` | exit 0 |

V1 daemon path:

| # | Command | Expect |
|---:|---|---|
| 1 | `cargo test -p descry-daemon` | exit 0 |
| 2 | `cargo test -p descry-cli --test evaluate --test claude_hook --no-fail-fast` | exit 0 |
| 3 | daemon parity integration test | exit 0 |

## Risks

| Risk | Likelihood | Mitigation |
|---|---|---|
| Shipping daemon doubles runtime complexity | high | keep it experimental for V1 unless a customer requires it |

---

# DG-V1-170 - Align Public Docs README Roadmap And Website

Purpose: public claims must match the implemented product.

## In Scope

- README.
- ROADMAP.
- Website copy in strategy repo if needed.
- V1 claim matrix final update.

## Out Of Scope

- New product behavior.

## Allowed Paths

- `README.md`
- `ROADMAP.md`
- `CHANGELOG.md`
- `SUPPORT.md`
- `docs/**`
- `/home/aniol/Documents/Descry/descry-website/src/App.jsx`
- `/home/aniol/Documents/Descry/descry-website/src/styles.css` only if copy
  causes layout issues

## Implementation Steps

1. Update claim matrix.
   - Every `partial` item either becomes `implemented`, `planned`, or `not_v1`.
   - Every launch claim points to a test or command.

2. README status.
   - State V1 support precisely:
     - local CLI;
     - supported host hooks;
     - protected action classes;
     - local audit;
     - local approvals;
     - no cloud required.
   - State known limitations:
     - unsupported agents;
     - no team cloud platform in OSS repo;
     - daemon/proxy status;
     - no guarantee against malicious same-user processes.

3. README install.
   - Accurate release install instructions.
   - Accurate Homebrew status.
   - Accurate source install instructions.

4. Website copy.
   - Match README claims.
   - No claim that managed team features exist.
   - No claim that MCP gateway exists unless DG-V1-160 ships it.
   - "Try launch demo" should show a command that works.

5. Changelog.
   - Add V1 readiness section with exact behavior.

## Acceptance Tests

| # | Command | Expect |
|---:|---|---|
| 1 | `rg -n "MCP gateway|team policy|SSO|SIEM|Homebrew" README.md ROADMAP.md docs /home/aniol/Documents/Descry/descry-website/src/App.jsx` | manually inspect no overclaims |
| 2 | `cargo test --workspace` | exit 0 |
| 3 | `npm --prefix /home/aniol/Documents/Descry/descry-website run build` | exit 0 if website dependencies installed |

## Risks

| Risk | Likelihood | Mitigation |
|---|---|---|
| Marketing copy reintroduces overclaims | medium | claim matrix must be reviewed with docs |

---

## Final V1 Release Gate

V1 can be tagged only after these pass:

```bash
cargo fmt --check
cargo clippy --workspace -- -D warnings
cargo test --workspace
cargo install --locked --path crates/descry-cli --root /tmp/descry-v1-cargo-root
/tmp/descry-v1-cargo-root/bin/descry --version
/tmp/descry-v1-cargo-root/bin/descry init --project /tmp/descry-v1-project
/tmp/descry-v1-cargo-root/bin/descry doctor --project /tmp/descry-v1-project --fix --policy policies/safe-defaults.yml
cargo run --quiet -p descry-cli -- demo pocketos
cargo run --quiet -p descry-cli -- policy test fixtures/railway-delete.json --expect block
cargo run --quiet -p descry-cli -- policy test fixtures/normal-edit.json --expect allow
```

Manual verification before release:

1. Clean macOS machine or VM:
   - install via release artifact or Homebrew tap if published;
   - run `descry init --all`;
   - verify Claude hook config has absolute binary path;
   - verify Codex hook config and `codex_hooks = true`;
   - verify Cursor shell and MCP hooks.

2. Real host smoke:
   - Claude Code attempts `rm -rf ~` in a harmless dry fixture: denied.
   - Codex attempts `apply_patch` touching `.env.production`: denied.
   - Cursor MCP destructive tool fixture: denied.

3. Privacy smoke:
   - `.descry/state/recent-actions.jsonl` contains no shell command body.
   - `.descry/audit.log` contains no secret value or raw MCP argument value.

4. Package smoke:
   - release archive extracts;
   - binary runs `--version`;
   - checksum matches;
   - Homebrew formula installs if tap is part of V1.

## Notes For Future Agents

- If a ticket becomes too large, split it and update the Ticket Map before
  implementing.
- If implementation discovers a product contradiction, stop and update
  `docs/V1_LAUNCH_CONTRACT.md` before code changes.
- Prefer adding tests before refactors on tickets DG-V1-040 through DG-V1-130.
- Do not weaken Tier-1 hard blocks to make demos or tests pass.
- Do not use the daemon as a workaround for missing hook behavior unless
  DG-V1-160 explicitly makes daemon V1.
