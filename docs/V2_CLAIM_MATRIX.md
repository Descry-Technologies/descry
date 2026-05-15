# Descry Guard V2 Claim Matrix

Status values match those in [V1_CLAIM_MATRIX.md](V1_CLAIM_MATRIX.md): `implemented`, `partial`, `planned`, `not_v2`.

Launch copy allowed values: `yes`, `qualified`, `roadmap`, `no`.

**Positioning rule.** The local firewall is the headline claim. Provability (Merkle audit, `descry-verify`) and team/cloud are explicit extensions. No V2 launch copy may present provability or team sync as the primary product — they are subordinate to the inline block/allow engine.

| Claim | Status | Implementation path | Test path | Launch copy allowed |
|---|---|---|---|---|
| Descry Guard is a semantic firewall for AI agent actions — inline, deterministic, no hand-written rules, no LLM in the hot path. | implemented | `crates/descry-engine/src/lib.rs`, `crates/descry-policy`, `crates/descry-core` | `cargo test -p descry-engine`; `cargo test -p descry-policy` | yes |
| Adapter origin provenance classifies instruction source as `User`, `AgentReasoning`, `ToolOutput`, `RepoContent`, or `WebContent`. | implemented | `crates/descry-adapters/src/provenance.rs`, `crates/descry-core/src/acp.rs` | `cargo test -p descry-adapters`; `cargo test -p descry-cli --test claude_hook --test codex_hook --test cursor_hook` | yes |
| `User` provenance is never emitted by heuristics — only confirmed by hook signal. | implemented | `crates/descry-adapters/src/provenance.rs` (explicit guard) | `cargo test -p descry-adapters` | yes |
| Drift/hijack detection fires only on external-provenance irreversible or destructive actions; emits `HighConfidence`, `Suspicious`, or `None`. | implemented | `crates/descry-engine/src/lib.rs` (`drift_inspection_stage`) | `cargo test -p descry-engine`; `cargo test -p descry-cli --test evaluate` | yes |
| Drift detection is skipped entirely when a Tier-1 hard-block rule was authoritative, preventing double-counting. | implemented | `crates/descry-engine/src/lib.rs` (`is_tier_one_block` flag) | `cargo test -p descry-engine` | yes |
| Behavior baseline stores per-`(agent, action, target)` observation counts and exposes `unseen / rare / occasional / familiar` familiarity tiers. | implemented | `crates/descry-memory/src/lib.rs` (`BehaviorStore`, `behavior_count`) | `cargo test -p descry-memory` | yes |
| `descry baseline explain` reports observed count and familiarity tier for a given triple. | implemented | `crates/descry-cli/src/commands/baseline.rs` | `cargo test -p descry-cli --test baseline` | yes |
| Precision gate: `descry policy precision --manifest <path> --min-precision <f>` evaluates fixtures and exits 1 if TP/(TP+FP) < threshold. | implemented | `crates/descry-cli/src/commands/policy.rs` (`run_precision`) | `cargo test -p descry-cli --test policy_test` | yes |
| Precision gate reports `precision`, `recall`, and `false_positive_rate` from a manifest corpus. | implemented | `crates/descry-cli/src/commands/policy.rs` | `cargo test -p descry-cli --test policy_test` | yes |
| Engine evaluation latency is under 50 ms p95 on representative fixture corpus. | implemented | `crates/descry-engine/src/lib.rs` (`evaluate_latency_is_under_50ms_p95` test) | `cargo test -p descry-engine evaluate_latency` | yes |
| Engine decisions are deterministic: identical inputs always produce identical decisions. | implemented | `crates/descry-engine/src/lib.rs` (`representative_verdicts_are_deterministic`) | `cargo test -p descry-engine` | yes |
| Audit records include SHA-256 Merkle checkpoints over 100-record batches. | implemented | `crates/descry-audit/src/checkpoint.rs` (`build_checkpoints`, `compute_merkle_root`) | `cargo test -p descry-audit` | yes |
| Audit chains can be exported as a self-contained JSON proof bundle (schema_version 2). | implemented | `crates/descry-audit/src/checkpoint.rs` (`export_bundle`, `ExportBundle`) | `cargo test -p descry-audit`; `cargo test -p descry-verify` | yes |
| `descry-verify` is a standalone binary that verifies chain integrity or exports a proof bundle without the full CLI runtime. | implemented | `crates/descry-verify/src/main.rs` | `cargo test -p descry-verify` | yes |
| `descry-verify` exits 0 (chain intact), 1 (broken or missing), 2 (usage/IO error). | implemented | `crates/descry-verify/src/main.rs` | `cargo test -p descry-verify` | yes |
| Daemon exposes `GET /v1/status` (version, cwd, live approvals count) and `POST /v1/approve` (scoped TTL approval broker). | implemented | `crates/descry-daemon/src/routes.rs` (`status`, `approve`) | `cargo test -p descry-daemon` | yes |
| Daemon binds only to 127.0.0.1 and rejects non-localhost bind addresses. | implemented | `crates/descry-daemon/src/lib.rs` | `cargo test -p descry-daemon` | yes |
| Provability primitives (Merkle audit, `descry-verify`, export bundles) are extensions on top of the firewall — not required for the inline block/allow engine. | implemented | local-only crate architecture; `descry-verify` standalone; `audit_path: None` in `RuntimeContextConfig` | `cargo test --workspace` | yes |
| Team policy sync, cloud audit retention, SSO, SIEM export, and managed detection feeds are future commercial extensions, not part of the local firewall. | not_v2 | no implementation in this repository | public copy may mention only as future roadmap | roadmap |
