# Contributing to Descry Guard

Thanks for helping make AI coding agents safer.

Descry Guard is in alpha. The best contributions are small, testable changes that improve the local engine, published policies, adapters, demos, or documentation.

## Ground Rules

- Keep safety-critical behavior deterministic on the hot path.
- Prefer conservative Tier-1 blocks over broad rules that create false positives.
- Add regression fixtures for policy changes.
- Do not commit local runtime state, credentials, API keys, transcripts, private customer data, or generated audit logs.
- No contributor license agreement. Contributions are licensed under Apache-2.0, matching the project license.

## Development Setup

```bash
git clone https://github.com/descry-dev/descry.git
cd descry
cargo test --workspace
```

Before opening a pull request, run:

```bash
cargo fmt --check
cargo clippy --workspace -- -D warnings
cargo test --workspace
```

## Policy Contributions

Policy rules live under `policies/`; regression inputs live under `fixtures/`.

For every new hard block:

1. Add or update a fixture that should block.
2. Add the fixture to `crates/descry-cli/tests/policy_test.rs`.
3. Add it to `crates/descry-policy/tests/safe_defaults.rs` when it belongs to the default pack.
4. Explain the real-world incident or failure mode in the pull request.

Avoid broad regexes that block common safe workflows. Descry earns trust by being precise.

## Adapter Contributions

Adapters normalize host-specific hook payloads into the Action Context Packet. Keep raw sensitive values out of summaries and auditable fields unless there is a redaction layer in place.

## Pull Request Checklist

- [ ] The change is scoped and documented.
- [ ] New behavior has tests or fixtures.
- [ ] `cargo fmt --check` passes.
- [ ] `cargo clippy --workspace -- -D warnings` passes.
- [ ] `cargo test --workspace` passes.
- [ ] No secrets, local state, or private transcripts are included.
