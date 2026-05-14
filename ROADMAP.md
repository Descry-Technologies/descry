# Roadmap

Descry Guard is the open-source local engine for AI coding-agent safety. This roadmap is intentionally biased toward a small product that developers can install, understand, and trust.

## v0.1 Alpha

- Deterministic local policy engine
- Safe-default Tier-1 blocks
- Claude Code, Codex, and Cursor hook support
- Local hash-chained audit log
- Codex path-aware patch evaluation
- Project asset/action policy enforcement
- Typed scoped TTL approvals
- Branch, recent-file, and prompt-informed task inference
- `descry init`
- source install script
- staged/pre-push secret scanning
- release artifact packaging
- Homebrew formula generation
- source installer smoke-tested with isolated install root
- `cargo install --locked --path crates/descry-cli` smoke-tested
- `descry doctor --fix` for project init and hook repair
- `descry logs tail` / `descry logs search`
- `descry demo pocketos`
- `descry demo rm-rf`
- `descry demo mcp-poison`
- SQL-aware `DELETE FROM ...` without `WHERE`
- Public CI and source-ready repository hygiene

## v0.1 Remaining

V1 launch scope is governed by [docs/V1_LAUNCH_CONTRACT.md](docs/V1_LAUNCH_CONTRACT.md), and public claims are tracked in [docs/V1_CLAIM_MATRIX.md](docs/V1_CLAIM_MATRIX.md).

- Publish Homebrew tap repository.
- Clean-machine README install test outside the development checkout.
- Tag and publish the first public v0.1 release artifacts.

## v0.2

- Better asset sensitivity configuration
- Richer block UX with fix suggestions and override phrase
- MCP proxy prototype outside the V1 local hook runtime
- False-positive regression suite against representative repositories

## Commercial Platform Boundary

The cloud platform is not part of this repository. Planned commercial features include:

- team policy management
- centralized audit retention and search
- SSO/RBAC/SCIM
- SIEM export
- org-wide MCP allowlist/signature service
- managed detection feed
