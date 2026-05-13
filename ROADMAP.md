# Roadmap

Descry Guard is the open-source local engine for AI coding-agent safety. This roadmap is intentionally biased toward a small product that developers can install, understand, and trust.

## v0.1 Alpha

- Deterministic local policy engine
- Safe-default Tier-1 blocks
- Claude Code, Codex, and Cursor hook support
- Local hash-chained audit log
- Scoped TTL approvals
- `descry demo pocketos`
- Public CI and source-ready repository hygiene

## v0.1 Remaining

- `descry init`
- install script and Homebrew tap
- staged/pre-push secret scanning
- SQL-aware `DELETE FROM ...` without `WHERE`
- `descry demo rm-rf`
- `descry demo mcp-poison`
- README install path tested on a clean machine

## v0.2

- Better asset sensitivity configuration
- Richer block UX with fix suggestions and override phrase
- Log tail/search
- MCP proxy prototype
- False-positive regression suite against representative repositories

## Commercial Platform Boundary

The cloud platform is not part of this repository. Planned commercial features include:

- team policy management
- centralized audit retention and search
- SSO/RBAC/SCIM
- SIEM export
- org-wide MCP allowlist/signature service
- managed detection feed
