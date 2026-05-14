# Changelog

All notable user-facing changes will be documented here.

Descry Guard is pre-release. Versioning will follow SemVer once public releases begin.

## Unreleased

- Added local policy engine and safe-default Tier-1 hard blocks.
- Added Claude Code, Codex, and Cursor hook normalization.
- Added Cursor MCP target, tool-summary, and argument-key matching.
- Added SQL-aware `DELETE FROM ...` without `WHERE` hard-block coverage.
- Added scoped TTL approvals.
- Added hash-chained local audit verification.
- Added `descry init`.
- Added source installer at `scripts/install.sh`.
- Added release artifact packaging through `scripts/package.sh` and the tag release workflow.
- Added Homebrew formula generation for release artifacts.
- Added `descry scan secrets` and `descry hook install git` for staged/pre-push secret scanning.
- Added launch demos for `pocketos`, `rm-rf`, and `mcp-poison`.
