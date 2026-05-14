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
- Added source-install and release-artifact installer support.
- Added `descry doctor --fix` repair for project setup and hooks.
- Added task evidence and scored context matching from branch, recent files, prompt, and project index data.
- Added multi-target asset evaluation so the strictest matching asset controls the decision.
- Added structural classifiers for deploy, cloud, database, git, secret, and MCP actions.
- Added full-engine `descry policy test` evaluation with `--hard-block-only` for matcher-only checks.
- Added typed approval validation for `path:`, `action:`, and `mcp:` scopes.
- Added host contract fixtures for Claude Code, Codex, Cursor shell, and Cursor MCP hooks.
- Added audit records with verified chain state and structured search metadata.
- Added isolated launch demos with optional `--json` output.
- Added fixture manifest coverage for positive and false-positive policy cases.
- Documented the daemon as experimental and outside the V1 hook runtime.
