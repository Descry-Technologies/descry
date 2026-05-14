# Descry Guard V1 Launch Contract

This document is the V1 source of truth for public launch claims. Public README, roadmap, website, release, and demo copy must agree with this contract or with `docs/V1_CLAIM_MATRIX.md`.

## V1 Readiness Definition

Descry Guard V1 is launch-ready when a clean user can install one binary, run project initialization, install hooks for supported coding agents, and receive correct pre-execution decisions for shell, file, git, secret, deploy, cloud, database, and MCP actions without manually setting task context for normal use.

## Launch Requirements

1. Install into Claude Code, Codex, and Cursor.
2. Intercept shell, file, git, MCP, secret, deploy, cloud, and database actions through supported harness surfaces.
3. Gather context from harness events, repo state, branch, recent files, recent commands, static project policy, and bounded session history.
4. Infer a task envelope without requiring manual user input.
5. Classify proposed actions structurally enough that V1 behavior is not raw regex only.
6. Match targets against asset sensitivity and action defaults.
7. Decide through one shared runtime path.
8. Keep normal in-context work quiet.
9. Block catastrophic actions decisively.
10. Require approval only for rare high-risk or ambiguous cases.
11. Write tamper-evident local audit records.
12. Explain every intervention in a useful host-specific message.

## Supported Hosts

V1 support is limited to these host surfaces:

| Host | Supported V1 surface |
|---|---|
| Claude Code | `PreToolUse` hook via `descry hook claude pretooluse` |
| Codex | `PreToolUse` hook via `descry hook codex pretooluse` |
| Cursor | shell hook via `descry hook cursor before-shell-execution` |
| Cursor | MCP hook via `descry hook cursor before-mcp-execution` |

Hook installation for those hosts is part of the V1 contract. Any other host integration is outside V1 unless the claim matrix is updated with implementation and test coverage.

## Supported Action Classes

V1 decisions cover these action classes when they arrive through a supported host surface:

| Action class | V1 expectation |
|---|---|
| shell | classify catastrophic commands, deploy commands, cloud destructive commands, database destructive commands, and policy-matched shell actions |
| file read | evaluate sensitive reads, including secrets and high-sensitivity project assets |
| file write | evaluate source, infrastructure, secret, and project asset writes |
| git | evaluate protected destructive operations such as force pushes to protected branches |
| secret | detect and block critical secret access or staged/pre-push secret exposure where supported |
| deploy | identify high-risk deployment operations and require approval or block by policy |
| cloud destructive | identify destructive cloud control-plane commands for supported providers in policy fixtures |
| database destructive | identify destructive SQL operations including `DROP`, `TRUNCATE`, and unsafe `DELETE FROM` |
| MCP read/write/destroy | evaluate MCP targets, tool summaries, destructive tool names, and safe argument keys without recording sensitive raw values |

## Explicitly Unsupported V1 Surfaces

These surfaces are not part of the V1 open-source local launch contract:

- SaaS team policy sync.
- SSO, RBAC, or SCIM.
- SIEM export.
- Managed cloud audit retention or search.
- Managed detection feeds.
- Broad cloud API proxying.
- Finance workflow enforcement.
- CI/CD enforcement.
- MCP gateway proxy, unless DG-V1-160 explicitly changes the launch contract.
- Daemon/proxy runtime path, unless DG-V1-160 explicitly promotes it to V1.

The current daemon may exist as an experimental local HTTP route skeleton, but it is not the V1 runtime path unless DG-V1-160 changes this document and the claim matrix.

## Public Copy Rule

Every public claim must be represented in `docs/V1_CLAIM_MATRIX.md` with:

- claim text or a precise claim summary;
- status: `implemented`, `partial`, `planned`, or `not_v1`;
- implementation path or roadmap ticket;
- test path or verification command;
- whether launch copy may say it without qualification.

Claims marked `partial` or `planned` must include the limitation in public copy. Claims marked `not_v1` must not be described as shipping V1 behavior.

## Release Gate

V1 can be tagged only after the final release gate in `docs/v1/V1_EXECUTION_PLAN.md` passes and this contract plus `docs/V1_CLAIM_MATRIX.md` have been reviewed against README, ROADMAP, and website copy.
