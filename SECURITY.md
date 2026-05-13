# Security Policy

Descry Guard is a security tool. Please report vulnerabilities privately first.

## Reporting a Vulnerability

Email: security@descry.dev

Include:

- affected version or commit SHA
- reproduction steps
- expected vs actual behavior
- whether the issue can cause an unsafe allow, audit bypass, secret exposure, or denial of service

We will acknowledge receipt as soon as possible and coordinate disclosure before public details are posted.

## Scope

In scope:

- policy bypasses that allow a documented Tier-1 block to execute
- audit-log tampering that verifies as intact
- hook adapter normalization bugs that hide dangerous actions
- accidental capture or exposure of secrets in audit output
- approval-scope or TTL bypasses

Out of scope:

- attacks that require already controlling the user's shell or editing Descry's executable
- denial of service through intentionally malformed local files unless it creates unsafe allow behavior
- vulnerabilities in third-party dependencies without a Descry-specific exploit path

## Trust Boundary

Descry Guard runs at user privilege. It is not a sandbox and does not claim to stop a malicious process running as the same user. Its security value is pre-execution policy enforcement, user friction, and tamper-evident local audit for normal agent workflows.
