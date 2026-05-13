# Descry License Promise

This document is a binding promise from Descry Technologies about how the open-source components of Descry will be licensed, now and in the future. It exists to give users, contributors, and operators a durable assurance that the engine they depend on will not be relicensed out from under them.

## 1. Scope of this promise

This promise covers:

- The `descry` Rust workspace in this repository — every crate published from this repo, every binary built from it, and every policy pack shipped alongside it under `policies/`.
- The example demos under `demos/`.
- The specs and operator docs that describe the on-disk formats and protocols (Action Context Packet schema, policy DSL, audit-log hash chain, MCP gateway behavior).

It does **not** cover:

- The Descry cloud platform (web UI, encrypted audit sync service, billing, identity). That lives in a separate repository under a separate, proprietary license. The cloud platform is optional; Descry is fully usable without it.
- Third-party dependencies brought in via `Cargo.toml` — those retain their upstream licenses.

## 2. The license

The covered components are licensed under the **Apache License, Version 2.0** (see [`LICENSE`](./LICENSE)).

This grants every user, in perpetuity:

- The right to run Descry, including for commercial purposes, without paying us.
- The right to modify Descry and to redistribute modified versions.
- A patent grant from contributors covering any patents necessarily infringed by their contributions.
- Protection from us suing you over the Work, subject to the standard Apache 2.0 patent-litigation reciprocity clause.

## 3. What we will not do

For the covered components, Descry Technologies promises:

1. **No relicensing to a more restrictive license.** We will not move this code to BSL, SSPL, Elastic License, FSL, or any other source-available or non-OSI-approved license. If we ever fork the project under a new name, the existing Apache-2.0 codebase at the SHA of this commit remains Apache-2.0 forever.
2. **No "open-core" gating of safety primitives.** The decision engine, ACP schema, policy DSL, hash-chained audit log, MCP gateway, and all adapters that ship in this repo will remain open. We will not move a hot-path safety feature behind a paywall and leave the open version subtly broken.
3. **No CLA that transfers ownership.** Contributors retain copyright in their contributions; the inbound license is the project's outbound license (Apache-2.0). If we adopt a DCO sign-off requirement, the license itself does not change.
4. **No retroactive license change.** A license change to future code would not, and could not, apply to code already released under Apache-2.0. The history is permanent.

## 4. What we may do

To be honest about the boundary:

- We may rename, restructure, or split crates. The license travels with the code, not the path.
- We may add new optional features that live in a separate, proprietary repository (the cloud platform). Those will be clearly marked, will never be required to run Descry locally, and will never break feature parity for the OSS-only path.
- We may dual-license future *new* additions under an additional permissive license (e.g., MIT) where useful for ecosystem compatibility. Apache-2.0 remains available.
- We may revoke a contributor's patent grant if they sue us over patent infringement — this is the standard Apache-2.0 §3 reciprocity, not a special carve-out.

## 5. Trust boundary

Descry runs at user privilege. We provide detection and friction, not kernel-grade prevention. A hostile process running as the same user can disable Descry. This is stated plainly in the README and in `doctor`. The license promise above is about how we will treat the code, not a claim about what the code can guarantee at runtime.

## 6. Enforcement

If Descry Technologies (or any successor entity) violates this promise, the violating action is void with respect to the covered components: the Apache-2.0 grant on every commit through HEAD at the time of violation remains valid and exercisable by anyone, including via forks. We will not contest such forks in court.

## 7. Versioning of this promise

This promise is itself versioned. Changes to this file are commits in the public history. Any future amendment that *weakens* the promise above is non-binding with respect to code committed under earlier versions of this file. The strongest historical promise wins.

---

Signed-off on initial commit by Descry Technologies. Reaffirmed on every release tag.
