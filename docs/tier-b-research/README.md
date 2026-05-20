# Tier B Research

Plan §3.9. Subprocess-sandboxed plugin runtime. Research-grade — not on the committed roadmap.

The plan calls Tier B "shape-defined; deferred-until-store-ships" and notes that the sandbox-policy compiler is itself a research item (Apple marks `sandbox-exec` unsupported; App Sandbox + XPC is the alternative).

## What this directory holds

- `feasibility.md` — does the App Sandbox + XPC approach actually work for the kinds of plugins MacCrab's first-party catalog produces? Answer + caveats.
- `xpc-ipc-contract.md` — IPC schema for daemon-side loader ↔ XPC plugin service. Aligned to plan §3.6 (MCP JSON-RPC over stdio).
- `sandbox-profile-shape.md` — declarative DSL the plugin's manifest declares; what the generator produces; what's enforceable.
- `gaps.md` — what's missing before Tier B can ship: signing CA + revocation list infrastructure (plan §12) + plan-level commitment.

## Status

Research only. None of this is on a release branch.
