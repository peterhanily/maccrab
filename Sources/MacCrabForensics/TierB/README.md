# MacCrabForensics/TierB

Research-grade. Plan §3.9 + §12.

Tier B = subprocess-sandboxed plugin runtime. Not loaded by the live `PluginRegistry`; lives in this directory while design is being validated. Promoted to first-class once:

1. Sandbox profile generator emits profiles macOS accepts.
2. XPC service IPC contract is stable + reuses the MCP JSON-RPC wire format (plan §3.6).
3. Signing CA + revocation infrastructure (plan §12) is wired.
4. Plan-level commitment is made via a new chapter.

Until then this directory contains exploratory code + the reference Tier B FixturePlugin XPC service.

## Files

- `SandboxProfileBuilder.swift` — declarative DSL → text profile.
- `XPCPluginLoader.swift` — daemon-side loader (alongside the existing Tier A in-process loader).
- `Reference/` — reference Tier B plugin (FixturePlugin re-implemented as an XPC service).
- `docs/tier-b-research/` — the actual research write-up.

## What is NOT here

Anything user-facing. No Tier B plugins are auto-registered. The `LoggingConsentManager` / `PluginRegistry` / `PluginRunner` paths are unchanged. Track 1 + the v1.13a-v1.16 catalog continues to ship as Tier A only.
