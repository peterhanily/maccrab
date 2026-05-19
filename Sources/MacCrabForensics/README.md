# MacCrabForensics

The Mac Context Plugin Platform — Track 2 of the MacCrab forward plan
(`plans/2026-05-19-plugin-platform-plan.md`).

This SPM library hosts the plugin runtime, the encrypted ArtifactStore,
the Case model, and the four kinds of first-party plugins (Collector,
Enricher, Fingerprinter, Analyzer). It is shared by:

- `maccrabctl` — v1.13a CLI surface (case + plugin subcommands)
- `MacCrabApp` — v1.13b Dashboard Forensics tab
- `maccrab-mcp` — auto-registered MCP tools per plugin
- `maccrab-forensicsd` — v1.13b user LaunchAgent daemon (not landed yet)

It is intentionally NOT linked by `MacCrabAgent` (the Endpoint Security
system extension) or `maccrabd` (the legacy standalone daemon). The
plugin runtime must not crash the detection engine.

## Sub-directories (as they land)

```
Plugins/        ForensicPlugin protocol + sub-protocols + PluginManifest +
                static registry. Fixture plugin lives here too until
                concrete collectors arrive.
Storage/        ArtifactStore (SQLCipher-backed) + per-blob AES-GCM vault
                + snapshot helpers for live application databases.
Cases/          Case model, per-case directory layout, login-keychain
                DEK wrap, idle-relock policy.
Plan §3 ↔ this directory:
  §3.3 protocol       → Plugins/ForensicPlugin.swift, Plugins/PluginManifest.swift
  §3.4 ArtifactStore  → Storage/ArtifactStore.swift, Storage/SchemaV1.swift
  §3.5 lifecycle      → Plugins/PluginInvocation.swift
  §3.8 audit Passes   → covered by scripts/pre-release-audit.sh (cross-cutting)
  §10.4 encryption    → Cases/CaseManager.swift, Cases/KeychainDEK.swift
```

## Build flags

The target depends on `CSQLCipher` (the vendored SQLCipher amalgamation,
`Sources/CSQLCipher/`) for the encrypted Case stores, and on
`MacCrabCore` for `Event` / `Alert` / `ProcessIdentity` types that the
plugin protocols reference.

## Tier

v1.13a ships first-party plugins only. They run in-process as Swift
code linked into the calling binary (Tier A). Third-party / sandboxed
plugins (Tier B) are explicitly out of scope until at least the
post-v1.15 chapter — see plan §3.9, §12.
