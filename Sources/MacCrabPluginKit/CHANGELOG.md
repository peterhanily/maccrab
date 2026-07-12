# MacCrabPluginKit Changelog

The plugin-author SDK for MacCrab Tier-B forensic plugins. This changelog
tracks the SDK's **public API surface** only, and is versioned independently
of the MacCrab app/engine (see `MacCrabPluginKitVersion.swift`). Plugin
authors should pin against the SDK version here, not the app version.

Versioning is SemVer: MAJOR = breaking surface change, MINOR = backwards-
compatible addition, PATCH = behaviour-preserving fix.

## 1.0.0

First documented, stable SDK contract. First shipped in the MacCrab v1.21.3
app.

Public surface, all under `TierBBroker`:

- `TierBBroker.brokerFDEnv` — the environment-variable name
  (`MACCRAB_TIERB_BROKER_FD`) the sandboxed host uses to pass the broker
  socket fd.
- `TierBBroker.brokerFD` — the broker socket fd when running sandboxed,
  `nil` on the first-party lane.
- `TierBBroker.isSandboxed` — `true` on the community/store (brokered) lane.
- `TierBBroker.openHandle(_:)` — open a DECLARED read path as a read-only
  `FileHandle`. Brokered when sandboxed, opened directly when first-party.
- `TierBBroker.readDeclared(_:)` — read the full contents of a DECLARED path.

Use `openHandle` / `readDeclared` (not `open()` / `FileManager`) for your
declared reads so the same plugin works on both the first-party and the
sandboxed lanes without change.
