# Repo audit — after v1.17.0-rc.7

**Date:** 2026-05-25
**Branch:** release/v1.17 at v1.17.0-rc.7
**Scope:** commit + file tracking, repo structure, refactor opportunities.

---

## 1. Tracking state

**Working tree clean.** No uncommitted, no untracked, no orphans:

```
$ git status --short
(empty)

$ git log --oneline v1.17.0-rc.7..HEAD
(empty — every commit is tagged)
```

**Every rc.1 → rc.7 commit is tagged.** Tags exist for:
`v1.17.0-rc.1` `v1.17.0-rc.2` `v1.17.0-rc.3` `v1.17.0-rc.4` `v1.17.0-rc.5` `v1.17.0-rc.6` `v1.17.0-rc.7`.

**Branches in use:**

| Branch | Purpose | State |
|---|---|---|
| `release/v1.17` | active rebuild line (this branch) | at `d48d46c` = rc.7 |
| `release/v1.13a` | v1.16.0 line | frozen at v1.16.0-rc.21 |
| `release/v1.12.7` | older shipping release | unchanged |
| `research/post-v15` | research spawn surface | unchanged |
| `main` | trunk | v1.12.9 — far behind the release branches |
| `v1.3.0-sysext` | legacy sysext checkpoint | dormant |

**Concern: `main` is at v1.12.9; the live shipping line `release/v1.13a` is at v1.16.0-rc.21.** main hasn't been advanced since the v1.16 series. Worth deciding whether to fast-forward main to release/v1.13a (or release/v1.17 once GA), or to keep main as the trunk-with-everything view. Recommend the fast-forward + a single trunk model in v1.18.

**Concern: 30+ active worktrees** under `.git/worktrees/`. These come from parallel agent sessions (`worktree-agent-*`). They're invisible to `git status` but consume disk + can confuse later cleanup. Not blocking; flagging for hygiene.

**`.gitignore` coverage** is fine. `.build/`, `.swiftpm/`, Xcode user data, macOS junk all excluded. `Package.resolved` IS tracked — correct decision per the file's own comment (Sparkle pinned).

### v1.17 cumulative delta (rc.1 → rc.7)

23 files added, 2 deleted, ~5,000 net lines added across 7 commits. Files concentrated in three buckets:

- `Sources/MacCrabApp/V2/Forensics/` (4 files) — operator-facing helpers (Kit, KitRunner, OperatorVisibilityFilter, RaveCatalogClient)
- `Sources/MacCrabApp/V2/Workspaces/` (6 forensics view files) — Scans / Findings / ScanDetail / SettingsSheet / Workspace / RaveCatalogBrowserSheet
- `Sources/maccrabctl/` (3 files) — ScanCommands, EvidenceCommands, PluginCatalogFetch (the last from the parallel rave session)
- `Sources/MacCrabApp/Resources/{kits,rave-keys}/` — bundled kit JSONs + catalog signing key
- `docs/` (4 planning docs preserved for the audit trail)

Two files deleted (rc.3 + rc.4 cleanup): the `V2ForensicsTierBView` view + the `XPCPluginLoader` research stub that had carried over from research/post-v15.

---

## 2. Structure — Sources/

```
Sources/
├── CSQLCipher/             — vendored SQLCipher 4.16.0 (C, ~0 Swift files)
├── MacCrabCore/    224 .swift   — detection + storage + LLM + collectors + ...
├── MacCrabForensics/ 79 .swift  — Mac Context Plugin Platform
├── MacCrabApp/      65 .swift   — SwiftUI menubar + dashboard
├── maccrabctl/      29 .swift   — CLI (maccrabctl)
├── MacCrabAgentKit/ 17 .swift   — shared daemon bootstrap
├── MacCrabAgent/     1 .swift   — System Extension entry point
├── maccrabd/         1 .swift   — legacy standalone daemon entry
└── maccrab-mcp/      1 .swift   — MCP server entry (2,051 lines, one file)
```

### Files over 1,500 lines

Most of these are pre-existing — not from the v1.17 rebuild — but worth flagging.

| File | Lines | Refactor verdict |
|---|---|---|
| `MacCrabApp/AppState.swift` | 2,648 | **Split** — should be ≤5 smaller files (poll loop, data ingest, persistence, navigation glue, settings bridge). |
| `MacCrabCore/Storage/EventStore.swift` | 2,243 | **Split** — already mixes schema mgmt, insert path, query path, rollup, prune. Each is a candidate file. |
| `MacCrabAgentKit/DaemonSetup.swift` | 2,158 | **Split** — config parsing + LLM service wiring + monitor activation + signal handling all in one file. |
| `MacCrabApp/V2/Workspaces/V2InvestigationWorkspace.swift` | 2,101 | **Split** — TraceGraph + Agent Traces + AI Analysis + legacy Forensics tabs all here. Each subview deserves its own file. |
| `maccrab-mcp/main.swift` | 2,051 | **Split into a target** — currently one giant `main.swift`. Should be `Sources/maccrab-mcp/{Server.swift, ToolRegistry.swift, Handlers/*.swift}` etc. |
| `MacCrabAgentKit/EventLoop.swift` | 1,996 | Split candidate. |
| `MacCrabAgentKit/DaemonTimers.swift` | 1,969 | Split candidate. |
| `MacCrabApp/Views/SettingsView.swift` | 1,712 | Split per Settings section. |
| `MacCrabCore/Storage/SQLiteCausalGraphStore.swift` | 1,604 | Split — store + query + migration. |
| `MacCrabApp/V2/Workspaces/V2AlertsWorkspace.swift` | 1,481 | Split per tab (Open / Campaigns / History / Suppressions). |

**Top refactor priorities (operator-impact, not lines):**

1. **`maccrab-mcp/main.swift`** (2,051 lines, 25 tools in one file) — adding/removing MCP tools is high-friction. Split into:
   ```
   Sources/maccrab-mcp/
     main.swift                ~80 lines (entry + JSON-RPC loop)
     ToolRegistry.swift        ~300 (the [String: Any] tool array)
     Handlers/
       AlertsHandlers.swift
       EventsHandlers.swift
       ForensicsHandlers.swift     ← rc.7's tierb.* / forensics.* renames
       TraceHandlers.swift
       IntelligenceHandlers.swift
       StylometricHandlers.swift
   ```
   Net: easier to evolve, cleaner diff per change.

2. **`MacCrabApp/V2/Workspaces/V2InvestigationWorkspace.swift`** (2,101 lines) — half is legacy Forensics tabs that v1.18 will delete anyway. Wait for v1.18, then trim aggressively.

3. **`MacCrabApp/AppState.swift`** (2,648 lines) — this is the central nervous system. Splitting carries real risk; should be a focused effort, not a side task. Mark as v1.18 backlog.

### Forensics-specific structure (after rc.7)

```
Sources/MacCrabForensics/
├── Cases/                    — case manager + DEK vault + layout
├── Plugins/                  — Tier A (in-process, first-party)
│   ├── Analyzers/
│   ├── Collectors/
│   ├── Enrichers/
│   ├── Fingerprinters/
│   ├── PluginRegistry.swift
│   ├── PluginRunner.swift
│   └── PluginManifest.swift
├── TierB/                    — third-party install/verify/trust
│   ├── PluginInstaller.swift  ← rc.7's plugin/tier-b → plugins migration
│   ├── PluginSignatureVerifier.swift
│   ├── TierBBootstrap.swift   ← still TierB internally; v1.18 rename → PluginCatalog
│   ├── TierBManifest.swift    ← v1.18 → ExternalPluginManifest
│   ├── TierBRegistry.swift    ← v1.18 → ExternalPluginRegistry
│   ├── CryptoSigning.swift
│   └── SandboxProfileBuilder.swift
├── Storage/                  — ArtifactStore + manifests + schema
├── MCFPResearch/             — R0 / R1 / R2 / R3 corpus tooling
├── Snapshots/                — LiveDBSnapshot
└── Integrations/             — TBD
```

The `TierB/` directory is the last operator-visible "Tier B" word in the codebase tree. The MCP names, on-disk path, CLI prints all use customer vocabulary now; the directory + internal types are the remaining hygiene. **v1.18 rename**: `TierB/` → `Plugins/External/` + `TierB*` types → `External*` / `PluginCatalog` types.

### MacCrabApp/V2 structure (after rc.7)

```
Sources/MacCrabApp/V2/
├── Components/              — shared UI bits
├── Data/                    — V2LiveDataProvider, V2HeartbeatSnapshot
├── Forensics/               ← rc.4 + rc.7 additions
│   ├── Kit.swift
│   ├── KitRunner.swift
│   ├── OperatorVisibilityFilter.swift
│   └── RaveCatalogClient.swift
├── Mock/                    — V2MockData for previews
├── Navigation/              — V2Workspace, V2DashboardState, V2DeepLink, V2NavigationHistory
├── Sidebar/                 — V2Sidebar
├── Workspaces/              ← rc.4 + rc.6 + rc.7 additions
│   ├── V2ForensicsWorkspace.swift
│   ├── V2ForensicsScansView.swift
│   ├── V2ForensicsScanDetailView.swift
│   ├── V2ForensicsFindingsView.swift
│   ├── V2ForensicsSettingsSheet.swift
│   ├── V2RaveCatalogBrowserSheet.swift
│   ├── V2InvestigationWorkspace.swift  ← 2,101 lines; legacy
│   └── ... (other workspaces)
├── V2RootView.swift
├── V2DashboardShell.swift
└── V2SettingsBridge.swift
```

The `Forensics/` subdirectory under V2 is the right home for forensics-specific helpers. Keep it.

The 6 V2Forensics*View files in `Workspaces/` are all under 400 lines each — clean. Good shape.

---

## 3. Documentation

- **9 source targets, only 1 has a README** (`Sources/MacCrabForensics/README.md`).
- Repo-level docs: well-served by `docs/` (4 v1.17 planning docs added during the rebuild).
- 151 markdown files repo-wide — most are rule documentation under `Rules/` (Sigma-style metadata). Reasonable.

**Recommendation:** add a one-page README to each source target explaining what the target is + its public entry points. Especially `maccrab-mcp/` (since the single main.swift hides the tool surface), `MacCrabAgentKit/` (since "Kit" is ambiguous), and `MacCrabApp/V2/` (since V2 vs the legacy v1 dashboard isn't obvious from the directory name).

---

## 4. Refactor backlog — proposed

Scope refactors as discrete v1.18-rc tasks. Each is a single-RC piece:

| Refactor | Scope | Risk | Operator value |
|---|---|---|---|
| `maccrab-mcp/main.swift` → split into `Server.swift` + `ToolRegistry.swift` + `Handlers/*.swift` | medium | low (purely organizational) | engineer-only; faster diffs on tool changes |
| `TierB*` internal rename → `ExternalPlugin*` / `PluginCatalog` | medium | low (mechanical) | invisible to operators, but stops the "Tier B in stack traces" leak |
| `MacCrabApp/V2/Workspaces/V2InvestigationWorkspace.swift` cleanup | small (after v1.18 deletes legacy tabs) | low | none |
| `MacCrabAgentKit/DaemonSetup.swift` split | medium | medium (touches the daemon entry path) | none |
| `MacCrabCore/Storage/EventStore.swift` split | large | high (this is the hot path) | none — defer indefinitely |
| `MacCrabApp/AppState.swift` split | large | high | defer to its own chapter |
| Per-target READMEs | small | none | engineer onboarding |

**Recommended v1.18 refactor sequence:**

1. v1.18.0-rc.1 — `maccrab-mcp` split + `TierB*` internal rename. Both mechanical, low risk, deliver as one RC.
2. v1.18.0-rc.2 — per-target READMEs + delete v1.17 legacy workspace tabs.
3. v1.18.0-rc.3 — `MacCrabAgentKit/DaemonSetup.swift` split (touches startup; care needed).
4. Defer the EventStore + AppState splits to v1.19 unless a concrete pain point surfaces.

---

## 5. Summary action items

| What | When |
|---|---|
| Decide: fast-forward `main` to current release line, or keep as trunk-of-everything | before v1.17.0 GA |
| Clean up `.git/worktrees/` (30+ stale agent worktrees) | one-time maintenance |
| `maccrab-mcp/main.swift` split into Server + ToolRegistry + Handlers/* | v1.18.0-rc.1 |
| `TierB*` Swift type rename → `ExternalPlugin*` / `PluginCatalog` | v1.18.0-rc.1 |
| Per-target READMEs | v1.18.0-rc.2 |
| `V2InvestigationWorkspace.swift` cleanup (after legacy tabs deleted) | v1.18.0-rc.2 |
| Decide EventStore + AppState split fate | v1.19 planning |

**Tracking state is healthy.** Every rebuild commit is tagged, working tree is clean, no orphans, `.gitignore` is correct. The structural issues are pre-existing accumulation, not regressions from the v1.17 rebuild.
