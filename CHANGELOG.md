# Changelog

All notable changes to MacCrab. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning: [SemVer](https://semver.org/spec/v2.0.0.html).

## [1.7.11] — 2026-04-30

Dashboard memory hot-fix. Field-reproduced: parking the dashboard on
the Events tab grew daemon-process retained memory ~1.5 GB/day via
1+ million NSLayoutConstraint + NSISRestrictedToZeroMarkerVariable
allocations. **Different process, different bug class** from the
v1.7.6-v1.7.10 daemon-side leaks — this one is in the SwiftUI app
target, retained (not autoreleased), driven by NSTableView
constraint inflation.

### Fixed — `EventStream` memoizes its filtered list

`Sources/MacCrabApp/Views/EventStream.swift`: replaced the computed
`filteredEvents` and `timeFilteredEvents` properties with a `@State`
cache that recomputes only when an actual input changes (the events
list, filter category, filter text, time range, sort order). The
body reads the cache directly. Previously the body re-filtered AND
re-sorted the entire `appState.events` list on every body
re-evaluation, AND read `timeFilteredEvents` twice per body call
(count badge + Table data) — so each unrelated `@Published` mutation
in AppState (heartbeat, agentLineage, mcpBaselines, etc.) drove a
double recomputation followed by a fresh `Table` rebind. Each
rebind inflated Auto Layout constraints in NSTableView's solver
that aren't released until the view is dismantled. Field-reproduced
rate: ~333 constraints/sec.

### Fixed — `AppState.refresh()` no-op `@Published` writes

Three high-frequency refresh functions (`refreshHeartbeat`,
`refreshStorageHealth`, `refreshRuleTamper`) re-read their backing
JSON file every poll and unconditionally re-published their snapshot,
even when neither the file nor the parsed value had changed. Each
unconditional write fired SwiftUI body re-evaluations across every
view bound to AppState. v1.7.11 adds mtime short-circuit guards
mirroring the existing pattern in `refreshAgentLineage`,
`refreshMCPBaselines`, and `refreshTCCSnapshot`. The functions now
skip the parse + assignment entirely when the file hasn't been
re-written since the last successful refresh.

### Fixed — equality-checked `@Published` Bool writes in `refresh()`

`isConnected`, `appHasFDA`, `sysextHasFDA`, and `fullDiskAccessGranted`
change at most once per session in normal operation (daemon up/down,
FDA grant/revoke). Pre-fix the unconditional assignment at every
poll fired `@Published` regardless. Now wrapped:
`if x != newValue { x = newValue }`. Reduces SwiftUI body re-eval
pressure across every view, not just Events.

### Added — Pass 9 extended to scan `Sources/MacCrabApp/`

`scripts/pre-release-audit.sh` Pass 9's directory list now includes
the dashboard target. The current leak shape (constraint retention)
isn't catchable by the existing `while-let / for-await + autoreleasing
Foundation API` regex, but extending the directory list:
- Catches future polling-path code that lands in a streaming-loop
  shape with autoreleasing Foundation calls
- Forces future authors to think about Foundation pool drainage when
  adding to MacCrabApp's hot paths

### Compatibility

Dashboard target only. Daemon code unchanged from v1.7.10. No data
migration. No reboot or extension re-approval required.

### Expected steady-state

For a dashboard parked on the Events tab:
- `NSLayoutConstraint` count: **stable around 5-15K** (normal
  SwiftUI layout churn), instead of climbing at ~333/sec
- Daemon-process RSS: **~120-250 MB**, stable indefinitely
- 24-hour soak should add < 50 MB of resident memory, vs the ~1.5 GB
  growth seen on v1.7.10

## [1.7.10] — 2026-04-29

UX hot-fix on top of v1.7.9: the Settings → About tab version label
read "v1.3.4" — hardcoded ~20 releases ago and never updated.

### Fixed — About page version label dynamic

`Sources/MacCrabApp/Views/SettingsView.swift`: replaced the hardcoded
`Text("v1.3.4")` with `Text(verbatim: "v\(Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "?")")`.
Now tracks `Info.plist` automatically — every future release is
correctly self-reported in the About panel without a manual edit.

The adjacent stats line ("7 event sources | 8 detection layers | 304
rules") was also updated to current values: 19 event sources | 5
detection layers | 424 rules. Still hardcoded (these counts only
change when the architecture changes), but at least current.

### v1.7.9 release rollout

v1.7.9 was published to GitHub but its Sparkle appcast and Homebrew
tap were intentionally held pending verification of the memory fix
on a second test machine. Verification confirmed the fix; v1.7.10
bundles the About-page fix and rolls v1.7.9's content out to all
channels in one shipping action.

## [1.7.9] — 2026-04-29

Memory hot-fix (round 2) + 3 new detection rules + observability +
audit codification + UX cleanup. Bigger than a typical patch but
targeted: every change is patch-scope (no new architecture, no new
training data, no design redesign).

### Fixed — autorelease pool drain extended to OUTER collector loops

v1.7.7 wrapped the inner per-LINE body of `EsloggerCollector` and
`UnifiedLogCollector` in `autoreleasepool`, draining JSON-parser
temporaries. v1.7.8 field reproduction on a different machine
showed 2.07 GB private heap dominated by **135,689 × 16 KB
NSConcreteData buffers** — the per-CHUNK `fileHandle.availableData`
return value was still autoreleased and accumulating in the OUTER
loop's pool. v1.7.7's fix was incomplete.

v1.7.9 wraps the OUTER `while true` body so the chunk Data drains
every iteration. Inner pool retained as belt-and-suspenders for
peak memory on chunks containing many lines. Same pattern applied
to `KdebugCollector` (caught by the new Pass 9 audit) and
`FileHasher.computeSHA256` (file-hash chunked reads via
`handle.read(upToCount:)` — likely the dominant leak source on
the field machine, called from per-file-event IOC matching).

### Added — Pass 9 + Pass 10 audits

`scripts/pre-release-audit.sh`:
- **Pass 9**: autoreleasing Foundation calls (`JSONSerialization`,
  `NSRegularExpression`, `DateFormatter`, `ISO8601DateFormatter`,
  `fileHandle.availableData`, `fileHandle.readDataOfLength`,
  `handle.read(upToCount:)`, `Data(contentsOf:)`) inside `while
  true`/`while let`/`for await` bodies without a surrounding
  `autoreleasepool` block fail the audit. Found 2 sites the v1.7.7
  fix had missed (`KdebugCollector.swift`, `FileHasher.swift`).
- **Pass 10**: when ≥ 2 stores share a `.db` file, each store's
  migrations must be runnable independent of the global
  `user_version` counter — verified via `SchemaMigrator.run()` call
  + no direct `PRAGMA user_version` manipulation. Codifies the
  v1.7.6 SchemaMigrator multi-store fix.

### Fixed — heartbeat per-collector counters

`event_count: 0` for every primary collector while
`events_processed: 1M+` was a broken telemetry signal: pre-fix,
only secondary collectors with their own MonitorTask `for await`
loop (TCC, USB, Clipboard, etc.) called `recordTick`. Primary
collectors (ESCollector, NetworkCollector, DNSCollector,
UnifiedLogCollector) feed the merged stream consumed by EventLoop
which lacked source attribution. Now EventLoop attributes each
event to a representative primary collector by `event_category`
and increments its tick. Operators can finally trust the
per-collector health flag.

### Added — three new detection rules

- `Rules/persistence/xpc_service_replacement.yml` — writes to
  `/Library/LaunchDaemons/*.plist` or `/Library/LaunchAgents/*.plist`
  by unsigned/ad-hoc-signed processes. Severity: **high**. T1543.004.
- `Rules/defense_evasion/network_extension_unsigned.yml` — unsigned
  `NEPacketTunnelProvider` / `NEDNSProxyProvider` /
  `NEAppProxyProvider` / `NEFilterDataProvider` installs. These
  providers can intercept every packet leaving the device.
  Severity: **critical**. T1556.
- `Rules/credential_access/crypto_wallet_data_access.yml` — reads
  of native cryptocurrency wallet directories (Electrum, Exodus,
  Atomic, Coinomi, Daedalus, Trezor Suite, Ledger Live) AND
  browser-extension wallet storage (MetaMask, Phantom, Coinbase,
  Trust Wallet, Binance Chain) by anything other than the wallet
  app or browser itself. Targets Atomic Stealer (AMOS), Banshee,
  similar macOS infostealers. Severity: **critical**. T1555.

The `c2_beacon_pattern.yml` timing-variance rewrite was descoped —
Sigma sequence engine doesn't support "step A repeated N times in
a window" (only "step A then step B"). Substituted with the
crypto-wallet rule which fills a real coverage gap.

### Added — `maccrabctl repair --fix-storage` schema check

`PRAGMA integrity_check` passes for the v1.7.5 → v1.7.6 bug shape
(alerts table missing `llm_investigation_json` column from a
silently-skipped migration) — the file is valid SQLite, just
schema-stale. v1.7.9 adds a `PRAGMA table_info(alerts)` column-
presence sanity check that fingerprints the v1.7.5 bug shape and
recommends installing v1.7.6+ instead of a destructive backup.

### Added — `ESCollector` defensive autoreleasepool

The per-event ES kernel callback isn't a `while let`/`for await`
shape so Pass 9 doesn't flag it, but the same Foundation autorelease
accumulation that bit Eslogger/UnifiedLog could happen here too.
Wrapped defensively to keep the discipline holding across collectors.

### Added — brew ↔ Sparkle drift detection

`MacCrabApp.isBrewInstalled` checks `Bundle.main.bundleURL.path` for
`/Caskroom/`. When true:
- `SPUStandardUpdaterController` initialised with `startingUpdater:
  false` and `automaticallyChecksForUpdates = false`
- Settings → AI Backend (next to "Check for Updates") shows a
  caption: "Installed via Homebrew. Background auto-update is off;
  upgrade with `brew upgrade --cask maccrab`. Manual checks above
  still work."

Stops the v1.6.13 → v1.7.5 channel-drift incident from recurring:
without this, Sparkle silently bumps the .app to v1.7.x while brew
still thinks it owns v1.6.x, then `brew upgrade` overwrites the
newer Sparkle binary with the older brew-formula one.

### Changed — metrics export format (schema 2)

`/var/tmp/maccrab.metrics.json`:
- Added `resident_memory_mb` (via `mach_task_basic_info`, no sudo
  required) — continuous RSS visibility so the next leak shape is
  caught at 100 MB rather than 1+ GB
- Added `events_dropped_total` and `events_per_sec_lifetime`
- Schema bumped 1 → 2

### Removed — zombie-sysext banner

The reboot-recommendation banner (introduced v1.7.5, restyled
v1.7.8) is gone. Showed every dashboard launch on installs with
leftover sysexts queued for uninstall, with no productive action
available from the dashboard. The diagnostic + recommendation
already lives in `maccrabctl repair`, which is the right surface.

Removed: the `.safeAreaInset(.top)` banner block in `MainView.swift`,
the `@AppStorage("dismissedZombieSysextCount")` declaration, the
`AppState.zombieSysextCount` published property, the
`refreshZombieSysextCount()` method, and the per-poll-cycle call.
Net deletion: ~50 lines.

### Changed — sidebar layout (Mail.app pattern)

v1.7.8's column-width-constraint + `.balanced` style still showed
the sidebar visibly narrowing on resize before snapping. The
cleaner UX, matching Mail.app and Calendar.app: enforce a generous
window minimum so the user simply can't drag the window into the
awkward state.

`MainView.swift`:
- `.navigationSplitViewStyle(.prominentDetail)` (replaces `.balanced`)
- `.frame(minWidth: 1100, minHeight: 600)` (up from 950)
- Removed `.navigationSplitViewColumnWidth(min: 200, ideal: 220,
  max: 280)` — let the system pick the sidebar default at the
  now-guaranteed comfortable window width

### Compatibility

No data migration. Existing v1.7.8 installs upgrade in place via
manual download, `brew upgrade --cask maccrab`, or Sparkle when
that channel is published. No reboot or extension re-approval
required.

Tests: 929/929 passing. Pre-release audit: 10/10 passes green.

## [1.7.8] — 2026-04-29

Dashboard UX hot-fix: zombie-sysext banner styling + sidebar layout.

### Fixed — zombie-sysext banner now opaque + dismissible

The reboot-recommendation banner (added v1.7.5, shown when 3+ prior
sysexts are queued for uninstall) used `Color.orange.opacity(0.12)`
as its background — translucent enough that the underlying content
showed through, and on tall windows it visually overlapped the
daemon-disconnect banner stacked above it. It also had no way to
dismiss.

Fix in `Sources/MacCrabApp/Views/MainView.swift`:
- Background: `.regularMaterial` (opaque, system-blur appearance)
- Visual cue: a 3-pt orange leading edge stripe instead of full-tint
- Dismiss: `xmark.circle.fill` button on the right, persisted via
  `@AppStorage("dismissedZombieSysextCount")`. Hides the banner once
  the user has acknowledged the count, but **re-appears** if a future
  upgrade adds MORE zombies (because the comparison is `current >
  dismissed`, not equality).

### Fixed — sidebar no longer overlays content on narrow windows

`NavigationSplitView`'s default `.automatic` style collapses the
sidebar into an overlay (sliding over the detail content) once the
window narrows past a threshold. Combined with no width constraint
on the sidebar column, this caused the sidebar to obscure detail
content during normal window-resizing rather than letting the detail
area scroll.

Fix:
- `.navigationSplitViewColumnWidth(min: 200, ideal: 220, max: 280)`
  on the sidebar column constrains its width range
- `.navigationSplitViewStyle(.balanced)` keeps both columns visible
  side-by-side; sidebar collapses only when explicitly toggled via
  the toolbar, never as a side-effect of window resize

### Compatibility

UX-only. No data migration. Same install path as v1.7.7.

## [1.7.7] — 2026-04-29

Memory hot-fix: 1.31 GB private heap → bounded steady state. Field-reproduced
on a v1.7.6 install where the daemon climbed from 50 MB → 1.52 GB RSS over
~1 hour at 197 events/sec sustained. Heap dump pinpointed 2.34M each of
`NSDictionary` / `NSError` / `_NSJSONReader` (1:1:1 ratio = one matched
triplet per parse) and 692 MB of `NSConcreteData` buffers — Foundation
objects autoreleased by `JSONSerialization.jsonObject(with:)` accumulating
in the autorelease pool of long-running async Tasks that never drain.

### Fixed — autorelease pool drained per event in collector hot loops

`EsloggerCollector.readLoop` and `UnifiedLogCollector` both stream NDJSON
through `JSONSerialization.jsonObject(with:)` per line, in `while` loops
that run for the lifetime of the daemon. Swift async Tasks don't carry
an implicit `@autoreleasepool` — Foundation autoreleased objects (the
parser's `NSDictionary`, `NSError`, `_NSJSONReader`, plus the input
`NSConcreteData` buffer for each chunk) accumulate until the Task ends,
which for these collectors is "never".

Fix: wrap each per-line iteration body in `autoreleasepool { ... }`.
The inner `continuation.yield` is synchronous (AsyncStream.yield doesn't
suspend), so the pool unwinds cleanly per event with zero behavior change.

Cost: one autoreleasepool entry/exit per event (~nanoseconds).
Benefit: at the field-reproduction rate (197 events/sec, 75% file events
streamed through these collectors), this prevents the ~1 GB/hour Swift
heap growth that v1.7.6 exposed.

The leak was masked in v1.7.5 because the daemon was crash-looping in
storage init (the SchemaMigrator bug that v1.7.6 fixed). With v1.7.6
keeping the daemon alive, both collector loops finally ran long enough
to reveal the autorelease accumulation. So v1.7.7 doesn't introduce a
new fix — it surfaces and patches a latent bug that pre-dates v1.7.0.

### Compatibility

No data migration. Existing v1.7.6 installs upgrade in place via Sparkle
or `brew upgrade --cask maccrab`. The new daemon takes over from sysextd
on next launch with bounded heap behaviour from the first event onwards.

No reboot or extension re-approval required.

## [1.7.6] — 2026-04-28

Hot-fix for a v1.7.5 daemon-init crash-loop reproduced in the field.
Root cause: a long-standing `SchemaMigrator` bug where co-resident
stores sharing a single SQLite file silently skipped each other's
migrations. Surfaced now because both EventStore and AlertStore hit
version 2 in this release. Field DB had `events` table fully migrated
but no `alerts.llm_investigation_json` column → AlertStore prepare
crashed on every boot, daemon exited in 127 ms, launchd respawned
every 10 s, dashboard showed "Detection engine appears silent".

### Fixed — SchemaMigrator multi-store user_version skip (the actual bug)

`PRAGMA user_version` is a single per-database counter, but EventStore
and AlertStore both run their own migration chains against `events.db`.
Pre-fix logic (`pending = migrations.filter { $0.version > current }`)
meant whichever store opened first set the counter, and the second
store's `pending` was empty even though its `ADD COLUMN` migration had
never run.

Fix in `Sources/MacCrabCore/Storage/SchemaMigrator.swift`: always
re-apply this store's migrations idempotently, in version order.
Bump `user_version` only on a forward step (`m.version > current`);
never lower the counter. Broadened `apply()`'s already-applied
detector from `duplicate column name` only to also include
`already exists` for `CREATE TABLE` / `CREATE INDEX` re-runs.

Cost: a few cheap fail-fast SQLite calls per store init. Benefit:
the second store's schema actually gets applied on existing DBs
that pre-date the new migration, with **no data loss** — events
and alerts history is preserved (probe-verified: 448 events + 182
alerts retained on the field-broken DB).

New regression test `Co-resident store: second store's migrations
apply when counter is at-or-ahead` in `SchemaMigratorTests.swift`
reproduces the exact two-store sequence that was failing in prod.

### Added — visible storage-init errors (defense in depth)

`DaemonSetup.swift` logs storage-init failures with `.public` privacy
so console diagnostics surface the actual SQLite error instead of
`<private>`. Pre-v1.7.6 logs read `Failed to initialize storage: <private>`,
leaving operators no way to diagnose without entitled `private_data:on`
log profile (which SIP-protected machines reject).

### Added — auto-recovery on storage-init failure

`DaemonSetup.recoverEventStore` / `recoverAlertStore`: on init
exception, back up `events.db{,-wal,-shm}` to a timestamped sibling
(`events.db.corrupt-<unix-ts>`) and retry init from scratch. On
retry-failure, writes `last_crash.json` with the original error
and exits, halting the launchd respawn loop after the second
consecutive failure. Used as a defense-in-depth fallback; for the
v1.7.5 issue specifically, the SchemaMigrator fix above means
recovery never triggers and history is preserved.

### Added — startup marker before storage init

`DaemonBootstrap.runForever` now writes
`/Library/Application Support/MacCrab/sysext_started.json` as its
very first action — synchronous, no actors, no storage. Mtime
distinguishes "launched but crashed in init" (banner: storage
recovery hint) from "never launched" (banner: reactivate extension).

### Added — `maccrabctl repair --fix-storage`

Operator escape hatch: backs up corrupt `events.db` files and lets
the daemon recreate them on next launch. Includes `PRAGMA integrity_check`
probe to skip the destructive backup if the DB is healthy.
`--force-fix-storage` overrides the integrity gate. For users hit
by the v1.7.5 SchemaMigrator bug specifically, this command is **not**
needed — installing v1.7.6 is sufficient and preserves history.

### Compatibility

No data migration required. Existing v1.7.5 installs: launching
v1.7.6 applies the missing `ADD COLUMN llm_investigation_json` to
the existing alerts table on first boot. No events or alerts lost.

No reboot or system extension re-approval required. sysextd swaps
the binary in-place when MacCrab.app reactivates the extension
(via Sparkle auto-update or `brew upgrade --cask maccrab`).

## [1.7.5] — 2026-04-28

Architectural improvements driven by a real v1.7.3 silent-heartbeat
incident. Three additions: split heartbeat (liveness vs rich
payload), `maccrabctl repair` self-diagnostic command, dashboard
zombie-sysext banner.

### Added — heartbeat split (`heartbeat.json` + `heartbeat_rich.json`)

New `livenessTimer` in `DaemonTimers.swift` runs **synchronously**
on the dispatch queue every 30 s and writes a minimal
`heartbeat.json` with only `written_at_unix`, `uptime_seconds`,
`sysext_has_fda`, `events_processed`, `alerts_emitted`. No actor
hops, no queries, no async work — cannot deadlock. The dashboard's
"engine silent" banner is gated on this file.

The rich payload (per-event-category counts, collector health,
drop counter) now lives in `heartbeat_rich.json` written by the
existing async heartbeat Task. Decoupling means a future stall
in EventStore queries or snapshot writes can never cause the
dashboard to show "engine silent" when the engine is actually
alive.

`AppState.refreshHeartbeat` reads `heartbeat.json` for liveness
and merges in fields from `heartbeat_rich.json` if present.
Backward-compatible: pre-v1.7.5 daemons wrote everything inline,
those fields still decode from `heartbeat.json` directly.

### Added — `maccrabctl repair`

New `Sources/maccrabctl/RepairCommand.swift`. Diagnose + auto-fix
common install issues. Six phases:

1. Daemon process liveness (`pgrep`)
2. Heartbeat staleness (mtime check)
3. System-extension state (`systemextensionsctl list`)
4. Orphaned writeSnapshot `.tmp` files (cleaned up)
5. SIGHUP daemon to reload config + rules
6. Operator-action recommendations for issues needing reboot /
   re-approval / FDA grant

`--dry-run` shows what would be done without taking action.

### Added — zombie-sysext banner

`AppState.refreshZombieSysextCount()` runs `systemextensionsctl
list` each poll tick and counts MacCrab entries in `[terminated
waiting to uninstall on reboot]` state. When ≥3, MainView shows a
top banner: "N prior MacCrab versions queued for uninstall —
reboot to clear them." Distinguishes the "needs reboot" case from
the generic "engine offline" case so operators see the right fix
immediately.

### Tests

926 in 188 suites pass (same as v1.7.4). v1.7.5 changes are
file-format split + new CLI + AppState property — covered by
existing snapshot-writer tests + manual `maccrabctl repair`
verification.

### Updated cadence

→ **1.7.5** (heartbeat split + repair tooling — defense against
the v1.7.x silent-heartbeat class)

### Updated key design lessons

- **Liveness signals must be on the simplest path possible.** The
  v1.7.0–v1.7.4 history shows that any async work in the heartbeat
  body is a future deadlock waiting to happen. v1.7.5 puts the
  liveness write on the dispatch thread itself — no Tasks, no
  actors, no queries. The richer signals live separately and can
  fail without affecting "is the daemon alive."
- **Operator self-service tooling reduces support load.** Without
  `maccrabctl repair`, every "engine silent" report required the
  user to run pgrep / stat / systemextensionsctl manually and
  paste output. With it, one command produces the full picture +
  attempts safe auto-repair + tells the operator exactly what's
  required.
- **The dashboard should distinguish reboot-needed from engine-
  hung.** Same symptom (no fresh heartbeat) but different fixes.
  The zombie-sysext banner surfaces a specific, actionable
  message instead of a generic warning.

## [1.7.4] — 2026-04-28

Follow-up hotfix to v1.7.3. The v1.7.3 memory fix combined two
changes that produced a new failure mode: any blocked snapshot
writer held the outer heartbeat-overlap-guard lock indefinitely,
every subsequent 30 s tick was dropped, and the dashboard showed
"Detection engine appears silent" after 120 s.

### Fixed — heartbeat-silent regression

Per-resource guards, not per-caller guards. Each snapshot writer
that lacked one (`MCPBaselineService.writeSnapshot`,
`RuleEngine.writeTelemetrySnapshot`, `TCCMonitor.writeSnapshot`)
now has a `snapshotWriteInFlight: Bool` matching the v1.6.6
`AgentLineageService` pattern. Concurrent writeSnapshot calls
no-op gracefully instead of queueing on the actor.

### Changed — `DaemonTimers.swift` heartbeat back to fire-and-forget

Removed the `HeartbeatInFlight` class and the outer overlap guard
introduced in v1.7.3. The four snapshot writes are once again
`Task { await ... }` fire-and-forget. The heartbeat write itself
is back on the critical fast path — no longer gated on snapshot
completion.

### Why this works

The v1.7.0–v1.7.2 leak was actor-queue buildup at the *writer*
level (concurrent writeSnapshot calls queueing on a busy actor's
mailbox). v1.7.3 cured it by serialising at the *caller* level
(one heartbeat Task at a time). v1.7.4 cures it at the right
level: the writer's own guard. Now the queue can't form because
the second call returns early before reaching the work.

### Tests

926 in 188 suites pass (was 922). +4 net (`V174GuardTests.swift`):
each writer round-trips a real snapshot file; 50 concurrent
`writeSnapshot` calls don't crash and at least one succeeds.

### Updated cadence

→ **1.7.4** (heartbeat-silent regression hotfix —
[[v174-heartbeat-fix]])

### Updated key design lessons

- **Don't add overlap guards at multiple layers.** v1.7.3 added a
  layer at the heartbeat scope on top of the existing per-writer
  guard at AgentLineageService. If even one inner writer lacks
  its own guard and blocks, the outer guard becomes a deadlock.
  Per-resource guards are the right level — each writer protects
  its own work, each caller doesn't need to know about the
  protection.
- **The heartbeat write is the critical path.** It's what the
  dashboard reads to determine "is the daemon alive." If the
  heartbeat write blocks on anything else (slow query, slow
  snapshot, slow lock), the operator sees "engine silent." The
  heartbeat must NEVER block on auxiliary work.
- **Fix at the right scope.** v1.7.3 was a real fix for a real
  leak, but applied at the wrong scope. The fix-the-fix in v1.7.4
  preserves the leak cure (no actor-queue buildup) while
  restoring the heartbeat fast path (writers can no-op if busy
  without blocking the heartbeat). Same shape as the v1.6.22
  audit chain — the real bug was 1 layer deeper than the first
  fix attempt.

## [1.7.3] — 2026-04-28

Memory regression hotfix. The v1.6.22 perf reduction (2.76 GB →
50 MB resident) had regressed back to 2.31 GB on a v1.7.2 test
host. This release restores the cap.

### Fixed — Heartbeat detached-Task accumulation (v1.7.1 cause)

The heartbeat-every-30s body in `DaemonTimers.swift` was wrapped in
`Task { ... }` to allow `await` across actor isolation, then
spawned 4 nested fire-and-forget `Task { ... }` calls for snapshot
writers (lineage, MCP baseline, rule telemetry, TCC). When any
snapshot write stalled (slow disk, contention, busy actor), the
next tick spawned 4 more — Tasks accumulated holding strong
`state: DaemonState` captures.

Fix: new `HeartbeatInFlight` class (NSLock + Bool) wraps the entire
heartbeat body. `tryAcquire()` returns false if a previous tick is
still running, dropping the new tick with one `WARN` log line. The
4 snapshot writes are now serialised via plain `await` inside the
outer Task. Hard cap: 1 outstanding heartbeat Task at any time.

### Fixed — `CollectorRegistry.entries` uncapped (v1.7.2 cause)

`recordTick(name:)` lazy-registered unknown names without an upper
bound. Any variance in collector name strings (PIDs, paths,
timestamps embedded in names) grew the dictionary indefinitely.

Fix: `init(maxEntries: Int = 64)` parameter floored at 16. When
`recordTick` lazy-registers and the cap is reached, evict
oldest-by-lastTick — preferring never-ticked entries first. One
`WARN` log per eviction surfaces missing `register()` calls.

### Fixed — `MCPAttributor.cache` non-deterministic eviction (v1.7.0 cause)

`cache.keys.first` removes an arbitrary entry from a Swift
Dictionary on overflow — not LRU. Frequently-accessed entries got
evicted; stale negative-cache entries persisted; re-walk pressure
grew.

Fix: new `accessSeq: [pid_t: UInt64]` parallel map bumped on every
cache hit and miss. Eviction picks the entry with the lowest seq.
Same pattern as v1.6.21 `RuleEngine.regexAccessSeq`.

### Added — `pre-release-audit.sh` Pass 8

Every `private var <field>: [...]` or `private var <field>: Set<...>`
declaration in actor source files (`MacCrabCore` +
`MacCrabAgentKit`) must show evidence of bounding:

- explicit cap-and-evict logic in the same file
  (`removeValue(forKey:)`, `removeFirst`, `removeAll`, `count >=`),
- an inline `// bounded:` comment, or
- an entry in the audit's `BOUNDED_FIELD_ALLOWLIST` with rationale.

A v1.7.3 baseline allowlist documents 22 pre-existing fields
(`MCPMonitor.knownServers`, `USBMonitor.knownDevices`,
`SystemPolicyMonitor.knownPlugins`, ...) where the bound is
external. New unbounded actor maps fail the audit and the release
pipeline. Catches the v1.7.2 regression class going forward.

### Tests

922 in 187 suites pass (was 918). +4 net (`V173HotfixTests.swift`):
CollectorRegistry cap eviction (oldest-tick), never-ticked-first
eviction, cap floor, MCPAttributor LRU eviction.

### Updated cadence

→ **1.7.3** (memory regression hotfix + Pass 8 codification —
[[v173-memory-hotfix]])

### Updated key design lessons

- **Detached `Task { ... }` calls inside a periodic timer
  accumulate.** Each tick that spawns a fire-and-forget Task creates
  a new captured-state graph. If the work doesn't complete before
  the next tick, the captures pile up. Pre-v1.7.3 the v1.7.1
  heartbeat spawned 5 Tasks per tick (1 outer + 4 nested). Fix:
  one Task per tick + serialise inner writes + overlap guard.
- **Every actor map needs a cap.** v1.7.2 added two unbounded
  collections (`CollectorRegistry.entries`,
  `MCPAttributor.accessSeq`) that grew with name-variance and
  eviction-skew respectively. Pass 8 codifies the cap-or-leak
  invariant — every `[K: V]` field on an actor needs bounding,
  documented or explicit.
- **Audit-then-fix beats reactive triage.** The 2 GB regression was
  caught from real Activity Monitor data, then localised by an
  Explore-agent audit before the fix bundle started. Same shape as
  v1.6.22.

## [1.7.2] — 2026-04-28

The 8-item carry-over queue from v1.7.0 + v1.7.1, all in one release.
Pre-ship deep-dive review found 2 HIGH + 3 MEDIUM issues (and
correctly rejected 1 falsely-reported BLOCKER and 1 falsely-reported
HIGH after verification) — all real findings fixed before push.

### Added — `CollectorRegistry` + heartbeat schema v4

New `Sources/MacCrabAgentKit/CollectorRegistry.swift` actor. Tracks
per-collector last-tick timestamps, event counts, error counts,
last-error strings, derived health. 16 collectors pre-registered at
daemon startup with characteristic intervals + event-driven flags.
Heartbeat schema bumped v3 → v4 with `collector_health` array +
aggregate `events_dropped` counter. Backward-compatible: older
dashboards see legacy fields unchanged.

`MonitorTasks` event-stream consumers call `recordTick(name:)` once
per emitted event — 12 single-line insertions across the existing
`for await event in state.<collector>.events` loops. Lazy-
registration default after pre-ship review fix:
`eventDriven: false, expected: 300s` + warning log so a forgotten
explicit `register()` surfaces.

### Added — `ESHealthView` daemon-driven collector list

Replaces the previous hardcoded 10-entry list with the
`heartbeat.collectorHealth` array. Per-row: name, healthy badge,
event count, error count, last-tick relative time, last-error inline.
Drop counter surfaces as a top banner when non-zero.

### Added — Search across 4 panels (AI Analysis, Prevention, Package Freshness, Integrations)

All four newly added `searchText` `@State`. Filtering applies before
the existing categorization splits (Investigations / Recommendations,
risky / safe, suspicious / non-suspicious, etc.).

### Added — Prevention per-mechanism drill sheet

Tap any "Recent Prevention Activity" row → sheet showing every
alert attributed to the inferred mechanism (DNS sinkhole, supply
chain gate, persistence guard, sandbox analysis, AI containment,
network blocker, TCC revocation, Other). Mechanism inference uses
rule-title token matching; pre-ship review added an explicit
`.other` enum case so unknown alert titles no longer mis-bucket
into AI Containment.

### Added — Integrations per-tool drill sheet

Tap any installed tool card → sheet showing path, log path, version,
running status, and full capabilities list. New
`ToolSelection: Identifiable` wrapper over the core
`InstalledTool` type so `.sheet(item:)` accepts it without
retroactive `Identifiable` conformance.

### Added — Aider / Codex MCP spawn-shape matchers

`MCPAttributor.looksLikePackageToken` recognizes `aider_mcp_*`
(Python module flag form), `@openai/codex` (NPM scope), and
`openai-codex-mcp-*` (Codex CLI MCP server form). Category
extraction supports the new prefixes. Two new tests cover each
shape. Carry from v1.7.0's deferred matcher list.

### Added — Rule engine P50 / P95 / P99 execution percentiles

`RuleEngine.RuleStats` gains an `execSamplesNs: [UInt64]` reservoir
(256 samples × 8 B × 420 rules ≈ 860 KB worst case). Sampling uses
Vitter Algorithm R: under reservoirSize append; once full replace
at a uniform-random index in `[0, reservoirSize)` with probability
`reservoirSize / evaluationCount`. Computed properties
`p50ExecNs` / `p95ExecNs` / `p99ExecNs` derive from the reservoir.
`RuleRow` shows p95 inline when ≥50 samples exist (threshold raised
from 20 → 50 in pre-ship review).

### Added — EventStore schema migration v2

Migration v2 promotes MCP attribution from `raw_json` only (v1.7.0)
to top-level indexed columns: `mcp_server_name`,
`mcp_server_category`, `ai_tool_session_id`. Composite index
`idx_events_mcp_server` on `(timestamp, mcp_server_name)`.
Insert SQL bumped from 21 → 24 bind columns; missing attributions
bind NULL. Migration runs inside `SchemaMigrator`'s existing
BEGIN/COMMIT wrapper with idempotent ADD COLUMN re-run support.

### Pre-ship deep-dive review

Five-axis review (perf / security / stability / functionality /
UX-accessibility) ran against v1.7.2 changes before push. 11
candidate findings; 2 falsely-reported (Vitter R correctness was
mathematically valid; SchemaMigrator already wrapped each migration
in a transaction with rollback). Real fixes applied:

- **HIGH**: CollectorRegistry lazy-register default
  (`eventDriven: false`, log warning).
- **HIGH**: AppState heartbeat decoder logs malformed
  `collector_health` entry drops via `os.log` warning.
- **MEDIUM**: PreventionView `.other` mechanism enum case
  (eliminates `.aiContainment` mis-bucketing of unknown titles).
- **MEDIUM**: RuleRow p95 threshold 20 → 50 samples.
- **MEDIUM**: ESHealthView empty state `.tertiary` → `.secondary`
  (WCAG AA on dark mode).

### Tests

918 in 185 suites pass (was 905 in v1.7.1). +13 net
(`V172Tests.swift` + extended `MCPAttributorTests`):
- CollectorRegistry: initial state, tick, lazy register, health
  decay, error tracking, drop counter (6)
- RuleEngine percentile: empty / single sample / sorted (3)
- EventStore schema v2: fresh insert with attribution / without (2)
- MCPAttributor: Aider + Codex shape (2)

### Deferred (not blocking ship)

Pre-ship review MEDIUMs not fixed: button styling consistency in
PreventionView, IntegrationsView Scan button visibility under
search, hardcoded collector name strings (refactor not regression).
Future scope: per-call LLM telemetry, daemon CPU/memory in
heartbeat, more MCP spawn shapes (await field reports).

## [1.7.1] — 2026-04-28

Track 2 panel-richness audit. The carry-over from v1.6.19 → v1.6.20 →
v1.6.21 → v1.6.22 → v1.7.0. Four primary panels (Rules, Browser
Extensions, Permissions, ES Health) gain the v1.6.17 Threat Intel
rebuild template: search + per-row metadata + per-source health +
multi-view modes for the panels where one list view didn't tell the
whole story.

### Added — RuleBrowser per-rule telemetry

- `RuleEngine.RuleStats` Codable type tracks per-rule fire count,
  total exec ns, last-fired Date. Updated on every `evaluate(_:)`
  call (fired or not). `writeTelemetrySnapshot(to:)` +
  `readTelemetrySnapshot(at:)` follow the same atomic temp+rename
  pattern as `AgentLineageService.writeSnapshot`.
- Daemon writes `<supportDir>/rule_telemetry.json` on the heartbeat
  tick. ~35 KB at 420 rules.
- Dashboard `AppState.refreshRuleTelemetry()` polls on the 10 s
  refresh cycle with mtime-skip optimization.
- `RuleRow` (in `Components.swift`) takes an optional `stats`
  parameter and renders fire count + last-fired + mean exec ms below
  the existing technique badges. `SLOW` row badge appears on rules
  whose mean exec exceeds the daemon's 50 ms slow-rule threshold.
- `RuleBrowser` adds a "Slow only" toggle and a "Most fires" sort
  mode alongside the existing alphabetical sort.

### Added — BrowserExtensionsView search + collapsible per-browser sections

- Cross-browser search by name, extension ID, or permission token.
- Per-browser collapsible sections via chevron click. Per-browser
  "N flagged" badge surfaces suspicious-extension count without
  expanding the section.

### Added — TCCTimeline three view modes (Permissions panel)

- New `TCCMonitor.PublicEntry` + `PermissionSnapshot` Codable types
  expose the previously-private current-state matrix to the
  dashboard.
- `TCCMonitor.writeSnapshot(to:)` + `readSnapshot(at:)` — atomic
  temp+rename to `<supportDir>/tcc_snapshot.json`.
- `AppState.refreshTCCSnapshot()` polls on the 10 s refresh cycle.
- `TCCTimeline.ViewMode` enum: `Timeline` (existing), `Services`
  (new, per-service group → list of apps with status), `Apps` (new,
  per-app group → list of services with status). Segmented picker
  in the header.

### Added — ESHealthView event-rate sparkline + per-category breakdown

- Rolling 60-point event-rate window (10 s × 60 = 10 min) rendered
  with `Charts.LineMark` + `AreaMark`.
- Per-event-category breakdown horizontal bar chart from the new
  heartbeat field.
- New `EventStore.eventCountsByCategory(since:)` indexed query over
  `idx_events_ts_category` returning `[String: Int]`.
- Heartbeat schema bumped v2 → v3: new `event_type_counts_1h` field.
  Backward-compatible: older readers ignore the new field.
- `heartbeatTimer.setEventHandler` body wrapped in a `Task` so the
  EventStore query can await across actor isolation. Failure is
  swallowed — heartbeat write must succeed even if the EventStore
  query times out under contention.

### Added — `pre-release-audit.sh` Pass 7

Primary panel view richness invariant. Every panel in
`Sources/MacCrabApp/Views/` listed in `PRIMARY_PANELS` must declare:

- A search-state (`@State` named `searchText` / `query` /
  `filterText` / `searchQuery`)
- A drill-down hook (`.sheet` / `.popover` / `NavigationLink` /
  `HSplitView` / multi-view `Picker` bound to a `viewMode` /
  `selectedSection` / `selectedTab` / `selectedMode` state)

`ESHealthView` is exempt on the strength of its sparkline + breakdown
+ collector list. Codifies the v1.6.17 Threat Intel rebuild template
as an architectural invariant. Add a new entry to `PRIMARY_PANELS`
when shipping a new primary panel.

### Tests

905 in 182 suites pass (was 898). +7 net (`Panel171SnapshotTests.swift`):
- `RuleEngine.TelemetrySnapshot` JSON round-trip
- `RuleStats.meanExecNs` zero-divisor guard
- Live `RuleEngine` write produces a readable empty snapshot
- `TCCMonitor.PermissionSnapshot` lossless encode/decode
- Missing-path returns nil (both telemetry + TCC readers)
- Malformed-JSON returns nil
- `EventStore.eventCountsByCategory` empty-store coverage

### Deferred to v1.7.2

- Drop-count + collector health registry on the heartbeat
- Rule engine P50/P95/P99 exec percentiles (mean is enough for the
  slow-rule filter)
- Aider / Codex MCP spawn-shape matchers (carry from v1.7.0)
- AI Analysis / Prevention / Package Freshness / Integrations panel
  rebuilds (P1/P2)

## [1.7.0] — 2026-04-28

First feature minor since v1.6.0. Closes the longest-standing
"wire-the-orphans" gap: `MCPBaselineService` (`Sources/MacCrabCore/
AIGuard/MCPBehavioralBaseline.swift`) has carried a complete
learning/enforcing API and `BaselineDeviation` AsyncStream since
v1.6.6, but the **producer half** that feeds it observations from
real events was never built. v1.7.0 builds it.

### Added — `MCPAttributor` actor

New `Sources/MacCrabCore/AIGuard/MCPAttributor.swift`. Walks each
AI-child event's process ancestry and matches each ancestor's
commandline against the AI tool's configured MCP servers (parsed by
`MCPMonitor` from the user's claude/cursor/etc. config files). On
match, returns an `Attribution` with server name, category,
boundary PID, and confidence (`high` / `medium` / `low`).

Cached by PID with a 5000-entry LRU. Negative results are also
cached — events from non-MCP processes pay one walk and zero
re-walks. Hot-path lookup is O(1) on cached PIDs;
O(ancestors × configured-servers) on first encounter (typically
< 50 work units).

### Added — per-event MCP attribution wiring

`EventLoop.swift` calls `MCPAttributor.attribute(...)` inside the
existing AI-child detection branch (only paying the cost on events
under an AI tool). On a positive match, three new keys are added to
`Event.enrichments`:

- `mcp_server_name`
- `mcp_server_category`
- `mcp_attribution_confidence`

These flow through the standard event pipeline and persist in
`raw_json` — no schema migration. (Indexed columns deferred to
v1.7.1 if/when the panel needs faster queries.)

### Added — MCP behavioral baseline observation feed

For each high/medium-confidence attributed event, EventLoop now
calls `MCPBaselineService.observe(...)` with a populated
`MCPBaselineObservation`. The dormant baseline service is now
fully wired into `DaemonState`: the dispatch loop in
`MonitorTasks.swift` consumes the `deviations` AsyncStream and
submits `Alert`s through the existing `AlertSink` chokepoint with
ruleId pattern `maccrab.mcp.baseline-anomaly.<tool>.<server>.
<kind>`, severity `medium`, MITRE-mapped to `attack.initial_access`
and `attack.command_and_control`.

Baselines need both 20 observations AND 5 minutes of wall-clock
before promoting from learning → enforcing.

### Added — `MCPBaselineService.writeSnapshot/readSnapshot`

The dormant baseline now also writes
`<supportDir>/mcp_baselines.json` on the 30 s heartbeat tick (same
cadence and atomic temp+rename pattern as
`AgentLineageService.writeSnapshot`). New `BaselineSnapshot`
Codable type wraps the snapshot for cross-process consumption.

### Added — `MCPActivityView` dashboard panel

New `Sources/MacCrabApp/Views/MCPActivityView.swift`. Lives in the
Intelligence sidebar group between AI Analysis and Integrations.
Per-server rows with name, AI tool, observation count, and
learning/enforcing badge. Click a row to see the full fingerprint
— every file basename, domain, and child process basename the
baseline has learned. Recent Baseline Drift alerts surface as a
banner above the list.

`AppState.refreshMCPBaselines()` polls
`<dataDir>/mcp_baselines.json` on the same 10 s dashboard refresh
cycle as the lineage snapshot, with mtime-skip optimization.

### Added — `MCPMonitor.serversForTool(_:)` + `allConfiguredServers()`

Public accessors over the previously-private `knownServers` map.
Used by `MCPAttributor` to look up the configured-server list for
an AI tool without re-parsing config files. New
`MCPMonitor.ConfiguredServer` struct is the public copy-by-value
shape.

### Added — `pre-release-audit.sh` Pass 6

Every public Codable snapshot type exposed by a daemon-side writer
(`AgentLineageService.LineageSnapshot`,
`MCPBaselineService.BaselineSnapshot`) must have at least one
`MacCrabApp` consumer. Fails release on regression. Catches the
snapshot variant of the wire-the-orphans pattern. Add a new pair
to `SNAPSHOT_PAIRS` when shipping a new daemon snapshot writer.

### Tests

898 in 181 suites pass (was 892). +6 net:
- `MCPAttributor` package-token match (high confidence)
- Negative-cache reuse on non-MCP processes
- Server-category derivation from `@modelcontextprotocol/server-X`
  and `mcp-server-X` package tokens
- No-match returns nil
- `MCPBaselineService` snapshot round-trip (with and without
  baselines)

### Updated cadence

→ **1.7.0** (MCP attribution producer half + behavioral baseline
deviation alerts + MCP Server Activity panel + Pass 6 audit
codification)

### Deferred

- v1.7.1 panel-richness audit (Rules / Browser Extensions /
  Permissions / ES Health) — carry-over from v1.6.19 → v1.6.20 →
  v1.6.21.
- AI tool spawn-shape matchers for Aider, Codex (Phase 1 covers
  Node-via-npx and Python-via-`-m`).

## [1.6.22] — 2026-04-28

Endpoint footprint reduction. Production observation on a v1.6.21
test host showed the sysext at 2.76 GB Real / 2.65 GB Private /
416 GB Virtual / 27 M Unix syscalls / 15 M Mach syscalls / 128 ports
over a 7-min CPU window. v1.6.22 retargets to ~800 MB resident,
~5 M syscalls per equivalent window through six structural cuts and
one bug fix the audit surfaced. Zero feature, detection-rule, or
dashboard changes.

### Fixed — `CampaignStore` opened `events.db` (third long-lived handle)

Pre-v1.6.22 `CampaignStore.init` called
`dir.appendingPathComponent("events.db")` and created its `campaigns`
table inside the shared events database — the third long-lived
SQLite connection on one file (EventStore + AlertStore + this).
Each handle carries its own page cache plus busy-timeout buffer; the
extra connection contributed unnecessarily to the daemon's resident
memory. CampaignStore now opens `campaigns.db`. The previous
`campaigns` table inside `events.db` is left in place; the next
size-cap-driven VACUUM reclaims the (small) space. Campaign history
persisted before v1.6.22 will reappear as the detector re-derives
campaigns from current alerts.

### Changed — SQLite per-connection memory pragmas

Centralized in `Sources/MacCrabCore/Storage/StoragePragmas.swift`.

- `EventStore` — `mmap_size` 256 MB → 64 MB; `cache_size` 64 MB →
  16 MB. Saves ~190 MB virtual + ~48 MB heap.
- `AlertStore` — `mmap_size` 256 MB → 16 MB; `cache_size` 64 MB →
  4 MB. Alerts table is 2–3 orders of magnitude smaller than events;
  the previous mmap was ~99 % wasted. Saves ~240 MB virtual +
  ~60 MB heap.
- `wal_autocheckpoint` 10 000 pages → 1 000 pages on both stores —
  drains the `.db-wal` file at ~4 MB instead of ~40 MB, reducing
  transient memory and the per-checkpoint stall length.

### Changed — outbound HTTP routes through `SecureURLSession.shared`

Pre-v1.6.22 the daemon-target callers (`ThreatIntelFeed`,
`MISPClient`, `FleetClient`, `CertTransparency`,
`NotificationIntegrations`, `PackageFreshnessChecker`) used
`URLSession.shared`. That session uses
`URLSessionConfiguration.default`, which writes a disk cache to
`~/Library/Caches/<bundle>/Cache.db` (+ WAL + SHM) and an HSTS /
cookie store to `httpstorages.sqlite`. When the daemon runs as root
those files land under `/private/var/root/Library/Caches/com.maccrab.agent/`
and accumulate forever — observed on a v1.6.21 test host alongside
the 2.76 GB resident spike.

`SecureURLSession.shared` (new module-shared singleton) uses
`URLSessionConfiguration.ephemeral`: no disk cache, no cookies,
no credential storage, TLS 1.2+ enforced. Same connection-pool
semantics as `URLSession.shared`, none of the side effects.

### Changed — heap caps tightened

- `AgentLineageService` per-session ring 10 000 → 2 000 events.
  At 32 sessions × 10 000 × ~300 B/event the worst case was
  ~96 MB resident; new worst case is ~19 MB.
- `CampaignDetector.recentAlerts` cap 50 000 → 5 000. Kill-chain
  detection runs on the recent campaign window (`campaignWindow`,
  default 600 s); beyond that, alerts are time-evicted anyway. The
  larger cap was ~100 MB heap with no detection benefit.
- `ProcessLineage.maxProcessCount` cap 50 000 → 10 000. LRU
  eviction prefers exited processes; a busy machine has ~200–800
  live PIDs, so 10 000 covers the live set plus a 1-hour retention
  window of recently-exited ones. ~30 MB heap.
- `ThreatIntelFeed` per-IOC-type defaults: hashes 200 K → 100 K;
  IPs 25 K → 10 K; domains 100 K → 50 K; URLs 75 K → 25 K. ~55 MB
  heap. Age-based eviction (30-day TTL) keeps coverage current.

### Changed — syscall volume per equivalent CPU window

- `LibraryInventory.getLoadedLibraries` per-process region cap
  10 000 → 2 000. Empirically every common process has fewer than
  800 distinct memory regions; 2 000 covers Xcode and Electron
  outliers with margin. The 10 000 cap dominated the 27 M
  Unix-syscall total at ~200 PIDs × up to 10 K `proc_pidinfo` calls
  per scan, every 5 minutes.
- `LibraryInventory` scan now actually runs every-other forensic-
  timer cycle (10 min cadence) instead of every cycle (5 min). The
  v1.6.21 inline comment promised "every other cycle" but no skip
  logic existed.
- `NetworkCollector` default poll 2 s → 10 s. Each sweep walks every
  PID with `proc_pidinfo(PROC_PIDLISTFDS)` + `proc_pidfdinfo` per
  FD. 5× interval = 5× syscall reduction. ES gives us real-time
  spawn context for the spawning process; the per-PID FD scan
  doesn't need 2 s resolution.
- `RootkitDetector` base interval 60 s → 120 s + PowerGate-gated.
  The dual-API discrepancy detection is not latency-sensitive — a
  true rootkit hides processes for the full daemon lifetime, not
  for sub-minute windows.

### Changed — hot-path stdout removed

18 `print()` calls on the alert hot path in
`Sources/MacCrabAgentKit/EventLoop.swift` removed. They were stdout
duplicates of work already going through the proper
`notifier.notify(alert:)` + `alertSink.submit(...)` paths. Net win
is small (~10–50 µs per call × 100 alerts/s ≈ 1–5 ms/s) but real,
and the orphan removal cleaned up unused severity-icon and
rule-result locals along the way.

### Added — `pre-release-audit.sh` Pass 4 + Pass 5

Two new architectural invariants enforced at release time:

- **Pass 4 — URLSession discipline.** Every outbound HTTP call in
  `Sources/MacCrabCore`, `Sources/MacCrabAgentKit`,
  `Sources/MacCrabAgent`, `Sources/maccrabd` must use
  `SecureURLSession.shared`. `URLSession.shared` fails the release.
  `MacCrabApp` is exempt because Sparkle and AppKit internals
  depend on it.
- **Pass 5 — `events.db` long-lived handle count.** Counts actors
  that BOTH open `events.db` (via `appendingPathComponent("events.db")`)
  AND declare a long-lived `private var db: OpaquePointer?`. The
  audited target is 2 (EventStore + AlertStore); 3+ fails the
  release. This is the pass that caught the CampaignStore bug
  fixed in this release.

### Tests

892 in 179 suites pass — same count as v1.6.21. No new test files;
all changes are behavioral / structural and covered by existing
storage, threat-intel, and HTTP suites.

## [1.6.21] — 2026-04-28

Surface completion + comprehensive multi-domain audit pass. Three small
surface fixes complete v1.6.x threads (no new features); a five-axis
review of v1.6.0–v1.6.20 found 6 BLOCKERs and 6 HIGHs, all fixed
before push.

### Audit fixes (BLOCKER)

- **TOCTOU in EventLoop network-convergence path** — was using legacy
  split `shouldSuppress()` + `recordAlert()` pair; under sustained
  cross-process convergence two threads could both pass the check
  and emit duplicate alerts. Now uses atomic
  `shouldSuppressAndRecord` (`EventLoop.swift:455-460`).
- **TOCTOU in EventLoop rule-engine match path** — same shape
  (`EventLoop.swift:986-987`).
- **Notify-after-suppress regression in 23 emission sites** — across
  EventLoop + MonitorTasks, `notifier.notify(alert:)` was firing
  unconditionally after `alertSink.submit` regardless of return
  value. Operators received notification banners for duplicates
  even though the alert was correctly suppressed from the store.
  All 23 sites now gate `notify` on `inserted == true`.
- **`SafeBlockableIP` IPv6 CIDR coverage** — pre-fix only exact-
  match IPv6 was supported, so `2001:4860:4860::8889` (one byte off
  Google DNS `::8888`) bypassed and blocking it would silently break
  IPv6 DNS. Added IPv6 CIDR matching for Cloudflare, Google, Quad9,
  OpenDNS DNS prefixes, plus loopback / link-local / multicast.
- **`MISPClient.fetchCategorized` validator gap** — extracted IPs/
  domains/hashes from MISP feeds without running them through the
  v1.6.18 validators that custom imports use. A compromised MISP
  server could push `127.0.0.1` as an IP and have it sinkholed.
  Now every value passes `ThreatIntelFeed.validate*`.
- **`SystemPolicyMonitor` PowerGate gap** — 5-min poll ignored
  battery / thermal pressure. Now uses `PowerGate.adjustedInterval`
  for the same throttling as other collectors.

### Audit fixes (HIGH)

- **`AlertDeduplicator.normalizePath` regex pre-compile** — was
  re-compiling 4 NSRegularExpression patterns per call (~0.9 ms ×
  100 alerts/sec ≈ 9 % CPU). Now pre-compiled once at class load.
- **`SafeQuarantinePathValidator` regex → string slicing** — replaced
  24 regex evals per call with O(1) `userHomeRemainder` + 12
  `hasPrefix` checks. ~10× faster, identical semantics.
- **`SafeBlockableIP.currentDefaultGateway` 30 s TTL cache** —
  pre-fix every `isSafeToBlock` call shelled out to `route -n get
  default` (~5–10 ms). Under PF block storms that was 5 % CPU. Now
  cached with 30-second TTL.
- **`ResponseEngine.executionLog` cap** — was unbounded; under
  sustained action firing it grew memory indefinitely. Now capped
  at 50 K entries with 5 K LRU evict on overflow.
- **`SettingsView.scheduleWebhookSync` cancellation handling** —
  `try? await Task.sleep(...)` swallowed CancellationError; partial
  writes possible under rapid keystrokes. Now catches explicitly
  and bails on cancel.
- **`ResponseActionsView` "Daemon reloaded" banner truthfulness** —
  banner said "Daemon reloaded." regardless of whether `pkill`
  succeeded. Now checks `terminationStatus` and shows
  "Saved. Daemon will reload on next start." when the sysext
  isn't reachable.

### Surface completion (no new features)

- **Pending Actions surface (completes v1.6.20's `requireConfirmation`
  thread).** When `ResponseEngine.execute` skips an action because
  `requireConfirmation = true`, it now also emits a synthetic
  `.informational` alert via AlertSink with rule ID
  `maccrab.pending-action.<action>`. Existing AlertsView / AlertDetailView
  manual-action buttons (kill / quarantine / blockNetwork via
  ManualResponse) become the "Run now" surface; existing alert-
  suppression UI becomes "Dismiss." No new SwiftUI view; reuses
  every existing piece.
- **LLM "Test Connection" button in Settings → AI Backend.** Calls
  `LLMService.makeFromConfig` against the current editor state
  (transient — does not write to disk). Inline status indicator:
  green check with provider name on success, red X with reason on
  failure (missing API key, unreachable backend, etc.). Resets to
  untested on any config edit so a stale OK doesn't mislead.
  Completes Tier 3 #15 from the v1.6.0 best-in-show roadmap.
- **AI Guard timeline surface** — verified already shipped in
  v1.6.15 (`AIActivityView.swift:130` already invokes
  `AIActivityTimelineView`). Listed as planned but no-op.

### Tests

892 in 179 suites pass — same count as v1.6.20 (no new test files;
all fixes are behavioral changes covered by existing suites).

## [1.6.20] — 2026-04-27

Response-action surface follow-up to v1.6.19's safety-hardening pass.
Same audit pattern applied to the per-rule auto-actions; five issues
found, all fixed.

### Added — quarantine system-path safety guard

`SafeQuarantinePathValidator` (new, `Sources/MacCrabCore/Prevention/`)
refuses to quarantine files in:

- System code: `/System/`, `/Library/Apple/`, `/Library/Frameworks/`,
  `/Library/PrivilegedHelperTools/`, `/Library/SystemExtensions/`,
  `/Library/LaunchDaemons/`, `/Library/LaunchAgents/`, `/usr/`,
  `/sbin/`, `/bin/`
- Runtime state: `/private/var/db/`, `/private/var/folders/`,
  `/etc/`, `/Library/Application Support/MacCrab/`
- Per-user data: Mail, Calendar, Contacts, Reminders, Keychain,
  Safari, iCloud, Photos, Time Machine, MacCrab user-home support

Symlink-safe (resolves via `resolvingSymlinksInPath` before prefix
match). Wired into both `ResponseEngine.quarantineFile` and
`ManualResponse.quarantineFile`. Quarantine remains opt-in by default
(built-in defaults are `notify` + `log` only).

### Added — `blockNetwork` protected-IP allowlist

`SafeBlockableIP` (new) refuses to PF-block public DNS (1.1.1.1,
8.8.8.8, 9.9.9.9, 208.67.222.222 + IPv6), Apple's 17.0.0.0/8 range,
loopback, link-local, multicast, carrier-grade NAT, and the current
default gateway (resolved at runtime via `route -n get default`).
Wired into `ResponseEngine.blockNetworkDestination` and
`ManualResponse.blockDestination`.

### Fixed — `requireConfirmation` now actually checked

Pre-v1.6.20 the `ResponseActionConfig.requireConfirmation: Bool`
field was decoded from `actions.json` and ignored by `ResponseEngine.
execute`. Operator who set it expecting a confirmation gate got
instant execution. Now: actions with `requireConfirmation = true`
are logged as pending and skipped. Surfaced as a per-action checkbox
in the Response Actions tab; destructive actions (kill / quarantine
/ blockNetwork) default to `true` when added from the editor with a
warning-icon visual marker.

### Fixed — `actions.json` user-home overlay + SIGHUP reload

Pre-v1.6.20 the dashboard tried to write `actions.json` to the
system path `/Library/Application Support/MacCrab/actions.json` —
which the user app can't write without root. `try?` swallowed the
EPERM and the "Saved." banner lied. Same pattern as the v1.6.19
webhook fix.

Now: dashboard always writes to user-home; `ResponseEngine.
loadConfig` walks `/Users/*` (with file-ownership validation) and
prefers the most-recent copy. SIGHUP triggers reload — no daemon
restart required. Save banner correctly says "Saved. Daemon reloaded."

### Fixed — `ManualResponse.killProcess` defense-in-depth

User-initiated kill path now uses `SafePIDValidator` for parity with
auto-kill. Practically safe before because the app runs unprivileged
and `kill()` would EPERM on system PIDs anyway, but explicit refusal
gives a better error message and protects against a future signed-
installer flow.

### Added — `pre-release-audit.sh` Pass 1b: Codable Config field consumer audit

Catches the `requireConfirmation`-shaped bug class for the future.
Walks public fields on `ResponseActionConfig` and
`NotificationIntegrations.Config`, counts `.fieldName` references
across `Sources/` minus trivial `self.fieldName = fieldName` init
self-assignments, errors when count is zero (decoded but never
read). Wired into `release.sh` Step 0b. Adding a new decoded-config
field without a runtime consumer now fails the release pipeline
before push.

### Tests

892 in 179 suites pass (was 860). +32 net:
SafeQuarantinePathValidator (17), SafeBlockableIP (15).

## [1.6.19] — 2026-04-26

A safety + architecture release. The bigger of the two threads.

### Added — safety guards (4 paths the audit found could damage the user's machine)

- `SafePIDValidator` refuses to kill PID ≤ 1, MacCrab itself, the
  critical-system-process list (kernel_task / launchd / WindowServer /
  loginwindow / securityd / opendirectoryd / cfprefsd / coreaudiod /
  bluetoothd / mDNSResponder / ...), or anything running from
  `/System/`, `/usr/libexec/`, `/sbin/`, `/usr/sbin/`. Wired into
  `ResponseEngine.killProcess` and `SupplyChainGate.gate`.
- `SupplyChainGate` now also requires the installer PID to descend from
  a known package manager (npm / pnpm / yarn / pip / brew / cargo /
  ...) within 5 hops, AND re-checks the path before the delayed
  SIGKILL so a recycled PID can't hit a different process.
- `DNSSinkhole` protected-domain allowlist refuses to sinkhole anything
  matching `apple.com`, `*.icloud.com`, `ocsp.apple.com`, `github.com`,
  `googleapis.com`, `microsoft.com`, `aws.amazon.com`, `stripe.com`,
  `jetbrains.com`, `slack.com`, `digicert.com`, `sectigo.com`,
  `letsencrypt.org`, `maccrab.com` itself, etc. (75+ patterns) plus
  IP literals. A poisoned threat-intel feed can no longer brick
  code-signing or strand the user.
- `PanicButton.activate` takes `disableBluetoothInPanic: Bool = false`
  so a wireless-only user with Magic Keyboard/Trackpad isn't stranded
  mid-panic. Panic is opt-in for BT now. (`PanicButton` itself was
  removed from `DaemonState` — `activate()` had zero callers.)

### Added — `AlertSink` chokepoint (closes the v1.6.9 NoiseFilter-layering bug class)

- New `AlertSink` actor: every alert reaches `AlertStore` through one
  point that applies `AlertDeduplicator` first. 39 direct
  `alertStore.insert` call sites in `EventLoop` / `MonitorTasks` /
  `DaemonTimers` / `SignalHandlers` migrated to `alertSink.submit`.
  Two audited exceptions in `DaemonSetup` (self-defense + ES-health)
  carry inline justification.
- `AlertDeduplicator.shouldSuppressAndRecord` is a new atomic actor
  method. It closes a TOCTOU window between the previous
  `shouldSuppress` + `recordAlert` pair: 50 concurrent submits with
  the same key now insert exactly one (test pins the contract).

### Added — institutional audit (`scripts/pre-release-audit.sh`)

Three architectural invariants enforced at release time:

- **Pass 1 — orphan audit.** Every Settings `@AppStorage` that affects
  daemon behavior must declare a sync function. Catches the
  wire-the-orphans pattern that produced four bugs in seven releases.
- **Pass 2 — single-sink.** Zero direct `alertStore.insert` outside
  `AlertSink` plus the two audited `DaemonSetup` exceptions.
- **Pass 3 — duplicate-source.** Cross-file constants (default
  support directory, sysext launchd label) must agree.

Wired into `release.sh` as Step 0b, fails the release on regression.

### Added — extended `prerelease-check.sh` manifest equality

Cask version (`Casks/maccrab.rb` ↔ `homebrew/maccrab.rb`), Sparkle
appcast URL (project.yml ↔ Info.plist), Sparkle EdDSA public key,
app + sysext `CFBundleIdentifier`, Apple Team ID with cask references.
Five new drift checks layered on the v1.6.18 short-version catch.

### Added — webhook config wiring

Pre-v1.6.19 the Settings → Slack/Teams/Discord/PagerDuty fields wrote
to UserDefaults but no daemon code consumed them. Configured webhooks
silently never fired. Now: SettingsView writes
`~/Library/Application Support/MacCrab/notifications.json`,
SIGHUP triggers `NotificationIntegrations.reloadConfig()`, alerts
fire to the configured services. 500 ms debounce on `onChange` so
typing the URL doesn't SIGHUP per keystroke.

### Removed — `autoQuarantine` / `autoKill` / `autoBlock` toggles

Same wire-the-orphans pattern: toggles wrote to UserDefaults, no daemon
code consumed them. Per-rule auto-actions live in the Response Actions
tab, which IS wired into `ResponseEngine`. 181 dead translation lines
swept across 14 locale files at the same time.

### Fixed (pre-push review)

- Webhook URL secrets no longer leak via Unified Logging on HTTP 4xx
  (added `privacy: .private` to `NotificationIntegrations` log lines).
- `SupplyChainGate`'s 2-second-delayed SIGKILL closure no longer
  captures the actor's logger (uses a fresh `Logger` inline) so it
  can't dangle if the actor were deallocated.

### Tests

860 in 177 suites pass (was 807). +53 net: SafePIDValidator (9),
SupplyChainGate safety (13), DNSSinkhole allowlist (22 — including
the BLOCKER-fix protected-domain coverage), AlertSink contract (9 —
including a 50-concurrent-submit TOCTOU pin).

## [1.6.18] — 2026-04-25

Three-issue follow-up to v1.6.17.

### Fixed

- **FP on own daemon at install.** v1.6.17's Refresh Now button sends
  `pkill -USR1 com.maccrab.agent` / `maccrabd`, which tripped the
  `security_tool_killed` rule (had `maccrabd` in target list and no
  non-fatal-signal filter). Removed `maccrabd` from both rules
  (`security_tool_killed.yml` and `defense_evasion_kill_persist.yml`),
  added `filter_nonfatal_signal` (`-HUP`, `-USR1`, `-USR2`,
  `SIGHUP`, `SIGUSR1`, `SIGUSR2`) and `filter_maccrab_self` (excludes
  command lines naming our own daemons). Other security tools still
  alert as before.
- **Custom-import IOC validation.** `addCustomIOCs` /
  `loadCustomFile` accepted any string — a user pasting "TODO" got
  it inserted as a domain. Five new public validators
  (`validateHash`, `validateIP`, `validateDomain`, `validateURL`)
  reject malformed entries. Both import APIs now return an
  `ImportResult { accepted, rejected }`. Dashboard import flow shows
  "Imported N of M. Rejected K malformed: ..." status.
- **CFBundleShortVersionString drift.** `Xcode/project.yml` had been
  stuck at `1.6.4` since that release. `prerelease-check.sh` only
  validated `CFBundleVersion` so the drift went unnoticed for 13
  releases. Bumped to 1.6.18 + added `prerelease-check.sh` guard.

### New

- `ThreatIntelFeed.ImportResult` struct + return values from
  `addCustomIOCs(...)` and `loadCustomFile(path:type:)`.
- Public validators: `validateHash`, `validateIP`, `validateDomain`,
  `validateURL`. Used by both the daemon-side imports and the
  dashboard's local pre-validation.

### Tests

**807 pass (up from 801).** Six new in `ThreatIntelValidatorTests`.
Two existing cache tests updated to use real 64-hex-char SHA-256
fixtures.

## [1.6.17] — 2026-04-25

Threat Intelligence panel rebuilt for context. The v1.6.16 browser
exposed bare strings; v1.6.17 carries source / firstSeen / malware
family / tags / fileType per IOC, switches feeds from "_recent"
endpoints to full CSV exports (10–100× more IOCs), adds per-feed
health badges, a Refresh Now button (SIGUSR1 to daemon), and
per-category caps with 30-day age-based eviction.

### New

- **`ThreatIntelFeed.IOCRecord`** — per-IOC metadata struct replaces
  `Set<String>` storage. New `recordFor*` accessors return the full
  record for alert enrichment.
- **CSV-backed feeds** — Feodo full `ipblocklist.csv`, URLhaus
  `csv_online/`, MalwareBazaar `csv/recent/`. Brings family + tag +
  first-seen metadata that the txt endpoints don't carry.
- **Rich Browse IOCs rows** — color source chip, family pill, tags,
  fileType, first-seen date, hash compaction. Search matches across
  all fields. Picker shows per-category counts.
- **Per-feed health row** — green/orange/red badges + tooltip with
  last-success / last-error timestamp + reason.
- **Refresh Now button** — SIGUSR1 to the daemon triggers a one-shot
  feed refresh; AppState invalidates the mtime gate and re-decodes
  on the next poll.
- **Per-category caps + age eviction** — 200K hashes / 25K IPs /
  100K domains / 75K URLs hard caps, 30-day stale eviction. Custom
  imports pinned through both.
- **`SIGUSR1` handler** in `SignalHandlers` calls
  `state.threatIntel.refreshNow()`.

### Schema

`feed_cache.json` changed shape. Daemon rewrites within hours of
upgrade; dashboard may show "no cache yet" briefly until the first
v1.6.17 refresh completes.

### Tests

**801 pass.** Two existing `ThreatIntelFeedCachedStatsTests` cases
updated to drive a real `ThreatIntelFeed` actor through the new
encoder.

## [1.6.16] — 2026-04-25

Makes the Threat Intelligence panel actually inspectable. v1.6.15
wired `threatIntelStats` end-to-end, but the counts were the *only*
thing visible — no way to see what the loaded IOCs actually were or
what the IOC list had been catching.

### New

- **Browse IOCs tab** — category picker (Hashes / IPs / Domains /
  URLs), substring search, source attribution per category, capped
  virtualized list.
- **Recent Matches panel** — alerts from `maccrab.threat-intel.hash-match`
  and `maccrab.dns.threat-intel-match` rendered with kind chip,
  process, matched-value description, timestamp.
- **`ThreatIntelFeed.cachedIOCs(at:)`** static accessor exposes the
  full on-disk IOC set for the dashboard.
- Empty-state differentiates "no cache file yet" from "loaded zero
  IOCs" — points to Feeds tab for manual refresh.

### Tests

**801 pass** (up from 799). Two new in `ThreatIntelFeedCachedStatsTests`.

## [1.6.15] — 2026-04-25

A four-bundle audit-driven release. Closes the same "intent-vs-reality"
gap that bit v1.6.9 / v1.6.12 / v1.6.14 — every shipped feature now
has daemon code consuming or producing it. Adds the agent-activity
timeline view that substantiates the "MacCrab sees what your agents
actually did" positioning that has been aspirational since v1.6.7.

### Bundle A — Wire the orphans

- **`TriageService`, `LLMConsensusService`, `AgenticInvestigator`** were
  declared in `DaemonState` but had zero callers. Moved to `AppState` —
  outbound HTTPS with vendor API keys does not belong at root
  privilege when the dashboard already owns the LLM config.
  `TriageService` is now wired to `AlertDetailView` as a one-click
  "Get AI Triage Recommendation" with `suppress` / `keep` / `escalate`
  / `inconclusive` disposition + rationale.
- **`threatIntelStats`** was a published property nothing wrote to.
  `ThreatIntelView` rendered "Malicious Hashes/IPs/Domains/URLs: 0"
  forever. Wired to `ThreatIntelFeed.cachedStats(at:)` reading the
  daemon's IOC cache.
- **`alertClusterService` + `mcpBaselineService`** instantiated on
  `DaemonState` but never invoked. Removed — `ClusterSheet` already
  creates per-render copies and `MCPBaselineService` lacks its
  producer half.

### Bundle B — Cache eviction perf

- **`LLMCache`**: O(n log n) full-dict sort on every overflow → O(n)
  min-scan over existing `accessSeq` counter. Header doc now matches
  implementation.
- **`RuleEngine` + `SequenceEngine` regex caches**: the same O(n)
  `lastIndex+remove+append` LRU pattern that commit `de5ed04`
  replaced in `LLMCache` was still in both engines. At the 2048-entry
  cap and 420 rules under burst this was the dominant rule-eval cost.
  Both rewritten to O(1) hit promotion via sequence-number sidecar.

### Bundle C — Stop double-scanning

- **`SecurityToolIntegrations`**: daemon now writes
  `integrations_snapshot.json` at startup and refreshes hourly.
  `IntegrationsView` reads the snapshot first, falls back to a local
  scan when missing. `BrowserExtensionsView` left intentionally
  unchanged — the sysext can't reliably read user-home paths so the
  dashboard's local scan is the authoritative producer.

### Bundle D — Agent activity timeline

- **`AgentEvent` + `AgentSessionSnapshot` Codable**, new
  `LineageSnapshot` wrapper. Daemon writes
  `agent_lineage.json` every 30 s on the heartbeat tick.
- **New `AIActivityTimelineView`** rendered under AI Guard: session
  picker chips, per-session kind-counts, chronological event rows
  with kind-specific SF Symbols and severity-colored alert rows,
  inline cap with "Show all" disclosure. Empty-state lists the 8
  supported tools.

### Stability hardening

- In-flight guard on `AgentLineageService.writeSnapshot` so a slow
  disk can't pile up Tasks under the heartbeat timer.
- Atomic-swap race fixed: `moveItem` first, fall back to
  `removeItem + moveItem` only on conflict (matches the existing
  heartbeat-write pattern).
- mtime gate on `AppState.refreshAgentLineage` so the dashboard's
  10 s poll doesn't re-decode an unchanged 30 s file 2/3 of the time.
- Orphan `.tmp` cleanup on encoder error in both writers.

### Tests

**799 pass (up from 783).** Sixteen new across:

- `LLMServiceFactoryTests` (3) — disabled / claude-no-key /
  openai-no-key paths.
- `ThreatIntelFeedCachedStatsTests` (3).
- `SecurityToolIntegrationsSnapshotTests` (4).
- `AgentLineageSnapshotTests` (4) — full round-trip across all 6
  event kinds, plus the in-flight guard regression.
- `LLMCacheTests.evictsBulkOverflow` (1).

## [1.6.14] — 2026-04-24

Closes the end-to-end gap on the size-cap path: v1.6.12 wired the
daemon, v1.6.13 hardened it, v1.6.14 actually connects the dashboard
slider to the daemon and fixes two silent-decode bugs in
`daemon_config.json` parsing that had been voiding operator configs
for many releases.

### Surfaced bugs

- **Settings slider was inert.** `@AppStorage("maxDatabaseSizeMB")`
  and `@AppStorage("retentionDays")` wrote to the app's
  `UserDefaults` (`~/Library/Preferences/com.maccrab.app.plist`).
  Nothing copied those values to `daemon_config.json`, which is what
  the sysext reads. Operators who moved the slider got no behavior
  change — the sysext kept the 500 MB / 30 d defaults.
- **`daemon_config.json` decoder was silently broken.** Two
  compounding hazards: `JSONDecoder.keyDecodingStrategy =
  .convertFromSnakeCase` mangles trailing-uppercase abbreviations
  (`max_database_size_mb` → `maxDatabaseSizeMb`, but the property is
  `maxDatabaseSizeMB`), and Swift's auto-synthesized `Decodable`
  ignores stored-property defaults — every non-Optional field must
  be present. Either hazard caused a full decode failure, which
  `load()` swallowed via `try?` and returned `DaemonConfig()`. Any
  operator-supplied `daemon_config.json` (snake_case or partial) has
  been silently reverting to all defaults on every field since the
  feature shipped.
- **Size cap ignored WAL.** Enforcer measured only the main `.db`
  file. A 480 MB main + 40 MB WAL presented as "under cap" while
  consuming 520 MB on disk.
- **Orphan user-domain DB from pre-sysext dev runs.** After a
  reinstall, the sysext writes to `/Library/.../events.db` while
  old `~/Library/.../events.db` (sometimes hundreds of MB) lingered
  untouched. Dashboard's mtime-based DB picker could select the
  orphan.

### Fixes

- `SettingsView.swift`: slider `onChange` writes to
  `~/Library/Application Support/MacCrab/user_overrides.json` and
  sends `pkill -HUP com.maccrab.agent`.
- `DaemonConfig.decode()`: overlays the user's JSON dict onto a
  freshly-encoded defaults dict (handles partial configs) and
  rewrites known snake_case keys to exact camelCase before decode
  (handles trailing-uppercase mismatches). `applyUserOverrides()`
  merges the dashboard's overrides file, bounded to the two
  storage keys and gated by home-dir uid ownership.
- `SignalHandlers.swift`: SIGHUP now reloads `DaemonConfig` and
  kicks an immediate size-cap sweep when `maxDatabaseSizeMB` or
  `retentionDays` changed.
- `DaemonTimers.swift`: `measureDatabaseFootprintMB()` sums
  `db + db-wal + db-shm`. Prune and size-cap timers read the cap /
  retention live from `state` each tick so SIGHUP reloads are
  honored on the next sweep.
- `DaemonSetup.swift`: orphan-DB reaper renames stale (>24h)
  `/Users/*/Library/Application Support/MacCrab/events.db*` to
  `events.db.orphan-<stamp>*` at sysext startup — forensic
  evidence preserved, dashboard picker stops selecting the orphan.

### Tests

**783 tests pass (up from 776).** New suites:

- `DaemonConfigOverridesTests` — snake_case, camelCase, partial,
  and defaults decode paths all lock in.
- `DatabaseFootprintTests` — db-only, db+wal+shm, and missing-files
  footprint math.

### Upgrading

Install v1.6.14, open Settings → Storage Limit, set the cap you want.
The slider now writes to disk and SIGHUP triggers an immediate
sweep. `log show --predicate 'subsystem == "com.maccrab.agent"'
--last 5m | grep -i "storage config\|size-cap"` confirms the sysext
received the new value. No data migration.

## [1.6.13] — 2026-04-24

Hardens the size-cap enforcer landed in v1.6.12 against real-world
failure modes (low disk, WAL-invisible shrinks, concurrent
invocations). No detection-engine or user-visible-feature changes.

### Changed

- **Pre-flight disk-space check** — VACUUM requires scratch space
  ~= DB size; enforcer now queries
  `volumeAvailableCapacityForImportantUsage` and skips VACUUM with
  an explicit warning log when free disk < 1.3× current DB size.
  Row prune still happens; file shrink deferred to next tick once
  disk frees.
- **Single VACUUM per sweep** — moved out of the prune loop, so
  a big DB gets one full-file rewrite per hour instead of up to
  8×.
- **50% per-sweep deletion cap** — a misestimated overage can
  never wipe more than half the rows in one pass. DB converges to
  target across a few hours on heavily over-cap installs.
- **WAL checkpoint pair** — `wal_checkpoint(PASSIVE)` runs before
  and after VACUUM so the main `.db` file (what Settings reads)
  reflects the shrink. PASSIVE never blocks; escalates to RESTART
  only if the passive pass couldn't drain the WAL.
- **Reentrancy guard** — `EventStore.beginSizeCapPrune()` /
  `endSizeCapPrune()`. Hourly timer + on-demand entry points
  can't double-invoke. Enforcer uses `defer` for the release.
- **First-sweep delay 10 min → 15 min** — lets collectors,
  inventory scans, and baseline hydration settle before the
  enforcer competes for IO. Hourly cadence unchanged.
- **Startup confirmation log** — daemon now emits a single line
  on boot confirming the cap is armed, the target, and the
  current DB size. Operators can grep to verify.

### Tests

776 pass (up from 769). +7 hardening tests: reentrancy guard,
walCheckpoint safety + drainage, VACUUM+checkpoint interaction,
guard lifecycle with defer, concurrent-acquire honor, pruneOldest
independence from the guard.

## [1.6.12] — 2026-04-24

### Fixed

- **`maxDatabaseSizeMB` now actually caps the database size.** The
  field had been defined in `DaemonConfig` and surfaced in Settings
  since forever, but no code ever read it — retention was time-only
  (`retentionDays`). A field report showed the SQLite file at
  18.95 GB against a 500 MB configured cap. Fixed by:
  - Adding `EventStore.pruneOldest(count:)` — batch-deletes oldest
    events + FTS rows, 100K per batch with `Task.yield()` between.
  - Adding `EventStore.vacuum()` — runs `VACUUM` to reclaim pages
    into on-disk file size (without this, `DELETE` doesn't shrink
    the file).
  - New hourly `sizeCapTimer` in `DaemonTimers` that checks the
    `events.db` file size and iteratively prunes + vacuums until
    the file drops below 80% of the configured cap.
  - `DaemonState.maxDatabaseSizeMB` plumbed through from
    `DaemonConfig` (clamped at 50 MB minimum).

### Tests

769 tests pass (up from 764). +5 tests cover the new `pruneOldest`
and `vacuum` APIs including cumulative disk-usage shrinkage.

## [1.6.11] — 2026-04-24

Pre-publication hygiene release. No detection-engine changes — just
the release pipeline and CI posture being honest about what they do.

### Fixed

- **`MacCrab-v*.pkg` was broken in every release.** `productbuild`'s
  distribution XML referenced `#maccrab.pkg` while the actual
  component pkg is named `maccrab-component-$$.pkg`. Result: a
  valid-looking 1.9 KB xar archive that installed nothing. Fixed by
  removing the PKG path entirely — `scripts/release.sh` and
  `.github/workflows/release.yml` no longer call `build-pkg.sh` and
  the asset is dropped from GitHub release uploads. DMG + Homebrew
  are the supported install paths.

### Changed

- **PR workflow permissions hardened.** `.github/workflows/build.yml`
  and `rules.yml` now declare `permissions: contents: read` at the
  workflow level. Previously inherited the default `contents: write`
  scope which gave fork-PR runners more than they needed.
- **Release scripts checked in.** `scripts/release.sh`,
  `scripts/build-release.sh`, and `scripts/notarize.sh` are now
  tracked so CI and fresh clones can run the release pipeline.
  Configuration is read from environment variables at runtime.
  `scripts/build-pkg.sh` remains gitignored and was removed locally.

## [1.6.10] — 2026-04-24

Three FP patterns surfaced by an overnight soak after v1.6.9 shipped.
Each one has a structural fix rather than an allowlist addition — the
same pattern: anchor on something the vendor can't rename around.

### Fixed

- **`hidden_file_created.yml` re-scoped to unsigned/adhoc only.**
  v1.6.5's Logitech vendor allowlist kept failing as Logitech renamed
  its binaries. Replaced with `selection_signer: SignerType in
  [unsigned, adHoc]` — every developer-ID-signed vendor peripheral
  agent is now excluded at the selection stage, no allowlist needed.
  Terminal-launched editors writing dotfiles still bypass via a
  `filter_terminal_parent`.
- **`c2_beacon_pattern.yml` filters developer-ID-signed
  `/Applications/` apps.** "Keynote Creator Studio" (3rd-party paid
  app) fired 3× in 5h because its 1-hour dedup window expired between
  beacons. Added `filter_devid_applications` — drops matches where
  the process is devId-signed AND installed in `/Applications/`.
  Covers paid app licensing / analytics / update HTTPS without
  allowlisting each vendor by name. Unsigned dropper-staged binaries
  still fire.
- **`PowerAnomalyDetector.knownLegitimate` adds `dasd`.** Duet
  Activity Scheduler is macOS's background-task scheduler; power
  assertions are its entire job. Added `dasd` + companions
  (`xpcproxy`, `ScheduleProxy`, `BackgroundTask`,
  `signpost_reporter_activity`) plus always-on cloud-sync clients
  (`Dropbox`, `OneDrive`, `Google Drive`, `iCloud Drive`, `Box`,
  `Boxclient`) that were missed in the v1.4.5 pass.

### Tests

764 tests pass (up from 761). +3 regression tests covering the
compiled-rule signer anchor, the devId+Applications filter
translation, and the live-scan dasd suppression.

## [1.6.9] — 2026-04-24

The architectural FP fix that ends the v1.6.x `networkserviceproxy`
thread, plus a security + performance audit pass on the v1.6.6 AI
Suite.

### Fixed

- **NoiseFilter now applies to every detection layer.** The
  longstanding `networkserviceproxy` credential-exfil FP was
  caused by `EventLoop` calling `NoiseFilter.apply` ONLY against
  Layer 1 (Sigma) matches — Layer 2 (Sequence) and Layer 3
  (Baseline / Behavioral Composite) matches were appended to the
  match list AFTER the filter ran, bypassing every gate we'd
  added since v1.6.2. Moved the call to after all three layers
  append.

### Added (security hardening — from audit)

- **`MCPBaselineService` DoS caps.** New `maxBaselines` (default
  256) and `maxSetSize` (default 512) parameters. Rotating
  `serverName` spoofing now triggers LRU eviction at the service
  level; per-server file/domain/child sets cap at `maxSetSize`.
- **`AgenticInvestigator` input validation.** `extractParam` caps
  values at 256 chars; `isSafeRuleId` rejects path separators and
  shell meta-characters; `isSafeProcessPath` rejects path traversal
  and control characters; `alert_descriptions` caps batch size at
  20 rule IDs per call.

### Changed (performance — from audit)

- **NoiseFilter gate reorder.** Gate 7 (Apple platform binary —
  O(1) bool check) runs first instead of seventh. Majority of Mac
  events short-circuit at the cheapest gate, bypassing the O(N-
  ancestors) Gate 6. Estimated ~40% CPU cut under burst.
- **NoiseFilter short-circuits.** `guard !matches.isEmpty` and
  `allSatisfy(.critical)` exits before the first gate in the
  cases where no gate could possibly change the outcome.
- **EventLoop AI-child fast path.** `AIProcessTracker.hasActiveSessionsHint`
  — a nonisolated, lock-protected Bool mirror of `sessions.isEmpty`.
  When no AI tools are running the whole AI-child detection block
  is skipped, saving ~3 actor hops per event on idle machines.
- **`AgentLineageService` ring buffer.** Replaced `[AgentEvent]` +
  `removeFirst(n)` with a fixed-capacity circular `EventRing`. O(1)
  append, O(1) overflow drop. Old code memmoved the entire tail on
  every overflow.

### Tests

761 tests pass (up from 748). +13 new tests covering the sequence
match regression, MCPBaseline cap enforcement under DoS-style
input, AgenticInvestigator input validation, and NoiseFilter
short-circuits.

## [1.6.8] — 2026-04-24

FP backstop closing out the v1.6.x discovery-rule thread, first AI
Suite dashboard surface, and two UI fixes for the allowlist manager
and campaign-card tap behavior.

### Fixed

- **NoiseFilter Gate 7: Apple platform binary backstop.** The recurring
  `/bin/ps`, `/usr/bin/defaults`, `/usr/bin/csrutil`, `/usr/bin/sw_vers`,
  and `/usr/sbin/system_profiler` FPs now suppress at the engine level
  regardless of rule-level filters. Gate 7 fires when the event's
  subject is flagged `isPlatformBinary`, code-sig-enriched as Apple,
  or running from a SIP-protected path prefix. Critical rules still
  fire.
- **`c2_beacon_pattern.yml` filter_apple_signed.** Keynote, Pages,
  Numbers, Mail, and every other Apple-bundled `/Applications/` app
  no longer fires the regular-interval beacon pattern when they make
  their routine iCloud syncs. Added `filter_apple_signed: SignerType:
  'apple'` to the rule.
- **Allowlist "Manage" button count vs content mismatch.** Button
  label previously used `AppState.suppressionPatterns.count` (v1
  legacy pattern list), dialog rendered v2 `SuppressionManager` entries
  from disk. Now `AppState.allowlistEntryCount` is authoritative and
  sourced from the same `SuppressionManager` the dialog uses;
  refreshed on every poll and on dialog dismiss.
- **Campaign row tap doesn't expand.** Only the header-HStack button
  toggled expand; clicking the summary text or tactics pills did
  nothing. Wrapped the collapsed-region VStack in `.contentShape(Rectangle())`
  + `.onTapGesture { onToggle() }` so every pixel toggles. Expanded-
  area buttons (Dismiss / Restore / Copy Details) sit outside the
  tap block so they retain their own hit regions.

### Added

- **`ClusterSheet`** — first UI surface for the v1.6.6 `AlertClusterService`.
  Opened from AlertDashboard's toolbar ("Clusters" button), groups the
  current alert list by `ruleId::processName` fingerprint, shows size
  + max severity + tactics union + first/last-seen per cluster.
  Expanded rows show contributing alerts; "Suppress all in cluster"
  bulk-silences every member in one click.

### Tests

748 tests pass (up from 741). +7 new tests for Gate 7 including
counter-tests (critical-on-ps still fires; non-Apple `/tmp/evil`
still fires at medium). Two pre-existing Gate 5 tests updated to
reflect Gate 7 interplay.

## [1.6.7] — 2026-04-24

Follow-up to v1.6.6's AI Suite: credential-audit hardening, EventLoop
wiring for the new services, first MCP tool for the Suite.

### Added

- **`LLMSanitizer` now redacts every known API-key shape** — Anthropic
  (`sk-ant-…`), OpenAI (`sk-…` / `sk-proj-…`), Google (`AIza…`), AWS
  (`AKIA…`/`ASIA…`/`AGPA…`/etc.), GitHub (`ghp_…`/`gho_…`/`ghu_…`/
  `github_pat_…`), Slack (`xox[aboprs]-…`), and generic `Bearer` tokens
  — regardless of surrounding context. Previously these were only
  caught when embedded in a recognized flag (`--api-key=…`).
- **IPv6 private-range redaction** — link-local (`fe80::/10`) and
  unique-local (`fc00::/7`) now redact to `[PRIVATE_IPV6]`. Public
  `2001:db8::` is preserved.
- **Mac `ComputerName` redaction** — `Peters-MacBook-Pro`,
  `Corp-Ops-iMac`, etc. redact to `[COMPUTER_NAME]`. Scoped to Mac
  product keywords so ordinary hyphenated prose passes through.
- **`OllamaBackend.isPlaintextRemote` guard** — refuses to send a
  Bearer token to a non-loopback host over plain `http://`, logs a
  diagnostic explaining how to fix (use `https://` or drop the key).
- **`cluster_alerts` MCP tool** — stateless alert clustering over the
  persisted alert DB, exposed to AI agents via the MCP server. Takes
  `hours` and `min_severity` filters, returns clusters with size,
  max severity, MITRE tactics union, first/last-seen timestamps.

### Changed

- **`LLMConfig` gains `CustomStringConvertible`/`debugDescription`**
  that masks API keys as `<len=N,first=X,last=Y>`. Accidental
  `print(config)` or `String(describing: config)` no longer dumps
  secrets via Mirror reflection.
- **`EventLoop` now routes AI-child events into `AgentLineageService`**
  automatically — file I/O, network connections, and process spawns
  under an AI-tool ancestor populate the timeline without any
  caller action. Fresh sessions start when an AI-tool process is
  seen; process spawns in its subtree record chronologically.
- **`DaemonState` gains six fields for the v1.6.6 AI Suite services**
  so EventLoop, polling timers, and MCP handlers can reach them
  through the standard `state.*` plumbing.

### Tests

**741 tests pass (up from 719).** +22 new tests covering
`LLMSanitizer` API-key redaction, IPv6 private ranges, Mac
ComputerName matching, `LLMConfig` description masking, and the
`OllamaBackend` plaintext-remote guard.

## [1.6.6] — 2026-04-23

The biggest AI push in the codebase yet. Six independent services
land in this release — every one covered by unit tests, every one
feature-flaggable, every one designed around MacCrab's unique kernel
vantage: **what agents actually do on the machine**, not just what
they say to the model.

### Added

- **`AlertClusterService`** (`Sources/MacCrabCore/Detection/`) —
  Deterministic-first alert clustering by `ruleId::processName`
  fingerprint. Optional on-demand LLM rationale pass for clusters
  the analyst expands. 11 unit tests.

- **`LLMConsensusService`** (`Sources/MacCrabCore/LLM/`) — Fan out
  a classification prompt to N configured backends in parallel;
  declare consensus only when ≥ threshold backends agree on a
  non-inconclusive label. Per-backend timeouts prevent the slowest
  from gating the result. 17 unit tests.

- **`TriageService`** (`Sources/MacCrabCore/LLM/`) — Single-backend
  disposition recommender. Produces one of `suppress / keep /
  escalate / inconclusive` with a one-sentence rationale. Advisory
  only; no auto-action. 12 unit tests.

- **`MCPBaselineService`** (`Sources/MacCrabCore/AIGuard/`) —
  Runtime behavioral fingerprint per MCP server (file basenames,
  DNS domains, child-process basenames). Dual-gate promotion
  (observation count AND wall-clock window) from `learning` to
  `enforcing`. Broadcasts `BaselineDeviation` via AsyncStream. 9
  unit tests.

- **`AgentLineageService`** (`Sources/MacCrabCore/AIGuard/`) —
  Chronological timeline of LLM API calls, process spawns, file
  I/O, network connections, and alerts per AI tool session.
  Per-session ring buffer, LRU session eviction. 9 unit tests.

- **`AgenticInvestigator`** (`Sources/MacCrabCore/LLM/`) — Bounded
  multi-round loop over a campaign with three tool calls
  (`describe_rule`, `alert_descriptions`, `process_children`) the
  LLM can issue to pull local context. Returns a structured
  `InvestigationReport` (verdict, summary, up to 5 findings,
  recommended action). 12 unit tests.

### Tests

**719 tests pass (up from 649).** +70 new tests across six feature
suites. Zero modifications to existing public APIs; each service
wires in as an opt-in dependency.

## [1.6.5] — 2026-04-23

Continuation of the v1.6.x FP-reduction thread. Eight distinct noise
patterns surfaced by overnight test-machine soak; four are fixed at the
engine level (new ancestor-walk gate), four at the rule level.

### Fixed

- **New NoiseFilter Gate 6: auto-updater ancestor walk.** v1.6.4's
  per-rule `ParentImage|contains 'GoogleUpdater'` filters only caught
  the immediate parent. Real chains nest deeper —
  Chrome → GoogleUpdater → launcher → GoogleUpdater → profiles — so
  `profiles`'s parent is the second GoogleUpdater but MDM-enrollment
  still fires. The new gate walks the full ancestor list, dropping
  non-critical matches whenever the subject or any ancestor is a
  known auto-updater (Sparkle, GoogleUpdater/Keystone, Microsoft
  AutoUpdate, `softwareupdated`, Homebrew). Critical still fires.

- **`isKnownBenignProcess` split into `isAutoUpdater` + daemon check.**
  The previous single helper mixed Apple-system-daemon paths with
  auto-updater paths; using it for ancestor-walk filtering swept in
  Terminal.app as "benign" and would silently disable detection for
  anything launched from a terminal. The narrower `isAutoUpdater`
  variant excludes Apple system paths and is the one used by
  Gate 6. Campaign detector continues to use the broader
  `isKnownBenignProcess` where "is this an OS component or updater?"
  is the right question.

- **TCC bypass rule allow-lists auto-updaters.** GoogleUpdater
  spawned from `/Applications/Google Chrome.app/` matched
  `selection_bundle_path` but the updater binary lives under
  `~/Library/Application Support/Google/…`, so
  `filter_developer_signed: Image|startswith '/Applications/'`
  didn't apply. Added explicit `filter_auto_updater_image` and
  `filter_auto_updater_endswith` covering GoogleUpdater, Sparkle,
  Keystone, Microsoft AutoUpdate, and the `launcher` basename.

- **Credential-theft sequence rule adds Apple-daemon basename
  filter.** `/usr/libexec/networkserviceproxy` fired
  `credential_theft_exfil` at CRITICAL despite the existing
  `filter_system_path`. The sequence engine's per-step filter
  evaluation can race with SignerType enrichment, so the cred_read
  step now also anchors on 16 well-known Apple daemon basenames
  (nsurlsessiond, trustd, apsd, accountsd, identityservicesd,
  cloudd, bird, fileproviderd, keychainsharingmessagingd, …).

- **Discovery-rule platform-path backstop.**
  `process_listing_by_unsigned.yml`, `defaults_read_sensitive.yml`,
  `system_enumeration_burst.yml`, and `csrutil_status_check.yml` now
  carry a `filter_system_path: Image|startswith` list covering
  `/bin/`, `/sbin/`, `/usr/bin/`, `/usr/sbin/`, `/usr/libexec/`,
  `/System/`. This is belt-and-braces with `filter_platform`
  (`PlatformBinary: true`) — field data showed PlatformBinary
  enrichment isn't always populated when ES events arrive before
  code-sig resolution settles. Since these paths are SIP-protected
  on a healthy system, a hard path anchor is a safe guarantee.

- **Hidden-file rule hardware-vendor allow-list.** Logitech Options+
  (`logioptionsplus_agent`) writes per-user dotfiles for state.
  Added `filter_hw_vendor_bundle: Image|startswith` for
  `/Library/Application Support/` subdirs Logitech, Razer, Elgato,
  Corsair, SteelSeries, Blackmagic, plus `/Applications/Logi Options+
  .app/` and `/Applications/Logitech*`. Vendor binaries rename
  frequently (`logi_agent` → `LogiMgrDaemon` → `logioptionsplus_agent`)
  so anchoring on install path is more durable than basename matching.

### Tests

649 tests pass (up from 643). New `AutoUpdaterAncestorGateTests`
suite (6 tests) locks in Gate 6: GoogleUpdater-as-subject suppressed,
`profiles` under 4-deep GoogleUpdater chain suppressed, Sparkle
Autoupdate ancestor suppressed, critical-under-updater still fires
(counter-test), non-updater ancestors NOT suppressed (counter-test),
public API exposed for detector reuse.

## [1.6.4] — 2026-04-23

Field-driven FP reduction in alerts and campaigns. Three structural bugs
and two rule-content fixes surfaced by user dogfooding after v1.6.2 shipped.

### Fixed

- **Coordinated-attack campaign no longer fires on single alerts with
  multi-tactic tags.** A rule carrying both `attack.discovery` and
  `attack.defense_evasion` (e.g., csrutil-status) counted as "2 tactics
  from 1 process" and triggered `Coordinated Attack from single process`
  despite only a single underlying event. The detector now requires ≥2
  distinct rule IDs before cross-tactic correlation kicks in.
  (`CampaignDetector.swift` — both PID and path branches.)

- **Campaign detector allow-list broadened to cover auto-updaters and
  package managers.** New `isKnownBenignProcess` helper covers Sparkle's
  `Autoupdate` binary (any path containing `Sparkle.framework/` or
  `.sparkle-project.Sparkle/Installation/`), Google's `GoogleUpdater` /
  `GoogleSoftwareUpdate` / `Keystone`, Microsoft AutoUpdate, macOS
  `softwareupdated` / `SoftwareUpdateNotificationManager`, and Homebrew.
  Previously those binaries produced repeated `Coordinated Attack` and
  `Kill Chain` campaigns during routine update cycles.

- **Kill-chain threshold raised 3 → 4.** Three distinct tactics within
  a 10-minute window was trivially hit on developer machines running
  everyday admin commands (ps / lsof / find + csrutil status + curl).
  Four tactics is a materially stronger signal while still matching
  real multi-stage attack shapes (discovery → credential_access →
  persistence → exfiltration).

- **`csrutil_status_check.yml` restricted to status-like commands.**
  The rule previously fired on any csrutil invocation; when a user ran
  `csrutil disable`, BOTH that rule AND `sip_check_before_tampering.yml`
  fired on the same event, producing two alerts tagged `discovery` and
  `defense_evasion` respectively. Now only fires on `status`, `netboot`,
  `authenticated-root status`, `--help`.

- **`mdm_enrollment_check.yml` excludes auto-updater processes.** Google's
  Updater runs `profiles status -type enrollment` as a legitimate
  MDM-awareness check before applying a Chrome/Drive update. Added filters
  for GoogleUpdater, GoogleSoftwareUpdate, Sparkle, SoftwareUpdate, and
  `launcher` parent processes.

### Tests

643 tests pass (up 5) — new `CampaignDetectorFPRegressionTests` locks in
the single-alert-multi-tag gate, the Sparkle + GoogleUpdater allow-list,
and the kill-chain threshold. Counter-test proves two distinct alerts on
the same process still fire coordinated-attack (the detector isn't just
turned off).

## [1.6.3] — 2026-04-23

Bring back the 🦀 menu-bar icon after immediate user feedback on v1.6.2.

### Fixed

- **Menu-bar icon is a crab again.** v1.6.2 replaced the emoji 🦀 with a
  template-rendered `shield.lefthalf.filled` SF Symbol for "proper" macOS
  styling — but the crab is the brand. Restored the emoji; kept the
  accessibility label ("MacCrab" / "MacCrab — protection degraded") and
  the degraded-state variant (⚠️🦀). Severity flash now prepends a
  colored severity dot to the crab (🔴🦀 for critical, 🟠🦀 for high)
  instead of replacing it with a shield.

## [1.6.2] — 2026-04-23

Dashboard polish release. Adds a theme system matching maccrab.com, proper
About panel with a website link, SF Symbol statusbar icon, and a set of
smaller fixes surfaced by three parallel specialist review agents
(SwiftUI architecture, macOS-native UX, a11y+performance).

### Added

- **`MacCrabTheme`** (new `Sources/MacCrabApp/Theme/MacCrabTheme.swift`) —
  ports maccrab.com's CSS custom properties verbatim: base/elevated/card
  backgrounds, border pairs, text primary/dim/mute, `accent`/`accentHot`/
  `accentDim`, `accentGhost` overlays, and severity palette. Each value
  ships Light + Dark variants via an `NSColor` dynamic provider so the
  dashboard tracks the system appearance setting. Applied via
  `.tint(MacCrabTheme.accent)` at the scene root so every native control
  (buttons, links, toggles, progress views, date pickers) picks up the
  brand orange automatically.

- **About MacCrab panel with maccrab.com link** — new
  `CommandGroup(replacing: .appInfo)` invokes a styled About panel with
  a clickable maccrab.com link in the credits, version + build, and
  CaddyLabs copyright. Plus a new Help menu with "Visit maccrab.com",
  "MacCrab Documentation", and "Report an Issue…" entries.

- **SF Symbol status-bar icon** — replaces the emoji 🦀 with template-
  rendered `shield.lefthalf.filled` (healthy) or
  `shield.lefthalf.filled.trianglebadge.exclamationmark` (degraded), so
  the icon adapts to light/dark menu bar automatically. Severity flash
  uses palette-rendered red/orange system shields.

### Fixed

- **Alert popover `.white` background** — `MacCrabApp.swift:284` now uses
  `NSColor.windowBackgroundColor` so the critical-alert NSPanel respects
  Dark Mode instead of floating bright white.
- **Hardcoded RGB severity colors in OverviewDashboard** — replaced with
  `MacCrabTheme.severityCritical` / `.severityHigh` / `.ok`.
- **`eventsPerSecond` churn** — idle polls no longer re-publish the same
  value; full-app view invalidation on a quiet system drops from "every
  10 s" to "when it actually changes."
- **AlertDashboard filter churn** — single-pass lazy filter replaces the
  three-stage `.filter → .map → .filter → .filter` chain. Each keystroke
  in the search box now does ~1× array traversal instead of 3–4×, and
  the intermediate AlertViewModel allocation on every pass is gone.
- **Poll timer lifecycle** — `AppState.startPolling()` / `.stopPolling()`,
  wired to `.onChange(of: scenePhase)`. Closing the dashboard window (or
  backgrounding the app) now pauses the 10-second DB poll.
- **Reduce Motion parity** — `CampaignView.swift:158, 181` and
  `AIAnalysisView.swift:243` expand/collapse now respect
  `\.accessibilityReduceMotion`.

### Changed

- `Info.plist` gains `LSApplicationCategoryType`, `NSHumanReadableCopyright`,
  `NSFullDiskAccessUsageDescription`, `NSLocalNetworkUsageDescription`,
  and an expanded `NSMicrophoneUsageDescription` — Security & Privacy
  panel now shows meaningful strings for every permission.
- `SuppressionManagerView` migrated from `.onAppear { Task { await ... } }`
  to `.task { await ... }` (auto-cancels on view dismount).
- Alert popover's `DispatchQueue.main.async` call site migrated to
  `Task { @MainActor in ... }` idiom.

## [1.6.1] — 2026-04-23

Field-driven noise reduction. v1.6.0 user dogfood showed 19 identical alerts
per 48h on a developer machine — all Xcode-session false positives. This
release fixes the structural and content issues behind that pattern.

### Fixed

- **Forensic-loop alerts now go through the AlertDeduplicator.** CrashReportMiner,
  PowerAnomalyDetector, and LibraryInventory in `DaemonTimers.swift` were
  inserting directly into AlertStore, bypassing `shouldSuppress(ruleId:processPath:)`.
  A long-lived process emitting the same finding on every forensic scan now
  suppresses correctly after the first alert.

- **LibraryInventory skips legitimate debug/build workflows.** Process allow-list
  (`lldb-rpc-server`, `lldb`, `debugserver`, `Instruments`, `xctest`, `XCTRunner`)
  + Xcode.app path prefix + build-artifact pattern match (`.debug.dylib`,
  `/DerivedData/`, `/.build/debug/`, `/target/debug/`). Also an internal
  `(pid, library)` pair dedup so the same loaded dylib can't re-alert across
  scan cycles even if the outer dedup window expires.

- **`c2_beacon_pattern.yml` filters developer tools.** Added `/usr/bin/` (where
  curl/wget/git/python live), `/Applications/Xcode.app/Contents/Developer/`,
  `/Library/Developer/CommandLineTools/`, and `/sbin/` to `filter_system`.
  Severity downgraded medium → low (timing-variance analysis not actually
  implemented in a Sigma rule; flagged in description for a future sequence
  rule). Eliminates the Xcode-git-pull "alert storm" campaign trigger.

- **CrossProcessCorrelator: dev-workflow allow-list.** New `allEventsAreDevWorkflow`
  gate in `evaluateNetworkChain` — skips convergence alerts when every
  contributing process is under `/Applications/GitHub Desktop.app/`,
  `/Applications/Xcode.app/`, `/Library/Developer/CommandLineTools/`,
  `/opt/homebrew/`, or is one of a small allow-list of exact paths
  (`/usr/bin/git`, `/usr/bin/curl`, `/usr/bin/wget`, `/usr/bin/ssh`). Also
  wires dedup around the convergence-alert emission path in `EventLoop.swift`.

- **Six high-FP-likelihood Sigma rules gained `filter_terminal` + `filter_apple_parent`.**
  `command_and_control/curl_to_raw_ip.yml`, `command_and_control/python_http_server.yml`,
  `command_and_control/netcat_listener.yml`, `command_and_control/ngrok_or_tunnel.yml`,
  `discovery/sensitive_file_search.yml`, `credential_access/ssh_key_file_read.yml`.
  Also added IDE + backup-tool filters to the SSH key rule.

### Tests

638 tests pass (up from 636) — 2 new regression tests in
`LibraryInventoryAllowlistTests.swift` that compile-time-lock the allowlist
members so a future refactor can't silently remove them.

## [1.6.0] — 2026-04-23

Minor release: new shape-based detection class + battery-aware polling +
analyst-triage CLI + three new detection rules + metrics export.

### Added

- **TopologyAnomalyDetector** (`Sources/MacCrabCore/Detection/TopologyAnomalyDetector.swift`).
  A new detection class, complementary to the existing Markov-chain
  `ProcessTreeAnalyzer`: shape-based categorical invariants over process
  lineage. Fires on `launchd_spawned_shell`, `system_process_spawning_
  staged_binary`, `anomalous_process_fanout` (20+ children from one parent
  in ≤10s), and `deep_process_descent` (depth > 15). No commercial macOS
  EDR does this class of detection — it catches attacks that use
  legitimate tools in illegitimate shapes. Emits via BehaviorScoring so
  the scoring / alert fan-out / suppression pipelines work unchanged.

- **PowerGate** (`Sources/MacCrabCore/Utilities/PowerGate.swift`).
  Battery + thermal state gate for poll-based collectors. Exposes
  `PowerGate.adjustedInterval(base:)` / `adjustedInterval(base:aggressiveness:)`
  that stretches poll intervals under low-power mode or thermal pressure.
  Wired into `ClipboardMonitor` (aggr 2.0), `USBMonitor` (aggr 2.0),
  `NetworkCollector` (aggr 1.0), `EDRMonitor` (aggr 1.0). Expected 15–25%
  battery-day improvement on laptops in low-power mode.

- **`maccrabctl why <alert_id>`** — new CLI subcommand that prints the
  compiled rule's predicates alongside the alert's captured fields so
  an analyst can see exactly why a rule fired without spelunking through
  YAML. Also handles synthetic alerts (`maccrab.behavior.*`,
  `maccrab.topology.*`, `maccrab.campaign.*`, `maccrab.self-defense.*`)
  by explaining the indicator family.

- **Metrics export** — sysext now writes `/var/tmp/maccrab.metrics.json`
  every 30 s alongside the heartbeat. Prometheus-textfile-style counters
  (`events_total`, `alerts_total`, `uptime_seconds`, `sysext_has_fda`,
  `power_state`) for external scraping.

### New detection rules

- `persistence/system_launchdaemon_plist_replaced.yml` — writes to
  `/System/Library/LaunchDaemons/` by non-Apple-signed processes (classic
  rootkit persistence after SIP bypass).
- `defense_evasion/network_extension_unsigned_install.yml` — unsigned
  NEPacketTunnelProvider / NEDNSProxyProvider installs. Allow-lists the
  major legitimate VPN and endpoint-security vendors.
- `persistence/dock_persistence_entry_written.yml` — non-terminal process
  running `defaults write com.apple.dock persistent-apps` (Dock-injection
  persistence).

Total rule count: **420** (378 single-event + 38 sequences + 4 topology
invariants emitted as synthetic alerts).

### Changed

- CLAUDE.md: rule count 417 → 420, test count 628/135 → 636/136.
- README.md: test badge 628 → 636.

## [1.5.5] — 2026-04-23

FDA banner fix v4 — architectural redesign + manual dismiss escape hatch.

### Fixed

- **Sysext FDA state is now reported by the sysext, not inferred by the app.**
  v1.5.2 through v1.5.4 all tried to detect sysext FDA by reading TCC.db
  from the app process. That approach is fundamentally broken: the system
  TCC.db (`/Library/Application Support/com.apple.TCC/TCC.db`, where the
  sysext's FDA grant actually lives) is mode `600 root:wheel` PLUS TCC-gated
  — a non-root process cannot open it regardless of its own FDA.

  The sysext runs as root and CAN reliably probe its own FDA by trying to
  read the system TCC.db (TCC gates the open, so success implies FDA). It
  now does this on every 30 s heartbeat tick and writes the result into
  `heartbeat.json` as `sysext_has_fda`. The app reads that field as the
  authoritative signal. The v1.5.2–1.5.4 TCC.db probe + WAL heuristic are
  kept as fallbacks for legacy sysexts that haven't written a schema v2
  heartbeat yet.

- **"Dismiss — I've granted access" button added to the FDA banner.**
  Escape hatch so the user is never stuck behind a stale banner if our
  detection fails again. The dismissal is persisted to UserDefaults and
  auto-cleared once detection later confirms both principals have FDA,
  so a future FDA revocation still re-surfaces the banner.

- Heartbeat schema bumped to version 2 (adds `sysext_has_fda` and
  `fda_checked_at_unix` fields). App handles v1 heartbeats gracefully via
  the fallback path.

## [1.5.4] — 2026-04-23

Install UX + hardening: suppress false tamper alert on first launch,
harden TCC.db probe, tighten FDA client match, correct documentation drift.

### Fixed

- **No more `rules_modified` tamper alert on fresh install.** SelfDefense
  now suppresses rules-directory write alerts during a 60-second startup
  grace window, covering the RuleBundleInstaller copy and DaemonSetup's
  `sequences/` subdir creation. Each write rebaselines the hash silently
  during the window; writes after the window keep the original hash
  comparison + critical-alert behavior. Also added a public
  `SelfDefense.snapshotRules()` entry point for a future Sparkle-upgrade
  sentinel flow.

- **TCC.db probe now rejects symlinks.** `querySysextFDAInDB` in AppState
  now calls `lstat` before `sqlite3_open_v2` (matching the existing pattern
  in EventStore / AlertStore). Closes a theoretical read-redirect attack
  where an attacker with write access to `/Library/Application Support/com.apple.TCC/`
  could swap the DB for a symlink.

- **FDA client match tightened.** Replaced the broad `LIKE 'com.maccrab.agent%'`
  clause with an explicit `IN ('com.maccrab.agent', 'com.maccrab.agent.systemextension')`
  set so future bundle IDs under that prefix don't get silently treated as
  the sysext.

### Changed

- Documentation: DocsView tactic count 16→17 (adds missing "Wireless" row),
  CLAUDE.md tactic directory count 18→17, README test count badge alignment
  (588 → 628 in body text).

## [1.5.3] — 2026-04-23

Fix sysext FDA detection: query both user and system TCC.db; widen WAL fallback to 30 min.

### Fixed

- `sysextHasFDA` detection now checks `/Library/Application Support/com.apple.TCC/TCC.db`
  (system-level) in addition to the user-level TCC.db — macOS stores the
  Endpoint Security extension FDA grant in the system DB on some builds.
  A `LIKE 'com.maccrab.agent%'` clause handles any `.systemextension` suffix
  variant seen across OS versions. Either database matching clears the banner.
- WAL mtime fallback window extended from 5 minutes to 30 minutes for the
  case where neither TCC.db is readable (app hasn't been granted FDA yet).
  A quiet system with no recent events no longer incorrectly shows the
  sysext as needing FDA.

## [1.5.2] — 2026-04-22

Dashboard UX fixes: reliable Full Disk Access detection and drag-to-install DMG.

### Fixed

- **Full Disk Access banner now clears immediately after both grants.**
  The sysext FDA check was using a WAL file mtime heuristic that tested
  whether the sysext was actively writing to disk, not whether it actually
  had FDA. When the app gains FDA it now queries `TCC.db` directly for the
  sysext's `auth_value` row — authoritative and instant. The banner updates
  within one 10-second poll cycle after each grant.

- **FDA banner redesigned as a two-row checklist.**
  Instead of switching between three paragraphs of text, the banner now
  shows "MacCrab ○/✓" and "MacCrab Endpoint Security Extension ○/✓" so
  users can see at a glance which grant is still pending after completing
  one of the two steps. The "Reveal MacCrab in Finder" button is now
  conditional — only shown when the app itself needs FDA (dragging from
  Finder is useful for the app; for the sysext entry, the list already
  contains it automatically).

- **DMG now shows the classic drag-to-Applications install window.**
  The release DMG was missing an `/Applications` symlink in the staging
  directory, so Finder opened it as a plain folder. Added the symlink so
  users see the standard side-by-side drag install UI.

## [1.5.1] — 2026-04-22

False positive fixes in 6 detection rules. No new detections, no Swift
source changes, no schema changes. 628 tests pass.

### Fixed

- `ssh_agent_access_suspicious`: condition changed from OR to AND — now
  fires only when python3/curl/wget/node specifically open `SSH_AUTH_SOCK`,
  not on any file access by those processes. Was the source of spurious HIGH
  alerts and cascading campaign noise on developer machines.
- `csrutil_status_check`: removed `attack.defense_evasion` tag. A single
  csrutil execution was contributing two MITRE tactics, triggering a
  "Coordinated Attack from single process" campaign on its own.
- `mdm_enrollment_check`: added `filter_terminal` so `profiles status` run
  interactively from any shell no longer fires.
- `hidden_file_created`: added image-path filter for Logitech Options+
  (`logioptionsplus_agent`, `LogiMgr`) which legitimately writes dotfiles
  in the user home directory.
- `process_listing_by_unsigned`: expanded terminal filter to include Cursor,
  VS Code, node, and ruby as known benign parents.
- `system_enumeration_burst`: same terminal filter expansion plus new
  `filter_apple_child: SignerType: apple` to suppress Apple-signed system
  tools (e.g. `system_profiler`, `scutil`) launched by non-terminal parents
  such as software installers.

## [1.5.0] — 2026-04-22

Major detection expansion: 37 new rules (417 total), 3 new sequence rules
(38 total), 2 new CLI commands, 18 new tests (628 total), and deep LLM
analysis for high-severity campaigns.

### Added

- **37 new Sigma-compatible rules** across exfiltration (rclone, cloud
  provider CLI, messaging API data upload, ICMP tunnel, paste service),
  lateral movement (Bonjour/mDNS host discovery, AirPlay to non-Apple
  receiver), and wireless/container/impact/supply chain tactics.
- **3 new sequence rules**: archive-then-cloud-exfil chain (T1560+T1567),
  LLM API key harvest+exfil (CanisterWorm pattern, T1552+T1041), and
  TEMPEST prep chain (SDR launch + outbound transfer, T1125+T1048).
- **`maccrabctl vulns`** — dedicated subcommand surfacing CVE scanner
  alerts (`maccrab.vuln.*`) with CVE ID, severity, affected app, and
  remediation detail. Supports `--hours` and `--severity` filters.
- **`maccrabctl privacy`** — dedicated subcommand surfacing egress
  anomaly alerts (`maccrab.privacy.*`) with human-readable labels
  (Bulk Egress / Domain Spike / Tracker Contact). Supports `--hours`.
- **Extended thinking** (`LLMBackend.completeWithExtendedThinking`):
  Claude Opus 4 backend uses `interleaved-thinking-2025-05-14` for
  deep campaign analysis. All other backends fall back to regular
  `complete()` transparently. `EventLoop` activates deep analysis for
  HIGH/CRITICAL campaigns with ≥3 distinct tactics.
- **UEBA weekday/weekend split**: per-user hour buckets are now
  maintained separately for weekdays and weekends. Off-hours severity
  escalation (0–4h and 22–23h = high, 5–6h and 19–21h = medium,
  7–18h = low). Backward-compatible Codable; existing profiles load
  with zeros for new fields.
- **VulnerabilityScanner → alert store**: critical/high CVEs emit
  `Alert` objects with deterministic IDs (`vuln-<cveId>`) that
  deduplicate via `INSERT OR REPLACE` across hourly scans.
- **AppPrivacyAuditor → alert store**: hourly egress anomaly checks
  emit medium alerts with deterministic IDs (`privacy-<process>-<kind>`).
- **DoH resolver expansion**: 28 IPs now detected (was 16). Added
  Cloudflare for Families (1.1.1.2/1.1.1.3), Quad9 IPv6, OpenDNS IPv6,
  AdGuard IPv6, Mullvad, ControlD, DNS.SB, and Comodo Secure DNS.
- **AppPrivacyAuditor tracking domains** expanded from 20 to 70+
  (Amplitude, Heap, Pendo, PostHog, Braze, Datadog, New Relic, Firebase,
  FullStory, LogRocket, LaunchDarkly, and more).

### Changed

- Three supply chain rules with unsupported count aggregation
  (`developer_credential_bulk_harvest`, `pip_install_triggers_credential_harvest`,
  `process_scans_for_llm_tools`) have the count expression removed
  (silently dropped by compiler). Replaced with stronger process filters.
  Severity reduced from critical → high/medium to reflect single-access
  detection threshold.
- Two sequence rules fixed for invalid `|not|` Sigma modifier
  (`keylogger_install_and_persist`, `package_typosquat_full_chain`).

## [1.4.9] — 2026-04-22

Same-day hotfix for a CampaignDetector FP surfaced after 1.4.8.

### Fixed

- **`CampaignDetector.checkCoordinatedAttack` skips trusted
  browser helpers.** Google Chrome Helper was triggering a
  HIGH "Coordinated Attack from single process" campaign
  spanning `credential_access` + `exfiltration` tactics during
  normal Chrome sync (reading its own Cookies / Login Data
  DBs and uploading to Google). Individual rule matches were
  already suppressed by NoiseFilter Gate 3, but the campaign
  path counted tactics one tier up. Added early-return for
  `NoiseFilter.isTrustedBrowserHelper(path:)` parallel to the
  existing `isAppleSystemDaemon` skip.

## [1.4.8] — 2026-04-22

Discovery-rule filter-gap fix, USB hub noise, CTK error-line
parsing.

### Added

- **`PlatformBinary` Sigma field** mapped to
  `process.is_platform_binary` in `Compiler/compile_rules.py`.
  Directly reads the ES-framework-provided platform bit without
  depending on the code-signing enrichment path (which returns
  nil for short-lived Apple CLI tools and silently breaks
  `SignerType: 'apple'` filters).

### Fixed

- **Discovery rules firing on Apple CLI tools from shell
  parents.** `filter_platform: PlatformBinary: 'true'` added
  to `system_enumeration_burst`, `xpc_service_enumeration`,
  `csrutil_status_check`, `process_listing_by_unsigned`, and
  `defaults_read_sensitive`. The existing `filter_apple:
  SignerType: 'apple'` silently failed when code-sign
  enrichment returned nil, allowing launchctl / system_profiler
  / defaults / ps / csrutil to fire when run from a Terminal
  shell.

- **USB device class `0x09` (hub) suppressed for
  informational.** Third-party USB hubs (Realtek, VIA, Intel
  chipsets) are not a credible exfil vector and churned on
  every replug and USB-C mode change. Mass-storage still
  surfaces regardless of vendor.

- **`SystemPolicyMonitor` skips pluginkit error lines.**
  `match: Connection invalid` and similar pluginkit status
  output was being parsed as CTK plugin bundle IDs and
  surfacing as informational alerts. New filter on
  `Connection invalid`, `Operation not permitted`, `No such`,
  `error`.

## [1.4.7] — 2026-04-22

Alert detail now surfaces the triggering event, and two more
v1.4.6-field-test FPs close.

### Added

- **Triggering Event panel in AlertDetailView.** The detail
  view now fetches the originating `Event` by id (via new
  `AppState.fetchEvent(id:)`) and renders command line, PID,
  signer + team id, parent process, ancestor chain, file path,
  destination endpoint, and TCC service fields. `AlertViewModel`
  gained an `eventId` field. Tamper / USB / clipboard alerts
  with no backing Event omit the section.

### Fixed

- **`SelfDefense` no longer flags attrib changes on non-critical
  paths.** sysextd stamps xattrs on the sysext executable every
  install + activation cycle, triggering "MacCrab Tamper
  Detection: Config Modified" at HIGH on the daemon's own
  binary. Only the LaunchDaemon plist and compiled-rules
  directory still escalate on attrib.
- **`plist_written_to_library.yml` filters browser helpers and
  Developer-ID-signed processes.** `filter_apple_signed`
  broadened to `apple | appStore | devId`. New
  `filter_browser_helper` covers Chrome / Chromium / Firefox /
  Safari / Edge / Arc / Brave / Opera / Vivaldi bundles.
  Fixes the Google-Chrome-from-`/var/folders/` → `~/Library/
  Google/Chrome/.../*.plist` FP.

## [1.4.6] — 2026-04-22

Same-day FP hotfix after v1.4.5 landed. Six false positives
observed on a real MacBook Pro — all six closed. No new
detection added; each change removes one specific FP class.

### Fixed

- **`credential_theft_exfil.yml` no longer fires on Apple system
  daemons.** Added step-level `filter_apple` (SignerType=apple)
  and `filter_system_path` to the `cred_read` step. Previously
  `networkserviceproxy` (Apple-signed, `/usr/libexec/`) was
  firing Critical on legitimate cred-path reads followed by the
  daemon's normal network activity.
- **`CrossProcessCorrelator` ignores rotated system logs.**
  New `hasRotatedLogSuffix` helper recognises `*.log.N`,
  `*.log.N.gz`, `*.log.N.bz2`. `/private/var/log/` and
  `/var/log/` added to `ignoredPathSubstrings`. `.log.bz2`
  added alongside `.log.gz`. Fixes the 3-process chain on
  `newsyslog` rotating `wifi.log.0`.
- **Apple VID 0x5AC USB events suppressed entirely for
  non-mass-storage.** Built-in keyboard, trackpad, camera,
  touchbar, T2 churn on every sleep/wake — filtered upstream
  of the rate limiter. Mass storage still surfaces regardless
  of vendor.
- **`csrutil_status_check.yml` adds `filter_terminal` step.**
  Previously filtered only `ParentImage|startswith /System/`;
  shell-parent csrutil from Terminal now suppressed.
- **`system_enumeration_burst.yml` adds `filter_terminal`
  step.** Covers shell-launched `whoami` / `uname` / `sw_vers`
  / `ifconfig` / `launchctl` from Terminal, which the
  `SignerType apple AND /System/ parent` filter missed.
- **`process_listing_by_unsigned.yml` filter_terminal includes
  shell basenames.** Added bash / zsh / sh / fish / dash
  alongside the existing Terminal.app bundle list.

## [1.4.5] — 2026-04-21

Waves B and C of the 1.4.x quality pass, shipped together. Wave B
addresses noise sources observed on a real MacBook Pro developer
workstation running v1.4.4. Wave C is a noise-severity rebalance
and a set of correctness fixes across the rule pack, sequence
engine, and UI-state persistence.

### Changed

- **Severity recalibration sweep.** 16 single-event rules moved
  from `level: critical` to `level: high` because their current
  selectors produce too many false positives on a developer
  workstation for a pager-level signal. Still actionable at HIGH,
  still aggregatable into a campaign. Rules affected:
  `memory_dump_credential_tools`, `ai_tool_downloads_script`,
  `crypto_miner_process`, `wifi_attack_tool`, `keychain_cli_extract`,
  `git_credential_helper_abuse`, `sensitive_file_read_untrusted`,
  `microphone_access_unsigned`, `pkg_downloads_and_executes`,
  `ai_tool_prompt_injection`, `rosetta_binary_from_downloads`,
  `endpoint_security_slot_exhaustion`, `shadow_hash_access`,
  `ssh_launched_security_dump`, `ai_tool_writes_persistence`,
  `keylogger_event_tap_active`. Total critical-level rules drops
  from 81 → 65.
- **`trojan_source_bidi_code.yml` deprecated.** The rule fires on
  any source-file write (`.py`, `.js`, …) without actually
  inspecting content for Unicode bidi overrides — no `FileContent`
  field reference. Status flipped to `deprecated`; compiler marks
  the rule `enabled: false` so it keeps its id/suppressions but
  the engine skips it. File kept for future reimplementation once
  the collector exposes content.
- **Four sequence rules now declare correlation explicitly.**
  `cron_install_then_exec`, `download_then_cryptominer`,
  `ransomware_kill_chain` get `correlation: process.lineage`.
  `usb_drop_then_exec` gets `correlation: file.path`. Rule-level
  correlation for `process.lineage` is loose (accepts all,
  precision comes from step-level `processRelation`); the
  declaration documents intent and locks the contract so future
  rule-engine tightening applies cleanly.

### Fixed

- **`CampaignDetector.checkLateralMovement` requires a real
  lateral-movement alert.** Previous trigger was ≥2 user contexts
  in the campaign window, which fires on every dev workstation
  (root daemon alert + user process alert = 2 user contexts). Now
  requires at least one contributing alert tagged with
  `lateral_movement` tactic *and* ≥2 user contexts. Real SSH /
  VNC / ARD launches across users still fire; idle dual-context
  noise stops.
- **`AppState.writeUIState` uses temp + rename.** The UI state
  writer (suppressions, suppressed IDs) previously wrote in place
  — a crash between open and close left a half-written JSON file
  that silently wiped the user's suppressions on next read. Now
  writes to `<filename>.tmp` and renames into place, matching the
  pattern DaemonTimers already uses for `heartbeat.json`.
- **`PowerAnomalyDetector.knownLegitimate` expanded.** Added
  `useractivityd`, `appleh13camerad`, `applecamerad`, `Signal`,
  `nsurlsessiond`, `AssetCacheLocatorService`, `AssetCache`,
  `mobileassetd`, `assetsubscriptiond`, `SEPAuthSession`,
  `SmartCardServices`, plus meeting apps `Google Meet`, `Zoom`,
  `Cisco Webex`. Every entry validated against observed field FPs.
- **`SystemPolicyMonitor` CryptoTokenKit alerts no longer fire
  HIGH on legitimate auth hardware.** New `trustedCTKProviders`
  substring list covers Yubico, 1Password, OneSpan, Thales,
  Entrust, Gemalto, OpenSC, mTrust. Unknown CTK extensions drop
  from HIGH to `.informational`.
- **USB alert rate limiting** via new `USBRateLimiter` actor in
  `MacCrabAgentKit`. Tracks `(vid:pid:direction)` tuples and
  suppresses duplicates within 24h per session. Mass-storage
  bypasses the limiter. Eliminates the per-hub-replug spam.
- **`BehaviorScorer.addRuleMatch` skips contributions from trusted
  browser helpers.** `NoiseFilter.isTrustedBrowserHelper(path:)`
  check at the scoring source. Fixes the "Google Chrome Helper
  accumulated suspicious behavior score of 10.8" HIGH alert
  driven by false `sigma_rule_match_critical` contributions.
- **NoiseFilter Gate 5 recognizes shell-binary ancestors as
  interactive.** New `shellAncestorBasenames` set (bash/zsh/sh/
  fish/dash/ksh/tcsh/csh) added to `isInteractiveTerminalAncestor`.
  Covers cases where the ES ancestor chain doesn't reach
  Terminal.app but the immediate parent is a shell.
- **`ssh_agent_access_suspicious.yml` adds `filter_terminal`.**
  Excludes parents of `/bash`, `/zsh`, `/sh`, `/fish`, `/dash`
  so dev work (Paramiko, Ansible, Fabric, `git clone` via ssh)
  stops firing HIGH alerts.

## [1.4.4] — 2026-04-21

Same-day hotfix for v1.4.3 — a user on v1.4.3 immediately saw the new
storage-error banner fire on a single transient `SQLITE_BUSY` during
WAL checkpoint, which is too noisy. Two changes close the gap.

### Fixed

- **`PRAGMA busy_timeout = 5000`** added in `EventStore.openDatabase`,
  `AlertStore.openDatabase`, `CampaignStore.openDatabase`. Default was
  0 (no retry), so any transient lock contention — e.g., a background
  WAL autocheckpoint briefly holding the write lock while an event
  insert queued — returned `SQLITE_BUSY` immediately. With 5s the
  insert waits for the checkpoint to complete and proceeds cleanly.
  Standard SQLite multi-writer best practice.
- **Storage-error banner threshold tuned.** New
  `AppState.hasConcerningStorageError(snap)` replaces the v1.4.3
  `hasRecentStorageError`. Requires ≥5 total write failures AND the
  most recent within 120s (was: any failure within 600s). Keeps the
  banner a signal for real persistent issues — disk full,
  permissions, corruption — without firing on single transients.

## [1.4.3] — 2026-04-21

Wave A of the 1.4.x quality pass — "fail loud, not silent". Five
protection-guarantee failure modes where MacCrab looked fine while
not actually protecting the user get made visible: zero-rules-loaded,
sysext crashed/hung, storage writes failing, sysext silently replaced
by a no-op, rules tampered post-install.

### Added

- **`DetectionHealthBanner`** (`Sources/MacCrabApp/Views/OverviewDashboard.swift`)
  — reusable critical/warning banner shared by four new protection-health
  states. Keeps the Overview from accumulating bespoke one-off banners
  when new health signals land.
- **`AppState.isProtectionDegraded`** aggregates health signals. The
  statusbar crab flips between `🦀` (healthy) and `⚠️🦀` (degraded)
  via a 5s-cadence timer in AppDelegate.
- **Heartbeat timer in sysext** (`DaemonTimers.swift`). Writes
  `/Library/Application Support/MacCrab/heartbeat.json` every 30s
  via a temp+rename pattern so readers never catch a half-written
  file. Payload: written_at, uptime, events/alerts counters.
- **`refreshHeartbeat`, `refreshStorageHealth`, `refreshRuleTamper`**
  in `AppState.refresh()`. Three sysext-written JSON snapshots
  polled every 10s.
- **Watchdog callback** wired from MacCrabApp.onAppear →
  `AppState.sysextWatchdogActivate`. When heartbeat has been stale
  ≥120s and we haven't retried in the last 5min, AppState calls
  `sysextManager.activate()` to respawn via OSSystemExtensionRequest.
  Idempotent; cooldowned.
- **Rule-manifest SHA-256 verification** in `RuleBundleInstaller`.
  `build-release.sh` now generates `manifest.json` listing SHA-256
  of every compiled rule. `verifyManifest(at:)` runs on both the
  bundled and installed trees on every launch; mismatch → refuse to
  sync (bundled tampered) or auto-resync (installed tampered) plus
  a `rule_tamper.json` snapshot the dashboard polls.
- **Fail-loud banners** surface all four signals on Overview:
  zero-rules, stale heartbeat, storage errors, rule tamper. Each
  with actionable body text and an appropriate SF Symbol icon.

### Changed

- **`StorageErrorTracker.writeSnapshot()`** persists every storage
  failure to `/Library/Application Support/MacCrab/storage_errors.json`.
  Before v1.4.3 these only hit os_log, invisible to anyone not
  running `sudo log show`.
- **`DaemonTimers.Handles`** gains `heartbeatTimer: DispatchSourceTimer`.
  Seven periodic timers total now (was six).

### Developer notes

- `scripts/build-release.sh` post-`compile_rules` step emits
  `compiled_rules/manifest.json` with SHA-256 hashes. Every release
  DMG from now forward will ship a manifest; pre-v1.4.3 bundles
  without one are accepted by `verifyManifest` to preserve upgrade
  paths.
- Three new snapshot files to be aware of under
  `/Library/Application Support/MacCrab/`: `heartbeat.json`,
  `storage_errors.json`, `rule_tamper.json`. All sysext-written, all
  user-readable. Safe to delete on support calls — they're
  regenerated on the next tick.

## [1.4.2] — 2026-04-21

Fixes the update-channel gap that prevented v1.3.11-v1.4.1 rule
improvements from reaching Sparkle-updated users. Ships five
noise-reduction gates validated against v1.4.1 field data.

### Fixed

- **Compiled rules now ship inside `MacCrab.app/Contents/Resources/
  compiled_rules/`.** New `RuleBundleInstaller.syncIfNeeded()` runs
  at app launch (before `AppState` init). It compares the bundled
  `.bundle_version` marker against
  `/Library/Application Support/MacCrab/compiled_rules/.bundle_version`;
  when bundled is newer it removes the installed tree, copies the
  bundled one in place, and `pkill -HUP`'s the detection engine so
  the new rule JSON takes effect without relaunching. Fixes the
  root cause of v1.4.1 field data showing pre-v1.3.11 rule bugs —
  the Homebrew cask's postflight, which used to be the only copy
  path, doesn't run on Sparkle updates.
- **`CrossProcessCorrelator` new shell-utility gate.** Chains where
  ≥80% of participants are small shell helpers (bash / ruby / curl /
  git / dirname / readlink / env / locale / cat / 30 others) AND
  ≥4 distinct utilities AND no `execute` action are dropped at
  evaluation time. A `brew reinstall` fired 3,000+ chain events
  in 30 seconds in v1.4.1 field data; this gate drops them. A
  real curl→bash download-and-run attack has only 2 utilities +
  execute action so it still fires.
- **`CrossProcessCorrelator.ignoredPathSubstrings` expanded.**
  Added `/dev/tty`, `/dev/pts/`, `/dev/ttys` (the "sudo+zsh
  touched /dev/ttys000" 62-hit FP is a shell writing your
  password prompt to your terminal). Also `/private/tmp/homebrew-`,
  `/private/tmp/brew-`, `/private/tmp/d20`, `/opt/homebrew/var/`,
  `/opt/homebrew/Cellar/`, `/usr/local/Homebrew/`,
  `/usr/local/Cellar/`.
- **`CampaignDetector.checkKillChain` excludes USB and
  crypto-token-kit alerts from tactic contribution.** Plugging in
  a YubiKey produced "5 tactics, 14 alerts Multi-Stage Attack"
  campaigns in field data. `maccrab.usb.*` and
  `maccrab.deep.crypto_token_extension` no longer count.
- **`CampaignDetector.checkCoordinatedAttack` skips Apple system
  daemons.** Processes under `/usr/libexec/`, `/System/Library/`,
  `/System/Applications/Utilities/` don't emit coordinated-attack
  campaigns even when they span multiple tactics. User's 24h
  field window had 15+ bogus campaigns — all xpcproxy,
  mobileassetd, usernoted, rtcreportingd, nsurlsessiond.
- **`credential_theft_exfil` sequence rule lowered from critical
  to high.** Critical bypasses NoiseFilter Gate 3 (trusted-
  browser-helper suppression), so every Chrome Helper reading its
  own Cookies DB and uploading to Google fired at critical. At
  high, Gate 3 drops the match on browsers — a non-browser doing
  credential-read→upload still fires at high. 22 critical FPs
  eliminated in field data.

### Added

- **Three new CrossProcessCorrelator regression tests** lock the
  new behaviour: brew-install shell-utility chain suppressed,
  curl→evil-binary chain still fires, `/dev/ttys000` terminal
  I/O not correlated.

## [1.4.1] — 2026-04-21

Hotfix: Sparkle update sheets rendered v1.4.0's Markdown release notes as
raw text. Sparkle's `<description>` field is HTML, not Markdown. Also
adds diagnostic logging to suppression save/load paths so a user report
that survived the v1.3.12/v1.4.0 fix has a trail to follow.

### Fixed

- **Sparkle update sheet renders release notes as HTML.**
  `scripts/generate-appcast-entry.sh` now runs `RELEASE_NOTES/vX.Y.Z.md`
  through a pure-Python Markdown→HTML converter (`scripts/_md_to_html.py`)
  before embedding the result in the appcast's CDATA `<description>`.
  GitHub releases keep rendering the same file as Markdown.
  Converter handles headings, paragraphs, bulleted lists, **bold**,
  *italic*, `code`, [links](#), and horizontal rules — the subset we
  use. Extend the script if new constructs appear.

### Added

- **Suppression persistence diagnostics.** `saveSuppressedIDs`,
  `loadSuppressedIDs`, `saveSuppressPatterns`, `loadSuppressPatterns`,
  `readUIState`, `writeUIState`, and `suppressAlert` now emit
  `os_log` info/notice/error records under subsystem
  `com.maccrab.app` category `ui-state`. Showing path chosen, bytes
  written/read, and counts loaded on every save/load. Users reporting
  "suppressions come back after update" can run
  `sudo log show --subsystem com.maccrab.app --predicate
  'category == "ui-state"' --last 1h` to produce a diagnostic trail.
- **One-shot on-load migration.** `loadSuppressedIDs` now rewrites
  the state to `uiStateDir` immediately if it found the file only at
  the legacy `dataDir` location. Next launch hits the stable path on
  the first try.

## [1.4.0] — 2026-04-21

Broad quality-of-life release. Noise-reduction pass, stability fixes,
new UX surfaces, enterprise MDM profile template, and a reproducible
release-hygiene checklist. v1.3.12 is rolled in rather than shipped
independently — its suppression-persistence fix is the first item
below.

### Fixed

- **Dashboard UI state survives app upgrades.** Suppression IDs and
  rule/process suppression patterns are now anchored to a stable
  user-home directory (`uiStateDir`) instead of the volatile
  `dataDir` that flips between user and system paths after every
  sysext write. Previously every upgrade silently discarded
  suppressions because the non-root dashboard couldn't write to the
  root-owned system dir. Legacy state is read from the old location
  on first launch and migrated automatically.
- **CampaignStore now rejects symlink DB paths.** Matching the guard
  EventStore and AlertStore already had; closes a privilege-
  escalation path where a swapped DB symlink could redirect
  root-owned writes.
- **Sysext crash-write failures are logged, not swallowed.** 14
  `try?` call sites in `MonitorTasks.swift` now route failures
  through `StorageErrorTracker.shared.recordAlertError` so a crash
  mid-alert leaves a forensic trail in Unified Log.
- **PRAGMA failures are logged across EventStore / AlertStore /
  CampaignStore.** A failed `journal_mode = WAL` used to silently
  drop the store to rollback-journal mode; operators now see the
  return code + error message under `sudo log show`.
- **dataDir fail-loud when both DBs are unreadable.** New `isReadableFile`
  checks replace `fileExists` so dataDir doesn't return a path the
  dashboard can't actually read. Logs a warning when permissions
  problems are evident (system DB exists but non-root app can't read).
- **Flaky `CollectorTests` lifecycle race.** 10 monitor lifecycle
  tests routed through a new `withStartedMonitor` helper that
  guarantees `stop()` runs even if the body throws. Previously a
  cancelled `Task.sleep` left the monitor running and polluted
  later test state — the "1 issue" flake reported on first runs.

### Added

- **NoiseFilter Gate 5: interactive admin CLI.** Drops non-critical
  matches on a curated set of admin binaries (ps, lsof, defaults,
  dscl, csrutil, system_profiler, spctl, profiles, etc.) when any
  process ancestor is a desktop terminal emulator (Terminal, iTerm,
  Warp, Alacritty, kitty, WezTerm, Hyper, Tabby, Ghostty) or a
  multiplexer (tmux, screen, byobu, zellij). 5 new regression tests
  in `InteractiveAdminGateTests`.
- **Alert retention control.** Settings → Detection Engine →
  Retention exposes `AlertStore.prune(olderThan:)` as a one-click
  "Clear alerts older than N days" (7 / 30 / 90 / 365).
- **Copy as Markdown.** `AlertDetailView` gains a Copy-as-Markdown
  button alongside Copy Details. Formats severity as bold, wraps
  identifiers in code spans, links MITRE technique IDs to
  attack.mitre.org, and uses ATX-style headings for paste into
  tickets / Slack / incident docs.
- **Keyboard Shortcuts reference.** New section in DocsView
  enumerates every in-app keyboard shortcut.
- **One-click sysext activation in WelcomeView.** Step 3's button
  now reads "Enable Protection" (instead of "Get Started") when the
  sysext isn't activated yet, and kicks off
  `OSSystemExtensionRequest` directly instead of sending the user
  to the Overview tab to find the button themselves.
- **`maccrabctl rule enable|disable <id>`.** CLI subcommand to
  toggle a compiled rule's `enabled` flag without rebuilding or
  deleting the YAML. Writes the JSON and prompts SIGHUP.
- **MacCrab.mobileconfig template for MDM deployment** (`deploy/`).
  Pre-authorizes the sysext, grants FDA to both app + sysext,
  registers MacCrab as a managed login item. Full deployment
  walkthrough in `deploy/README.md`.
- **`RELEASE_CHECKLIST.md` + `scripts/prerelease-check.sh`.** The
  release pipeline now runs the checklist as step 0: version sync
  across project.yml / plists / README / CHANGELOG, RELEASE_NOTES/
  file presence + non-trivial content, rule compile success,
  localization coverage per locale, SPM pin discipline. Release.sh
  refuses to sign if any hard check fails.

### Changed

- **Cross-process correlator suppresses more vendor paths.** Added
  Adobe / Creative Cloud / JetBrains / Zoom / 1Password / Firefox /
  Notion / Obsidian / iCloud Drive (Mobile Documents) / Time Machine
  volumes / Homebrew temp / dev-tool fan-outs (`.npm`, `.yarn`,
  `.gradle`, `.m2`, `.venv`, `__pycache__`) to `ignoredPathSubstrings`.
- **evaluateFileChain now applies the same homogeneity gates
  evaluateNetworkChain had.** Chains where every event shares the
  same executable path, app bundle, tool-version directory, trusted
  helper lineage, or process name are dropped at evaluation time.
  Belt-and-braces over v1.3.10's path filter.
- **Kill-chain detection ignores Low-severity tactics.** Previously
  `Multi-Stage Attack` fired when `recentAlerts` spanned three
  distinct MITRE tactics — easily triggered by three Low-severity
  discovery rules. Now only medium+ severity alerts contribute to
  the tactic set.
- **Discovery-rule severity recalibration.** 6 discovery rules
  dropped from Medium / High to Low: `bluetooth_scanning_tool`,
  `dscl_user_enumeration`, `ioreg_hardware_enum`, `lsof_network_enum`,
  `process_listing_by_unsigned`, `debugger_evasion_check`.
  `edr_remote_session_active` dropped from High to Medium.
- **Compiler honours `status: deprecated`.** Rules marked deprecated
  still compile (so rule browser + existing suppressions keep
  working) but ship `enabled: false` so the engine skips them.
- **"Daemon" → "Detection Engine"** in three remaining UI strings
  missed in the v1.3.9 rename sweep: Settings Response Actions
  save toast, status-bar fallback label, Integrations fleet-help
  copy.
- **`.mcp.json` now carries an explicit comment** explaining the
  dev-vs-release path split so end users understand the file is
  pointed at a local build and need to edit it when registering
  the Homebrew-installed binary.

## [1.3.12] — 2026-04-21

Hotfix: suppressions reset after upgrade.

### Fixed

- **Dashboard UI state no longer lives in `dataDir`.** `saveSuppressedIDs`,
  `loadSuppressedIDs`, `saveSuppressPatterns`, `loadSuppressPatterns`,
  and the LLM-config-detected read in `AppState.swift` all went through
  `dataDir`, which resolves to either `~/Library/Application Support/MacCrab/`
  (user home, dashboard-writable) or `/Library/Application Support/MacCrab/`
  (system, root-only, sysext-writable) depending on which `events.db` was
  most recently modified. After each sysext upgrade the system DB's
  modification time jumps, `dataDir` flips to the system path, and every
  `try? json.write(...)` from the non-root dashboard silently fails.
  Next app launch reads from the flipped-to directory, finds no
  suppressions file, and wipes the in-memory set. All previously dismissed
  alerts reappear on every upgrade. Anchored UI state to a new
  `uiStateDir` that is always the user-home MacCrab subdir; added a
  legacy-path fallback in the read path so existing users migrate
  automatically on first load.

### Added

- **`RELEASE_NOTES/v{VERSION}.md` convention.** Polished user-facing
  release notes now live in a dedicated directory and are the default
  source for Sparkle update sheets and GitHub release descriptions.
  The CHANGELOG remains the authoritative developer history;
  `scripts/generate-appcast-entry.sh` prefers the polished file over
  the CHANGELOG extract when it exists.

## [1.3.11] — 2026-04-21

Major noise-reduction release driven by field data from a real workstation:
one user reported 1,144 cross-process alerts and a flood of ~32 wifi-attack /
22 invisible-unicode / 14 EDR-remote-session alerts over 24 hours, all
false positives. Root cause turned out to be a **Sigma compiler bug** that
collapsed `selection_A or selection_B` into a flat `any_of` across every
predicate, so any command with `-s` / `scan` / `connect` / `live-response`
in its argv fired rules it had no business firing. Plus two UX bugs and a
bulk-action gap.

### Fixed

- **Sigma compiler preserves intra-selection AND semantics** under OR.
  `_needs_condition_tree` in `Compiler/compile_rules.py` now forces the
  hierarchical-tree compilation path when any clause of a pure `or`
  condition references a selection with more than one field/value pair.
  Previously those rules compiled to a flat `"condition": "any_of"` list
  which matched on ANY single predicate — so:
  - `wifi_attack_tool` at **critical** matched every commandline
    containing `-s` or `scan` (spctl, Chrome Helper, GoogleUpdater).
  - `edr_remote_session_active` at **high** matched every commandline
    containing `connect` (xpcproxy, every `ssh` invocation).
  - `gatekeeper_override` at **high** matched every spctl invocation
    regardless of `--add` / `--master-disable` flag context.
  After the fix the compiled JSON emits a proper nested
  `condition_tree: or → group[all_of]` structure that the runtime
  already knew how to evaluate. All 380 rules recompiled; 3 noisy
  rules now fire only in their intended narrow contexts.
- **Sidebar Alerts badge no longer counts campaigns twice.**
  `AppState.swift` had five separate `dashboardAlerts.filter { … }`
  recomputes of `totalAlerts` and `recentAlerts`, none of which
  excluded campaign-prefixed ruleIds. Campaigns ship as alerts
  with `ruleId: maccrab.campaign.*` and have their own sidebar
  badge. All five call sites consolidated into a single
  `refreshAlertBadges()` helper that also filters out the
  campaign prefix. Net: Alerts badge is now alert-only;
  Campaigns badge unchanged.
- **CrossProcessCorrelator file chains get the same homogeneity
  gates network chains had.** `evaluateFileChain` now also skips
  chains where `allEventsShareExecutable`, `allEventsShareAppBundle`,
  `allEventsShareToolDirectory`, or `allEventsAreTrustedHelpers`
  is true, plus a new `allEventsShareProcessName` check. This is
  the belt-and-braces defense underneath v1.3.10's path filter —
  even if a new vendor-dir path slips past the substring list, a
  chain where every event comes from the same process identity is
  worker fan-out, not attacker convergence.

### Changed

- **`invisible_unicode_in_source` rule marked `status: deprecated`.**
  Rule claimed to detect zero-width characters in source writes, but
  its YAML selectors only checked filename extension — there was no
  `FileContent|matches` regex. Every JSON/YAML/py/md write by a
  non-Apple-signed process was firing it at medium. Re-enable when
  the compiler supports content-based regex matching.
- **Compiler honours Sigma `status: deprecated`.** Deprecated rules
  still compile (so the rule browser and suppression state keep
  working for existing alerts) but ship with `enabled: false` so
  the RuleEngine's hot-path loop skips them.

### Added

- **Bulk-dismiss for campaigns.** `CampaignView` gains a Select /
  Cancel toggle; in select mode each active campaign card shows
  a checkbox. A "Dismiss N Selected" toolbar action pipes to a
  new `AppState.suppressAlerts(Set<String>)` batch method — one
  DB loop, one badge refresh, no flicker on 20-item dismisses.
  Delete-key dismisses selected, Escape cancels.
- **UPGRADE.md documents manual DMG upgrade semantics.** Clarifies
  that drag-n-drop replace triggers `OSSystemExtensionRequest`
  `.replace` automatically on next launch; recommends Sparkle /
  Homebrew for cleaner coordinated handover.

### Rule browser

- Top 3 rules by flat-`any_of` hit count pre-fix, by actual process
  (24h on one machine): `wifi_attack_tool` → spctl (8), GoogleUpdater
  (6), Chrome Helper (4); `edr_remote_session_active` → xpcproxy (8),
  GoogleUpdater (6); `gatekeeper_override` → spctl (8), GoogleUpdater
  (6). All drop to zero hits on the new compiler output because the
  intra-selection AND is restored.

## [1.3.10] — 2026-04-20

Noise-reduction hotfix for a v1.3.9 false positive. Field testing
turned up "13 processes, 140 events, 106s" cross-process chain alerts
fired by `GoogleUpdater` repeatedly writing to its own
`~/Library/Application Support/Google/GoogleUpdater/updater.log` from
multiple worker PIDs. Every event in the chain was a write or
close_modified against a log file inside a single vendor's own
state directory — indistinguishable from attack convergence to the
correlator, but semantically nothing more than a noisy logger.

### Fixed

- **CrossProcessCorrelator ignores `.log`/`.crash`/`.ips` files.** Log
  files don't carry payloads; an attack doesn't propagate through a
  log write. Adding these as ignored path suffixes at the correlator's
  ingress gate stops the 100-plus-event chains that legitimate vendor
  loggers were producing. New `ignoredPathSuffixes` set in
  `CrossProcessCorrelator.swift`.
- **CrossProcessCorrelator ignores noisy vendor app-support + cache
  paths.** Added a substring-match list covering
  `Library/Application Support/Google/`, `/Microsoft/`,
  `/CrashReporter/`, `/Code/` (VSCode), `/Slack/`, `/Spotify/`,
  `/Dropbox/`, `/iCloud/`, `/MobileSync/`; plus user-home
  `/Library/Caches/`, `/Library/Logs/`, `/Library/Preferences/`,
  `/Library/HTTPStorages/`, `/Library/WebKit/`,
  `/Library/Saved Application State/`, `/Library/Cookies/`, and
  `/Library/Metadata/CoreSpotlight/`. Also dev-tooling fan-outs
  `/.git/`, `/node_modules/`, `/.pnpm/`, `/.cargo/`, `/.rustup/`. New
  `ignoredPathSubstrings` set — substring rather than prefix so
  `/Users/<u>/Library/...` matches without per-user variants.
- **Four regression tests in `CrossProcessCorrelatorTests`** lock the
  behaviour: the exact GoogleUpdater 13-process scenario, a generic
  `.log` suffix, a sweep across Caches/Preferences/WebKit, and a
  positive control that `/tmp/payload.bin` write→execute from
  different PIDs *still* fires. 592 tests in 131 suites.

## [1.3.9] — 2026-04-18

Polish bundle: closes three findings from the v1.3.8 post-release audit
plus two long-standing UX gaps. No new features, no schema changes,
backwards-compatible DB — ships through the validated Sparkle pipeline.

### Security

- **SQLite WAL/SHM no longer world-readable.** `EventStore`,
  `AlertStore`, and `CampaignStore` now open their databases under
  `umask(0o027)` and explicitly `chmod 0o640` the main DB plus its
  `-wal` / `-shm` sidecars. v1.3.8 and earlier used `umask(0o022)` so
  the SQLite WAL — which contains recent event and alert inserts
  before checkpoint — was readable by any local user. `0o640` lets
  the dashboard (user in `admin` group) keep reading while closing
  the cross-user exposure. Tightening to `0o600` would have broken
  the dashboard, which runs as the user while the sysext runs as root.
- **SPM dependencies pinned to exact versions.** `Package.swift` now
  uses `.exact("2.9.1")` for Sparkle instead of `from: "2.6.4"`, and
  `swift-testing` is pinned to a specific revision instead of a
  branch. `Package.resolved` is now committed. Sparkle runs
  privileged update installs, so a compromised upstream release
  could push code to every MacCrab user on auto-update; exact pins
  mean a version bump is always explicit.

### Added

- **Dashboard response actions now do real work.** Kill Process,
  Quarantine File, and Block Destination buttons in `AlertDetailView`
  previously called `osascript display notification` stubs — no
  actual process was killed, no file was quarantined, no PF rule
  was written. New `Sources/MacCrabCore/Prevention/ManualResponse.swift`
  provides three typed-throw helpers the dashboard invokes:
  - **Kill Process**: `kill(SIGTERM)` by PID with `pkill -f` fallback;
    distinguishes `EPERM` (root-owned — prompts user toward
    `sudo kill`), `ESRCH` (already exited), and launch failure.
  - **Quarantine File**: moves the offending binary to
    `~/Library/Application Support/MacCrab/quarantine/<iso-ts>_<name>`,
    stamps `com.apple.quarantine` xattr, `chmod 000` the copy so
    accidental re-execution is blocked, writes a JSON sidecar with
    rule id/title/alert id for forensics.
  - **Block Destination**: extracts IPv4/IPv6 from the alert
    description, validates via `inet_pton`, writes to a per-user
    persistent block list, calls
    `osascript do shell script "pfctl ..." with administrator privileges`
    so the user authorizes once and the block takes effect in the
    kernel immediately. Uses a dedicated `com.maccrab.dashboard`
    anchor to not collide with the sysext's automated
    `com.maccrab` blocks.
  All three surface descriptive error messages (permissionDenied,
  notFound, cancelled, invalidInput) as the `actionFeedback` toast
  so the user knows whether the action succeeded, why it didn't,
  and what to do next.

### Changed

- **"Daemon" renamed to "Detection Engine" in the UI.** Post-1.3.0
  the detection runtime moved from a LaunchDaemon to an Endpoint
  Security system extension, but the dashboard still called it
  "Daemon" in the Settings tab, Overview health row, status-bar
  not-running label, and a few help strings in Threat Intel,
  Integrations, and Response Actions. Updated `defaultValue:` in
  every `String(localized:)` call plus the base English
  `Localizable.strings` file. Non-English locales keep their
  existing translation until re-localized.
- **README version badge bumped to 1.3.8** (was stuck at 1.3.4 through
  the v1.3.5 → v1.3.8 release run) plus a line pointing at the
  Sparkle-signed release channel.

## [1.3.8] — 2026-04-20

Quality-of-life release following field testing of v1.3.5–v1.3.7. Seven
fixes grouped around the rough edges a real end-to-end install flow
surfaced: cask wiping user data on every upgrade, MacCrab's own install
firing its own tamper-detection rules, the Sparkle "Check for Updates…"
menu item being unreachable on a menubar-only app, and a handful of
false-positive alert patterns on everyday Mac activity.

### Fixed

- **Cask preserves user data on upgrade.** The `uninstall` stanza in
  `Casks/maccrab.rb` and `homebrew/maccrab.rb` no longer lists
  `/Library/Application Support/MacCrab` in its `delete:` block. Every
  `brew upgrade --cask maccrab` through v1.3.7 was wiping alerts,
  baselines, suppressions, and LLM keys — a clean reinstall disguised
  as an upgrade. The `zap` stanza still removes the directory on an
  explicit `brew uninstall --zap maccrab` for users who really want
  a clean slate.
- **MacCrab no longer alerts on its own activity.** New gate in
  `NoiseFilter.apply` and a `NoiseFilter.isMacCrabSelf(event:)` helper
  drop non-`.critical` matches whose subject is a MacCrab binary
  (`com.maccrab.app`, `com.maccrab.agent`, `maccrabd`, `maccrabctl`,
  `maccrab-mcp`) or a file under `/Library/Application Support/
  MacCrab/` or `~/Library/Application Support/MacCrab/`. Critical
  matches still survive so a real integrity compromise against our
  binaries still fires. 5 new `FPRegressionTests` encode the
  scenarios that were noisy in the field: tamper-detection against
  our own rules directory during `brew upgrade`, xpcproxy events
  from our sysext firing EDR-remote-session rules, TCC-rate alerts
  when the user grants FDA to MacCrab.
- **Power-anomaly allowlist widened.** `AddressBookSourceSync` (normal
  iCloud contacts sync), `CalendarAgent`, `ContactsAgent`, `NotesMigratorService`,
  `ReportCrash`, `diagnosticd`, plus the WebKit networking helpers are
  all added to the `knownLegitimate` set in `PowerAnomalyDetector`. None
  of these are threat signal; all of them held sleep assertions on a
  typical Mac and produced Medium alerts every hour.
- **USB hub + non-mass-storage device alerts are now Informational, not
  Medium.** A USB hub or HID (keyboard/mouse) connecting is completely
  benign; severity floor reserved for mass-storage events where an
  attacker could be exfiltrating. Change is in `MonitorTasks.swift`'s
  USB handler.
- **SQLite error messages are visible under `sudo log show`.** The
  `.localizedDescription` interpolation in `StorageErrorTracker` was
  default-redacted to `<private>` by Foundation. Marked `.public` so
  operators diagnosing a broken install can see the actual SQLite
  return code without needing an Apple developer configuration
  profile. The message content is SQLite return codes + paths —
  never user secrets — so `.public` is safe.

### Added

- **Check for Updates… in the statusbar menu AND Settings.** Previously
  the v1.3.7 Sparkle integration wired the menu item via SwiftUI's
  `CommandGroup(after: .appInfo)`, which doesn't render for menubar-
  only apps (`LSUIElement=true`) — users had no in-UI way to trigger
  a manual update check. v1.3.8 wires the updater into
  `AppDelegate` and exposes it via two accessible entry points: the
  🦀 statusbar dropdown ("Check for Updates…" above the separator
  before Quit), and Settings → Daemon → Actions (a button alongside
  Reload Rules / Refresh Connection).
- **Launch at login defaults to on and is actually wired up.** The
  `@AppStorage("launchAtLogin")` preference has existed in
  `SettingsView` since v1.0 but never called anything — the toggle
  was dead. New `LaunchAtLogin` helper uses macOS 13+'s
  `SMAppService.mainApp.register()` / `.unregister()` to do the
  real work. Preference default flipped from `false` to `true`:
  MacCrab protects the system, so auto-starting after every login
  matches the product's intent. Users who'd rather start it manually
  can still flip it off; preference is honoured. On first launch,
  `LaunchAtLogin.reconcile(preferenceEnabled:)` aligns the SMAppService
  registration state with the stored preference.
- **FDA banner is principal-aware.** Previously the banner's body text
  was one generic "MacCrab needs FDA" message regardless of which of
  the two principals (`com.maccrab.app` or `com.maccrab.agent`)
  actually lacked the grant — both are separate TCC subjects on macOS.
  v1.3.8 probes both via `AppState.appHasFDA` and
  `AppState.sysextHasFDA` (inferred from WAL-write recency) and surfaces
  which one the user needs to add, naming the exact principal string
  as it appears in System Settings.
- **"Reveal MacCrab in Finder" link on the FDA banner.** Next to the
  existing Open Settings button. Opens Finder with MacCrab.app
  selected so users can drag it directly into the FDA settings pane
  — less ceremony than navigating to /Applications/ themselves.

### Infrastructure

- No sysext provisioning-profile, entitlement, or signing changes.
  v1.3.7 infrastructure carries forward unchanged.

### Known not-yet-fixed

Remaining items from the v1.3.7 field-test report that aren't in
this release:

- **Signed `.mobileconfig` for one-click FDA** — needs an MDM-signed
  profile for `SystemPolicyAllFiles` to auto-grant on personal Macs;
  lives in the v1.4 MDM / enterprise scope.
- **More rule-precision pass** — the spctl / csrutil / system_profiler /
  Wi-Fi-tool rules need parent-process anchoring. Scheduled for
  v1.4.x rule tuning.

## [1.3.7] — 2026-04-20

Cosmetic hotfix for v1.3.6's Overview banner — users saw the literal
string `^[1 high-severity alert](inflect: true) to review` instead of
a rendered English pluralization.

### Fixed

- **Overview alert-count banner no longer renders the Apple inflection
  markdown verbatim.** The `^[...](inflect: true)` syntax only resolves
  correctly when backed by a matching `.xcstrings` / `.stringsdict`
  entry with grammatical-agreement rules for the target locale. With
  just an in-source `String(localized:defaultValue:)` default, the
  Foundation localization layer falls through without processing the
  markdown, and the raw text lands in the UI. Replaced with plain
  English singular/plural branching. The localization keys
  (`overview.critical.count`, `overview.high.count`) are unchanged so
  existing translations keep working; only the English default value
  was wrong.

## [1.3.6] — 2026-04-20

Critical hotfix: v1.3.5 shipped with a broken binary that aborted on
launch with `dyld: Library not loaded: @rpath/Sparkle.framework`.
Anyone who installed v1.3.5 has an app that won't open — reinstall
v1.3.6 to recover.

### Fixed

- **`Sparkle.framework` now embedded in `MacCrab.app/Contents/Frameworks/`.**
  The Wave 1 Sparkle integration (v1.3.5) added the SPM dependency + the
  link-time requirement but the private release script never copied the
  framework into the output bundle. SPM lacks Xcode's automatic
  Copy-Files build phase; the framework must be manually staged. The
  release pipeline now detects the xcframework at
  `.build/artifacts/sparkle/Sparkle/Sparkle.xcframework/macos-arm64_x86_64/Sparkle.framework`,
  copies it with symlink-preserving `-R`, re-signs Sparkle's XPC
  services + Autoupdate + the framework itself with the Developer ID,
  then signs the outer app bundle last as before.
- **Sparkle keys added to the release-path `Info.plist`.** `SUFeedURL`,
  `SUPublicEDKey`, `SUEnableAutomaticChecks`, `SUScheduledCheckInterval`,
  `SUAutomaticallyUpdate` had been added to the checked-in
  `Xcode/Resources/MacCrabApp-Info.plist` in v1.3.5 but the release
  script writes its own `Info.plist` via heredoc — it didn't pick up
  the new keys. Now both paths carry the same Sparkle config.

Both issues are in the private build pipeline, not in source code.
Users with v1.3.5 should `brew uninstall --cask maccrab && brew install
--cask maccrab` to land on v1.3.6, or download the v1.3.6 DMG directly
from the GitHub Release.

### Infrastructure

- v1.3.5 appcast entry has been pulled so new installs don't pick up
  the broken build. v1.3.6 is the first working Sparkle-enabled
  release.

## [1.3.5] — 2026-04-19

First release after the v1.3 SystemExtension migration settled. Lands
the auto-update channel via Sparkle, moves API keys out of
world-readable preferences into the macOS Keychain, and sweeps up a
backlog of UX safety rails, localization gaps, documentation, and
runtime hardening flagged by a post-v1.3.4 multi-domain audit. From
this version onward, `brew upgrade --cask maccrab` is optional — the
app checks for updates itself and offers them via the application
menu's *Check for Updates…* item.

### Added

- **Auto-update channel via Sparkle 2.** MacCrab now polls
  `https://maccrab.com/appcast.xml` daily (configurable) and surfaces
  new versions through the app menu. Updates are verified with EdDSA
  signatures against a public key embedded in the app bundle —
  downgrade or tampered-DMG attacks can't install on existing
  installs. Sysext updates cascade via
  `OSSystemExtensionRequest(.replace)` on relaunch, so no
  re-approval prompt for same-team-ID upgrades.
- **MonitorSupervisor for clean shutdown.** All 12 background monitor
  tasks now register with a supervisor that SIGTERM cancels and
  awaits cleanly before process exit, with a 3-second deadline. The
  Sparkle "Install and Relaunch" flow now unwinds collectors without
  losing in-flight SQLite writes.
- **API keys move to the macOS Keychain.** A new `SecretsStore`
  (`Sources/MacCrabCore/Storage/SecretsStore.swift`) wraps
  `SecItemAdd/Copy/Delete` with a typed `SecretKey` enum covering
  every secret the dashboard handles (5 LLM providers + 7 threat-
  intel APIs + 3 output transports). Keys are encrypted at rest
  under your login password; the Settings UI reads and writes
  through it transparently.
- **Full Disk Access warning banner** on the Overview tab. Clicks
  through to System Settings via three URL variants that cover
  macOS 13 / 14 / 15 pane reshuffles. Closes the #1 UX failure mode
  from the audit — "protection enabled but TCCMonitor is blind".
- **Undo button on suppression toast.** 5-second window, bound to
  ⌘Z, with a monotonic-token pattern so rapid double-suppresses
  don't cancel each other's timers.
- **Filter persistence.** Alert dashboard severity filter and "show
  suppressed" toggle now survive tab switches and app restarts via
  `@AppStorage`.
- **Severity differentiator via SF Symbol.** Filter chips and
  menubar status dots now carry a shape, not just color.
  Colourblind and VoiceOver users can distinguish severity levels
  without relying on hue.
- **Webhook SSRF policy.** `MACCRAB_WEBHOOK_URL` now requires
  `https` (loopback `http` excepted), blocks cloud metadata IPs
  unconditionally (AWS `169.254.169.254`, AWS IPv6
  `fd00:ec2::254`, Alibaba `100.100.100.200`), and rejects RFC1918
  / IPv6 link-local / unique-local unless
  `MACCRAB_WEBHOOK_ALLOW_PRIVATE=1` is set. 10-test suite in
  `WebhookValidationTests.swift`.
- **Rule compiler archive.** `Compiler/compile_rules.py` snapshots
  the previous `compiled_rules/` into
  `compiled_rules.archive/<YYYYMMDD-HHMMSS>/` (keeps last 5) before
  overwriting. Rollback on a bad compile is `cp -R` — no git
  history required.
- **Release pipeline scripts** in `scripts/`:
  `generate-appcast-entry.sh` (signs a DMG with `sign_update` and
  emits a Sparkle `<item>`), `publish-appcast-entry.sh` (PUT's the
  item into the the site repo repo via a scoped PAT),
  `bump-cask.sh` (syncs `version` + `sha256` across both cask
  files).
- **User-facing documentation.** `TROUBLESHOOTING.md` covers
  sysext approval hangs with the real rejection signatures from
  1.3.0–1.3.3, FDA silent drops, compile failures, webhook
  rejections, and Homebrew upgrade cleanup. `UPGRADE.md` explains
  the v1.2 → v1.3 migration. `FAQ.md` has 14 common questions.
- **Annotated example configs.** `docs/daemon_config.example.json`
  and `docs/suppressions.example.json` document every tunable and
  every output-sink type with `_comment_*` keys the decoder
  ignores.
- **Module-level doc headers** on `AlertStore.swift` (schema table,
  concurrency notes, read-only degradation) and `ESCollector.swift`
  (ASCII event-pipeline diagram, required-privileges block).
- Localization catch-up: 40 new `en.lproj` keys covering
  destructive-action confirmations (kill / quarantine / block),
  the `SystemExtensionPanel` end-to-end, Overview stray strings
  (with Apple's automatic inflection syntax for locale-safe
  pluralization), and the ThreatIntel API-key UX refactored 7→1.
- CLI secret resolution now prefers the Keychain over
  `llm_config.json` + env vars (env still wins as the override for
  CI and one-off invocations).

### Fixed

- **Retention policy now honors `config.retentionDays`.** Previously
  hardcoded to 30 days regardless of `daemon_config.json`. Clamped
  to [1, 3650] at the timer site so a typo (`"retentionDays": 0`)
  can't wipe the database on next tick.
- **`EventStore` and `AlertStore` reject symlinks on the DB path +
  `-wal` / `-shm` / `-journal` sidecars** before `sqlite3_open_v2`.
  Closes the symlink-redirect attack class the rules directory
  already had protection against.
- **Merged event stream now uses `.bufferingNewest(100 000)`** —
  previously unbounded. Under pathological burst the oldest events
  drop instead of the resident set growing without limit.
- **Destructive-action confirmation dialogs localize.** The
  kill / quarantine / block prompts no longer render in English
  only for the 14 locales MacCrab ships.
- **SystemExtensionPanel fully localized** (15 keys covering
  headlines, body states, state chips, buttons).
- **`LLMSanitizer` regex compilations hoisted to `static let`.**
  Previously recompiled on every sanitize call; now compiled once
  at module load.
- **`KdebugCollector` force-unwrap guarded.** `parts.last!` at
  line 202 now uses a safe `guard let`. No crash path under any
  observed input.
- **`maccrabctl suppress` JSON decode now logs parse errors**
  instead of silently treating a corrupt `suppressions.json` as
  empty. `unsuppressRule` refuses to write on parse failure to
  avoid overwriting user state.
- **Stale "sudo maccrabd" guidance replaced** in 6 user-visible
  strings: `StatusCommand`, `SecurityScorer`, `ESHealthView`,
  `MainView`, `WelcomeView`, and the `DaemonSetup` startup
  banner — now point at "Open MacCrab.app → Enable Protection"
  which is the v1.3+ shipping path.

### Changed

- **`WebhookOutput` uses `SecureURLSession.makeGeneric`** for the
  same TLS 1.2+ floor, ephemeral config, and cookie/credential
  scrubbing as the LLM + threat-intel sessions. Pinning doesn't
  apply to user-supplied URLs, but everything else does.
- Bundle versions bumped 1.3.0 → 1.3.5 across
  `MacCrabApp-Info.plist`, `MacCrabAgent-Info.plist`, and
  `Xcode/project.yml`. `CFBundlePackageType` corrected from `SYEX`
  → `SYSX` in the checked-in `MacCrabAgent-Info.plist` (the
  release build pipeline had been overriding this; now the checked-
  in file matches).
- `ThreatIntelView` API-key boxes refactored from seven
  copy-pasted `GroupBox` blocks into a single `apiKeyRow(...)`
  helper — ~50 lines of duplication removed.

### Infrastructure

- Security contact: `maccrab@peterhanily.com` (was
  `security@maccrab.dev`; the former never resolved).
- Distribution domain: `maccrab.com` (Cloudflare Pages serving
  the site repo). Permanent URLs:
  `https://maccrab.com/appcast.xml`,
  `https://maccrab.com/maccrab.mobileconfig` (the MDM profile
  ships in v1.4).
- **Apple Developer Team ID**: 79S425CW99 (unchanged).
- **Sparkle EdDSA public key**:
  `de+dzPjBve7LP5qxoE7nR6shThsjubkVasi+i8ehT4E=`.
- **Minimum macOS**: 13.0 Ventura (unchanged).
- Detection rules: 380 total (353 single-event + 27 sequences)
  across 17 MITRE tactic directories.
- Tests: **583 in 130 suites passing**.

### Upgrade notes

- Users on v1.3.0–v1.3.4 upgrading via Homebrew cask or manual DMG
  will see the sysext replace itself silently on first launch
  (same team ID — no System Settings re-approval needed).
- API keys previously stored in `llm_config.json` continue to work
  unchanged; newly-entered keys via Settings → AI Backend land in
  the Keychain. Until the shared `keychain-access-groups`
  entitlement ships (targeted for v1.4), the sysext still reads
  API keys from `llm_config.json` — the Dashboard writes both.
- Env vars (`MACCRAB_LLM_*_KEY` etc.) continue to override Keychain
  and JSON, so CI / automation flows are unchanged.

## [1.3.4] — 2026-04-18

Fixes a flood of `maccrab.correlator.network-convergence` alerts on
hosts with active Chrome / Electron usage. Field diagnosis from a
noisy box showed every alert description read `N unrelated processes
contacted :443 over Ns` — no IP, just the port. Network events that
arrived before DNS / flow enrichment carried an empty
`destinationIp`, which the correlator keyed under `":443"`, collapsing
every HTTPS flow on the host into one artifact bucket. `syspolicyd`,
`Google Chrome Helper`, `WeatherWidget`, `mDNSResponder`, and
`Keynote` all got lumped together as "convergence" simply because
they opened HTTPS before the IP resolved.

### Fixed

- `CrossProcessCorrelator.shouldIgnoreNetworkDestination` now rejects
  empty, whitespace-only, `0.0.0.0`, `::`, and any string that
  doesn't look like an IP. This is the fix that actually stops the
  flood — no cloud-prefix list could match an absent IP.
- Expanded `trustedCloudDomains` from 15 → 49 suffixes to cover
  Google's full browser/update/media stack (`gvt1.com`,
  `googleusercontent.com`, `youtube.com`, `doubleclick.net`, …) plus
  Microsoft, Mozilla, Apple CDN, and Slack/Discord/Zoom. These help
  the domain-keyed path when DNS *is* attached.
- New `allEventsAreTrustedHelpers` gate reuses
  `NoiseFilter.trustedBrowserPrefixes` to suppress cross-bundle
  fan-out (Chrome Helper + Slack Helper + Code Helper all to one
  destination) — the existing bundle-identity filter couldn't see
  across bundles.

### Tests

Four new regressions in `CrossProcessCorrelatorTests`:
`emptyDestinationIPIgnored`, `chromeFamilyFanOutSuppressed`,
`unrelatedProcessesStillConverge`, `googleUpdateDomainSuppressed`.
All 7 correlator tests pass.

## [1.3.3] — 2026-04-18

Second hotfix for the same sysext categorization error. 1.3.2 added
`NSSystemExtensionPointIdentifier` but `sysextd` still rejected
activation with "does not appear to belong to any extension
categories". The real bug was a `CFBundlePackageType` typo: I wrote
`SYEX` back in 1.3.0 and carried it through every release. `sysextd`
specifically checks for `DEXT` (DriverKit) or `SYSX` (system
extension) and silently fails anything else.

### Fixed

- `CFBundlePackageType = SYEX` → `SYSX` in the sysext Info.plist
  template in `build-release.sh`.

The diagnostic log is unambiguous:

    sysextd: ...com.maccrab.agent.systemextension: package type not `DEXT`
    sysextd: ...com.maccrab.agent.systemextension: package type not `SYSX`
    sysextd: system extension does not appear to belong to any extension categories

1.3.2's `NSSystemExtensionPointIdentifier` change was a no-op —
`sysextd` rejects the bundle at the package-type check before
looking at the category key. Both keys are technically required, so
1.3.2's change stays.

## [1.3.2] — 2026-04-18

Hotfix for 1.3.1. The system extension bundled correctly and signed
correctly, but macOS refused to activate it:

    Invalid extension configuration in Info.plist and/or entitlements:
    System extension com.maccrab.agent.systemextension does not
    appear to belong to any extension categories

Missing `NSSystemExtensionPointIdentifier` key in the sysext's
Info.plist. Without it macOS can't categorize the bundle as an
Endpoint Security extension, so `sysextd` rejects activation.

### Fixed

- `scripts/build-release.sh` now emits
  `NSSystemExtensionPointIdentifier =
  com.apple.system_extension.endpoint_security` in the sysext's
  Info.plist. This is the category key every commercial ES
  product sets; omitting it was an oversight on my part when I
  wrote the 1.3.0 bundle template.

Drop-in upgrade. `brew upgrade --cask maccrab` → relaunch
MacCrab.app → Enable Protection. Extension should now activate
cleanly through the System Settings approval flow.

## [1.3.1] — 2026-04-18

Hotfix for 1.3.0. The Overview tab hid the "Enable Protection"
activation control behind a `!appState.isConnected` spinner that
told the user to run `sudo maccrabd` — but 1.3.0 removed that
command entirely. The activation card became unreachable in
exactly the state it was meant for (first launch after install).

### Fixed

- `OverviewDashboard` now shows `SystemExtensionPanel` at the top
  unconditionally when `sysextManager.state != .activated`.
  Previously the panel was nested inside the `isConnected` branch,
  so on a fresh install (no connection, no rules yet) the user
  saw only the obsolete "Start the daemon: sudo maccrabd" message
  and could never reach the Enable Protection button.
- Replaced "Start the daemon: sudo maccrabd" with a message
  pointing at the activation panel. The follow-up "Connecting to
  the detection engine…" state only appears after the sysext is
  actively running but the dashboard hasn't read its first rows
  yet — a genuinely brief window, not a deadlock.

Drop-in upgrade over 1.3.0. No schema/config changes.

## [1.3.0] — 2026-04-18

Native Endpoint Security via a proper system extension. Ends the
1.1.1 → 1.2.5 investigation arc — the daemon now runs where Apple's
AMFI expects, and the `-413 "No matching profile found"` error is
gone.

### What changed architecturally

The detection engine no longer runs as a LaunchDaemon. On macOS Catalina
and later, Apple's AMFI refuses the
`com.apple.developer.endpoint-security.client` entitlement on any
binary that isn't loaded through `OSSystemExtensionRequest`. This was
the root cause of the SIGKILL + `-413` error on every 1.2.4/1.2.5
install. Every commercial ES product (CrowdStrike, SentinelOne, Jamf
Protect, Microsoft Defender, Objective-See LuLu/BlockBlock) ships as
a `.systemextension` for exactly this reason.

1.3.0 follows that pattern:

```
/Applications/MacCrab.app/
  Contents/
    MacOS/MacCrab                                       (dashboard + activator)
    embedded.provisionprofile
    Library/SystemExtensions/
      com.maccrab.agent.systemextension/
        Contents/
          Info.plist                                    (SYEX, ES entitlement)
          embedded.provisionprofile
          MacOS/com.maccrab.agent                       (the daemon)
          _CodeSignature/
```

The app bundle signs with `system-extension.install`; the sysext
signs with `endpoint-security.client`. AMFI matches the sysext
identifier against the provisioning profile automatically.

### User-facing flow

- Install (via Homebrew cask or DMG): `MacCrab.app` is copied to
  `/Applications`.
- First launch of the app: the new "Enable Protection" card on the
  Overview tab invokes `OSSystemExtensionRequest.activationRequest`.
- macOS prompts the user to approve the extension in **System
  Settings > General > Login Items & Extensions > Endpoint Security
  Extensions**.
- After approval the sysext becomes active. The activation card
  disappears; detection starts.
- Subsequent app launches: no prompt, no user action.

### Changed (internal restructure)

- New `MacCrabAgentKit` SPM library target holds the daemon bootstrap
  (DaemonSetup, DaemonState, EventLoop, MonitorTasks, DaemonTimers,
  SignalHandlers, StartupBanner, Globals, DaemonBootstrap). Extracted
  out of `Sources/maccrabd/` so both the legacy `maccrabd` executable
  and the new `MacCrabAgent` sysext can share identical logic — only
  `main.swift` differs between the two.
- New `MacCrabAgent` SPM executable target — compiles to the binary
  that gets wrapped into the `.systemextension` bundle by
  `build-release.sh`. Thin `main.swift` calls
  `DaemonBootstrap.runForever()`.
- `Xcode/project.yml` + `Xcode/Resources/*.entitlements` added as an
  alternative build path for anyone with full Xcode installed.
  `scripts/build-release.sh` uses SPM + manual bundle assembly so
  full Xcode isn't required.

### Added

- `SystemExtensionManager` in `Sources/MacCrabApp/` — ObservableObject
  wrapping `OSSystemExtensionRequest` with `@Published state`.
  Handles the full delegate protocol: `actionForReplacingExtension`
  (always `.replace` on upgrade), `requestNeedsUserApproval`
  (transitions to `.awaitingApproval`), `didFinishWithResult`,
  `didFailWithError`.
- `SystemExtensionPanel` in `Sources/MacCrabApp/Views/` — banner-style
  card on the Overview tab that shows the activation state with
  plain-English body text, state icon, and contextual actions:
  "Enable Protection" initially, "Open System Settings" while
  awaiting approval (falls through three URL variants because Apple
  has moved the pane between macOS 13/14/15), "Try again" for
  failures. Hides itself once the extension is active.

### Removed

- LaunchDaemon path. `com.maccrab.agent.plist` is no longer shipped
  in the DMG or installed to `/Library/LaunchDaemons/`. `launchctl`
  doesn't manage MacCrab anymore — `sysextd` does.
- Standalone `maccrabd` binary from the installed layout. The SPM
  target still builds (useful for `swift run maccrabd` during local
  development without ES), but it isn't part of the release DMG
  and isn't symlinked into `$HOMEBREW_PREFIX/bin/`.
- System-wide provisioning profile install. 1.2.4/1.2.5 copied the
  profile to `/Library/MobileDevice/Provisioning Profiles/` —
  1.3.0's upgrade path actively removes any MacCrab-related
  profile from that directory since the sysext embeds its own copy.

### Upgrade path

Automated in both the Homebrew cask postflight and `install.sh`:

1. Unload + remove `/Library/LaunchDaemons/com.maccrab.daemon.plist`
2. Unload + remove `/Library/LaunchDaemons/com.maccrab.agent.plist`
3. Remove stale `/opt/homebrew/bin/maccrabd` and
   `/usr/local/bin/maccrabd` symlinks
4. Remove any `com.maccrab.*` provisioning profile from
   `/Library/MobileDevice/Provisioning Profiles/`
5. Install the 1.3.0 rules + CLI tools + `MacCrab.app`

Users upgrading from 1.2.x need to **launch `MacCrab.app` and
approve the extension** in System Settings after the upgrade, since
the old LaunchDaemon is gone.

For a clean uninstall of the extension:

```bash
systemextensionsctl uninstall 79S425CW99 com.maccrab.agent
```

### Known limitations

- **No MDM silent-approve path yet.** Every fresh user sees the
  System Settings prompt. A future MDM configuration profile would
  pre-authorize the team ID + bundle ID combination; not shipping
  that in 1.3.0.
- **First-launch-from-Downloads gotcha.** On macOS 15+ the
  extension activation silently fails with code 4 if `MacCrab.app`
  is opened from `~/Downloads/` instead of `/Applications/`. The
  installer handles this; Homebrew cask users are covered
  automatically. Manual DMG installers need to drag the app to
  `/Applications` before first launch.
- **Dashboard ↔ daemon IPC still file-based.** The sysext writes
  SQLite under `/Library/Application Support/MacCrab/`; the
  dashboard reads from there. A proper XPC control plane is v1.4.0
  work.

## [1.2.5] — 2026-04-17

Hotfix for 1.2.4. The 1.2.4 daemon was signed with the ES entitlement
but AMFI refused to honour it because the binary sat outside an app
bundle — macOS only discovers `embedded.provisionprofile` inside an
`.app`. 1.2.5 moves the daemon into `MacCrab.app/Contents/Library/
LaunchDaemons/` so the profile is findable.

### Fixed

- **Daemon SIGKILL on 1.2.4 install** — AMFI emitted `Error
  Domain=AppleMobileFileIntegrityError Code=-413 "No matching profile
  found"` when launching `/opt/homebrew/bin/maccrabd`. Relocated the
  daemon binary into `MacCrab.app/Contents/Library/LaunchDaemons/
  maccrabd`; AMFI walks up from any contained Mach-O and finds the
  app's `embedded.provisionprofile`. This is the canonical Apple
  pattern used by Little Snitch, Objective-See tools, and every other
  Developer-ID-signed ES daemon on macOS.
- **LaunchDaemon plist path** updated from `/usr/local/bin/maccrabd`
  to `/Applications/MacCrab.app/Contents/Library/LaunchDaemons/
  maccrabd`. No per-install path rewriting; the plist is now
  Homebrew-prefix-independent.
- **Cask postflight UUID extraction** (carried over from
  mid-1.2.4-release hotfix): `security cms | PlistBuddy /dev/stdin`
  was unreliable in Ruby backticks; replaced with temp-file
  round-trip and UUID regex validator.

### Added

- **App icon bundled** — `AppIcon.icns` now copies into
  `MacCrab.app/Contents/Resources/` with `CFBundleIconFile` and
  `CFBundleIconName` keys set in `Info.plist`. The generic macOS app
  icon that was shipping in 1.2.1-1.2.4 is replaced with the real
  MacCrab crab icon.
- **Upgrade-path cleanup** in cask + `install.sh`: any stale
  `/opt/homebrew/bin/maccrabd` or `/usr/local/bin/maccrabd` symlinks
  from 1.2.4 are removed before installing 1.2.5. Any running
  `com.maccrab.agent` LaunchDaemon pointing at the defunct path is
  unloaded first.

### Internal

- `scripts/build-release.sh`: new signing order — sign bin/
  CLI tools, relocate `maccrabd` into app bundle, sign the daemon
  inside the app with ES entitlement + `com.maccrab.agent` identifier,
  sign inner app executable, sign outer app bundle (seals the
  provisioning profile).
- Cask no longer declares `binary "bin/maccrabd"` — the daemon lives
  in the app now. `maccrabctl` and `maccrab-mcp` still symlink into
  `$HOMEBREW_PREFIX/bin/`.

## [1.2.4] — 2026-04-17

Native Endpoint Security unlock. Apple approved the ES client
entitlement under bundle ID `com.maccrab.agent`; this release adopts
the new identifier, embeds the provisioning profile, and ships the
daemon signed with the real ES entitlement instead of relying on the
eslogger/kdebug/FSEvents fallback chain.

### Changed

- **LaunchDaemon label renamed** `com.maccrab.daemon` → `com.maccrab.agent`.
  Apple bound the Endpoint Security entitlement to the new identifier
  during their approval process, so we moved to match. All code paths,
  scripts, plist filenames, Homebrew cask actions, and log-stream
  subsystem names updated. The plist filename is now
  `com.maccrab.agent.plist`.
- **Daemon is now signed with `com.apple.developer.endpoint-security.client`.**
  `build-release.sh` picks up the provisioning profile from
  `~/.maccrab-signing/MacCrab.provisionprofile` (override via
  `PROVISION_PROFILE`) and signs `maccrabd` with `--entitlements
  entitlements.plist --identifier com.maccrab.agent`. Other binaries
  (`maccrabctl`, `maccrab-mcp`) stay unentitled.
- **Provisioning profile shipped in two places:**
  `MacCrab.app/Contents/embedded.provisionprofile` for app-scope
  verification + `/Library/MobileDevice/Provisioning Profiles/
  <UUID>.provisionprofile` for the standalone
  `/usr/local/bin/maccrabd` invocation.

### Added

- **Upgrade-path migration** in `install.sh` and the Homebrew cask:
  detects a pre-1.2.4 `com.maccrab.daemon.plist` on disk, unloads it,
  and removes it before installing the new `com.maccrab.agent.plist`.
  No duplicate competing daemons.
- **`scripts/verify-profile.sh`** — operator utility that inspects a
  `.provisionprofile` file (team, bundle ID, expiry, entitlements,
  profile type, provisioned devices) so you can confirm before
  shipping.
- **Hardened `.gitignore`** — broader coverage for private keys
  (every format), certs, env files in every variant, cloud vendor
  credential caches, SSH keys, keychain dumps, release artifacts,
  coverage data, crash dumps, scratch files.

### User-visible

- Daemon startup banner now reads "Endpoint Security: native client"
  on clean installs instead of "eslogger proxy".
- Dashboard ES Health view stops showing the "degraded" banner on
  fresh installs.
- `log stream --predicate 'subsystem=="com.maccrab.agent"'` replaces
  the previous `com.maccrab.daemon` predicate. Old predicate will
  stop matching after upgrade.

### Upgrade notes

- Drop-in over 1.2.3 via `brew upgrade --cask maccrab`. The cask
  `postflight` handles the plist migration and profile install.
- Manual installs (DMG + `install.sh`): run the 1.2.4 installer; it
  detects the old plist and removes it before proceeding.
- **If you're already running 1.2.3 with `com.maccrab.daemon.plist`
  loaded**: the 1.2.4 install gracefully unloads + replaces it, no
  user action needed.

## [1.2.3] — 2026-04-17

24-hour observation hotfix. Four specific noise sources identified by
running 1.2.2 against a real dev workstation overnight.

### Fixed

- **FSEvents path bypassed the noise filters.** `MonitorTasks` runs a
  separate rule-evaluation loop for FSEvents-sourced events (non-root
  fallback) that didn't go through `EventLoop`'s unknown-process /
  warm-up / trusted-browser filters, so Sigma rules fired on every
  file event even when the event had no process attribution. Extracted
  the filter logic into `EventLoop.applyNoiseFilters` and call it from
  both paths. Eliminates the 34 overnight alerts for invisible-unicode,
  trojan-source, cookie-DB-access, and contacts-DB-access firing on
  file writes from unknown processes.
- **RootkitDetector dual-API race.** `proc_listallpids()` and
  `sysctl(KERN_PROC_ALL)` are called sequentially, so any process that
  exits or spawns in the 1–2 ms gap appears in one set but not the
  other. That race was producing 100% of the `hidden-process`
  detections on a busy machine (46 in one day). Added second-chance
  verification: after a 300 ms delay we re-query both APIs and only
  alert when the discrepancy persists. A userland rootkit hides a
  process for its entire lifetime; an exit-timing race does not.
- **AI-guard cloud IP prefix list was incomplete.** Google serves
  several user-facing APIs from `74.125./16` and `172.253./16` ranges
  that weren't in the allowlist (only `142.250`, `142.251`, `172.217`,
  `209.85`, `216.58` were). Added the full Google-owned block set from
  gstatic.com/ipranges/goog.json (64.233, 66.102, 66.249, 72.14,
  74.125, 108.177, 172.253, 173.194, 216.239) to both the
  `AINetworkSandbox` fallback and the `CrossProcessCorrelator` cloud
  filter.
- **`runningboardd` missing from PowerAnomalyDetector allowlist.** Core
  macOS daemon that manages process lifecycles and holds power
  assertions on behalf of other processes. Added alongside
  `assertiond` and `ContextStoreAgent` for completeness.

## [1.2.2] — 2026-04-16

Hotfix on top of 1.2.1 targeting OS-notification floods. Drop-in
upgrade — no schema or config changes.

### Fixed

- **SelfDefense tamper alerts no longer re-fire every 15 seconds.** The
  periodic integrity check correctly re-evaluates every cycle, but
  firing a fresh critical alert each time turned a single real event
  (e.g. a local rebuild) into 100+ identical notifications. Added a
  per-type `alertedTamperTypes` gate — each tamper type alerts exactly
  once per daemon lifetime. Subsequent cycles still write to the
  forensic log (`~/.maccrab_tamper.log`, `/var/log/maccrab_tamper.log`,
  `$TMPDIR/maccrab_tamper.log`) but don't produce new alerts.
- **SUSTAINED TAMPERING summary fires exactly once** at the 3-failure
  mark, not every cycle thereafter. Counter still climbs internally.
- **Notifier dedup window: 5 min → 1 hour, per-key.** The previous
  `sweepKeysIfNeeded` cleared *all* dedup keys every 5 minutes, so a
  persistent condition produced a fresh OS banner every 5 min.
  Replaced with a `[String: Date]` map that expires individual keys on
  their own schedule. A single rule firing repeatedly from the same
  process now produces one banner per hour max.

### Added

- **Trusted browser/Electron-helper short circuit** in the event loop.
  Chromium-based apps (Chrome, Edge, Brave, Arc, Opera, Vivaldi,
  Firefox, Safari) and Electron apps (Slack, Discord, Teams, VS Code,
  Cursor, Claude, ChatGPT Atlas, Codex, GitHub Desktop, Signal,
  Telegram, WhatsApp) have large helper trees that fire individual
  Sigma rules on benign activity — reading their own cookie DB,
  writing to their own cache, opening long-lived HTTPS, spawning
  child tools for profile migration. Any process whose executable
  path sits under one of these bundles has its non-critical rule
  matches dropped at the event loop. Critical still fires. This
  complements the per-detector allowlists in TLSFingerprinter,
  PowerAnomalyDetector, CrossProcessCorrelator with a single
  short-circuit that covers rules we haven't individually hardened.

## [1.2.1] — 2026-04-16

Patch release focused on false-positive reduction on real dev workstations.
No schema or config changes — safe to upgrade from 1.2.0 in place.

### Changed

**Detection tuning (false-positive reduction):**
- `LibraryInventory` now allowlists Homebrew (`/opt/homebrew`,
  `/usr/local/Cellar`, `/usr/local/opt`), MacPorts (`/opt/local`), and
  Nix (`/nix/store`) roots, and gates any dylib in an unexpected
  location on `SecStaticCodeCheckValidity` against `anchor apple
  generic`. Signed libraries are skipped regardless of location. Per-path
  signature cache avoids re-evaluation cost.
- `SystemPolicyMonitor.scanDownloadsForMissingQuarantine` now dedups
  per path (was re-alerting every 5-min poll), skips files validly
  signed under an Apple anchor, and ignores `.dmg`/`.iso` containers
  (Gatekeeper re-evaluates them on mount).
- `TLSFingerprinter` beacon allowlist expanded from browsers-only to
  cover chat (Slack, Discord, Signal, Telegram), meeting (Zoom, Teams),
  dev tools (GitHub Desktop, VS Code, JetBrains, Docker), and AI
  helpers (Claude, Codex, Cursor, ChatGPT Atlas). `node`/`deno`/`bun`
  skipped outright.
- `PowerAnomalyDetector` legitimate-holder set expanded
  (`screensharingd`, `bluetoothd`, `rapportd`, `mediaremoted`, Xcode,
  Docker, OrbStack, etc.) with per-process-name dedup so a single poll
  re-entry can't double-fire.
- `CrossProcessCorrelator` now suppresses network-convergence alerts
  when every contacting process shares a `.app` bundle, an exact
  executable path, or a tool-version directory. Additionally suppresses
  by destination for well-known cloud CDNs (Anthropic, OpenAI, Google,
  Cloudflare, GitHub) — multi-process fan-out to those is architecture.
- `AINetworkSandbox` falls back to a cloud IP-prefix list when DNS
  correlation is absent, so repeated AI-tool calls to the same backend
  IP don't fire one violation per unique IP.
- `BehaviorScoring` now applies a 120s per-indicator cooldown per
  process. A single chatty signal can no longer walk a score to
  threshold alone.
- `AlertDeduplicator.normalizePath` regex now also strips
  version-like segments at end-of-path (`/v?\d+\.\d+(\.\d+)*$`) so
  `/.../versions/2.1.111` and `/.../versions/2.1.112` deduplicate.
- `RuleEngine` via `EventLoop` now drops non-critical rule matches
  when the event has no attributable process (`process.name == "unknown"`
  or empty executable). File-event rules with `Image|contains` filters
  fail open on FSEvents without process info, which produced
  unattributable mediums we couldn't triage.
- New warm-up window: non-critical rule matches are suppressed for the
  first 60s after daemon start. Inventory scans (browser extensions,
  quarantine state, process-tree baseline) complete in this window.
  `DaemonState.isWarmingUp` gates the event loop; critical matches
  still fire so a ransomware note at T+10s isn't missed.

**Rule updates (YAML):**
- `command_and_control/c2_beacon_pattern.yml`: new `filter_dev_tools`
  and `filter_homebrew_node` exclusions.
- `defense_evasion/invisible_unicode_in_source.yml` and
  `trojan_source_bidi_code.yml`: exempt `.lproj/`, `.strings`,
  `.xliff`, `.po`, `/locales/`, `/_locales/`, `/i18n/`,
  `/translations/` paths (legitimate RTL text and zero-width joiners
  in localization files).

### Added

**Feedback loop (self-tuning severity):**
- `AlertDeduplicator.recordDismissal(alertId:ruleId:)` +
  `dismissalCount` + `dismissalRate` + `effectiveSeverity`. Tracks
  user dismissals idempotently by alert ID. Rules with ≥3 dismissals
  at ≥70% rate auto-downgrade one severity level on future firings
  (e.g. `high` → `medium`). `critical` is never downgraded and no rule
  goes below `medium`.
- `AlertStore.listSuppressed(limit:)` returns `(id, ruleId)` pairs for
  alerts the user has dismissed in the dashboard.
- New 60-second `DaemonTimers.feedbackTimer` sweeps the AlertStore
  for new dismissals and feeds each into the deduplicator.
- `EventLoop` consults `effectiveSeverity` when persisting the alert
  and only surfaces OS notifications when the downgraded severity is
  still `high` or `critical`.

**Browser extensions dashboard:**
- `BrowserExtensionsView` rows are now buttons that open a detail
  sheet with full manifest metadata: description, version, manifest
  version, author, homepage URL, update URL (flagged non-Web-Store),
  host permissions, content scripts with match patterns, background
  service worker / script list.
- 0–100 risk score + 4-tier label (Low risk / Caution / Suspicious /
  High risk) replaces the binary "Suspicious" flag.
- Per-risk-factor breakdown explains why a rule scored.
- Every permission carries a category (network / data / execution /
  device / host / meta) and a plain-English description from an
  internal dictionary; dangerous permissions visually distinguished.
- On-disk facts: install date (manifest mtime), size on disk
  (recursive), extension path. Quick actions: Reveal in Finder,
  deep-link to `chrome://extensions/?id=…` / `brave://…` /
  `edge://…`, open homepage.
- `__MSG_*` locale tokens in `manifest.json` now resolve against
  `_locales/<locale>/messages.json` instead of displaying raw.

### Impact (measured)

Reference workstation, 24-hour observation:

- Before: **2,856 alerts / 24h**, top 5 rules accounted for ~95%.
- After: **3 alerts / 11min** across two full forensic scan cycles
  post-restart, with the remaining 3 being legitimate singletons.

### Migration

Drop-in upgrade from 1.2.0. No schema changes, no config changes.
Existing per-alert suppressions from 1.2.0 continue to work and now
feed the auto-tune.

## [1.2.0] — 2026-04-16

Minor release. Models, exports, integrations, and agentic triage land
alongside the existing v1 detection stack. No destructive schema
changes; earlier installs upgrade automatically via `PRAGMA user_version`.

### Added

**Foundation (Phase 1):**
- Forward-only SQLite schema migrator (`SchemaMigrator`) wired into
  every store. Earlier DBs auto-migrate on first 1.2.0 open.
- `FileHasher` actor: SHA-256 with LRU cache keyed on path+mtime+size,
  256 MB cap, skips network mounts via `URL.volumeIsLocalKey`.
- `ProcessHasher` combines SHA-256 (FileHasher) with CDHash
  (CDHashExtractor) concurrently via `async let`.
- `ProcessInfo` gains `ProcessHashes`, `SessionInfo`, opt-in env capture.
- `CodeSignatureInfo` gains `issuerChain`, `certHashes`,
  `isAdhocSigned`, `entitlements` — populated by `CodeSigningCache`.
- `Alert` gains `campaignId`, `hostContext`, `analyst` metadata,
  `d3fendTechniques`, `remediationHint`, `llmInvestigation`.
- `CampaignStore` — persistent campaigns table, survives daemon
  restarts with suppression + analyst notes.
- `OCSFMapper` — maps `Event` → OCSF 1.3 `process_activity` (1007) /
  `file_activity` (1001) / `network_activity` (4001); `Alert` →
  `security_finding` (2004) with MITRE ATT&CK attacks block.

**Enrichment wiring (Phase 1 second wave):**
- `SessionEnricher` infers `LaunchSource` from ancestor chain (sshd →
  `.ssh`, Terminal/iTerm/Ghostty → `.terminal`, Finder → `.finder`,
  cron → `.cron`, etc.).
- `EnvCapture` reads target-process environment via
  `sysctl(KERN_PROCARGS2)`, gated on `MACCRAB_CAPTURE_ENV=1`. Secret-
  bearing keys (AWS_SECRET_*, *_TOKEN, *_PASSWORD) denied by default.

**Detection (Phase 2):**
- 16 new rule selectors in `RuleEngine.resolveField` + compiler
  passthroughs: `ProcessSHA256`, `ProcessCDHash`, `SigningCertIssuer`,
  `SessionTTY`, `SessionSSHRemoteIP`, `LaunchSource`, `IsSSHLaunched`,
  `IsAdhocSigned`, `AncestorDepth`, `EnvVarsFlat`, etc.
- `falsepositives` annotations on every sequence rule (26 rules).
- Three new hash/session-aware rules:
  `persistence/adhoc_signed_launchagent_write`,
  `defense_evasion/dyld_insert_libraries_env`,
  `credential_access/ssh_launched_security_dump`.

**Deception (Phase 3):**
- `HoneyfileManager` deploys canary files at standard credential paths
  (~/.aws/credentials.bak, ~/.ssh/id_rsa.old, ~/.kube/config.backup,
  ~/.netrc.backup, ~/.docker/config.json.bak, ~/.gcp-service-account
  .json.bak, keychain + browser-password backups). Opt-in via
  `MACCRAB_DECEPTION=1`. Maps to MITRE D3FEND D3-DF.
- `Rules/persistence/honeyfile_accessed.yml`: critical severity with
  self-read filter.
- `maccrabctl deception {deploy, status, remove}` CLI.

**Allowlist v2 (Phase 3):**
- TTL expiration (`expiresAt`), scope kinds (`rule_path`, `rule_hash`,
  `rule`, `path`, `host`), source tagging, required reason field.
- v1 flat-dict → v2 versioned-file migration on load, rewritten on
  next save.
- Append-only audit log at `suppressions_audit.jsonl`.
- Daemon sweep every 5 min prunes expired entries.
- `maccrabctl allow {add, list, remove, stats}` CLI with `--ttl`,
  `--scope`, `--reason`, `--expired` flags.
- `SuppressionManagerView` overhauled with scope filter chips,
  expiry countdowns, live reload from disk.

**Agentic LLM triage (Phase 4):**
- Structured `LLMInvestigation` schema: `Verdict` enum, `Evidence`
  chain, `SuggestedAction` (8 kinds with D3FEND ref + blast radius +
  `requiresConfirmation`), `MITREMap`, confidence penalties.
- `LLMService.investigate(alert:event:)` — rigid JSON-only prompt,
  temperature 0.1, single retry on malformed output, markdown code-
  fence stripping, missing-id backfill.
- `AlertStore` schema v2 persists the investigation (`llm_investigation
  _json` column); `updateInvestigation(alertId:)` for in-place update.
- EventLoop auto-triggers on HIGH/CRITICAL alerts in a detached Task —
  model latency never blocks detection.
- Dashboard `InvestigationSection` renders verdict + confidence bar +
  evidence chain + MITRE reasoning + suggested-action rows with
  **Preview / Confirm / Dismiss** controls. Nothing auto-executes.

**UI complexity modes (Phase 5):**
- Basic / Standard / Advanced modes filter the sidebar. Settings >
  Appearance tab exposes the toggle. Default stays Advanced so
  upgrades preserve current UX.
- D3FEND technique references attached to all 9 Prevention modules +
  HoneyfileManager, with a shared `D3FENDMapping` catalog.

**Exports (Phase 7):**
- `Output` protocol unifies all alert sinks (`send(alert:event:)`,
  `flush()`, `outputStats()`, `health()`). Existing
  WebhookOutput / SyslogOutput / NotificationOutput retrofit.
- `FileOutput`: NDJSON writer with size + age rotation, N-archive
  retention, 0o600 permissions. OCSF by default; native-envelope
  alternative.
- `StreamOutput`: Splunk HEC, Elasticsearch Bulk API, Datadog Logs.
  Per-SIEM body framing, exponential-backoff retry, token resolution
  from env (never from on-disk config).
- `daemon_config.json.outputs[]` schema drives factory-based
  instantiation; `additionalOutputs: [any Output]` on DaemonState.

**SIEM integration bundles (Phase 8):**
- `integrations/wazuh/` — JSON decoder + 10 rules mapping MacCrab
  severities and MITRE tactics to Wazuh levels 1–14. Honeyfile
  access escalates to level 14.
- `integrations/elastic/` — typed index template for every OCSF field
  + starter Kibana saved-objects (index pattern + dashboard).
- `integrations/osquery/packs/maccrab.conf` — 12 macOS posture
  queries (listening ports, unsigned LaunchAgents, kexts, DYLD-
  injected processes, quarantined executables, etc.).

**Behaviour analytics (Phase 9):**
- `UEBAEngine` with per-user baseline (login hour histogram, SSH
  source IPs, tool usage). Emits anomalies after a cold-start gate
  (default 100 observations). Kinds: `unusualLoginHour`,
  `newSSHSource`, `novelTool`.

**Test hardening (Phase 6):**
- PanicButton / TravelMode coverage (previously greenfield).
- `ResponseActionCoverageTests` covers blockNetwork / script /
  escalateNotification plus Codable round-trip for every
  `ResponseActionType`.
- Test count grew from 326 (1.1.1 cut) to 535 (1.2.0 cut).

### Changed

- `Alert.llmInvestigation` type moved from a Phase 1 placeholder to
  the rich `LLMInvestigation` schema in `Sources/MacCrabCore/LLM/`.
  Verdict now an enum; old String-valued verdict values still decode.
- `RuleTestHelpers.ensureRulesCompiled()` now mtime-aware; adding a
  rule no longer requires `rm -rf /tmp/maccrab_v3` before tests.
- `SuppressionManager` v1 → v2 schema migration happens silently on
  first load and the file is rewritten in v2 shape on next save.
- About tagline: "Made with love and tokens in Ireland."

### Deferred to v2.1

- `S3Output` (hand-rolled SigV4 or AWS SDK for Swift dependency).
- `SFTPOutput` via NSTask `sftp`.
- `WazuhOutput` direct-to-manager API push (beyond file-tail).
- Osquery **producer** extension — exposing `maccrab_alerts`,
  `maccrab_events`, `maccrab_campaigns` as virtual tables so analysts
  can JOIN in `osqueryi`. Consumer (`OsqueryCollector`) still planned.
- Executing confirmed `SuggestedAction`s from the Investigation panel
  (currently UI-only).
- LLM eval harness with 50 labeled scenarios per backend.
- Native macOS 15.4+ `ES_EVENT_TYPE_NOTIFY_TCC_MODIFY` for TCC monitor
  (requires ES entitlement release builds don't carry).
- UEBA baseline persistence across daemon restarts.

### Security

- Every opt-in feature is default OFF:
  `MACCRAB_DECEPTION`, `MACCRAB_CAPTURE_ENV`,
  `daemon_config.json.outputs[]` array.
- Secrets never written to disk: StreamOutput tokens resolved from
  env (`tokenEnv:` in config); EnvCapture deny-list blocks
  AWS_SECRET_*, *_TOKEN, *_PASSWORD even if allowlisted.
- CommandSanitizer still wraps every outbound payload across all
  Output sinks.
- Files written by new outputs land at 0o600 (FileOutput) and 0o400
  (honeyfiles — matches real credential-file mode).

### Migration notes

- Schema migrations applied by 1.2.0 are one-way. After a 1.2.0
  daemon opens `events.db` or `suppressions.json`, downgrading to
  1.1.x is unsupported. Take a backup if you plan to roll back.
- `daemon_config.json` keys remain additive — every new 1.2.0 option
  has a default so existing files keep working.
- Existing shell environment variables (`MACCRAB_WEBHOOK_URL`,
  `MACCRAB_SYSLOG_HOST`, `MACCRAB_SYSLOG_PORT`) still work as before
  and coexist with the new `outputs[]` array.

## [1.1.1] — 2026-04-08

See git history for pre-1.2 entries. Individual 1.1.x releases were
tracked in `RELEASE_NOTES.md` and commit messages rather than this
changelog.
