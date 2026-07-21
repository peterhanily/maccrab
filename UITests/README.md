# MacCrab UI tests (XCUITest) — harness

End-to-end UI tests that drive the real dashboard `WindowGroup` against a
**seeded fixture database**, with no root daemon required.

This directory is **not** part of `Package.swift` — SPM cannot host a UITest
bundle, so `swift build` / `swift test` ignore it. The tests run through the
XcodeGen-generated `.xcodeproj` (see below) via `xcodebuild`, which needs a real
GUI login session. This stays a **non-blocking** lane (manual /
`workflow_dispatch` if it ever gets a CI job — none exists today, and adding a
blocking GUI job is explicitly a future option, not current state).

## The seams (already in the app)

- **Fixture DB** — `AppState.dataDir` honors `MACCRAB_DATA_DIR` when the app is
  launched with `-ui-testing`. Point it at a temp dir seeded via
  `AlertStore(directory:)` / `EventStore(directory:)` from `MacCrabCore`
  (both are actors — seed from an `async` setUp).
- **Window auto-show** — `-ui-testing` calls `showDashboard()` at launch so
  XCUITest attaches to the `WindowGroup` without automating the menu-bar item.
- **Accessibility identifiers** — shared components take an optional `axId`
  (see `V2AXIdentifier.swift`); `V2ActionButton` forwards it. Wired so far
  (v1.21.5 — exactly what `AlertsFlowUITest` targets):
  - `sidebar.item.<workspace.rawValue>` — every `V2SidebarItem` row
  - `alert.row.<alert id>` — Alerts Open-table title cell
  - `alert.suppress.<alert id>` — the inspector's Suppress `V2ActionButton`

  Everything else in the dashboard is still unidentified; add `axId`s at the
  surfaces a new test needs to target.

## Target wiring — DONE (v1.21.5)

`Xcode/project.yml` now defines the `MacCrabAppUITests` target
(`bundle.ui-testing`, ad-hoc signed, depends on `MacCrabApp` + the
`MacCrabCore` package product — note the package is keyed `MacCrabCore` in
that file, not `MacCrab` as an earlier draft of this README said), and the
`MacCrabApp` target declares an explicit scheme with `MacCrabAppUITests` as a
test target, so the command below resolves without relying on Xcode's scheme
autocreation.

The `.xcodeproj` is gitignored — regenerate it on-device, then run:

```bash
cd Xcode && xcodegen
xcodebuild test -scheme MacCrabApp -destination 'platform=macOS' \
  -only-testing:MacCrabAppUITests
```

## What's covered

`AlertsFlowUITest.swift` — the canonical flow: launch → open the Alerts
workspace → assert a seeded CRITICAL alert renders → select the row → click
Suppress in the inspector → assert it leaves the Open list → run a free
accessibility audit. It's the template; extend per workspace as `axId`s are
added.

## Honest limitations

- Needs a real GUI session (WindowServer) — can't share the `swift test` lane,
  and it has **not** been executed headless; running it is an on-device step.
- The suppress round-trip is optimistic-UI: with no daemon consuming the inbox
  IPC, the row disappearing proves the UI flow, not daemon-side persistence.
- Menu-bar-extra automation is flaky; the harness sidesteps it via the WindowGroup.
- Building the app via `xcodebuild` needs the Developer ID signing identity
  present (the UITest bundle itself is ad-hoc signed).
