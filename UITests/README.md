# MacCrab UI tests (XCUITest) — harness

End-to-end UI tests that drive the real dashboard `WindowGroup` against a
**seeded fixture database**, with no root daemon required.

This directory is **not** part of `Package.swift` — SPM cannot host a UITest
bundle, so `swift build` / `swift test` ignore it. The tests run through the
XcodeGen-generated `.xcodeproj` (see below) via `xcodebuild`, which needs a real
GUI login session (so this is a separate, non-blocking CI job, not the fast
`swift test` lane).

## The seams (already in the app, v1.21.4)

- **Fixture DB** — `AppState.dataDir` honors `MACCRAB_DATA_DIR` when the app is
  launched with `-ui-testing`. Point it at a temp dir seeded via
  `AlertStore(directory:)` / `EventStore(directory:)` from `MacCrabCore`.
- **Window auto-show** — `-ui-testing` calls `showDashboard()` at launch so
  XCUITest attaches to the `WindowGroup` without automating the menu-bar item.
- **Accessibility identifiers** — shared components take an optional `axId`
  (see `V2AXIdentifier.swift`); `V2ActionButton` already forwards it. Add `axId`
  at the surfaces a test needs to target (sidebar rows, alert rows, palette).

## Wiring the target (XcodeGen)

Add to `Xcode/project.yml`:

```yaml
  MacCrabAppUITests:
    type: bundle.ui-testing
    platform: macOS
    sources: [../UITests/MacCrabAppUITests]
    dependencies:
      - target: MacCrabApp
      - package: MacCrab            # so tests can seed via AlertStore/EventStore
    settings:
      CODE_SIGN_IDENTITY: "-"       # ad-hoc; no Developer ID / ES entitlement needed
```

Then `cd Xcode && xcodegen`, and run:

```bash
xcodebuild test -scheme MacCrabApp -destination 'platform=macOS' \
  -only-testing:MacCrabAppUITests
```

## What's covered

`AlertsFlowUITest.swift` — the canonical flow: launch → open the Alerts
workspace → assert a seeded CRITICAL alert renders → click Suppress → assert it
disappears → run a free accessibility audit. It's the template; extend per
workspace as `axId`s are added.

## Honest limitations

- Needs a real GUI session (WindowServer) — can't share the `swift test` lane.
- Menu-bar-extra automation is flaky; the harness sidesteps it via the WindowGroup.
- First-time XcodeGen UITest-bundle + signing plumbing is the main friction.
