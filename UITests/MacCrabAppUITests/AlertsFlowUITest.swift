// AlertsFlowUITest.swift
// v1.21.4 — example end-to-end UI test for the MacCrab dashboard.
//
// NOT compiled by `swift build`/`swift test` (this dir is outside Package.swift).
// Runs via the XcodeGen-generated MacCrabAppUITests bundle (see ../README.md):
//   xcodebuild test -scheme MacCrabApp -destination 'platform=macOS' \
//     -only-testing:MacCrabAppUITests
//
// It proves the harness seams end-to-end: a seeded fixture DB (no root daemon),
// the WindowGroup auto-shown by `-ui-testing`, and accessibility identifiers.
//
// PREREQUISITES (add the `axId`s these selectors reference — a few are wired,
// the rest are the next a11y pass):
//   - sidebar row:   V2SidebarItem  -> .v2AXID("sidebar.item.\(workspace.rawValue)")
//   - alert row:     V2DataTable Row -> .v2AXID("alert.row.\(id)")
//   - suppress btn:  V2ActionButton(..., axId: "alert.suppress.\(id)") [param exists]

import XCTest
@testable import MacCrabCore

final class AlertsFlowUITest: XCTestCase {

    private var fixtureDir: String!

    override func setUpWithError() throws {
        continueAfterFailure = false
        // Seed a deterministic fixture DB in a temp dir — no daemon required.
        fixtureDir = NSTemporaryDirectory() + "maccrab-uitest-\(UUID().uuidString)"
        try FileManager.default.createDirectory(atPath: fixtureDir, withIntermediateDirectories: true)
        let store = try AlertStore(directory: fixtureDir)
        try store.insert(alert: Self.fixtureCriticalAlert(id: "A-1"))
    }

    override func tearDownWithError() throws {
        if let dir = fixtureDir { try? FileManager.default.removeItem(atPath: dir) }
    }

    func testSuppressCriticalAlertRemovesRow() throws {
        let app = XCUIApplication()
        app.launchArguments = ["-ui-testing"]
        app.launchEnvironment["MACCRAB_DATA_DIR"] = fixtureDir
        app.launch()

        // launch -> open Alerts workspace
        app.buttons["sidebar.item.alerts"].click()

        // seeded critical alert renders
        let row = app.staticTexts["alert.row.A-1"]
        XCTAssertTrue(row.waitForExistence(timeout: 5), "seeded critical alert should render")

        // click Suppress -> row disappears
        app.buttons["alert.suppress.A-1"].click()
        XCTAssertFalse(app.staticTexts["alert.row.A-1"].waitForExistence(timeout: 3),
                       "suppressed alert should leave the Open list")

        // free accessibility audit (Xcode 15+/17 API)
        if #available(macOS 14.0, *) {
            try app.performAccessibilityAudit()
        }
    }

    // A small test factory — adjust to the real Alert initializer.
    private static func fixtureCriticalAlert(id: String) -> Alert {
        Alert(
            id: id,
            ruleId: "maccrab.test.critical",
            ruleTitle: "Test Critical Alert",
            severity: .critical,
            timestamp: Date(),
            processName: "evil",
            processPath: "/tmp/evil",
            description: "seeded fixture alert"
        )
    }
}
