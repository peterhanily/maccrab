// AlertsFlowUITest.swift
// v1.21.5 — example end-to-end UI test for the MacCrab dashboard.
//
// NOT compiled by `swift build`/`swift test` (this dir is outside Package.swift).
// Runs via the XcodeGen-generated MacCrabAppUITests bundle (see ../README.md):
//   xcodebuild test -scheme MacCrabApp -destination 'platform=macOS' \
//     -only-testing:MacCrabAppUITests
//
// It proves the harness seams end-to-end: a seeded fixture DB (no root daemon),
// the WindowGroup auto-shown by `-ui-testing`, and accessibility identifiers.
//
// SELECTORS (all three wired as of v1.21.5):
//   - sidebar row:   V2SidebarItem      .v2AXID("sidebar.item.\(workspace.rawValue)")
//   - alert row:     Alerts title cell  .v2AXID("alert.row.\(alert.id)")
//   - suppress btn:  inspector V2ActionButton(..., axId: "alert.suppress.\(alert.id)")

import XCTest
import MacCrabCore

final class AlertsFlowUITest: XCTestCase {

    private var fixtureDir: String!

    // Async setUp: AlertStore is an actor, so insert must be awaited.
    override func setUp() async throws {
        continueAfterFailure = false
        // Seed a deterministic fixture DB in a temp dir — no daemon required.
        // AlertStore(directory:) creates <dir>/alerts.db, the same file the
        // app opens read-only when MACCRAB_DATA_DIR points here.
        fixtureDir = NSTemporaryDirectory() + "maccrab-uitest-\(UUID().uuidString)"
        try FileManager.default.createDirectory(atPath: fixtureDir, withIntermediateDirectories: true)
        let store = try AlertStore(directory: fixtureDir)
        try await store.insert(alert: Self.fixtureCriticalAlert(id: "A-1"))
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

        // seeded critical alert renders in the Open table
        let row = app.staticTexts["alert.row.A-1"]
        XCTAssertTrue(row.waitForExistence(timeout: 5), "seeded critical alert should render")

        // select the row -> inspector opens with the Suppress action
        row.click()
        let suppress = app.buttons["alert.suppress.A-1"]
        XCTAssertTrue(suppress.waitForExistence(timeout: 5), "inspector should expose Suppress")

        // click Suppress -> row leaves the Open list (optimistic local flip)
        suppress.click()
        XCTAssertFalse(app.staticTexts["alert.row.A-1"].waitForExistence(timeout: 3),
                       "suppressed alert should leave the Open list")

        // free accessibility audit (Xcode 15+ API)
        if #available(macOS 14.0, *) {
            try app.performAccessibilityAudit()
        }
    }

    // Test factory. Argument order matches Alert.init exactly
    // (id, timestamp, ruleId, ruleTitle, severity, eventId, processPath,
    // processName, description, ... — see MacCrabCore/Models/Alert.swift).
    private static func fixtureCriticalAlert(id: String) -> Alert {
        Alert(
            id: id,
            timestamp: Date(),
            ruleId: "maccrab.test.critical",
            ruleTitle: "Test Critical Alert",
            severity: .critical,
            eventId: "uitest-event-\(id)",
            processPath: "/tmp/evil",
            processName: "evil",
            description: "seeded fixture alert"
        )
    }
}
