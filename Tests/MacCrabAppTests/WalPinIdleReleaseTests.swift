// WalPinIdleReleaseTests.swift
// v1.21.5-rc.3 — locks mother-of-all-audits finding #4: the app-side WAL-pin
// recycle (v1.21.5-rc.2, commit 88fdaf5) was getter-driven and never fired while
// the dashboard was backgrounded, so the read-only events.db connection — and its
// WAL read-mark — stayed open, pinning the sysext's WAL (the 512 MB case). The fix
// releases the cached connection in stopPolling(), which fires on scenePhase
// .background. This test proves the release happens.

import Testing
import Foundation
@testable import MacCrabApp
@testable import MacCrabCore

@Suite("Phase 3 (4): WAL-pin idle release on stopPolling")
struct WalPinIdleReleaseTests {

    @MainActor
    @Test("stopPolling() releases the cached events.db reader (drops its WAL mark)")
    func stopPollingReleasesEventStore() throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("walpin-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }

        // A real read-only events.db connection stands in for the one the getter
        // would open while the dashboard is foregrounded.
        _ = try EventStore(directory: dir.path)                  // create events.db
        let reader = try EventStore(directory: dir.path, forceReadOnly: true)

        let app = AppState(engineSource: .init(directory: dir.path), startBackgroundWork: false)
        app.primeCachedEventStoreForTesting(reader)
        #expect(app.hasCachedEventStoreForTesting, "precondition: a reader is cached")

        // Backgrounding the dashboard calls stopPolling(); it must drop the reader
        // so EventStore.deinit → sqlite3_close releases the WAL read-mark.
        app.stopPolling()
        #expect(!app.hasCachedEventStoreForTesting,
                "stopPolling() must release the cached events.db reader so the WAL mark is dropped when idle")
    }
}
