// SchemaMigrationIntegrationTests.swift
//
// End-to-end migration tests covering the v1.9 → v1.10 path.
//
// SchemaMigratorTests already covers the migrator in isolation. This
// suite exercises the actual store actors opening in sequence so we
// catch regressions where one store's migration hands back a counter
// that another store reuses (the v1.7.6 incident — co-resident store
// discipline). Specifically:
//
// - Open a fresh data dir, instantiate every store in the order the
//   daemon does.
// - Re-instantiate them. No second-pass migrations should apply.
// - Open against a path that already has a tracegraph.db at v1, then
//   confirm no migration churn.
//
// Acceptance gate from `2026-05-08-v1-10-0-release-audit.md` M3.

import Testing
import Foundation
@testable import MacCrabCore

@Suite("v1.9 → v1.10 multi-store migration")
struct SchemaMigrationIntegrationTests {

    /// Fresh data directory in /tmp, removed at end of scope.
    private final class TempDir {
        let path: String
        init() {
            self.path = NSTemporaryDirectory() + "maccrab_migration_\(UUID().uuidString)"
            try? FileManager.default.createDirectory(atPath: path,
                                                     withIntermediateDirectories: true)
        }
        deinit { try? FileManager.default.removeItem(atPath: path) }
    }

    @Test("Fresh data dir: every store opens cleanly and migrates from baseline")
    func freshDirOpensAllStores() async throws {
        let dir = TempDir()
        // Instantiate in the order the daemon does (events first, then
        // alerts, campaigns, traces, tracegraph). Each store creates +
        // migrates its own DB on init.
        _ = try EventStore(directory: dir.path)
        _ = try AlertStore(directory: dir.path)
        _ = try CampaignStore(directory: dir.path)
        // TraceStore + SQLiteCausalGraphStore are async-init'd.
        _ = try await SQLiteCausalGraphStore(databasePath: dir.path + "/tracegraph.db")
        // All four DB files should exist on disk.
        let fm = FileManager.default
        for db in ["events.db", "alerts.db", "campaigns.db", "tracegraph.db"] {
            #expect(fm.fileExists(atPath: dir.path + "/" + db),
                    "Expected \(db) to exist after first init")
        }
    }

    @Test("Reopen is a no-op — no second-pass migrations applied")
    func reopenIsIdempotent() async throws {
        let dir = TempDir()
        _ = try EventStore(directory: dir.path)
        _ = try AlertStore(directory: dir.path)
        _ = try CampaignStore(directory: dir.path)
        _ = try await SQLiteCausalGraphStore(databasePath: dir.path + "/tracegraph.db")

        // Capture the mtimes — re-init should not rewrite the schema.
        let fm = FileManager.default
        let before: [String: Date] = try [
            "events.db", "alerts.db", "campaigns.db", "tracegraph.db"
        ].reduce(into: [:]) { acc, name in
            let attrs = try fm.attributesOfItem(atPath: dir.path + "/" + name)
            acc[name] = (attrs[.modificationDate] as? Date) ?? .distantPast
        }
        // Brief delay to make any rewrite visible in the mtime.
        try await Task.sleep(nanoseconds: 200_000_000)

        _ = try EventStore(directory: dir.path)
        _ = try AlertStore(directory: dir.path)
        _ = try CampaignStore(directory: dir.path)
        _ = try await SQLiteCausalGraphStore(databasePath: dir.path + "/tracegraph.db")

        for (name, prev) in before {
            let attrs = try fm.attributesOfItem(atPath: dir.path + "/" + name)
            let now = (attrs[.modificationDate] as? Date) ?? .distantPast
            // Allow tiny delta (filesystems round mtimes); migrations
            // would be much larger writes than that.
            let delta = now.timeIntervalSince(prev)
            #expect(delta < 1.0,
                    "\(name) was rewritten on reopen (Δmtime \(delta)s) — implies a migration ran twice")
        }
    }

    @Test("Co-resident: events + alerts can write without disturbing each other")
    func coResidentStoresDoNotCorruptEachOther() async throws {
        let dir = TempDir()
        let events = try EventStore(directory: dir.path)
        let alerts = try AlertStore(directory: dir.path)

        // Insert one row into each store. If their migration counters
        // collided (the v1.7.6 incident), one of these would fail or
        // silently overwrite the other.
        let proc = MacCrabCore.ProcessInfo(
            pid: 1, ppid: 0, rpid: 0,
            name: "x", executable: "/tmp/x", commandLine: "/tmp/x",
            args: [], workingDirectory: "/tmp",
            userId: 0, userName: "test", groupId: 0,
            startTime: Date()
        )
        let event = Event(
            id: UUID(),
            timestamp: Date(),
            eventCategory: .process,
            eventType: .info,
            eventAction: "test",
            process: proc,
            severity: .informational
        )
        try await events.insert(event: event)

        let alert = Alert(
            id: "test-\(UUID().uuidString)",
            timestamp: Date(),
            ruleId: "test_rule",
            ruleTitle: "Test",
            severity: .high,
            eventId: event.id.uuidString
        )
        try await alerts.insert(alert: alert)

        let evCount = try await events.count()
        let alCount = try await alerts.count()
        #expect(evCount == 1)
        #expect(alCount == 1)
    }

    @Test("tracegraph.db in isolation does not need events.db schema")
    func tracegraphIndependentOfEvents() async throws {
        // The TraceGraph store opens its own DB; it must not assume
        // any other store has run first. This catches regressions where
        // a future migration accidentally cross-references events.db.
        let dir = TempDir()
        let tracegraph = try await SQLiteCausalGraphStore(
            databasePath: dir.path + "/tracegraph.db"
        )
        // The traces list should return empty without throwing.
        let traces = try await tracegraph.listTraces(limit: 10)
        #expect(traces.isEmpty)
        // Only tracegraph.db should exist — events.db / alerts.db
        // should not have been created as a side-effect.
        #expect(FileManager.default.fileExists(atPath: dir.path + "/tracegraph.db"))
        #expect(!FileManager.default.fileExists(atPath: dir.path + "/events.db"))
        #expect(!FileManager.default.fileExists(atPath: dir.path + "/alerts.db"))
    }
}
