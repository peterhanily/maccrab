// EventInsertFilterTests.swift
//
// v1.8.0 Layer 1: pre-insert filter coverage. Pins the contract that:
//
//   1. Default filter drops self-monitoring events (daemon writing to its
//      own support dir, log file, dev-null, pty)
//   2. Default filter passes legitimate events untouched
//   3. Process-name filtering exits early before path matching
//   4. Custom path + process extensions compose with the default
//   5. The drop counter increments accurately

import Testing
import Foundation
@testable import MacCrabCore

@Suite("EventInsertFilter (v1.8.0 Layer 1)")
struct EventInsertFilterTests {

    private func makeProcessEvent(
        name: String = "innocuous",
        executable: String = "/bin/innocuous",
        filePath: String? = nil
    ) -> Event {
        let proc = ProcessInfo(
            pid: 100, ppid: 1, rpid: 1,
            name: name, executable: executable,
            commandLine: executable, args: [],
            workingDirectory: "/",
            userId: 501, userName: "u", groupId: 20,
            startTime: Date(),
            ancestors: [],
            isPlatformBinary: false
        )
        let file = filePath.map { FileInfo(path: $0, action: .write) }
        return Event(
            timestamp: Date(),
            eventCategory: .file, eventType: .change,
            eventAction: "write", process: proc,
            file: file
        )
    }

    @Test("Default filter drops events under the daemon's own support dir")
    func defaultFilterDropsSelfMonitoring() {
        let filter = EventInsertFilter.defaultFilter(supportDir: "/Library/Application Support/MacCrab")
        let event = makeProcessEvent(filePath: "/Library/Application Support/MacCrab/events.db-wal")
        #expect(filter.shouldDrop(event: event))
    }

    @Test("Default filter drops the daemon's own log file")
    func defaultFilterDropsOwnLog() {
        let filter = EventInsertFilter.defaultFilter(supportDir: "/Library/Application Support/MacCrab")
        let event = makeProcessEvent(filePath: "/private/tmp/maccrabd.log")
        #expect(filter.shouldDrop(event: event))
    }

    @Test("Default filter drops /dev/null and /dev/ttys writes")
    func defaultFilterDropsDevNoise() {
        let filter = EventInsertFilter.defaultFilter(supportDir: "/Library/Application Support/MacCrab")
        let devNull = makeProcessEvent(filePath: "/dev/null")
        let pty = makeProcessEvent(filePath: "/dev/ttys003")
        #expect(filter.shouldDrop(event: devNull))
        #expect(filter.shouldDrop(event: pty))
    }

    @Test("Default filter passes legitimate file events untouched")
    func defaultFilterPassesUserData() {
        let filter = EventInsertFilter.defaultFilter(supportDir: "/Library/Application Support/MacCrab")
        let userFile = makeProcessEvent(filePath: "/Users/alice/Documents/secret.txt")
        let suspiciousTmp = makeProcessEvent(filePath: "/tmp/payload.sh")
        #expect(!filter.shouldDrop(event: userFile))
        #expect(!filter.shouldDrop(event: suspiciousTmp))
    }

    @Test("Default filter drops dev-mode daemon's user-uid support dir")
    // Sysext (root) running while a `swift run maccrabd` (user-uid) is also
    // alive: the sysext sees the user-uid daemon's writes to
    // ~/Library/Application Support/MacCrab/. The trailing-slash-no-leading-slash
    // pattern catches both /Library/ and /Users/.../Library/.
    func defaultFilterDropsCrossModeDaemonWrites() {
        let filter = EventInsertFilter.defaultFilter(supportDir: "/Library/Application Support/MacCrab")
        let devModeWAL = makeProcessEvent(filePath: "/Users/alice/Library/Application Support/MacCrab/events.db-wal")
        #expect(filter.shouldDrop(event: devModeWAL))
    }

    @Test("Default filter drops SQLite temp files (etilqs_ pattern)")
    // Field measurement showed ~5% of events were SQLite's own mkstemp temp
    // files in /private/var/folders/.../T/etilqs_<hash>. Universal across
    // any SQLite-using app, including MacCrab itself.
    func defaultFilterDropsSqliteTemps() {
        let filter = EventInsertFilter.defaultFilter(supportDir: "/Library/Application Support/MacCrab")
        let sqliteTemp = makeProcessEvent(filePath: "/private/var/folders/zz/abc/T/etilqs_80a9c80f5d002b6c")
        #expect(filter.shouldDrop(event: sqliteTemp))
    }

    @Test("Default filter drops Apple internal log/data daemon noise")
    func defaultFilterDropsAppleInternal() {
        let filter = EventInsertFilter.defaultFilter(supportDir: "/Library/Application Support/MacCrab")
        let launchdLog = makeProcessEvent(filePath: "/private/var/log/com.apple.xpc.launchd/launchd.log")
        let systemstats = makeProcessEvent(filePath: "/private/var/db/systemstats/12345.coalitions.XX.stats")
        #expect(filter.shouldDrop(event: launchdLog))
        #expect(filter.shouldDrop(event: systemstats))
    }

    @Test("Default filter drops /dev/ptmx and /dev/console")
    func defaultFilterDropsExtraDevNoise() {
        let filter = EventInsertFilter.defaultFilter(supportDir: "/Library/Application Support/MacCrab")
        let ptmx = makeProcessEvent(filePath: "/dev/ptmx")
        let console = makeProcessEvent(filePath: "/dev/console")
        #expect(filter.shouldDrop(event: ptmx))
        #expect(filter.shouldDrop(event: console))
    }

    @Test("Default filter drops only Codex database churn, not session evidence")
    func defaultFilterDropsCodexDatabaseChurn() {
        let filter = EventInsertFilter.defaultFilter(
            supportDir: "/Library/Application Support/MacCrab"
        )
        for path in [
            "/Users/alice/.codex/state_5.sqlite-wal",
            "/Users/alice/.codex/thread_history_1.sqlite-shm",
            "/Users/alice/.codex/logs_2.sqlite",
        ] {
            #expect(filter.shouldDrop(event: makeProcessEvent(
                name: "codex",
                filePath: path
            )))
        }
        #expect(!filter.shouldDrop(event: makeProcessEvent(
            name: "codex",
            filePath: "/Users/alice/.codex/sessions/2026/08/15/rollout.jsonl"
        )))
        #expect(!filter.shouldDrop(event: makeProcessEvent(
            name: "codex",
            filePath: "/Users/alice/Documents/incident-notes.md"
        )))
    }

    @Test("Default filter drops only the derived SpotlightKnowledge subtree")
    func defaultFilterDropsSpotlightKnowledgeChurn() {
        let filter = EventInsertFilter.defaultFilter(
            supportDir: "/Library/Application Support/MacCrab"
        )
        #expect(filter.shouldDrop(event: makeProcessEvent(
            name: "spotlightknowledged.updater",
            filePath: "/Users/alice/Library/Metadata/CoreSpotlight/SpotlightKnowledge/index.V2/embedding_cache/4.map.header"
        )))
        #expect(!filter.shouldDrop(event: makeProcessEvent(
            name: "mdworker_shared",
            filePath: "/Users/alice/Library/Metadata/CoreSpotlight/UserDocuments/index.db"
        )))
        #expect(!filter.shouldDrop(event: makeProcessEvent(
            name: "TextEdit",
            filePath: "/Users/alice/Documents/search-notes.txt"
        )))
    }

    @Test("Measured maintenance flood is filtered without a broad path blind spot")
    func measuredMaintenanceFloodIsFiltered() {
        let filter = EventInsertFilter.defaultFilter(
            supportDir: "/Library/Application Support/MacCrab"
        )
        for _ in 0..<10_000 {
            #expect(filter.shouldDrop(event: makeProcessEvent(
                name: "codex",
                filePath: "/Users/alice/.codex/state_5.sqlite-wal"
            )))
            #expect(filter.shouldDrop(event: makeProcessEvent(
                name: "spotlightknowledged.updater",
                filePath: "/Users/alice/Library/Metadata/CoreSpotlight/SpotlightKnowledge/index.V2/embedding_cache/4.map.header"
            )))
        }
        #expect(!filter.shouldDrop(event: makeProcessEvent(
            name: "sqlite3",
            filePath: "/Users/alice/Documents/case-evidence.sqlite-wal"
        )))
        let counters = filter.counters.snapshot()
        #expect(counters.dropped == 20_000)
        #expect(counters.passed == 1)
    }

    @Test("Default filter drops events whose actor is maccrabctl or maccrabd")
    // Field measurement showed maccrabctl invocations alone produced
    // 24% of events on a dev box (test runs, status checks, hunt queries
    // each generate hundreds of file events as the CLI walks support dirs).
    // Self-process filtering by name closes that loop.
    func defaultFilterDropsOwnProcesses() {
        let filter = EventInsertFilter.defaultFilter(supportDir: "/Library/Application Support/MacCrab")
        let cli = makeProcessEvent(name: "maccrabctl", filePath: "/Users/alice/Documents/notes.md")
        let dev = makeProcessEvent(name: "maccrabd", filePath: "/Users/alice/Documents/notes.md")
        #expect(filter.shouldDrop(event: cli))
        #expect(filter.shouldDrop(event: dev))
    }

    @Test("Custom process-name filter drops by process regardless of path")
    func processNameFilterShortCircuits() {
        let filter = EventInsertFilter(
            pathSubstrings: [],
            processNames: ["swiftpm-testing-helper", "dsymutil"]
        )
        let helperEvent = makeProcessEvent(name: "swiftpm-testing-helper", filePath: "/Users/alice/code/x.swift")
        #expect(filter.shouldDrop(event: helperEvent))
    }

    @Test("Counters track passed + dropped events accurately")
    func countersIncrement() {
        let filter = EventInsertFilter(
            pathSubstrings: ["/private/tmp/scratch/"],
            processNames: ["noisy"]
        )

        // 3 dropped: 2 by path, 1 by process
        _ = filter.shouldDrop(event: makeProcessEvent(filePath: "/private/tmp/scratch/a"))
        _ = filter.shouldDrop(event: makeProcessEvent(filePath: "/private/tmp/scratch/b"))
        _ = filter.shouldDrop(event: makeProcessEvent(name: "noisy"))

        // 2 passed
        _ = filter.shouldDrop(event: makeProcessEvent(filePath: "/Users/alice/x"))
        _ = filter.shouldDrop(event: makeProcessEvent(name: "ok", filePath: "/Users/alice/y"))

        let snap = filter.counters.snapshot()
        #expect(snap.dropped == 3)
        #expect(snap.passed == 2)
    }
}

// MARK: - v1.21.6 Layer 1b: duplicate-window suppression
//
// Measured on a wedged installed host: the exact journal (78% of the events
// family, 267 MiB) was dominated by near-identical platform-daemon chatter at
// a 16.4x duplication ratio — bluetoothd 5,171 rows, secd 3,582, mDNSResponder
// 1,631 — each copy hash-chained at ~1.4 KiB. Journaling every copy is what
// made the default family cap unreachable on a busy Mac.
//
// The window keeps the FIRST occurrence as the exact exemplar and suppresses
// in-window repeats. Detection is upstream of persistence and sees every
// instance; suppression costs replay of the Nth copy, never coverage.
@Suite("EventInsertFilter duplicate window (v1.21.6 Layer 1b)")
struct EventInsertFilterDuplicateWindowTests {

    private func chatterEvent(
        name: String = "bluetoothd",
        executable: String = "/usr/sbin/bluetoothd",
        platform: Bool = true,
        category: MacCrabCore.EventCategory = .process,
        action: String = "unified_log_event",
        at seconds: TimeInterval = 1_700_000_000,
        destinationIp: String? = nil
    ) -> Event {
        let proc = ProcessInfo(
            pid: 100, ppid: 1, rpid: 1,
            name: name, executable: executable,
            commandLine: executable, args: [],
            workingDirectory: "/",
            userId: 0, userName: "root", groupId: 0,
            startTime: Date(timeIntervalSince1970: seconds),
            ancestors: [],
            isPlatformBinary: platform
        )
        let network = destinationIp.map {
            NetworkInfo(
                sourceIp: "192.168.1.2", sourcePort: 5_000,
                destinationIp: $0, destinationPort: 443,
                destinationHostname: nil,
                direction: .outbound, transport: "tcp"
            )
        }
        return Event(
            timestamp: Date(timeIntervalSince1970: seconds),
            eventCategory: category, eventType: .info,
            eventAction: action, process: proc,
            network: network
        )
    }

    private func windowFilter() -> EventInsertFilter {
        EventInsertFilter(duplicateWindowSeconds: 300)
    }

    @Test("First occurrence journals; in-window repeats are suppressed")
    func repeatsSuppressed() {
        let filter = windowFilter()
        #expect(!filter.shouldDrop(event: chatterEvent(at: 1_700_000_000)),
                "the exemplar must always be journaled")
        #expect(filter.shouldDrop(event: chatterEvent(at: 1_700_000_010)))
        #expect(filter.shouldDrop(event: chatterEvent(at: 1_700_000_200)))
        #expect(filter.counters.duplicateSnapshot() == 2)
    }

    @Test("The window lapses: a repeat after expiry becomes a fresh exemplar")
    func windowExpiryReadmits() {
        let filter = windowFilter()
        #expect(!filter.shouldDrop(event: chatterEvent(at: 1_700_000_000)))
        #expect(!filter.shouldDrop(event: chatterEvent(at: 1_700_000_301)),
                "past the window the same tuple is a new forensic fact")
    }

    @Test("Non-platform binaries are never deduplicated")
    func nonPlatformAlwaysExact() {
        // Adversary tooling is by definition not platform-signed. Every
        // occurrence journals exactly, no matter how repetitive.
        let filter = windowFilter()
        for i in 0..<5 {
            #expect(!filter.shouldDrop(event: chatterEvent(
                name: "implant", executable: "/tmp/implant",
                platform: false, at: 1_700_000_000 + Double(i)
            )))
        }
    }

    @Test("TCC and network events are never deduplicated")
    func highSignalCategoriesAlwaysExact() {
        let filter = windowFilter()
        for i in 0..<3 {
            #expect(!filter.shouldDrop(event: chatterEvent(
                category: .network, action: "connect",
                at: 1_700_000_000 + Double(i), destinationIp: "203.0.113.7"
            )), "every network flow is high-signal per-instance")
        }
        for i in 0..<3 {
            #expect(!filter.shouldDrop(event: chatterEvent(
                category: .tcc, action: "tcc_decision",
                at: 1_700_000_000 + Double(i)
            )), "every TCC decision is high-signal per-instance")
        }
    }

    @Test("Distinct tuples do not suppress each other")
    func distinctTuplesIndependent() {
        let filter = windowFilter()
        #expect(!filter.shouldDrop(event: chatterEvent(name: "bluetoothd", executable: "/usr/sbin/bluetoothd")))
        #expect(!filter.shouldDrop(event: chatterEvent(name: "secd", executable: "/usr/libexec/secd")))
        #expect(!filter.shouldDrop(event: chatterEvent(action: "exit")))
    }

    @Test("Capacity eviction fails open: novel events are never lost")
    func capacityFailsOpen() {
        let filter = EventInsertFilter(
            duplicateWindowSeconds: 300,
            duplicateWindowCapacity: 16
        )
        // Flood far past capacity with distinct tuples; every one is novel and
        // every one must pass. Eviction may forget old exemplars (admitting an
        // extra exemplar later) but must never suppress a first occurrence.
        for i in 0..<200 {
            #expect(!filter.shouldDrop(event: chatterEvent(
                name: "daemon\(i)", executable: "/usr/sbin/daemon\(i)",
                at: 1_700_000_000 + Double(i)
            )))
        }
    }

    @Test("The default filter enables the window; bare init does not")
    func defaultEnablesWindow() {
        #expect(EventInsertFilter.defaultFilter(
            supportDir: "/Library/Application Support/MacCrab"
        ).duplicateWindow != nil)
        // The v1.8.0 identity contract for a bare filter is preserved.
        #expect(EventInsertFilter().duplicateWindow == nil)
    }
}
