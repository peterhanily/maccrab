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
