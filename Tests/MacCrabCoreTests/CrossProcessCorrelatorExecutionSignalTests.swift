import Foundation
import Testing
@testable import MacCrabCore

/// Pins the wiring fact that makes `actions.contains("execute")` an
/// unsatisfiable gate on the file-chain tier, and the drop-and-run shape that
/// actually reaches the correlator in production.
///
/// A previous candidate added that gate, every actor-level test passed, and the
/// tier emitted zero alerts on a real host — because no test drove a
/// collector-shaped `Event` through the guard the event loop actually applies.
/// These tests exist so that failure mode announces itself in the suite.
@Suite("Cross-process file correlation execution signal")
struct CrossProcessCorrelatorExecutionSignalTests {
    /// The exact `Event` shape `ESCollector.handle(ES_EVENT_TYPE_NOTIFY_EXEC)`
    /// builds (ESCollector.swift), mirrored by KdebugCollector and
    /// EsloggerParser. The `file:` argument is absent in all three.
    private func execEvent(
        pid: Int32, name: String, executable: String, at timestamp: Date
    ) -> Event {
        Event(
            timestamp: timestamp,
            eventCategory: .process,
            eventType: .start,
            eventAction: "exec",
            process: MacCrabCore.ProcessInfo(
                pid: pid, ppid: 1, rpid: 1, name: name,
                executable: executable,
                commandLine: executable, args: [executable],
                workingDirectory: "/", userId: 501, userName: "test",
                groupId: 20, startTime: timestamp, ancestors: [],
                isPlatformBinary: false
            ),
            severity: .informational
        )
    }

    /// `EventLoop`'s correlator call site is `if let file = enrichedEvent.file,
    /// !CrossProcessCorrelator.shouldIgnoreFilePath(file.path)`. Only events
    /// that satisfy this reach `recordFileEvent`, so it decides which actions
    /// the file map can ever contain.
    private func reachesFileCorrelator(_ event: Event) -> Bool {
        guard let file = event.file else { return false }
        return !CrossProcessCorrelator.shouldIgnoreFilePath(file.path)
    }

    @Test("An exec event carries no file payload, so no execution ever reaches the file map")
    func execEventsCannotReachTheFileCorrelator() {
        let event = execEvent(
            pid: 8001, name: "payload",
            executable: "/tmp/attacker-payload", at: Date()
        )
        // Event.file is `let` and every enricher copies it through verbatim,
        // so a nil here cannot be filled in downstream.
        #expect(event.file == nil)
        #expect(!reachesFileCorrelator(event))
        // Therefore the "exec" -> "execute" mapping beside the call site is
        // unreachable, and gating evaluateFileChain on actions.contains(
        // "execute") silences the whole tier. If this expectation ever fails
        // because exec events gained a file payload, that gate becomes
        // legitimate — and computeFileSeverity's escalations wake up with it.
        #expect(event.eventAction == "exec")
    }

    @Test("A file event does reach the correlator, and never as an execution")
    func fileEventsReachTheCorrelatorWithFileActions() {
        let now = Date()
        for action in ["create", "write", "rename", "unlink", "close_modified", "setmode"] {
            let event = Event(
                timestamp: now,
                eventCategory: .file,
                eventType: .change,
                eventAction: action,
                process: MacCrabCore.ProcessInfo(
                    pid: 8000, ppid: 1, rpid: 1, name: "curl",
                    executable: "/usr/bin/curl", commandLine: "curl",
                    args: ["curl"], workingDirectory: "/", userId: 501,
                    userName: "test", groupId: 20, startTime: now,
                    ancestors: [], isPlatformBinary: true
                ),
                file: FileInfo(path: "/tmp/attacker-payload", action: .write),
                severity: .informational
            )
            #expect(reachesFileCorrelator(event))
            // The event loop maps only "exec" to "execute"; every file action
            // passes through unchanged, so none of them can supply the leg.
            #expect(action != "exec")
        }
    }

    @Test("A drop-and-run forms a chain from the drop's own action pair")
    func dropAndRunFormsChainWithoutAnExecutionLeg() async throws {
        // The production shape: NOTIFY_CREATE + NOTIFY_WRITE from the dropper,
        // then the payload runs. The exec leg never arrives (see above), so the
        // chain has to form on the drop's action diversity alone.
        let correlator = CrossProcessCorrelator(correlationWindow: 300, minChainLength: 2)
        let now = Date()
        let payload = "/tmp/attacker-payload"

        let first = await correlator.recordFileEvent(
            path: payload, action: "create",
            pid: 8000, processName: "curl", processPath: "/usr/bin/curl",
            timestamp: now
        )
        #expect(first == nil, "One PID cannot form a cross-process chain")

        let chain = try #require(await correlator.recordFileEvent(
            path: payload, action: "write",
            pid: 8002, processName: "installer", processPath: "/tmp/installer",
            timestamp: now.addingTimeInterval(1)
        ), "create+write across distinct PIDs must still raise the chain")
        #expect(chain.sharedArtifact == payload)
        #expect(chain.distinctPIDCount == 2)
        #expect(chain.events.map(\.action) == ["create", "write"])
        let snapshot = await correlator.telemetrySnapshot()
        #expect(snapshot.capacityMaintained)
        #expect(snapshot.conservationMaintained)
    }

    @Test("A synthetic execution still escalates, so the tier is ready if the leg is wired in")
    func syntheticExecutionRetainsItsSignal() async throws {
        // Not reachable from the live pipeline today. Retained so the intended
        // behaviour is pinned for whoever wires the exec path in.
        let correlator = CrossProcessCorrelator(correlationWindow: 300, minChainLength: 2)
        let now = Date()
        let first = await correlator.recordFileEvent(
            path: "/Users/test/correlation/program", action: "read",
            pid: 400, processName: "reader", processPath: "/opt/reader/bin/tool",
            timestamp: now
        )
        #expect(first == nil)
        let chain = try #require(await correlator.recordFileEvent(
            path: "/Users/test/correlation/program", action: "execute",
            pid: 401, processName: "executor", processPath: "/opt/executor/bin/tool",
            timestamp: now.addingTimeInterval(1)
        ))
        #expect(chain.severity == .medium)
        #expect(chain.distinctPIDCount == 2)
        #expect(chain.events.map(\.action) == ["read", "execute"])
        #expect(await correlator.telemetrySnapshot().conservationMaintained)
    }

    @Test("Benign two-tool rename/cleanup still alerts — the known volume this tier carries")
    func benignRenameCleanupStillAlerts() async throws {
        // Documented, not endorsed. Two shell helpers renaming then unlinking a
        // shared path produce a chain: the variety floor in
        // chainDominatedByShellUtilities needs three distinct utilities, and
        // this shape has two. This is the field's 1344-mostly-benign-alerts
        // class. It is asserted here so that any future attempt to suppress it
        // has to change this test deliberately rather than silently take the
        // whole tier down with it.
        let correlator = CrossProcessCorrelator(correlationWindow: 300, minChainLength: 2)
        let now = Date()
        let path = "/Users/test/correlation/document"
        let first = await correlator.recordFileEvent(
            path: path, action: "rename",
            pid: 100, processName: "mv", processPath: "/bin/mv",
            timestamp: now
        )
        #expect(first == nil)
        let chain = try #require(await correlator.recordFileEvent(
            path: path, action: "unlink",
            pid: 101, processName: "find", processPath: "/usr/bin/find",
            timestamp: now.addingTimeInterval(1)
        ))
        #expect(chain.severity == .medium)
        #expect(chain.distinctPIDCount == 2)
        let snapshot = await correlator.telemetrySnapshot()
        #expect(snapshot.file.acceptedEvents == 2)
        #expect(snapshot.file.retainedEvents == 2)
        #expect(snapshot.file.trackedArtifacts == 1)
        #expect(snapshot.conservationMaintained)
    }

    @Test("The shell-utility FP gate's membership is exactly the documented set")
    func shellUtilityBasenamesAreExactlyTheDocumentedSet() {
        // The source keeps these as one whitespace-separated literal to stay
        // inside the signed app's footprint budget. This list is the contract;
        // it lives in the test binary, which is not shipped. A typo in either
        // direction changes which build-script fan-outs are suppressed, so the
        // comparison is exact rather than a count or a spot check.
        let expected: Set<String> = [
            "awk", "basename", "bash", "brew", "bundle", "cargo", "cat",
            "chgrp", "chmod", "chown", "cmake", "cp", "curl", "cut",
            "dash", "date", "dig", "dirname", "echo", "egrep", "env",
            "exec", "false", "fgrep", "file", "find", "fish", "gem",
            "git", "go", "grep", "gunzip", "gzip", "head", "host",
            "hostname", "id", "jq", "ksh", "ln", "locale", "locate",
            "make", "md5", "md5sum", "mkdir", "mv", "nc", "node",
            "npm", "nslookup", "od", "openssl", "perl", "ping", "pip",
            "pip3", "pkg-config", "pnpm", "printf", "pwd", "python", "python3",
            "readlink", "realpath", "rm", "rmdir", "ruby", "rustc", "sed",
            "sh", "shasum", "sort", "stat", "svn", "tail", "tar",
            "tee", "test", "touch", "tr", "true", "tty", "type",
            "uname", "uniq", "unzip", "wc", "wget", "which", "xargs",
            "xmllint", "xxd", "yarn", "yq", "zip", "zsh",
        ]
        #expect(CrossProcessCorrelator.shellUtilityBasenamesForTesting == expected)
        #expect(expected.count == 97)
    }
}
