// SFTPBatchScriptTests.swift
// v1.22.1: the `sftp -b` batch script used to be built by interpolating the
// operator's remotePath straight into `put <local> <remote>`. The batch
// language is line-oriented, so a path carrying a newline, a quote or a
// control character could append further commands to a root-run sftp
// session. Paths are now validated against a conservative allow-list and
// double-quoted, and the sink refuses a remotePath it cannot carry.
//
// The retain-and-retry half: a failed upload used to drop its batch. It is
// now kept (bounded, oldest-drop) and retried on the next flush behind an
// exponential backoff. Exercised through an injected runner so no server or
// `sftp` process is needed.

import Foundation
import Testing
@testable import MacCrabCore

@Suite("SFTPOutput: batch-script quoting and validation")
struct SFTPBatchScriptTests {

    @Test("Ordinary directory paths are representable and double-quoted")
    func ordinaryPathsAreQuoted() {
        for path in [
            "/srv/maccrab/alerts",
            "~/drops",
            "/var/log/MacCrab Alerts",
            "alerts_2026-09.d",
            "/home/terrance/in+box@site:1,2",
        ] {
            #expect(SFTPBatchScript.isRepresentable(path), "\(path) should be allowed")
            #expect(SFTPBatchScript.quoted(path) == "\"\(path)\"")
        }
    }

    @Test("Newlines, quotes, control characters and shell metacharacters are rejected")
    func injectionShapesAreRejected() {
        for path in [
            "/srv/x\nrm -rf /",           // second batch command
            "/srv/x\r\n!sh",              // CRLF + batch shell escape
            "/srv/x\tget /etc/passwd",    // tab
            "/srv/x\" \"/etc",            // closes our quote
            "/srv/x\\n",                  // backslash escape
            "/srv/x!",                    // `!` runs a local shell in sftp
            "/srv/x#comment",             // batch comment marker
            "/srv/$HOME",
            "/srv/`id`",
            "/srv/x;bye",
            "/srv/*",
            "/srv/x|y",
            "/srv/x\u{0}",
            "/srv/caf\u{e9}",             // non-ASCII is outside the allow-list
            "",
            String(repeating: "a", count: SFTPBatchScript.maximumPathLength + 1),
        ] {
            #expect(!SFTPBatchScript.isRepresentable(path), "\(path.debugDescription) must be rejected")
            #expect(SFTPBatchScript.quoted(path) == nil)
        }
    }

    @Test("The batch script quotes both paths and ends with bye")
    func buildQuotesEveryPath() throws {
        let script = try #require(SFTPBatchScript.build(
            localPath: "/private/tmp/maccrab-1-ABCDEF01.jsonl",
            remotePath: "/srv/MacCrab Alerts",
            localName: "maccrab-1-ABCDEF01.jsonl"
        ))
        #expect(script == """
            put "/private/tmp/maccrab-1-ABCDEF01.jsonl" "/srv/MacCrab Alerts/maccrab-1-ABCDEF01.jsonl"
            bye
            """)
    }

    @Test("A path that cannot be carried safely yields no script at all")
    func buildRefusesUnsafePaths() {
        #expect(SFTPBatchScript.build(
            localPath: "/private/tmp/a.jsonl", remotePath: "/srv\nrm -rf /", localName: "a.jsonl"
        ) == nil, "an unsafe remote path must never fall back to unquoted interpolation")
        #expect(SFTPBatchScript.build(
            localPath: "/tmp/with\"quote.jsonl", remotePath: "/srv", localName: "a.jsonl"
        ) == nil)
    }
}

// MARK: - Actor behaviour through an injected runner

/// Records every sftp invocation and captures the batch script and payload
/// at the moment they are handed to the runner (both are deleted afterwards).
private final class SFTPRunnerRecorder: @unchecked Sendable {
    struct Invocation {
        let arguments: [String]
        let batchScript: String
        let payload: Data
    }
    private let lock = NSLock()
    private var invocations: [Invocation] = []
    private var outcomes: [Bool]

    /// `outcomes` are consumed in order; the last one repeats.
    init(outcomes: [Bool]) { self.outcomes = outcomes }

    var runner: SFTPOutput.BatchRunner {
        { [self] arguments in
            let batchPath = arguments.firstIndex(of: "-b").map { arguments[$0 + 1] } ?? ""
            let script = (try? String(contentsOfFile: batchPath, encoding: .utf8)) ?? ""
            // put "<local>" "<remote>"
            var payload = Data()
            if let firstQuote = script.firstIndex(of: "\""),
               let closing = script[script.index(after: firstQuote)...].firstIndex(of: "\"") {
                let localPath = String(script[script.index(after: firstQuote)..<closing])
                payload = (try? Data(contentsOf: URL(fileURLWithPath: localPath))) ?? Data()
            }
            lock.lock()
            defer { lock.unlock() }
            invocations.append(Invocation(arguments: arguments, batchScript: script, payload: payload))
            let succeeded = outcomes.count > 1 ? outcomes.removeFirst() : (outcomes.first ?? false)
            return BoundedPrivilegedProcessRunner.Result(
                terminationStatus: succeeded ? 0 : 1,
                output: succeeded ? Data() : Data("ssh: connect to host: Connection refused".utf8),
                timedOut: false,
                outputLimitExceeded: false
            )
        }
    }

    var recorded: [Invocation] {
        lock.lock()
        defer { lock.unlock() }
        return invocations
    }
}

@Suite("SFTPOutput: retain-and-retry through the injected runner")
struct SFTPOutputRetryTests {

    private func alert(_ id: String) -> Alert {
        Alert(
            id: id,
            timestamp: Date(timeIntervalSince1970: 1_712_500_000),
            ruleId: "rule.test", ruleTitle: "Test",
            severity: .high, eventId: UUID().uuidString,
            description: "test", mitreTactics: "TA0005", mitreTechniques: "T1562"
        )
    }

    private func makeOutput(
        remotePath: String = "/srv/MacCrab Alerts",
        maxRetainedRecords: Int = 10_000,
        recorder: SFTPRunnerRecorder
    ) -> SFTPOutput {
        SFTPOutput(
            host: "sftp.example.invalid",
            user: "terrance",
            privateKeyPath: "/var/empty/id_ed25519",
            remotePath: remotePath,
            maxRetainedRecords: maxRetainedRecords,
            runner: recorder.runner
        )
    }

    @Test("A rejected remotePath disables the sink: alerts are dropped and sftp is never run")
    func rejectedRemotePathNeverReachesSFTP() async {
        let recorder = SFTPRunnerRecorder(outcomes: [true])
        let out = makeOutput(remotePath: "/srv/x\nrm -rf /", recorder: recorder)
        await out.send(alert: alert("a"), event: nil)
        await out.flush()
        let stats = await out.outputStats()
        #expect(stats.dropped == 1)
        #expect(stats.sent == 0 && stats.failed == 0)
        #expect(recorder.recorded.isEmpty, "no batch script may be produced for an unsafe path")
        #expect(await out.bufferedRecordCount == 0)
    }

    @Test("The live batch script is quoted and the temp files are removed afterwards")
    func liveScriptIsQuotedAndCleanedUp() async throws {
        let recorder = SFTPRunnerRecorder(outcomes: [true])
        let out = makeOutput(recorder: recorder)
        await out.send(alert: alert("a"), event: nil)
        await out.flush()

        let invocation = try #require(recorder.recorded.first)
        let lines = invocation.batchScript.split(separator: "\n", omittingEmptySubsequences: false)
        #expect(lines.count == 2)
        #expect(lines.last == "bye")
        let put = String(lines[0])
        #expect(put.hasPrefix("put \""))
        #expect(put.contains("\" \"/srv/MacCrab Alerts/maccrab-"))
        #expect(put.hasSuffix(".jsonl\""))
        #expect(put.filter { $0 == "\"" }.count == 4, "both paths are double-quoted exactly once")
        #expect(invocation.arguments.contains("StrictHostKeyChecking=yes"))
        #expect(invocation.arguments.last == "terrance@sftp.example.invalid")

        // One NDJSON line per alert reached the payload file.
        #expect(invocation.payload.split(separator: 0x0A).count == 1)

        // Temp batch + payload are gone once the upload returns.
        let batchPath = try #require(
            invocation.arguments.firstIndex(of: "-b").map { invocation.arguments[$0 + 1] }
        )
        #expect(!FileManager.default.fileExists(atPath: batchPath))

        let stats = await out.outputStats()
        #expect(stats.sent == 1 && stats.failed == 0 && stats.dropped == 0)
        #expect(await out.bufferedRecordCount == 0)
    }

    @Test("A failed upload keeps its batch and the next flush retries the same bytes after backoff")
    func failedUploadIsRetainedAndRetried() async throws {
        let recorder = SFTPRunnerRecorder(outcomes: [false, true])
        let out = makeOutput(recorder: recorder)
        await out.send(alert: alert("first"), event: nil)
        await out.send(alert: alert("second"), event: nil)

        let t0 = Date(timeIntervalSince1970: 1_800_000_000)
        await out.uploadBuffer(now: t0)
        var stats = await out.outputStats()
        #expect(stats.failed == 2, "the whole batch is counted failed")
        #expect(stats.sent == 0)
        #expect(stats.lastError?.contains("Connection refused") == true)
        #expect(await out.bufferedRecordCount == 2, "the batch is retained, not dropped")
        #expect(recorder.recorded.count == 1)

        // First backoff is one second: an immediate flush must not re-run sftp.
        await out.uploadBuffer(now: t0.addingTimeInterval(0.5))
        #expect(recorder.recorded.count == 1, "flush inside the backoff window is skipped")
        #expect(await out.bufferedRecordCount == 2)

        // Past the backoff the retained batch is retried byte-for-byte.
        await out.uploadBuffer(now: t0.addingTimeInterval(2))
        #expect(recorder.recorded.count == 2)
        let first = try #require(recorder.recorded.first)
        let retry = try #require(recorder.recorded.last)
        #expect(retry.payload == first.payload, "the retry carries the retained batch unchanged")
        #expect(retry.payload.split(separator: 0x0A).count == 2)

        stats = await out.outputStats()
        #expect(stats.sent == 2)
        #expect(stats.failed == 2, "the earlier failure is not rewritten")
        #expect(stats.dropped == 0)
        #expect(await out.bufferedRecordCount == 0)

        // A success clears the backoff: a new batch flushes immediately.
        await out.send(alert: alert("third"), event: nil)
        await out.uploadBuffer(now: t0.addingTimeInterval(2))
        #expect(recorder.recorded.count == 3)
    }

    @Test("Retention is bounded: the oldest records are dropped and counted")
    func retentionIsBoundedOldestFirst() async {
        let recorder = SFTPRunnerRecorder(outcomes: [false])
        let out = makeOutput(maxRetainedRecords: 2, recorder: recorder)
        await out.send(alert: alert("a"), event: nil)
        await out.send(alert: alert("b"), event: nil)
        await out.send(alert: alert("c"), event: nil)
        var stats = await out.outputStats()
        #expect(stats.dropped == 1, "the third append evicts the oldest")
        #expect(await out.bufferedRecordCount == 2)

        let t0 = Date(timeIntervalSince1970: 1_800_000_000)
        await out.uploadBuffer(now: t0)
        stats = await out.outputStats()
        #expect(stats.failed == 2)
        #expect(await out.bufferedRecordCount == 2, "a failed batch under the cap is kept whole")

        // Records arriving while the sink is down push the retained batch out
        // oldest-first rather than growing without bound.
        await out.send(alert: alert("d"), event: nil)
        stats = await out.outputStats()
        #expect(stats.dropped == 2)
        #expect(await out.bufferedRecordCount == 2)
    }
}
