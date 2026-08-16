// InboxGateTests.swift
// MacCrabCoreTests
//
// The privileged inbox IPC auth gate. The inbox dir is mode 1777 (any local
// user can drop a request file), so the daemon must (a) refuse symlinked /
// hardlinked request files that forge root ownership, (b) accept only root or
// the GUI console user, and (c) sanitize attacker-controlled fields before
// they hit the audit log. Without these a standard/guest user could blind the
// EDR by suppressing or deleting alerts. These were fully private + untested.

import Testing
import Foundation
@testable import MacCrabAgentKit

@Suite("Inbox IPC auth gate")
struct InboxGateTests {

    private func tempDir() throws -> String {
        let dir = NSTemporaryDirectory() + "maccrab-inboxgate-\(UUID().uuidString)"
        try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        return dir
    }

    // MARK: - sanitizeAuditField (audit-log injection)

    @Test("Neutralizes newline/CR audit-line forgery")
    func sanitizeNewlineForgery() {
        // A request id of `uuid\nresult=ok uid=0` would forge a fake success line.
        let out = DaemonTimers.sanitizeAuditField("valid-uuid\nresult=ok uid=0")
        #expect(!out.contains("\n"))
        #expect(!out.contains("\r"))
        #expect(out == "valid-uuid_result=ok uid=0")
    }

    @Test("Replaces control + non-ASCII, caps length, passes clean UUIDs")
    func sanitizeControlAndLength() {
        #expect(DaemonTimers.sanitizeAuditField("a\u{07}b") == "a_b")    // bell (control)
        #expect(DaemonTimers.sanitizeAuditField("caf\u{00E9}") == "caf?") // non-ASCII
        #expect(DaemonTimers.sanitizeAuditField(String(repeating: "x", count: 200), max: 128).count == 128)
        #expect(DaemonTimers.sanitizeAuditField("3F2504E0-4F89-41D3-9A0C-0305E82C3301")
                == "3F2504E0-4F89-41D3-9A0C-0305E82C3301")
    }

    // MARK: - requestOwnerUID (symlink / hardlink forgery)

    @Test("Regular file reports its real owner uid")
    func ownerOfRegularFile() throws {
        let dir = try tempDir()
        defer { try? FileManager.default.removeItem(atPath: dir) }
        let file = dir + "/req.json"
        try "{}".write(toFile: file, atomically: true, encoding: .utf8)
        #expect(DaemonTimers.requestOwnerUID(at: file) == Int(getuid()))
    }

    @Test("Symlink is rejected outright (-1) — the v1.11.0 forgery fix")
    func rejectsSymlink() throws {
        let dir = try tempDir()
        defer { try? FileManager.default.removeItem(atPath: dir) }
        let target = dir + "/real.json"
        try "{}".write(toFile: target, atomically: true, encoding: .utf8)
        let link = dir + "/req.json"
        try FileManager.default.createSymbolicLink(atPath: link, withDestinationPath: target)
        #expect(DaemonTimers.requestOwnerUID(at: link) == -1)
        // A symlink to a root-owned file must NOT forge root ownership.
        let rootLink = dir + "/req2.json"
        try FileManager.default.createSymbolicLink(atPath: rootLink, withDestinationPath: "/etc/hosts")
        #expect(DaemonTimers.requestOwnerUID(at: rootLink) == -1)
    }

    @Test("Hardlinked file is rejected (-1) — st_nlink > 1")
    func rejectsHardlink() throws {
        let dir = try tempDir()
        defer { try? FileManager.default.removeItem(atPath: dir) }
        let original = dir + "/orig.json"
        try "{}".write(toFile: original, atomically: true, encoding: .utf8)
        let hardlink = dir + "/req.json"
        try FileManager.default.linkItem(atPath: original, toPath: hardlink)
        #expect(DaemonTimers.requestOwnerUID(at: hardlink) == -1)
    }

    @Test("Nonexistent path returns -1")
    func nonexistentPath() {
        #expect(DaemonTimers.requestOwnerUID(at: "/nonexistent/\(UUID().uuidString)/x.json") == -1)
    }

    // MARK: - isAuthorizedInboxRequest (uid gate)

    @Test("Root authorized; stat-failure and a non-console uid rejected")
    func authGate() {
        #expect(DaemonTimers.isAuthorizedInboxRequest(uid: 0))            // root
        #expect(DaemonTimers.isAuthorizedInboxRequest(uid: -1) == false)  // stat failed
        #expect(DaemonTimers.isAuthorizedInboxRequest(uid: 99999) == false) // not root, not console
    }

    // MARK: - readIdRequest local-DoS hardening (v1.21.4 audit HIGH)
    //
    // The inbox dir is mode 1777 so any local user can plant a hostile dir entry
    // under a correctly-named request file. Before the fix, `readIdRequest` did
    // a plain `Data(contentsOf:)`, which (A) blocks the poller forever on a FIFO
    // — permanently wedging the privileged control plane — and (B) reads a
    // multi-GB file wholesale, OOMing the daemon. The gate must reject each
    // WITHOUT reading contents and WITHOUT blocking.

    @Test("FIFO request file is rejected promptly — never blocks the poller")
    func fifoNeverBlocks() throws {
        let dir = try tempDir()
        defer { try? FileManager.default.removeItem(atPath: dir) }
        let fifo = dir + "/suppress-alert-x.json"
        try #require(mkfifo(fifo, 0o644) == 0)

        // Run the (potentially blocking) read on a detached thread and wait on a
        // semaphore with a timeout. With the O_NONBLOCK fix the writer-less FIFO
        // is rejected in microseconds → .success. A regression that reverted to
        // a blocking open would hang the thread forever → .timedOut fails HERE
        // instead of wedging the whole daemon (and the whole test suite).
        let done = DispatchSemaphore(value: 0)
        let box = ReadIdResultBox()
        Thread.detachNewThread {
            box.set(DaemonTimers.readIdRequest(at: fifo))
            done.signal()
        }
        let outcome = done.wait(timeout: .now() + 5)
        #expect(outcome == .success)   // returned promptly, did NOT block
        #expect(box.get() == nil)      // FIFO is not a regular file → rejected
    }

    @Test("Oversized but well-formed request is rejected before reading it in")
    func oversizedRejected() throws {
        let dir = try tempDir()
        defer { try? FileManager.default.removeItem(atPath: dir) }
        let big = dir + "/suppress-alert-big.json"
        // Valid JSON whose id is > 64 KB: WITHOUT the size cap this parses and
        // returns the huge id; WITH the cap the file is rejected (nil) via the
        // fstat size gate before the bytes are pulled into memory.
        let hugeId = String(repeating: "A", count: 100 * 1024)
        try "{\"id\":\"\(hugeId)\"}".write(toFile: big, atomically: true, encoding: .utf8)
        #expect(DaemonTimers.readIdRequest(at: big) == nil)
    }

    @Test("safeReadInboxData honors a larger explicit cap (M1: clipboard reader)")
    func explicitLargerCapReadsPast64KB() throws {
        let dir = try tempDir()
        defer { try? FileManager.default.removeItem(atPath: dir) }
        let path = dir + "/record-clipboard-big.json"
        // A legit 100 KB clipboard record — larger than the 64 KB DEFAULT cap
        // because ClickFix payloads are grapheme-bounded, not byte-bounded.
        let payload = String(repeating: "x", count: 100 * 1024)
        let json = "{\"payload\":\"\(payload)\"}"
        try json.write(toFile: path, atomically: true, encoding: .utf8)
        // Default 64 KB cap rejects it (this was the M1 evasion).
        #expect(DaemonTimers.safeReadInboxData(at: path) == nil)
        // The clipboard reader's 4 MB cap reads it in full.
        let data = DaemonTimers.safeReadInboxData(at: path, maxBytes: 4 * 1024 * 1024)
        #expect(data != nil)
        #expect(data?.count == json.utf8.count)
    }

    @Test("Symlinked request file is refused at open (O_NOFOLLOW)")
    func symlinkRefused() throws {
        let dir = try tempDir()
        defer { try? FileManager.default.removeItem(atPath: dir) }
        let target = dir + "/real.json"
        try "{\"id\":\"abc\"}".write(toFile: target, atomically: true, encoding: .utf8)
        let link = dir + "/suppress-alert-link.json"
        try FileManager.default.createSymbolicLink(atPath: link, withDestinationPath: target)
        #expect(DaemonTimers.readIdRequest(at: link) == nil)
    }

    @Test("The owner gate rejects FIFOs and directories as non-regular")
    func ownerGateRejectsNonRegularEntries() throws {
        // lstat never opens the FIFO, but ownership alone is insufficient: a
        // FIFO owned by the authorized console uid must still be rejected before
        // any handler attempts a content read.
        let dir = try tempDir()
        defer { try? FileManager.default.removeItem(atPath: dir) }
        let fifo = dir + "/suppress-alert-y.json"
        try #require(mkfifo(fifo, 0o644) == 0)
        #expect(DaemonTimers.requestOwnerUID(at: fifo) == -1)

        let nested = dir + "/suppress-alert-dir.json"
        try FileManager.default.createDirectory(atPath: nested, withIntermediateDirectories: false)
        #expect(DaemonTimers.requestOwnerUID(at: nested) == -1)
    }

    @Test("Small well-formed request still parses (happy path intact)")
    func validSmallRequestParses() throws {
        let dir = try tempDir()
        defer { try? FileManager.default.removeItem(atPath: dir) }
        let file = dir + "/suppress-alert-ok.json"
        try "{\"id\":\"3F2504E0-4F89-41D3-9A0C-0305E82C3301\"}"
            .write(toFile: file, atomically: true, encoding: .utf8)
        #expect(DaemonTimers.readIdRequest(at: file) == "3F2504E0-4F89-41D3-9A0C-0305E82C3301")
    }

    // MARK: - Every arbitrary-JSON request shape uses the bounded reader

    /// Hardcoded independently from production so a newly introduced handler
    /// must be deliberately added to both the cap policy and this adversarial
    /// corpus. The four id handlers share `readIdRequest`; every other shape
    /// parses an arbitrary JSON dictionary directly.
    private static let jsonRequestShapes: [(handler: String, prefix: String, idBased: Bool)] = [
        ("handleSuppressAlertRequests", "suppress-alert-", true),
        ("handleUnsuppressAlertRequests", "unsuppress-alert-", true),
        ("handleDeleteAlertRequests", "delete-alert-", true),
        ("handleSuppressCampaignRequests", "suppress-campaign-", true),
        ("handleLLMConfigRequests", "llm-config-", false),
        ("handleRecordClipboardRequests", "record-clipboard-", false),
        ("handleBuiltinRuleSettingRequests", "builtin-rule-setting-", false),
        ("handleSetDaemonConfigRequests", "set-daemon-config-", false),
        ("handleInstallRuleRequests", "install-rule-", false),
        ("handleRemoveRuleRequests", "remove-rule-", false),
        ("handleSetAgentCapabilitiesRequests", "set-agent-capabilities-", false),
        ("handlePruneAlertsRequests", "prune-alerts-", false),
        ("handleApplyAgentTracesRequests", "apply-agent-traces-", false),
        ("handleTraceDashboardKeyRequests", "trace-dashboard-key-", false),
        ("handlePreventionConfigRequests", "prevention-config-", false),
    ]

    @Test("Every arbitrary-JSON request shape rejects FIFO and oversized carriers")
    func allJSONShapesRejectFifoAndOversize() throws {
        let dir = try tempDir()
        defer { try? FileManager.default.removeItem(atPath: dir) }

        let noPayloadPrefixes: Set<String> = [
            "refresh-intel-", "reload-rules-", "flush-request-",
        ]
        let productionPayloadPrefixes = Set(DaemonTimers.knownInboxRequestPrefixes)
            .subtracting(noPayloadPrefixes)
        #expect(productionPayloadPrefixes == Set(Self.jsonRequestShapes.map(\.prefix)),
                "Inbox request-shape corpus drifted from the production poller")

        for shape in Self.jsonRequestShapes {
            let fifo = dir + "/\(shape.prefix)fifo.json"
            try #require(mkfifo(fifo, 0o600) == 0, "mkfifo failed for \(shape.prefix)")

            let done = DispatchSemaphore(value: 0)
            let result = ReadDataResultBox()
            Thread.detachNewThread {
                result.set(DaemonTimers.safeReadInboxRequestData(at: fifo) != nil)
                done.signal()
            }
            #expect(done.wait(timeout: .now() + 2) == .success,
                    "\(shape.prefix) FIFO read blocked")
            #expect(result.get() == false, "\(shape.prefix) accepted a FIFO")
            DaemonTimers.removeInboxEntry(at: fifo)

            let oversized = dir + "/\(shape.prefix)oversized.json"
            #expect(FileManager.default.createFile(atPath: oversized, contents: Data()))
            let cap = try #require(DaemonTimers.inboxRequestMaxBytes(
                for: URL(fileURLWithPath: oversized).lastPathComponent
            ))
            try #require(truncate(oversized, cap + 1) == 0,
                         "truncate failed for \(shape.prefix)")
            #expect(DaemonTimers.safeReadInboxRequestData(at: oversized) == nil,
                    "\(shape.prefix) accepted \(cap + 1) bytes past cap \(cap)")
            DaemonTimers.removeInboxEntry(at: oversized)
        }
    }

    @Test("Source guard: every JSON handler calls the hardened request reader")
    func everyJSONHandlerUsesSafeReader() throws {
        let repoRoot = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent() // MacCrabCoreTests
            .deletingLastPathComponent() // Tests
            .deletingLastPathComponent() // repo
        let sourceURL = repoRoot
            .appendingPathComponent("Sources/MacCrabAgentKit/DaemonTimers.swift")
        let source = try String(contentsOf: sourceURL, encoding: .utf8)

        #expect(!source.contains("contentsOfDirectory(atPath: inboxDir)"),
                "Inbox poller regressed to allocating the full directory listing")
        #expect(!source.contains("Data(contentsOf: URL(fileURLWithPath: path))"),
                "An inbox handler regressed to an unbounded raw request-file read")
        #expect(source.contains("O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC"),
                "Inbox request descriptors must be nonblocking, no-follow, and close-on-exec")
        #expect(source.contains("let scan = inboxScanBatch("),
                "Inbox poller no longer uses bounded streaming enumeration")
        #expect(source.contains("defer { state.inboxPollerLock.withLock { $0 = false } }"),
                "Inbox poller no longer releases inFlight on every early return")

        for (index, shape) in Self.jsonRequestShapes.enumerated() {
            let marker = "private static func \(shape.handler)("
            let start = try #require(source.range(of: marker),
                                     "missing handler \(shape.handler)")
            let tail = source[start.lowerBound...]
            let end: String.Index = {
                guard index + 1 < Self.jsonRequestShapes.count else {
                    return source.endIndex
                }
                // Handler declaration order differs from the adversarial table;
                // stop at the next private handler in source, not table order.
                let afterMarker = tail.index(start.lowerBound, offsetBy: marker.count)
                return source[afterMarker...].range(of: "\n    private static func handle")?.lowerBound
                    ?? source.endIndex
            }()
            let body = String(source[start.lowerBound..<end])
            let expected = shape.idBased
                ? "readIdRequest(at: path)"
                : "safeReadInboxRequestData(at: path)"
            #expect(body.contains(expected),
                    "\(shape.handler) does not use \(expected)")
        }
    }

    // MARK: - Bounded streaming enumeration and fairness

    @Test("More than 512 recent dotfiles cannot starve a valid request")
    func dotfileFloodMakesBoundedForwardProgress() throws {
        let dir = try tempDir()
        defer { try? FileManager.default.removeItem(atPath: dir) }
        let fm = FileManager.default

        // Recent temp files must be preserved (an atomic writer may still rename
        // one), yet the retained directory cursor must advance past the first
        // capped batch instead of restarting at them forever.
        for index in 0..<700 {
            #expect(fm.createFile(
                atPath: dir + "/.atomic-\(String(format: "%04d", index)).tmp",
                contents: Data("in-flight".utf8)
            ))
        }
        let validName = "suppress-alert-legitimate.json"
        try Data("{\"id\":\"legitimate\"}".utf8)
            .write(to: URL(fileURLWithPath: dir + "/" + validName))

        let scanner = DaemonTimers.InboxDirectoryScanner(path: dir)
        var observed = false
        for _ in 0..<3 {
            let batch = DaemonTimers.inboxScanBatch(
                scanner: scanner,
                inboxDir: dir,
                maxEntries: 512,
                temporaryFileGrace: 3_600
            )
            #expect(batch.examinedEntryCount <= 512)
            if batch.requestNames.contains(validName) { observed = true; break }
        }
        #expect(observed, "valid request remained hidden behind recent dotfiles")
        #expect(fm.fileExists(atPath: dir + "/.atomic-0000.tmp"),
                "recent atomic temp was deleted without its grace period")
    }

    @Test("Stale atomic temp and unclaimed entries are drained without recursion")
    func staleAndUnclaimedEntriesDrain() throws {
        let dir = try tempDir()
        defer { try? FileManager.default.removeItem(atPath: dir) }
        let fm = FileManager.default
        let stale = dir + "/.suppress-alert-stale.tmp"
        let junk = dir + "/never-claimed.bin"
        #expect(fm.createFile(atPath: stale, contents: Data()))
        #expect(fm.createFile(atPath: junk, contents: Data()))
        let now = Date()
        try fm.setAttributes(
            [.modificationDate: now.addingTimeInterval(-120)],
            ofItemAtPath: stale
        )

        let scanner = DaemonTimers.InboxDirectoryScanner(path: dir)
        let batch = DaemonTimers.inboxScanBatch(
            scanner: scanner,
            inboxDir: dir,
            maxEntries: 512,
            temporaryFileGrace: 60,
            now: now
        )
        #expect(batch.examinedEntryCount == 2)
        #expect(!fm.fileExists(atPath: stale))
        #expect(!fm.fileExists(atPath: junk))
    }
}

/// Thread-safe holder for a value produced on a detached thread and read back
/// on the test thread after the semaphore signals (used by `fifoNeverBlocks`).
private final class ReadIdResultBox: @unchecked Sendable {
    private let lock = NSLock()
    private var value: String?
    func set(_ v: String?) { lock.lock(); value = v; lock.unlock() }
    func get() -> String? { lock.lock(); defer { lock.unlock() }; return value }
}

private final class ReadDataResultBox: @unchecked Sendable {
    private let lock = NSLock()
    private var value = false
    func set(_ v: Bool) { lock.lock(); value = v; lock.unlock() }
    func get() -> Bool { lock.lock(); defer { lock.unlock() }; return value }
}
