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

    @Test("The auth gate can evaluate a FIFO's owner without opening it")
    func ownerGateNeverOpensFifo() throws {
        // The reordered handlers call requestOwnerUID (lstat, no open) FIRST, so
        // a wrong-uid FIFO is rejected before any content read. Prove the owner
        // check itself never opens/blocks on a FIFO: lstat reports its owner.
        let dir = try tempDir()
        defer { try? FileManager.default.removeItem(atPath: dir) }
        let fifo = dir + "/suppress-alert-y.json"
        try #require(mkfifo(fifo, 0o644) == 0)
        #expect(DaemonTimers.requestOwnerUID(at: fifo) == Int(getuid()))
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
}

/// Thread-safe holder for a value produced on a detached thread and read back
/// on the test thread after the semaphore signals (used by `fifoNeverBlocks`).
private final class ReadIdResultBox: @unchecked Sendable {
    private let lock = NSLock()
    private var value: String?
    func set(_ v: String?) { lock.lock(); value = v; lock.unlock() }
    func get() -> String? { lock.lock(); defer { lock.unlock() }; return value }
}
