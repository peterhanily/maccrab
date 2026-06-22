// TierBBrokeredTCCTests — the brokered-TCC path: TCC classification, the
// snapshot+redirect plan, and the load-bearing property proven end-to-end over a
// real socket: when a sandboxed plugin requests a live TCC-protected path, the
// broker serves the SNAPSHOT (never the live store), and a directory / missing
// TCC source is fail-closed (denied).

import Foundation
import CSQLCipher
import CTierBBroker
import Testing
@testable import MacCrabForensics

@Suite("Brokered TCC (snapshot + redirect)")
struct TierBBrokeredTCCTests {

    static func makeSourceDB(at path: String) throws {
        var db: OpaquePointer?
        guard sqlite3_open_v2(path, &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX, nil) == SQLITE_OK,
              let h = db else { throw NSError(domain: "test", code: 1) }
        defer { sqlite3_close(h) }
        _ = sqlite3_exec(h, "CREATE TABLE message (rowid INT, text TEXT)", nil, nil, nil)
        _ = sqlite3_exec(h, "INSERT INTO message VALUES (1, 'hello from chat.db')", nil, nil, nil)
    }

    /// A throwaway home dir with the given relative files materialised.
    static func makeHome(_ files: [String: String]) throws -> String {
        let home = NSTemporaryDirectory() + "tcc-home-\(UUID().uuidString)"
        for (rel, contents) in files {
            let full = home + "/" + rel
            try FileManager.default.createDirectory(atPath: (full as NSString).deletingLastPathComponent, withIntermediateDirectories: true)
            try contents.write(toFile: full, atomically: true, encoding: .utf8)
        }
        return home
    }

    // MARK: - Classifier

    @Test("TCCProtectedPaths: personal-comms + TCC.db are protected; Documents is not")
    func classifier() {
        let home = "/Users/x"
        #expect(TCCProtectedPaths.isProtected("/Users/x/Library/Messages/chat.db", home: home))
        #expect(TCCProtectedPaths.isProtected("/Users/x/Library/Messages", home: home))         // the prefix itself
        #expect(TCCProtectedPaths.isProtected("/Users/x/Library/Safari/History.db", home: home))
        #expect(TCCProtectedPaths.isProtected("/Library/Application Support/com.apple.TCC/TCC.db", home: home))
        #expect(!TCCProtectedPaths.isProtected("/Users/x/Documents/notes.txt", home: home))
        #expect(!TCCProtectedPaths.isProtected("/Users/x/Library/MessagesOther/x", home: home)) // not a component prefix
        // trailing slash on home is tolerated
        #expect(TCCProtectedPaths.isProtected("/Users/x/Library/Mail/foo", home: "/Users/x/"))
    }

    @Test("classifier is CASE-FOLDED: a lowercase 'library/messages' can't bypass on case-insensitive APFS")
    func classifierCaseInsensitive() {
        let home = "/Users/x"
        // The leak vector C1: lowercase/mixed-case manifest path the kernel still
        // resolves to the real Library/Messages — must still classify as TCC.
        #expect(TCCProtectedPaths.isProtected("/Users/x/library/Messages/chat.db", home: home))
        #expect(TCCProtectedPaths.isProtected("/Users/x/Library/MESSAGES/chat.db", home: home))
        #expect(TCCProtectedPaths.isProtected("/users/X/Library/Messages/chat.db", home: home))
    }

    @Test("classifier covers the added FDA/TCC stores (knowledgeC, Accounts, Biome, …)")
    func classifierExtendedPrefixes() {
        let home = "/Users/x"
        for p in ["/Users/x/Library/Application Support/Knowledge/knowledgeC.db",
                  "/Users/x/Library/Accounts/Accounts4.sqlite",
                  "/Users/x/Library/Biome/streams/x",
                  "/Users/x/Library/Daemon Containers/abc/Data/x"] {
            #expect(TCCProtectedPaths.isProtected(p, home: home), "should be TCC-protected: \(p)")
        }
    }

    // MARK: - Plan

    @Test("prepare: non-TCC read is a direct root; no snapshot")
    func planDirect() throws {
        let snapDir = URL(fileURLWithPath: NSTemporaryDirectory() + "snap-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: snapDir) }
        let home = try Self.makeHome(["Documents/notes.txt": "x"])
        defer { try? FileManager.default.removeItem(atPath: home) }
        let plan = BrokeredTCC.prepare(manifestReadPaths: [home + "/Documents/notes.txt"], snapshotDir: snapDir, home: home)
        #expect(plan.directReadRoots == [home + "/Documents/notes.txt"])
        #expect(plan.redirects.isEmpty)
        #expect(plan.denied.isEmpty)
    }

    @Test("prepare: a TCC SQLite source is snapshotted (backup API) and redirected")
    func planTCCDatabase() throws {
        let snapDir = URL(fileURLWithPath: NSTemporaryDirectory() + "snap-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: snapDir) }
        let home = NSTemporaryDirectory() + "tcc-home-\(UUID().uuidString)"
        let chat = home + "/Library/Messages/chat.db"
        try FileManager.default.createDirectory(atPath: (chat as NSString).deletingLastPathComponent, withIntermediateDirectories: true)
        try Self.makeSourceDB(at: chat)
        defer { try? FileManager.default.removeItem(atPath: home) }

        let plan = BrokeredTCC.prepare(manifestReadPaths: [chat], snapshotDir: snapDir, home: home)
        #expect(plan.directReadRoots.isEmpty)
        #expect(plan.denied.isEmpty)
        #expect(plan.redirects.count == 1)
        #expect(plan.redirects.first?.prefix == chat)
        // the snapshot exists, is plugin-unwritable, and is a real SQLite file
        let snapPath = plan.redirects.first!.to
        #expect(FileManager.default.fileExists(atPath: snapPath))
        let head = FileManager.default.contents(atPath: snapPath)?.prefix(15)
        #expect(head.map { Array($0) } == Array("SQLite format 3".utf8))
    }

    @Test("prepare: a TCC directory source and a missing TCC file are fail-closed (denied)")
    func planFailClosed() throws {
        let snapDir = URL(fileURLWithPath: NSTemporaryDirectory() + "snap-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: snapDir) }
        let home = NSTemporaryDirectory() + "tcc-home-\(UUID().uuidString)"
        try FileManager.default.createDirectory(atPath: home + "/Library/Mail", withIntermediateDirectories: true)  // a dir
        defer { try? FileManager.default.removeItem(atPath: home) }
        let plan = BrokeredTCC.prepare(
            manifestReadPaths: [home + "/Library/Mail", home + "/Library/Messages/nope.db"],
            snapshotDir: snapDir, home: home)
        #expect(plan.redirects.isEmpty)
        #expect(plan.directReadRoots.isEmpty)
        #expect(Set(plan.denied) == Set([home + "/Library/Mail", home + "/Library/Messages/nope.db"]))
    }

    // MARK: - Exact-file redirect resolution

    @Test("broker resolve: an exact-file redirect serves the snapshot rooted at its parent")
    func exactRedirect() {
        let p = TierBFileBroker.Policy(redirects: [.init(prefix: "/Users/x/Library/Messages/chat.db", to: "/snap/abc.db")])
        let r = TierBFileBroker.resolve("/Users/x/Library/Messages/chat.db", policy: p)
        #expect(r?.path == "/snap/abc.db")
        #expect(r?.root == "/snap")
    }

    // MARK: - End to end: request the live TCC path → receive the SNAPSHOT

    @Test("e2e: a sandboxed request for the live chat.db is served the snapshot, not the live store", .timeLimit(.minutes(1)))
    func endToEnd() throws {
        let snapDir = URL(fileURLWithPath: NSTemporaryDirectory() + "snap-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: snapDir) }
        let home = NSTemporaryDirectory() + "tcc-home-\(UUID().uuidString)"
        let bookmarks = home + "/Library/Safari/Bookmarks.plist"   // non-DB TCC file → snapshotFile
        try FileManager.default.createDirectory(atPath: (bookmarks as NSString).deletingLastPathComponent, withIntermediateDirectories: true)
        try "PERSONAL-BOOKMARKS".write(toFile: bookmarks, atomically: true, encoding: .utf8)
        defer { try? FileManager.default.removeItem(atPath: home) }

        let scratch = NSTemporaryDirectory() + "scratch-\(UUID().uuidString)"
        try FileManager.default.createDirectory(atPath: scratch, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: scratch) }

        let plan = BrokeredTCC.prepare(manifestReadPaths: [bookmarks], snapshotDir: snapDir, home: home)
        #expect(plan.redirects.count == 1)
        let policy = plan.brokerPolicy(scratchDir: scratch)

        var fds: [Int32] = [0, 0]
        #expect(socketpair(AF_UNIX, SOCK_STREAM, 0, &fds) == 0)
        let hostSock = fds[0], clientSock = fds[1]
        defer { close(clientSock); close(hostSock) }
        let broker = TierBFileBroker()
        Thread { broker.serve(hostSocket: hostSock, policy: policy) }.start()

        func request(_ path: String) -> (Int32, Int32) {
            let frame = TierBFileBroker.encodeRequest(path)
            _ = frame.withUnsafeBytes { write(clientSock, $0.baseAddress, frame.count) }
            var outFd: Int32 = -1
            return (maccrab_tierb_recv_fd(clientSock, &outFd), outFd)
        }

        // Request the LIVE path; the broker redirects to the snapshot fd.
        let (status, fd) = request(bookmarks)
        #expect(status == 0)
        #expect(fd >= 0)
        if fd >= 0 {
            var data = Data(); var b = [UInt8](repeating: 0, count: 4096)
            while true { let n = b.withUnsafeMutableBytes { read(fd, $0.baseAddress, 4096) }; if n <= 0 { break }; data.append(contentsOf: b[0..<n]) }
            close(fd)
            #expect(String(data: data, encoding: .utf8) == "PERSONAL-BOOKMARKS")
        }
    }
}
