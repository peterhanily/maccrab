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
        // A1-06 deny-by-default: any ~/Library path not on the known-safe allowlist
        // is protected (even one no explicit prefix names) — the FDA broker must not
        // serve it live. Known-safe ~/Library/Preferences stays live.
        #expect(TCCProtectedPaths.isProtected("/Users/x/Library/MessagesOther/x", home: home))  // deny-by-default
        #expect(!TCCProtectedPaths.isProtected("/Users/x/Library/Preferences/com.example.plist", home: home))
        #expect(TCCProtectedPaths.isProtected("/Users/x/Library/PreferencesEvil/x", home: home)) // component boundary — NOT the safe prefix
        // System /Library and non-Library paths are unaffected by deny-by-default.
        #expect(!TCCProtectedPaths.isProtected("/Library/LaunchDaemons/foo.plist", home: home))
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

    @Test("MEDIUM: credential stores outside ~/Library are brokered/consent-gated, not served live")
    func credentialStoresProtected() {
        let home = "/Users/x"
        for p in ["/Users/x/.ssh/id_rsa",
                  "/Users/x/.aws/credentials",
                  "/Users/x/.config/gcloud/credentials.db",
                  "/Users/x/.netrc",
                  "/Users/x/.docker/config.json",
                  "/Users/x/.gnupg/secring.gpg",
                  "/Users/x/.kube/config",
                  "/Users/x/.azure/accessTokens.json"] {
            #expect(TCCProtectedPaths.isProtected(p, home: home), "credential path must be brokered/consent-gated: \(p)")
        }
        // A plain project file is unaffected (still a direct read).
        #expect(!TCCProtectedPaths.isProtected("/Users/x/Documents/notes.txt", home: home))
        // Case-folded bypass attempt is also caught (case-insensitive APFS).
        #expect(TCCProtectedPaths.isProtected("/Users/x/.SSH/id_rsa", home: home))
    }

    @Test("MEDIUM: a broker read of ~/.ssh/id_rsa is gated exactly like a TCC source (snapshot, never live)")
    func sshKeyBrokeredLikeTCC() throws {
        let snapDir = URL(fileURLWithPath: NSTemporaryDirectory() + "snap-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: snapDir) }
        let home = NSTemporaryDirectory() + "tcc-home-\(UUID().uuidString)"
        let key = home + "/.ssh/id_rsa"
        try FileManager.default.createDirectory(atPath: (key as NSString).deletingLastPathComponent, withIntermediateDirectories: true)
        try "-----BEGIN OPENSSH PRIVATE KEY-----".write(toFile: key, atomically: true, encoding: .utf8)
        defer { try? FileManager.default.removeItem(atPath: home) }

        // Gated exactly like chat.db: NOT a live direct read root — snapshotted + redirected.
        let plan = BrokeredTCC.prepare(manifestReadPaths: [key], snapshotDir: snapDir, home: home)
        #expect(plan.directReadRoots.isEmpty)
        #expect(plan.denied.isEmpty)
        #expect(plan.redirects.count == 1)
        #expect(plan.redirects.first?.prefix == key)

        // Defense in depth: even a broad ~/.ssh ancestor read root can't coax a live
        // serve — the served-path TCC guard denies it (same control as chat.db).
        let guarded = TierBFileBroker.Policy(allowedReadRoots: [home + "/.ssh"], tccGuardHome: home)
        #expect(TierBFileBroker.resolve(key, policy: guarded) == nil)
        // Without the guard it WOULD be served live — documents the guard is the control.
        let unguarded = TierBFileBroker.Policy(allowedReadRoots: [home + "/.ssh"])
        #expect(TierBFileBroker.resolve(key, policy: unguarded)?.path == key)
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

    @Test("A1-06: a ~/Library/Calendars source is snapshotted (never a live direct root)")
    func calendarsSnapshottedNotLive() throws {
        let snapDir = URL(fileURLWithPath: NSTemporaryDirectory() + "snap-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: snapDir) }
        let home = NSTemporaryDirectory() + "tcc-home-\(UUID().uuidString)"
        let cal = home + "/Library/Calendars/Calendar.sqlitedb"
        try FileManager.default.createDirectory(atPath: (cal as NSString).deletingLastPathComponent, withIntermediateDirectories: true)
        try Self.makeSourceDB(at: cal)
        defer { try? FileManager.default.removeItem(atPath: home) }

        let plan = BrokeredTCC.prepare(manifestReadPaths: [cal], snapshotDir: snapDir, home: home)
        #expect(plan.directReadRoots.isEmpty)      // NOT served live with the host's FDA
        #expect(plan.denied.isEmpty)
        #expect(plan.redirects.count == 1)         // snapshot + redirect instead
        #expect(plan.redirects.first?.prefix == cal)
        // The classifier and the served-path guard both treat it as protected.
        #expect(TCCProtectedPaths.isProtected(cal, home: home))
        let guarded = TierBFileBroker.Policy(allowedReadRoots: [home + "/Library"], tccGuardHome: home)
        #expect(TierBFileBroker.resolve(cal, policy: guarded) == nil)   // guard denies a live serve
    }

    @Test("A1-06 deny-by-default: an unenumerated ~/Library store dir is denied, not served live")
    func denyByDefaultUnenumeratedStore() throws {
        let snapDir = URL(fileURLWithPath: NSTemporaryDirectory() + "snap-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: snapDir) }
        let home = NSTemporaryDirectory() + "tcc-home-\(UUID().uuidString)"
        // A store NO explicit prefix names (a directory) — deny-by-default must
        // still protect it: a directory can't be snapshotted → denied (not live).
        let reminders = home + "/Library/Reminders"
        let future = home + "/Library/SomeFutureTCCStore"
        try FileManager.default.createDirectory(atPath: reminders, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(atPath: future, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: home) }

        let plan = BrokeredTCC.prepare(manifestReadPaths: [reminders, future], snapshotDir: snapDir, home: home)
        #expect(plan.directReadRoots.isEmpty)      // neither served live
        #expect(plan.redirects.isEmpty)
        #expect(Set(plan.denied) == Set([reminders, future]))
    }

    // MARK: - Exact-file redirect resolution

    @Test("broker resolve: an exact-file redirect serves the snapshot rooted at its parent")
    func exactRedirect() {
        let p = TierBFileBroker.Policy(redirects: [.init(prefix: "/Users/x/Library/Messages/chat.db", to: "/snap/abc.db")])
        let r = TierBFileBroker.resolve("/Users/x/Library/Messages/chat.db", policy: p)
        #expect(r?.path == "/snap/abc.db")
        #expect(r?.root == "/snap")
    }

    // MARK: - Served-path TCC guard (a broad ANCESTOR root must NOT leak a live store)

    @Test("broker resolve: a broad ancestor read root does NOT serve a live TCC store")
    func ancestorRootCannotLeakLiveTCC() {
        let home = "/Users/x"
        let chat = "/Users/x/Library/Messages/chat.db"
        // A plugin declares ~/Library as a recursive read root (an ANCESTOR of the
        // TCC store). The served-path guard must deny the live chat.db beneath it.
        let guarded = TierBFileBroker.Policy(allowedReadRoots: ["/Users/x/Library"], tccGuardHome: home)
        #expect(TierBFileBroker.resolve(chat, policy: guarded) == nil)
        // Non-TCC content under the same broad root is still served.
        let prefs = "/Users/x/Library/Preferences/com.example.plist"
        #expect(TierBFileBroker.resolve(prefs, policy: guarded)?.path == prefs)
        // Case-folded bypass attempt (lowercase library/messages) is also denied.
        #expect(TierBFileBroker.resolve("/Users/x/library/messages/chat.db", policy: guarded) == nil)
        // WITHOUT the guard the live store WOULD be served — documents the guard is
        // the control (and that a non-TCC context is unaffected).
        let unguarded = TierBFileBroker.Policy(allowedReadRoots: ["/Users/x/Library"])
        #expect(TierBFileBroker.resolve(chat, policy: unguarded)?.path == chat)
    }

    @Test("broker resolve: the guard does not break the legit exact-file snapshot redirect")
    func guardAllowsSnapshotRedirect() {
        let home = "/Users/x"
        // Even with the guard armed, an explicit redirect (the snapshot of chat.db)
        // is resolved first and served — the redirect target is non-TCC scratch.
        let p = TierBFileBroker.Policy(
            redirects: [.init(prefix: "/Users/x/Library/Messages/chat.db", to: "/snap/abc.db")],
            tccGuardHome: home)
        let r = TierBFileBroker.resolve("/Users/x/Library/Messages/chat.db", policy: p)
        #expect(r?.path == "/snap/abc.db")
        #expect(r?.root == "/snap")
    }

    @Test("prepare → brokerPolicy: an ANCESTOR ~/Library root denies the live chat.db end-to-end")
    func ancestorRootDeniedThroughPreparedPolicy() throws {
        let snapDir = URL(fileURLWithPath: NSTemporaryDirectory() + "snap-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: snapDir) }
        let home = NSTemporaryDirectory() + "tcc-home-\(UUID().uuidString)"
        let chat = home + "/Library/Messages/chat.db"
        try FileManager.default.createDirectory(atPath: (chat as NSString).deletingLastPathComponent, withIntermediateDirectories: true)
        try Self.makeSourceDB(at: chat)
        defer { try? FileManager.default.removeItem(atPath: home) }
        let scratch = NSTemporaryDirectory() + "scratch-\(UUID().uuidString)"

        // The plugin declares the broad ANCESTOR root, not the exact chat.db.
        // A1-06 deny-by-default: ~/Library is a protected directory (can't be
        // snapshotted) → prepare DENIES it outright rather than serving it live.
        let plan = BrokeredTCC.prepare(manifestReadPaths: [home + "/Library"], snapshotDir: snapDir, home: home)
        #expect(plan.directReadRoots.isEmpty)                  // ancestor root is NOT served live
        #expect(plan.redirects.isEmpty)
        #expect(plan.denied == [home + "/Library"])            // deny-by-default (directory under protected subtree)
        let policy = plan.brokerPolicy(scratchDir: scratch)
        #expect(policy.tccGuardHome == home)
        // Defense in depth: even were the ancestor root a direct grant, the guard
        // still fail-closes the live store reached beneath it.
        #expect(TierBFileBroker.resolve(chat, policy: policy) == nil)
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

@Suite("Broker scratch-read resolution (corpus regression)")
struct BrokerScratchResolveTests {
    @Test("a scratch read resolves through the prepared broker policy")
    func scratchResolves() {
        let scratch = "/var/folders/hf/x/T/corpus-ABC"
        let plan = BrokeredTCC.prepare(manifestReadPaths: [], snapshotDir: URL(fileURLWithPath: "/tmp/snap"), home: "/Users/x")
        let policy = plan.brokerPolicy(scratchDir: scratch)
        let r = TierBFileBroker.resolve(scratch + "/allowed.txt", policy: policy)
        #expect(r?.root == scratch, "roots=\(policy.allowedReadRoots)")
    }
}
