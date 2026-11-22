// TierBFileBrokerTests — the per-invocation file broker for the sandboxed lane.
// Pins the load-bearing controls that ARE assertable without an on-device
// sandbox: the allowlist resolution, the safe-open-beneath-root (no symlink
// traversal, files only), and one real SCM_RIGHTS round-trip over a socketpair
// (proves the C transport + serve loop end-to-end). The plugin-side sandbox
// integration is the deferred on-device corpus.

import Testing
import Foundation
import CTierBBroker
@testable import MacCrabForensics

@Suite("TierBFileBroker (sandboxed-lane file broker)")
struct TierBFileBrokerTests {

    // MARK: - resolve (pure allowlist)

    @Test("resolve: a file under an allowed root is permitted; a sibling-prefix is not")
    func resolveRoots() {
        let p = TierBFileBroker.Policy(allowedReadRoots: ["/a/b"])
        #expect(TierBFileBroker.resolve("/a/b/c.txt", policy: p)?.root == "/a/b")
        #expect(TierBFileBroker.resolve("/a/b", policy: p)?.root == "/a/b")     // root itself resolves; safeOpen denies dirs
        #expect(TierBFileBroker.resolve("/a/bc/x", policy: p) == nil)           // /a/bc is NOT under /a/b
        #expect(TierBFileBroker.resolve("/a/x", policy: p) == nil)
    }

    @Test("resolve: trailing slash on a root is normalized")
    func resolveTrailingSlash() {
        let p = TierBFileBroker.Policy(allowedReadRoots: ["/a/b/"])
        #expect(TierBFileBroker.resolve("/a/b/c", policy: p)?.root == "/a/b")
    }

    @Test("resolve: a literal allow matches exactly; its root is the parent dir")
    func resolveLiteral() {
        let p = TierBFileBroker.Policy(allowedReadLiterals: ["/etc/hosts"])
        let r = TierBFileBroker.resolve("/etc/hosts", policy: p)
        #expect(r?.path == "/etc/hosts")
        #expect(r?.root == "/etc")
        #expect(TierBFileBroker.resolve("/etc/passwd", policy: p) == nil)
    }

    @Test("resolve: a brokered-TCC redirect serves from the scratch snapshot, beneath `to`")
    func resolveRedirect() {
        let p = TierBFileBroker.Policy(redirects: [.init(prefix: "/Users/x/Library/Messages", to: "/scratch/snap")])
        let r = TierBFileBroker.resolve("/Users/x/Library/Messages/chat.db", policy: p)
        #expect(r?.path == "/scratch/snap/chat.db")
        #expect(r?.root == "/scratch/snap")
    }

    @Test("resolve: malformed requests are rejected")
    func resolveMalformed() {
        let p = TierBFileBroker.Policy(allowedReadRoots: ["/a"])
        #expect(TierBFileBroker.resolve("relative/path", policy: p) == nil)   // not absolute
        #expect(TierBFileBroker.resolve("/a/../etc/x", policy: p) == nil)     // .. segment
        #expect(TierBFileBroker.resolve("/a/\u{0}x", policy: p) == nil)        // NUL
        #expect(TierBFileBroker.resolve("", policy: p) == nil)
        let small = TierBFileBroker.Policy(allowedReadRoots: ["/a"], maxPathBytes: 4)
        #expect(TierBFileBroker.resolve("/a/toolong", policy: small) == nil)   // over cap
    }

    @Test("STAB-2: a path deeper than the component ceiling is rejected; a shallow one isn't")
    func depthCeiling() {
        let big = 8192
        // 65 components > maxPathDepth (64) → rejected, even within the byte cap.
        let deep = "/" + Array(repeating: "a", count: TierBFileBroker.maxPathDepth + 1).joined(separator: "/")
        #expect(!TierBFileBroker.isValidRequestPath(deep, maxBytes: big))
        // Exactly at the ceiling → allowed.
        let atCap = "/" + Array(repeating: "a", count: TierBFileBroker.maxPathDepth).joined(separator: "/")
        #expect(TierBFileBroker.isValidRequestPath(atCap, maxBytes: big))
        #expect(TierBFileBroker.isValidRequestPath("/a/b/c", maxBytes: big))
    }

    @Test("relativeComponents is component-wise (no string-prefix false positives)")
    func relComponents() {
        #expect(TierBFileBroker.relativeComponents(of: "/a/b/c", under: "/a/b") == ["c"])
        #expect(TierBFileBroker.relativeComponents(of: "/a/b", under: "/a/b") == [])
        #expect(TierBFileBroker.relativeComponents(of: "/a/bc", under: "/a/b") == nil)
    }

    // MARK: - safeOpenReadOnly (the load-bearing control)

    static func makeTree() throws -> String {
        let root = NSTemporaryDirectory() + "broker-root-\(UUID().uuidString)"
        try FileManager.default.createDirectory(atPath: root + "/sub", withIntermediateDirectories: true)
        try "hello-broker".write(toFile: root + "/sub/data.txt", atomically: true, encoding: .utf8)
        return root
    }

    @Test("safeOpen: opens a real file under the root and returns readable bytes")
    func safeOpenHappy() throws {
        let root = try Self.makeTree()
        defer { try? FileManager.default.removeItem(atPath: root) }
        let fd = TierBFileBroker.safeOpenReadOnly(path: root + "/sub/data.txt", root: root)
        #expect(fd >= 0)
        if fd >= 0 { #expect(Self.readAll(fd) == "hello-broker"); close(fd) }
    }

    @Test("an exact-file manifest root serves its selected regular file without granting siblings or directories")
    func exactFileRoot() throws {
        let base = try Self.makeTree()
        defer { try? FileManager.default.removeItem(atPath: base) }
        let selected = base + "/sub/data.txt"
        let policy = TierBFileBroker.Policy(allowedReadRoots: [selected])
        let resolved = try #require(TierBFileBroker.resolve(selected, policy: policy))
        #expect(resolved.path == selected && resolved.root == selected)
        let fd = TierBFileBroker.safeOpenReadOnly(path: resolved.path, root: resolved.root)
        #expect(fd >= 0)
        if fd >= 0 { #expect(Self.readAll(fd) == "hello-broker"); close(fd) }
        #expect(TierBFileBroker.resolve(base + "/sub/sibling.txt", policy: policy) == nil)
        #expect(TierBFileBroker.resolve(base + "/outside.txt", policy: policy) == nil)
        #expect(TierBFileBroker.safeOpenReadOnly(path: base + "/sub", root: base + "/sub") == -1)
        #expect(TierBFileBroker.safeOpenReadOnly(path: selected + "/child", root: selected) == -1)
        #expect(TierBFileBroker.safeOpenReadOnly(path: "/", root: "/") == -1)
        // The existing root-directory scope can still serve an explicitly
        // selected descendant; only the root directory itself is refused.
        let absolute = TierBFileBroker.safeOpenReadOnly(path: selected, root: "/")
        #expect(absolute >= 0)
        if absolute >= 0 { close(absolute) }
    }

    @Test("exact-file roots retain final and ancestor alias refusals")
    func exactFileAliases() throws {
        let base = try Self.makeTree()
        defer { try? FileManager.default.removeItem(atPath: base) }
        let finalAlias = base + "/alias.txt"
        let ancestorAlias = base + "/alias-dir"
        try FileManager.default.createSymbolicLink(atPath: finalAlias, withDestinationPath: base + "/sub/data.txt")
        try FileManager.default.createSymbolicLink(atPath: ancestorAlias, withDestinationPath: base + "/sub")
        for selected in [finalAlias, ancestorAlias + "/data.txt"] {
            let policy = TierBFileBroker.Policy(allowedReadRoots: [selected])
            let resolved = try #require(TierBFileBroker.resolve(selected, policy: policy))
            #expect(TierBFileBroker.safeOpenReadOnly(path: resolved.path, root: resolved.root) == -1)
        }
    }

    @Test("safeOpen: a symlink as the FINAL component is refused (ELOOP, no escape)")
    func safeOpenFinalSymlink() throws {
        let root = try Self.makeTree()
        defer { try? FileManager.default.removeItem(atPath: root) }
        try FileManager.default.createSymbolicLink(atPath: root + "/evil", withDestinationPath: "/etc/hosts")
        #expect(TierBFileBroker.safeOpenReadOnly(path: root + "/evil", root: root) == -1)
    }

    @Test("safeOpen: a symlink as an INTERMEDIATE component is refused")
    func safeOpenIntermediateSymlink() throws {
        let root = try Self.makeTree()
        defer { try? FileManager.default.removeItem(atPath: root) }
        // root/dlink -> /etc ; request root/dlink/hosts → the dir component is a symlink → refused
        try FileManager.default.createSymbolicLink(atPath: root + "/dlink", withDestinationPath: "/etc")
        #expect(TierBFileBroker.safeOpenReadOnly(path: root + "/dlink/hosts", root: root) == -1)
    }

    @Test("safeOpen: a directory is refused (regular files only)")
    func safeOpenDir() throws {
        let root = try Self.makeTree()
        defer { try? FileManager.default.removeItem(atPath: root) }
        #expect(TierBFileBroker.safeOpenReadOnly(path: root + "/sub", root: root) == -1)
    }

    @Test("safeOpen: the ROOT ITSELF being a symlink is refused (no whole-walk escape)")
    func safeOpenSymlinkRoot() throws {
        let base = NSTemporaryDirectory() + "broker-realroot-\(UUID().uuidString)"
        try FileManager.default.createDirectory(atPath: base, withIntermediateDirectories: true)
        try "SECRET".write(toFile: base + "/data.txt", atomically: true, encoding: .utf8)
        defer { try? FileManager.default.removeItem(atPath: base) }
        let symRoot = NSTemporaryDirectory() + "broker-symroot-\(UUID().uuidString)"
        try FileManager.default.createSymbolicLink(atPath: symRoot, withDestinationPath: base)
        defer { try? FileManager.default.removeItem(atPath: symRoot) }
        // Without O_NOFOLLOW on the root open this returned a valid fd to SECRET.
        #expect(TierBFileBroker.safeOpenReadOnly(path: symRoot + "/data.txt", root: symRoot) == -1)
    }

    @Test("broker refuses an ancestor alias to a protected store before delivering bytes")
    func safeOpenAncestorAliasToProtectedStore() throws {
        let base = try Self.makeTree()
        defer { try? FileManager.default.removeItem(atPath: base) }
        let home = base + "/dummy-home"
        let library = home + "/Library"
        try FileManager.default.createDirectory(atPath: library + "/Messages", withIntermediateDirectories: true)
        try "DUMMY-PROTECTED-BYTES".write(toFile: library + "/Messages/chat.db", atomically: true, encoding: .utf8)
        let alias = base + "/external-alias"
        try FileManager.default.createSymbolicLink(atPath: alias, withDestinationPath: library)
        let declared = alias + "/Messages"
        let requested = declared + "/chat.db"
        let policy = TierBFileBroker.Policy(allowedReadRoots: [declared], tccGuardHome: home)
        // The lexical declaration alone looks harmless. Opening the root with
        // only a final-component O_NOFOLLOW used to expose these dummy bytes.
        let resolved = try #require(TierBFileBroker.resolve(requested, policy: policy))
        #expect(TierBFileBroker.safeOpenReadOnly(path: resolved.path, root: resolved.root) == -1)
    }

    @Test("safeOpen rejects a FIFO without waiting for a writer", .timeLimit(.minutes(1)))
    func safeOpenFIFOIsNonblocking() throws {
        let root = try Self.makeTree()
        defer { try? FileManager.default.removeItem(atPath: root) }
        let fifo = root + "/fifo"
        try #require(mkfifo(fifo, 0o600) == 0)
        let finished = DispatchSemaphore(value: 0)
        let worker = Thread {
            let fd = TierBFileBroker.safeOpenReadOnly(path: fifo, root: root)
            #expect(fd == -1)
            if fd >= 0 { close(fd) }
            finished.signal()
        }
        worker.start()
        let result = finished.wait(timeout: .now() + .seconds(1))
        if result == .timedOut {
            // Release a regressed blocking implementation so this test does not
            // strand a worker; the assertion below still records the defect.
            let writer = open(fifo, O_RDWR | O_NONBLOCK | O_CLOEXEC)
            defer { if writer >= 0 { close(writer) } }
            #expect(finished.wait(timeout: .now() + .seconds(1)) == .success)
        }
        #expect(result == .success)
    }

    @Test("safeOpen validates the absolute root and path before its descriptor walk")
    func safeOpenMalformedRoots() throws {
        let root = try Self.makeTree()
        defer { try? FileManager.default.removeItem(atPath: root) }
        #expect(TierBFileBroker.safeOpenReadOnly(path: root + "/sub/../sub/data.txt", root: root) == -1)
        #expect(TierBFileBroker.safeOpenReadOnly(path: root + "/sub/data.txt", root: ".") == -1)
        #expect(TierBFileBroker.safeOpenReadOnly(path: root + "/sub/data.txt\0ignored", root: root) == -1)
    }

    @Test("TCC direct-read guard treats fixed macOS aliases and canonical spellings equally")
    func systemAliasesCannotBypassTCCGuard() {
        let policy = TierBFileBroker.Policy(allowedReadRoots: ["/private/var/example-home"], tccGuardHome: "/var/example-home")
        #expect(TierBFileBroker.resolve("/private/var/example-home/Library/Messages/chat.db", policy: policy) == nil)
        let reverse = TierBFileBroker.Policy(allowedReadRoots: ["/var/example-home"], tccGuardHome: "/private/var/example-home")
        #expect(TierBFileBroker.resolve("/var/example-home/Library/Messages/chat.db", policy: reverse) == nil)
    }

    @Test("repeated slash spellings cannot bypass the protected-path guard")
    func repeatedSlashesCannotExposeProtectedBytes() throws {
        let base = try Self.makeTree()
        defer { try? FileManager.default.removeItem(atPath: base) }
        let home = base + "/dummy-home"
        try FileManager.default.createDirectory(atPath: home + "/Library/Messages", withIntermediateDirectories: true)
        try "DUMMY-PROTECTED-BYTES".write(toFile: home + "/Library/Messages/chat.db", atomically: true, encoding: .utf8)
        let policy = TierBFileBroker.Policy(allowedReadRoots: [home], tccGuardHome: home)
        for path in [home + "/Library/Messages/chat.db", home + "//Library/Messages/chat.db",
                     home + "/Library//Messages/chat.db", home + "/Library/Messages//chat.db",
                     base + "//dummy-home/Library/Messages/chat.db"] {
            let resolved = TierBFileBroker.resolve(path, policy: policy)
            #expect(resolved == nil)
            if let resolved {
                let fd = TierBFileBroker.safeOpenReadOnly(path: resolved.path, root: resolved.root)
                if fd >= 0 { close(fd) }
                #expect(fd == -1)
            }
        }
        #expect(TierBFileBroker.safeOpenReadOnly(path: home + "//Library/Messages/chat.db", root: home) == -1)
        let malformedHome = TierBFileBroker.Policy(allowedReadRoots: [home], tccGuardHome: base + "//dummy-home")
        #expect(TierBFileBroker.resolve(home + "/Library/Messages/chat.db", policy: malformedHome) == nil)
    }

    @Test("safeOpen: a hardlinked file inside the root is refused (st_nlink check)")
    func safeOpenHardlink() throws {
        let root = try Self.makeTree()
        defer { try? FileManager.default.removeItem(atPath: root) }
        // A same-volume secret the plugin can't read but could link into its root.
        let secret = NSTemporaryDirectory() + "broker-secret-\(UUID().uuidString)"
        try "OUT-OF-BAND".write(toFile: secret, atomically: true, encoding: .utf8)
        defer { try? FileManager.default.removeItem(atPath: secret) }
        let linked = root + "/h"
        guard link(secret, linked) == 0 else { return }   // same-volume link; skip if EXDEV
        #expect(TierBFileBroker.safeOpenReadOnly(path: linked, root: root) == -1)
    }

    @Test("safeOpen: a missing file and a path not under root are refused")
    func safeOpenMissingAndOutside() throws {
        let root = try Self.makeTree()
        defer { try? FileManager.default.removeItem(atPath: root) }
        #expect(TierBFileBroker.safeOpenReadOnly(path: root + "/sub/nope.txt", root: root) == -1)
        #expect(TierBFileBroker.safeOpenReadOnly(path: "/etc/hosts", root: root) == -1)
    }

    // MARK: - End-to-end over a real socketpair (C SCM_RIGHTS transport + serve loop)

    @Test("round-trip: allowlisted → fd+content; denied → status 1; symlink → status 2", .timeLimit(.minutes(1)))
    func socketRoundTrip() throws {
        let root = try Self.makeTree()
        defer { try? FileManager.default.removeItem(atPath: root) }
        let filePath = root + "/sub/data.txt"
        try FileManager.default.createSymbolicLink(atPath: root + "/evil", withDestinationPath: "/etc/hosts")

        var fds: [Int32] = [0, 0]
        #expect(socketpair(AF_UNIX, SOCK_STREAM, 0, &fds) == 0)
        let hostSock = fds[0], clientSock = fds[1]
        defer { close(clientSock); close(hostSock) }

        let policy = TierBFileBroker.Policy(allowedReadRoots: [root])
        let broker = TierBFileBroker()
        let t = Thread { broker.serve(hostSocket: hostSock, policy: policy) }
        t.start()

        func request(_ path: String) -> (status: Int32, fd: Int32) {
            let frame = TierBFileBroker.encodeRequest(path)
            _ = frame.withUnsafeBytes { write(clientSock, $0.baseAddress, frame.count) }
            var outFd: Int32 = -1
            let status = maccrab_tierb_recv_fd(clientSock, &outFd)
            return (status, outFd)
        }

        // 1. allowlisted file → ok + fd + content
        let r1 = request(filePath)
        #expect(r1.status == 0)
        #expect(r1.fd >= 0)
        if r1.fd >= 0 { #expect(Self.readAll(r1.fd) == "hello-broker"); close(r1.fd) }

        // 2. denied path (outside root) → status 1, no fd
        let r2 = request("/etc/hosts")
        #expect(r2.status == 1)
        #expect(r2.fd == -1)

        // 3. symlink escape → status 2 (allowlisted prefix but safe-open refuses), no fd
        let r3 = request(root + "/evil")
        #expect(r3.status == 2)
        #expect(r3.fd == -1)
    }

    // MARK: - helpers

    static func readAll(_ fd: Int32) -> String {
        var out = Data()
        var buf = [UInt8](repeating: 0, count: 4096)
        while true {
            let n = buf.withUnsafeMutableBytes { read(fd, $0.baseAddress, 4096) }
            if n <= 0 { break }
            out.append(contentsOf: buf[0..<n])
        }
        return String(data: out, encoding: .utf8) ?? ""
    }
}
