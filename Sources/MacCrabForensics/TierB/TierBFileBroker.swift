// TierBFileBroker — the per-invocation file broker that gives a SANDBOXED
// third-party Tier-B plugin access to its manifest-declared files WITHOUT the
// plugin ever issuing an open() the deny-default sandbox would deny, and WITHOUT
// the plugin being able to win a symlink/TOCTOU race.
//
// Model (Plan §3.1 — "the file boundary is the broker"): the plugin runs under
// `(deny default)` (no file-read outside the runtime base). To read a declared
// path it sends the path to the broker over a unix socket (the host end of the
// fd-3 socketpair); the broker:
//   1. validates the path against the manifest allowlist (resolve), applying any
//      brokered-TCC redirect (a TCC-protected source is served from its scratch
//      SNAPSHOT, never the live store — the plugin never names the real path);
//   2. opens it SAFELY beneath the allowed root — every component openat'd with
//      O_NOFOLLOW, so a symlink planted anywhere in the relative path fails
//      (ELOOP) rather than escaping; regular files only;
//   3. passes the resulting fd back via SCM_RIGHTS (CTierBBroker).
// The plugin reads from the received fd — an already-open descriptor, no open()
// syscall — so the deny-default profile never has to grant it a file-read path.
//
// SECURITY NOTES:
//   - The broker, not the SBPL, is the file boundary. The allowed roots come from
//     the now-signature-bound manifest (see TierBRegistry resolve() manifest-
//     TOCTOU fix). The relative path under a root is attacker-influenced, so the
//     per-component O_NOFOLLOW walk is the load-bearing control.
//   - Symlinks ABOVE an allowed root (inside the operator-declared manifest
//     prefix) are trusted; the walk hardens the part a plugin can influence.
//   - Read-only in this build (no write/exec brokering). A hostile plugin is
//     bounded on COUNT (maxRequests), SIZE (maxPathBytes), and TIME (per-read
//     SO_RCVTIMEO + an absolute maxServeSeconds), and cannot SIGPIPE-kill the
//     host (SO_NOSIGPIPE on the serve socket).
//   - Symlink/hardlink defenses: every path component (incl. the root) is
//     O_NOFOLLOW; the final fd is fstat'd for a single-link regular file.
//
// STATUS: built + unit-tested; NOT yet wired into SandboxedTierBRunner's spawn.
// DEFERRED WIRING (on-device, with the rest of the lane): the fd-3 attachment;
// the brokered-TCC snapshot creation; the SBPL-vs-broker file-access decision;
// and — REQUIRED, not optional — invocation teardown that close()s the host
// socket and joins/cancels the serve thread, so a killed/desynced plugin cannot
// leave a blocked broker thread behind in the long-lived host. Nothing routes
// here yet.

import Foundation
import CTierBBroker

public final class TierBFileBroker: @unchecked Sendable {

    /// A brokered-TCC redirect: a request under `prefix` is served from `to`
    /// (the scratch snapshot root). Lets a plugin declare e.g. the chat.db path
    /// while the host hands an fd to the snapshot. Usually empty until the
    /// LiveDBSnapshot extension lands.
    public struct Redirect: Sendable, Equatable {
        public let prefix: String
        public let to: String
        public init(prefix: String, to: String) { self.prefix = prefix; self.to = to }
    }

    /// Wire status bytes (the 1-byte payload accompanying / replacing the fd).
    public enum Status: UInt8, Sendable {
        case ok = 0           // fd attached
        case denied = 1       // not on the allowlist
        case openFailed = 2   // allowlisted but safe-open failed (symlink/missing/not-a-file)
        case badRequest = 3   // malformed request frame
    }

    public struct Policy: Sendable {
        /// Recursive read roots (absolute, validated subpaths from the manifest).
        public let allowedReadRoots: [String]
        /// Exact-file read allowances.
        public let allowedReadLiterals: [String]
        /// Brokered-TCC redirects (usually empty for now).
        public let redirects: [Redirect]
        public let maxRequests: Int
        public let maxPathBytes: Int
        /// Per-read socket timeout (SO_RCVTIMEO) — a stalled frame can't block the
        /// serve thread past this. Seconds.
        public let readTimeoutSeconds: Int
        /// Absolute wall-clock budget for the whole invocation's serving — bounds
        /// a slow-drip (one byte per <readTimeout) attack that never trips the
        /// per-read timeout. Seconds.
        public let maxServeSeconds: Double

        public init(
            allowedReadRoots: [String] = [],
            allowedReadLiterals: [String] = [],
            redirects: [Redirect] = [],
            maxRequests: Int = 4096,
            maxPathBytes: Int = 4096,
            readTimeoutSeconds: Int = 30,
            maxServeSeconds: Double = 120
        ) {
            self.allowedReadRoots = allowedReadRoots.map(Self.normalizeRoot)
            self.allowedReadLiterals = allowedReadLiterals
            self.redirects = redirects
            self.maxRequests = max(0, maxRequests)
            self.maxPathBytes = max(1, maxPathBytes)
            self.readTimeoutSeconds = max(1, readTimeoutSeconds)
            self.maxServeSeconds = max(1, maxServeSeconds)
        }

        /// Build a read policy from a verified manifest + the per-invocation
        /// scratch dir (the plugin may always read its own scratch).
        public static func readOnly(manifest: TierBManifest, scratchDir: String) -> Policy {
            Policy(
                allowedReadRoots: manifest.fileReadSubpaths + [scratchDir],
                allowedReadLiterals: []
            )
        }

        static func normalizeRoot(_ p: String) -> String {
            var s = p
            while s.count > 1 && s.hasSuffix("/") { s.removeLast() }
            return s
        }
    }

    public init() {}

    // MARK: - Pure resolution (testable without sockets)

    /// A request path is well-formed for the broker: absolute, no NUL, no `..`
    /// component, within the byte cap.
    public static func isValidRequestPath(_ p: String, maxBytes: Int) -> Bool {
        guard !p.isEmpty, p.utf8.count <= maxBytes, p.hasPrefix("/") else { return false }
        if p.unicodeScalars.contains(where: { $0.value == 0 }) { return false }
        for seg in p.split(separator: "/", omittingEmptySubsequences: true) where seg == ".." || seg == "." { return false }
        return true
    }

    /// Resolve a requested path against the policy → (servedPath, root) to open,
    /// or nil if denied. Applies brokered-TCC redirects first, then the read
    /// allowlist. PURE.
    public static func resolve(_ requested: String, policy: Policy) -> (path: String, root: String)? {
        guard isValidRequestPath(requested, maxBytes: policy.maxPathBytes) else { return nil }
        // Brokered-TCC redirect: serve the snapshot instead of the live store.
        for rd in policy.redirects {
            let pfx = Policy.normalizeRoot(rd.prefix)
            let to = Policy.normalizeRoot(rd.to)
            if requested == pfx {
                // EXACT-file redirect (e.g. chat.db → its <sha>.db snapshot): serve
                // the mapped file, rooted at its parent dir for the safe-open walk.
                return (to, parentDirectory(of: to))
            }
            if requested.hasPrefix(pfx + "/") {
                // DIRECTORY redirect: append the suffix beneath the snapshot root.
                let suffix = String(requested.dropFirst(pfx.count))   // includes leading "/"
                return (to + suffix, to)
            }
        }
        for root in policy.allowedReadRoots {
            if requested == root || requested.hasPrefix(root + "/") {
                return (requested, root)
            }
        }
        for lit in policy.allowedReadLiterals where requested == lit {
            return (lit, parentDirectory(of: lit))
        }
        return nil
    }

    static func parentDirectory(of path: String) -> String {
        let comps = path.split(separator: "/", omittingEmptySubsequences: true).map(String.init)
        guard comps.count > 1 else { return "/" }
        return "/" + comps.dropLast().joined(separator: "/")
    }

    /// Components of `path` relative to `root`, or nil if `path` is not `root` or
    /// under it (component-wise prefix, so "/a/bc" is NOT under "/a/b").
    static func relativeComponents(of path: String, under root: String) -> [String]? {
        let p = path.split(separator: "/", omittingEmptySubsequences: true).map(String.init)
        let r = root.split(separator: "/", omittingEmptySubsequences: true).map(String.init)
        guard p.count >= r.count, Array(p.prefix(r.count)) == r else { return nil }
        return Array(p.dropFirst(r.count))
    }

    // MARK: - Safe open (the load-bearing control)

    /// Open `path` read-only BENEATH `root` such that no symlink anywhere in the
    /// relative path can redirect the open outside the root, and only a regular
    /// file is returned. Returns an owned fd (caller closes) or -1.
    ///
    /// Each relative component is openat'd with O_NOFOLLOW, so a symlink (final
    /// or intermediate) fails with ELOOP. The final fd is fstat-checked for
    /// S_IFREG (no dir/fifo/device/symlink). `root` itself is the operator-
    /// declared, signature-bound prefix and is opened as a directory.
    public static func safeOpenReadOnly(path: String, root: String) -> Int32 {
        guard let rel = relativeComponents(of: path, under: root), !rel.isEmpty else { return -1 }
        // O_NOFOLLOW on the ROOT too: a hostile plugin that can replace the root's
        // final component with a symlink (e.g. swap its own scratch dir for a
        // symlink to ~/Library) must NOT escape — every relative O_NOFOLLOW below
        // anchors to this descriptor, so the root open itself must refuse a
        // symlinked final component. (A legit symlinked PREFIX — /var → /private/var
        // — is unaffected: O_NOFOLLOW only guards the final component, and prefix
        // components are above the plugin's confinement.)
        let rootFD = open(root, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard rootFD >= 0 else { return -1 }
        var dirFDs: [Int32] = [rootFD]
        defer { for f in dirFDs { close(f) } }   // closes root + intermediates; returned file fd is separate
        var cur = rootFD
        for (i, comp) in rel.enumerated() {
            guard !comp.isEmpty, comp != ".", comp != ".." else { return -1 }
            let isLast = (i == rel.count - 1)
            if isLast {
                let fd = openat(cur, comp, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
                guard fd >= 0 else { return -1 }     // ELOOP if the final component is a symlink
                var st = stat()
                if fstat(fd, &st) != 0 || (UInt32(st.st_mode) & UInt32(S_IFMT)) != UInt32(S_IFREG) {
                    close(fd); return -1             // dir / fifo / device / etc. — files only
                }
                // Reject a hardlinked file: a plugin with write inside a read root
                // can link() an out-of-allowlist same-volume file into the root; a
                // hardlink is a regular file (passes O_NOFOLLOW + S_IFREG), so the
                // link count is the only tell. A brokered file should have exactly
                // one link.
                if st.st_nlink != 1 { close(fd); return -1 }
                return fd
            } else {
                let fd = openat(cur, comp, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
                guard fd >= 0 else { return -1 }     // ELOOP / not-a-dir
                dirFDs.append(fd)
                cur = fd
            }
        }
        return -1
    }

    // MARK: - Serve loop (host side of the fd-3 socketpair)

    /// Serve broker requests on `hostSocket` until the peer closes (EOF), an I/O
    /// error occurs, or `maxRequests` is reached. SYNCHRONOUS — the caller runs
    /// it on a dedicated thread tied to the invocation lifecycle. Each request is
    /// a 2-byte big-endian length + that many UTF-8 path bytes; each response is
    /// a status byte, with an fd attached only on `.ok`.
    public func serve(hostSocket: Int32, policy: Policy) {
        // SIGPIPE-safe: the in-process host (MacCrabApp/MacCrabForensics) has no
        // global SIG_IGN, so a plugin that closes its read end mid-send must never
        // signal/kill the host. Mirror what the runners do for their stdin pipes.
        var on: Int32 = 1
        _ = setsockopt(hostSocket, SOL_SOCKET, SO_NOSIGPIPE, &on, socklen_t(MemoryLayout<Int32>.size))
        // Per-read timeout so a stalled/partial frame can't block the serve thread.
        var tv = timeval(tv_sec: policy.readTimeoutSeconds, tv_usec: 0)
        _ = setsockopt(hostSocket, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))

        let deadline = Date().addingTimeInterval(policy.maxServeSeconds)
        var served = 0
        while served < policy.maxRequests {
            guard let req = Self.readRequest(hostSocket, maxBytes: policy.maxPathBytes, deadline: deadline) else {
                break   // EOF / error / per-read timeout / serve deadline / oversized
            }
            served += 1
            guard let resolved = Self.resolve(req, policy: policy) else {
                if maccrab_tierb_send_status(hostSocket, Status.denied.rawValue) != 0 { break }
                continue
            }
            let fd = Self.safeOpenReadOnly(path: resolved.path, root: resolved.root)
            if fd >= 0 {
                let sent = maccrab_tierb_send_fd(hostSocket, fd, Status.ok.rawValue)
                close(fd)                        // close BEFORE any break — never leak a host fd
                if sent != 0 { break }           // peer gone / desynced — stop serving
            } else {
                if maccrab_tierb_send_status(hostSocket, Status.openFailed.rawValue) != 0 { break }
            }
        }
    }

    /// Read one 2-byte-BE-length-prefixed path frame. Returns nil on EOF / error /
    /// timeout / deadline / a length outside (0, maxBytes].
    static func readRequest(_ sock: Int32, maxBytes: Int, deadline: Date) -> String? {
        guard let lenData = readExactly(sock, 2, deadline: deadline) else { return nil }
        let len = Int(lenData[0]) << 8 | Int(lenData[1])
        guard len > 0, len <= maxBytes else { return nil }
        guard let pathData = readExactly(sock, len, deadline: deadline) else { return nil }
        return String(data: pathData, encoding: .utf8)
    }

    static func readExactly(_ sock: Int32, _ n: Int, deadline: Date) -> Data? {
        guard n > 0 else { return Data() }
        var buf = [UInt8](repeating: 0, count: n)
        var got = 0
        let ok = buf.withUnsafeMutableBytes { (raw: UnsafeMutableRawBufferPointer) -> Bool in
            guard let base = raw.baseAddress else { return false }
            while got < n {
                let r = read(sock, base + got, n - got)
                if r < 0 {
                    if errno == EINTR { if Date() > deadline { return false }; continue }
                    return false   // includes EAGAIN/EWOULDBLOCK from the SO_RCVTIMEO timeout
                }
                if r == 0 { return false }                 // EOF
                got += r
                if Date() > deadline { return false }      // bound a slow byte-drip frame
            }
            return true
        }
        return ok ? Data(buf) : nil
    }

    /// Convenience for the (future) plugin-side / tests: write a request frame.
    public static func encodeRequest(_ path: String) -> Data {
        let bytes = Array(path.utf8)
        let len = min(bytes.count, 0xFFFF)
        var out = Data([UInt8((len >> 8) & 0xFF), UInt8(len & 0xFF)])
        out.append(contentsOf: bytes.prefix(len))
        return out
    }
}
