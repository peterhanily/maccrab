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
//   - Ancestors of the allowed root are walked too: a user-replaceable alias
//     must not route an otherwise harmless declaration to a live TCC store.
//     Only the three fixed, root-owned macOS /var, /tmp and /etc aliases are
//     accepted; their exact destinations are verified before expansion.
//   - Read-only in this build (no write/exec brokering). A hostile plugin is
//     bounded on COUNT (maxRequests), SIZE (maxPathBytes), and TIME (per-read
//     SO_RCVTIMEO + an absolute maxServeSeconds), and cannot SIGPIPE-kill the
//     host (SO_NOSIGPIPE on the serve socket).
//   - Symlink/hardlink defenses: every path component (incl. the root) is
//     O_NOFOLLOW; the final fd is fstat'd for a single-link regular file.
//
// STATUS: built, unit-tested, and WIRED LIVE. SandboxedTierBRunner.run creates the
// socketpair, dups the broker end onto the child's fd 3, serves on a dedicated
// thread, and tears it down after reap (close()s the host socket → EOF → bounded
// join), so a killed/desynced plugin cannot leave a blocked broker thread behind
// in the long-lived host. Brokered-TCC snapshots are prepared per invocation
// (BrokeredTCC.prepare) and the served-path TCC guard keeps live stores out.
// Containment is proven by ContainmentCorpus (`make test-corpus`).

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
        /// Home dir for the SERVED-PATH TCC guard. When set, `resolve` fail-closes
        /// any DIRECT (non-redirect) grant whose served path is TCC-protected — so
        /// a recursive read root that is an ANCESTOR of a TCC store (e.g. a plugin
        /// declaring `~/Library`) can never make the FDA-holding broker open the
        /// live `~/Library/Messages/chat.db`. TCC stores are reachable ONLY via the
        /// explicit snapshot redirects. nil = no guard (non-TCC contexts/tests).
        public let tccGuardHome: String?

        public init(
            allowedReadRoots: [String] = [],
            allowedReadLiterals: [String] = [],
            redirects: [Redirect] = [],
            maxRequests: Int = 4096,
            maxPathBytes: Int = 4096,
            readTimeoutSeconds: Int = 30,
            maxServeSeconds: Double = 120,
            tccGuardHome: String? = nil
        ) {
            self.allowedReadRoots = allowedReadRoots.map(Self.normalizeRoot)
            self.allowedReadLiterals = allowedReadLiterals
            self.redirects = redirects
            self.maxRequests = max(0, maxRequests)
            self.maxPathBytes = max(1, maxPathBytes)
            self.readTimeoutSeconds = max(1, readTimeoutSeconds)
            self.maxServeSeconds = max(1, maxServeSeconds)
            self.tccGuardHome = tccGuardHome
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

    /// A request path is well-formed for the broker: absolute, no NUL, no dot
    /// components or empty segments, within the byte cap. Guard and open must
    /// interpret exactly the same spelling; repeated slashes cannot bypass TCC.
    /// Depth ceiling for a brokered request path. Legitimate brokered reads are
    /// shallow; a depth cap is cheaper than walking thousands of components in
    /// safe-open (STAB-2) and bounds the per-component open-dir fd usage.
    static let maxPathDepth = 64

    public static func isValidRequestPath(_ p: String, maxBytes: Int) -> Bool {
        guard !p.isEmpty, p.utf8.count <= maxBytes, p.hasPrefix("/") else { return false }
        guard !p.contains("//"), p == "/" || !p.hasSuffix("/") else { return false }
        if p.unicodeScalars.contains(where: { $0.value == 0 }) { return false }
        let segs = p.split(separator: "/", omittingEmptySubsequences: true)
        guard segs.count <= maxPathDepth else { return false }   // STAB-2
        // String.split breaks on the Character "/", so a slash byte that
        // Unicode fuses into a grapheme cluster (after a Prepend scalar, before
        // a combining mark) stays inside a segment. The kernel's openat still
        // splits it at the byte, following the earlier component without
        // O_NOFOLLOW. Reject any segment that still carries a slash byte.
        for seg in segs
        where seg == ".." || seg == "." || seg.utf8.contains(UInt8(ascii: "/")) {
            return false
        }
        return true
    }

    /// Resolve a requested path against the policy → (servedPath, root) to open,
    /// or nil if denied. Applies brokered-TCC redirects first, then the read
    /// allowlist. PURE. `direct` is false for a snapshot redirect and true when
    /// the broker will open the live path itself; only a direct grant is
    /// re-classified after the open (`descriptorIsTCCProtected`).
    public static func resolve(_ requested: String, policy: Policy) -> (path: String, root: String, direct: Bool)? {
        guard isValidRequestPath(requested, maxBytes: policy.maxPathBytes) else { return nil }
        // Brokered-TCC redirect: serve the snapshot instead of the live store.
        for rd in policy.redirects {
            let pfx = Policy.normalizeRoot(rd.prefix)
            let to = Policy.normalizeRoot(rd.to)
            if requested == pfx {
                // EXACT-file redirect (e.g. chat.db → its <sha>.db snapshot): serve
                // the mapped file, rooted at its parent dir for the safe-open walk.
                return (to, parentDirectory(of: to), false)
            }
            if requested.hasPrefix(pfx + "/") {
                // DIRECTORY redirect: append the suffix beneath the snapshot root.
                let suffix = String(requested.dropFirst(pfx.count))   // includes leading "/"
                return (to + suffix, to, false)
            }
        }
        for root in policy.allowedReadRoots {
            if requested == root || requested.hasPrefix(root + "/") {
                return guardTCC(requested, root: root, policy: policy)
            }
        }
        for lit in policy.allowedReadLiterals where requested == lit {
            return guardTCC(lit, root: parentDirectory(of: lit), policy: policy)
        }
        return nil
    }

    /// Final served-path TCC guard for DIRECT (non-redirect) grants. The broker
    /// holds the host's FDA, so it must NEVER open a live TCC-protected store: a
    /// recursive read root can be an ANCESTOR of one (a plugin declaring
    /// `~/Library` would otherwise reach `~/Library/Messages/chat.db`). Fail-closed
    /// here — to read a TCC file a plugin must declare its EXACT path, which
    /// `BrokeredTCC.prepare` then snapshots into a redirect (resolved above, before
    /// this guard). No-op when the policy carries no `tccGuardHome` (non-TCC
    /// contexts / pure unit tests).
    private static func guardTCC(_ served: String, root: String, policy: Policy) -> (path: String, root: String, direct: Bool)? {
        if let home = policy.tccGuardHome {
            let normalizedHome = Policy.normalizeRoot(home)
            guard isValidRequestPath(normalizedHome, maxBytes: Int(PATH_MAX) - 1) else { return nil }
            if TCCProtectedPaths.isProtected(systemAliasExpansion(served), home: systemAliasExpansion(normalizedHome)) {
                return nil
            }
        }
        return (served, root, true)
    }

    /// True when the opened descriptor is a TCC-protected file by the path the
    /// KERNEL reports for it. `guardTCC` classifies the request's spelling, and a
    /// spelling is not the file: the Data volume is also mounted at
    /// `/System/Volumes/Data`, and a home folder can itself be reached through a
    /// link, so a protected store has spellings that match no protected prefix
    /// and contain no symbolic link for the open walk to refuse. The descriptor's
    /// own path is the same whichever spelling opened it. `home` is classified
    /// both as given and as the kernel reports it. Fails closed (protected) when
    /// the kernel gives no path for the file, or when the home cannot be opened
    /// or resolved — for a home reached through a link the given spelling alone
    /// is no prefix of the store's real path, so a lost kernel home could let a
    /// protected file through.
    static func descriptorIsTCCProtected(_ fd: Int32, home: String) -> Bool {
        guard let opened = kernelPath(of: fd) else { return true }
        let homeFD = open(home, O_RDONLY | O_DIRECTORY | O_NONBLOCK | O_CLOEXEC)
        guard homeFD >= 0 else { return true }
        defer { close(homeFD) }
        guard let reportedHome = kernelPath(of: homeFD) else { return true }
        let homes = [systemAliasExpansion(Policy.normalizeRoot(home)), reportedHome]
        return homes.contains { TCCProtectedPaths.isProtected(opened, home: $0) }
    }

    private static func kernelPath(of fd: Int32) -> String? {
        var buffer = [CChar](repeating: 0, count: Int(MAXPATHLEN))
        guard fcntl(fd, F_GETPATH, &buffer) == 0 else { return nil }
        return String(cString: buffer)
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

    /// Only these OS aliases have a supported meaning. This lexical projection
    /// also keeps the pure TCC guard consistent across /var and /private/var.
    /// The descriptor walk separately verifies any alias actually used.
    private static func systemAliasExpansion(_ path: String) -> String {
        for alias in ["var", "tmp", "etc"] {
            let prefix = "/" + alias
            if path == prefix || path.hasPrefix(prefix + "/") { return "/private" + path }
        }
        return path
    }

    private static func verifiedSystemAliasExpansion(_ path: String, rootFD: Int32) -> String? {
        let expanded = systemAliasExpansion(path)
        guard expanded != path else { return path }
        let alias = String(path.dropFirst().prefix { $0 != "/" })
        var parent = stat(), entry = stat()
        guard fstat(rootFD, &parent) == 0, parent.st_uid == 0,
              parent.st_mode & 0o022 == 0,
              fstatat(rootFD, alias, &entry, AT_SYMLINK_NOFOLLOW) == 0,
              entry.st_uid == 0, entry.st_mode & mode_t(S_IFMT) == mode_t(S_IFLNK) else { return nil }
        var bytes = [UInt8](repeating: 0, count: Int(PATH_MAX))
        let count = bytes.withUnsafeMutableBytes { readlinkat(rootFD, alias, $0.baseAddress!, $0.count) }
        guard count > 0, count < bytes.count,
              let target = String(bytes: bytes.prefix(count), encoding: .utf8),
              target == "private/" + alias || target == "/private/" + alias else { return nil }
        // The entry is owned by root beneath non-writable /. Replacing it is
        // outside the unprivileged plugin threat model; arbitrary aliases never
        // reach this exception. All expanded components still use O_NOFOLLOW.
        return expanded
    }

    /// Open a single-link regular file beneath the declared root. Walk every
    /// absolute component from /, including ancestors of that root, with
    /// O_NOFOLLOW. Special files cannot block the broker before fstat rejects
    /// them. Returns an owned fd (caller closes) or -1.
    public static func safeOpenReadOnly(path: String, root: String) -> Int32 {
        guard isValidRequestPath(path, maxBytes: Int(PATH_MAX) - 1),
              isValidRequestPath(root, maxBytes: Int(PATH_MAX) - 1),
              path != "/", relativeComponents(of: path, under: root) != nil else { return -1 }
        // A manifest read root may name one exact regular file. Equality does
        // not grant its parent: every absolute component is still walked below,
        // and the final fstat rejects directories (including a declared root).
        let rootFD = open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        guard rootFD >= 0 else { return -1 }
        var dirFDs: [Int32] = [rootFD]
        defer { for f in dirFDs { close(f) } }   // closes root + intermediates; returned file fd is separate
        guard let expanded = verifiedSystemAliasExpansion(path, rootFD: rootFD),
              isValidRequestPath(expanded, maxBytes: Int(PATH_MAX) - 1) else { return -1 }
        let components = expanded.split(separator: "/").map(String.init)
        var cur = rootFD
        for (i, comp) in components.enumerated() {
            guard !comp.isEmpty, comp != ".", comp != ".." else { return -1 }
            let isLast = (i == components.count - 1)
            if isLast {
                let fd = openat(cur, comp, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_NOCTTY | O_CLOEXEC)
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
                let fd = openat(cur, comp, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
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
            if fd >= 0, resolved.direct, let home = policy.tccGuardHome,
               Self.descriptorIsTCCProtected(fd, home: home) {
                // Another spelling of a protected store: never sent.
                close(fd)
                if maccrab_tierb_send_status(hostSocket, Status.denied.rawValue) != 0 { break }
                continue
            }
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
