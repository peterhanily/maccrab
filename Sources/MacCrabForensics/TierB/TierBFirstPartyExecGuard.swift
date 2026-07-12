// TierBFirstPartyExecGuard — exec-time hardening for the UNSANDBOXED first-party
// Tier-B lane (Shape 2, findings A1-01 + A1-05).
//
// A first-party plugin runs with the host's FULL Full-Disk-Access / TCC and NO
// sandbox profile, so the bytes we `posix_spawn` must be provably the verified
// bytes AND Developer-ID-anchored. `FirstPartyTierBRunner` previously spawned the
// registry's 0o500 temp DIRECTLY from a path string with no guard: a same-uid
// attacker could win a write→spawn TOCTOU (a symlink swap suffices — `posix_spawn`
// follows symlinks, and 0o500 on the file does not stop unlink+recreate in a
// user-owned dir) and run substituted code unsandboxed with the host's FDA.
//
// This helper closes that window with the SAME primitives the sandboxed lane
// already uses on its trampoline (`SandboxedTierBRunner.trampolinePathIsTamper‑
// Resistant` / the C trampoline's `validate_exec_target` / `isTrampoline‑
// SignatureTrusted`):
//   A1-01  (a) stage the verified bytes into a FRESH host-only 0o700 dir (not the
//              shared NSTemporaryDirectory the registry drops the temp into);
//          (b) open the exec target O_NOFOLLOW and require a single-link, regular
//              file owned by our euid and not group/other-writable;
//          (c) re-hash the bytes (read through the O_NOFOLLOW fd, never re-opened
//              by path) and compare to the verified digest IMMEDIATELY before
//              spawn — refuse on any mismatch (fail-closed).
//   A1-05  require a Developer-ID + host-team-anchored SecStaticCode validity on
//          the exact bytes we are about to exec — the same requirement the
//          sandbox lane applies to its trampoline. A first-party publisher-key
//          (Ed25519) compromise is then not enough to run unsandboxed FDA code:
//          the attacker also needs a Developer-ID signature under the host team.
//
// LACK OF fexecve: macOS has neither `fexecve` NOR exec of `/dev/fd/N`, so the
// spawn cannot be inode-pinned — `posix_spawn(path,…)` re-opens by path after our
// re-hash. The residual re-hash→spawn window is irreducible; it is same-uid-only
// and carries NO privilege crossing (this lane is uid-501 app/CLI/MCP, never the
// root sysext), exactly as the sandboxed lane documents for its trampoline. The
// fresh 0o700 dir with an unguessable name + the O_NOFOLLOW/owner/re-hash re-check
// immediately before spawn make a same-uid swap require winning that microsecond
// race, versus the prior code that offered no defense at all.

import Foundation
import Darwin
import Security
import CryptoKit

enum TierBFirstPartyExecGuard {

    enum GuardError: Error, CustomStringConvertible {
        case openFailed(role: String)           // O_NOFOLLOW open failed (ELOOP on a symlinked component, or gone)
        case notRegularFile(role: String)       // not a single-link regular file owned by our euid
        case writable(role: String)             // group/other-writable — a same-uid-adjacent swap surface
        case tooLarge(role: String)
        case digestMismatch(role: String)       // bytes do not hash to the verified digest (substitution)
        case stagingFailed(String)
        case payloadNotDeveloperIDTrusted        // A1-05: no Developer-ID + host-team code signature

        var description: String {
            switch self {
            case .openFailed(let r): return "exec-guard: cannot open \(r) (O_NOFOLLOW) — symlink swap or missing"
            case .notRegularFile(let r): return "exec-guard: \(r) is not a single-link regular file owned by the host uid"
            case .writable(let r): return "exec-guard: \(r) is group/other-writable — refused"
            case .tooLarge(let r): return "exec-guard: \(r) exceeds the size cap — refused"
            case .digestMismatch(let r): return "exec-guard: \(r) does not match the verified digest (TOCTOU substitution) — refused"
            case .stagingFailed(let m): return "exec-guard: failed to stage the verified binary: \(m)"
            case .payloadNotDeveloperIDTrusted:
                return "exec-guard: first-party payload is not Developer-ID-signed under the host team — refusing UNSANDBOXED execution (A1-05)"
            }
        }
    }

    /// SHA-256 (lowercase hex). Single source of truth for the digest both the
    /// registry (which stamps `VerifiedPlugin.binarySHA256`) and this guard use,
    /// so the two sides hash identically.
    static func sha256Hex(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    // MARK: - A1-01: O_NOFOLLOW read + owner/single-link/regular guard

    /// Open `path` with O_NOFOLLOW (no symlink swap of the final component), assert
    /// it is a single-link regular file owned by our euid and NOT group/other-
    /// writable, then read its whole content THROUGH the fd (never re-opened by
    /// path). Fail-closed. Mirrors the sandbox trampoline's `validate_exec_target`
    /// (main.c:144-154) + `trampolinePathIsTamperResistant`.
    private static func readGuarded(_ path: String, role: String,
                                    maxBytes: Int = 512 * 1024 * 1024) throws -> Data {
        let fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw GuardError.openFailed(role: role) }   // ELOOP if final component is a symlink
        defer { close(fd) }
        var st = Darwin.stat()
        guard fstat(fd, &st) == 0 else { throw GuardError.notRegularFile(role: role) }
        let mode = UInt32(st.st_mode)
        guard (mode & UInt32(S_IFMT)) == UInt32(S_IFREG),
              st.st_nlink == 1,
              st.st_uid == geteuid() else { throw GuardError.notRegularFile(role: role) }
        guard (mode & (UInt32(S_IWGRP) | UInt32(S_IWOTH))) == 0 else { throw GuardError.writable(role: role) }

        var data = Data()
        let bufSize = 64 * 1024
        var buf = [UInt8](repeating: 0, count: bufSize)
        while true {
            let n = read(fd, &buf, bufSize)
            if n < 0 {
                if errno == EINTR { continue }
                throw GuardError.openFailed(role: role)
            }
            if n == 0 { break }   // EOF
            data.append(buf, count: n)
            if data.count > maxBytes { throw GuardError.tooLarge(role: role) }
        }
        return data
    }

    /// A1-01 (a) + source snapshot: read the verified source via an O_NOFOLLOW fd,
    /// re-hash it to `expectedSHA256`, and write the bytes into `dir` (a FRESH
    /// host-only 0o700 dir the caller just created) as an owner-r-x (0o500) exec
    /// target. Returns the staged exec path. Fail-closed on any mismatch.
    static func stage(verifiedPath: String, expectedSHA256: String, into dir: String) throws -> String {
        let bytes = try readGuarded(verifiedPath, role: "verified source")
        guard sha256Hex(bytes) == expectedSHA256 else {
            throw GuardError.digestMismatch(role: "verified source")
        }
        let execPath = (dir as NSString).appendingPathComponent("binary")
        do {
            // O_NOFOLLOW|O_EXCL creation into the fresh dir: never follow a planted
            // symlink, never overwrite a pre-existing entry (both are swap attempts).
            let fd = open(execPath, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o500)
            guard fd >= 0 else { throw GuardError.stagingFailed("open(O_EXCL|O_NOFOLLOW) for the staged target failed") }
            defer { close(fd) }
            try bytes.withUnsafeBytes { (raw: UnsafeRawBufferPointer) in
                guard let base = raw.baseAddress, raw.count > 0 else { return }
                var off = 0
                while off < raw.count {
                    let n = write(fd, base + off, raw.count - off)
                    if n < 0 {
                        if errno == EINTR { continue }
                        throw GuardError.stagingFailed("write to the staged target failed")
                    }
                    off += n
                }
            }
        } catch let e as GuardError {
            throw e
        } catch {
            throw GuardError.stagingFailed("\(error)")
        }
        return execPath
    }

    /// A1-01 (b) + (c): O_NOFOLLOW re-open of the staged exec target + owner/single-
    /// link/regular/not-writable checks + re-hash to the verified digest,
    /// IMMEDIATELY before the caller spawns it. Throws on any mismatch (fail-closed).
    static func revalidateBeforeSpawn(execPath: String, expectedSHA256: String) throws {
        let bytes = try readGuarded(execPath, role: "exec target")
        guard sha256Hex(bytes) == expectedSHA256 else {
            throw GuardError.digestMismatch(role: "exec target")
        }
    }

    // MARK: - A1-05: Developer-ID + host-team code-signature validity

    /// True iff `path` carries a valid Developer-ID code signature anchored to
    /// Apple AND to the SAME team as the running host — the exact requirement the
    /// sandboxed lane applies to its signed trampoline (`SandboxedTierBRunner.is‑
    /// TrampolineSignatureTrusted`), reused here on the first-party PAYLOAD because
    /// it runs UNSANDBOXED with full FDA. `allowUnsigned` is the DEBUG-only dev/test
    /// override (see `devOverrideAllowed`); it is the ONLY way to bypass, and it is
    /// ignored in RELEASE.
    ///
    /// NOTE (documented gap): this verifies the EMBEDDED Developer-ID signature,
    /// which survives the byte-copy into the staging dir. It does NOT verify a
    /// stapled NOTARIZATION ticket — Apple cannot staple a notarization ticket to a
    /// standalone Mach-O (only bundles / disk images / packages), and a first-party
    /// plugin ships as a bare `binary` inside an Ed25519 bundle. The honest posture
    /// is therefore "Developer-ID-anchored validity", the sandbox lane's own bar.
    /// If first-party plugin binaries are ever packaged so a notarization ticket can
    /// be verified, tighten this to a notarization requirement then.
    static func developerIDTrusted(path: String, allowUnsigned: Bool) -> Bool {
        if allowUnsigned { return true }
        var staticCode: SecStaticCode?
        guard SecStaticCodeCreateWithPath(URL(fileURLWithPath: path) as CFURL, [], &staticCode) == errSecSuccess,
              let code = staticCode else { return false }
        let reqStr: String
        // Reuse the sandbox lane's host-team resolution — no duplicate logic.
        if let team = SandboxedTierBRunner.hostTeamIdentifier() {
            reqStr = "anchor apple generic and certificate leaf[subject.OU] = \"\(team)\""
        } else {
            // Host team unknown (a Sec failure, or the host is ad-hoc/unsigned). In
            // RELEASE this means a signed-app Sec failure → FAIL CLOSED: never accept
            // an arbitrary Developer-ID binary as the first-party payload. The bare
            // anchor-apple-generic fallback is DEBUG-only (dev host).
            #if DEBUG
            reqStr = "anchor apple generic"
            #else
            return false
            #endif
        }
        var req: SecRequirement?
        guard SecRequirementCreateWithString(reqStr as CFString, [], &req) == errSecSuccess,
              let requirement = req else { return false }
        return SecStaticCodeCheckValidity(code, [], requirement) == errSecSuccess
    }

    /// Whether an unsigned / non-Developer-ID first-party payload may run — the
    /// DEBUG-only dev/test channel. In RELEASE this is ALWAYS false, so a shipped
    /// binary cannot be tricked (via env or a threaded flag) into running an
    /// unsigned payload unsandboxed. Mirrors `SandboxedTierBRunner.devOverrideAllowed`.
    static func devOverrideAllowed(explicit: Bool) -> Bool {
        #if DEBUG
        if explicit { return true }
        let env = ProcessInfo.processInfo.environment
        return env["MACCRAB_TIERB_DEV_FIRSTPARTY"] == "1" || env["MACCRAB_CORPUS"] != nil
        #else
        _ = explicit
        return false
        #endif
    }
}
