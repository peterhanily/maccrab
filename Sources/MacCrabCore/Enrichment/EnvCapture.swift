// EnvCapture.swift
// MacCrabCore
//
// Captures environment variables from a target process via
// `sysctl(KERN_PROCARGS2)`. Opt-in only — controlled by the env var
// `MACCRAB_CAPTURE_ENV=1` checked at the call site. Never captures
// secret-bearing keys; allowlist is narrow by design.
//
// Used by EventEnricher on exec/fork events so rules like
// dyld_insert_libraries_env can match against the flattened env string.

import Foundation
import Darwin

public enum EnvCapture {

    // MARK: - Allow / deny lists

    /// Keys we capture by default. Values here are either behavior-changing
    /// system variables (DYLD_*, LD_*) or investigation context (SSH_*,
    /// SUDO_*, TERM_*). Secret-bearing keys are NOT here.
    public static let defaultAllowlist: Set<String> = [
        "PATH", "HOME", "USER", "LOGNAME", "SHELL", "PWD", "OLDPWD",
        "LANG", "LC_ALL",
        "TERM_PROGRAM", "TERM_SESSION_ID", "ITERM_SESSION_ID",
        // Dynamic linker injection hooks — high-signal for dylib hijacks.
        "DYLD_INSERT_LIBRARIES", "DYLD_FORCE_FLAT_NAMESPACE",
        "DYLD_PRINT_LIBRARIES", "DYLD_LIBRARY_PATH",
        "LD_LIBRARY_PATH", "LD_PRELOAD",
        // SSH session context.
        "SSH_CLIENT", "SSH_CONNECTION", "SSH_TTY",
        // sudo forensic trail.
        "SUDO_USER", "SUDO_UID", "SUDO_GID", "SUDO_COMMAND",
        // Cloud profile names (NOT secrets).
        "AWS_PROFILE", "AWS_DEFAULT_REGION", "AWS_REGION",
        "GOOGLE_APPLICATION_CREDENTIALS",  // path, not token
    ]

    /// Keys that must never be captured even if they somehow appear in an
    /// allowlist override. Kept separate so a user widening the allowlist
    /// can't accidentally sweep in secrets.
    public static let alwaysDeny: Set<String> = [
        "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
        "AZURE_CLIENT_SECRET",
        "GITHUB_TOKEN", "GH_TOKEN", "GITLAB_TOKEN",
        "SLACK_TOKEN", "SLACK_BOT_TOKEN",
        "NPM_TOKEN", "PYPI_TOKEN",
        "DATABASE_URL", "DATABASE_PASSWORD",
        "OPENAI_API_KEY", "ANTHROPIC_API_KEY",
    ]

    /// Substring patterns that trigger unconditional deny (covers custom
    /// app-specific secret keys). Case-insensitive.
    private static let denySubstrings: [String] = [
        "secret", "token", "password", "apikey", "api_key",
        "auth_token", "private_key", "credentials",
    ]

    // MARK: - Public API

    /// Capture and filter env vars for a PID. Returns nil if sysctl fails
    /// (process gone, permission denied, etc.).
    ///
    /// Secrets are filtered by both the explicit alwaysDeny set AND the
    /// denySubstrings fuzzy match, applied BEFORE the allowlist check.
    public static func capture(
        pid: Int32,
        allowlist: Set<String> = defaultAllowlist
    ) -> [String: String]? {
        guard let data = readProcArgs(pid: pid) else { return nil }
        let raw = parseEnv(from: data)
        return filter(raw, allowlist: allowlist)
    }

    // MARK: - Parser (testable)

    /// Parse the `KERN_PROCARGS2` buffer layout:
    /// [4 bytes: argc][exe path + null][null-padding][argc argv strings +
    /// nulls][envp strings + nulls][double-null]
    static func parseEnv(from data: Data) -> [String: String] {
        guard data.count > 4 else { return [:] }

        let argc = Int(data.withUnsafeBytes { raw -> Int32 in
            raw.load(as: Int32.self)
        })

        var offset = 4
        // Skip executable path
        while offset < data.count && data[offset] != 0 { offset += 1 }
        // Skip any alignment padding (zeros)
        while offset < data.count && data[offset] == 0 { offset += 1 }
        // Skip argc argv strings
        var seen = 0
        while offset < data.count && seen < argc {
            while offset < data.count && data[offset] != 0 { offset += 1 }
            offset += 1  // consume null
            seen += 1
        }

        // Now we're at the first env var.
        var env: [String: String] = [:]
        var start = offset
        while offset < data.count {
            if data[offset] == 0 {
                if offset == start {
                    break  // empty entry = end of envp
                }
                let slice = data[start..<offset]
                if let s = String(data: slice, encoding: .utf8),
                   let eq = s.firstIndex(of: "=") {
                    let k = String(s[..<eq])
                    let v = String(s[s.index(after: eq)...])
                    env[k] = v
                }
                start = offset + 1
            }
            offset += 1
        }
        return env
    }

    // MARK: - Filter (testable)

    /// Apply deny list + allowlist, returning only keys we're willing to
    /// capture. Secret values are replaced with an empty dict entry (nil
    /// key is dropped).
    static func filter(
        _ env: [String: String],
        allowlist: Set<String>
    ) -> [String: String] {
        var out: [String: String] = [:]
        for (k, v) in env {
            guard !alwaysDeny.contains(k) else { continue }
            let lower = k.lowercased()
            if denySubstrings.contains(where: { lower.contains($0) }) {
                continue
            }
            guard allowlist.contains(k) else { continue }
            out[k] = v
        }
        return out
    }

    // MARK: - sysctl read

    private static func readProcArgs(pid: Int32) -> Data? {
        var mib: [Int32] = [CTL_KERN, KERN_PROCARGS2, pid]
        var size: Int = 0
        if sysctl(&mib, 3, nil, &size, nil, 0) != 0 { return nil }
        guard size > 0 else { return nil }

        var buf = [UInt8](repeating: 0, count: size)
        let ok = buf.withUnsafeMutableBufferPointer { ptr -> Bool in
            sysctl(&mib, 3, ptr.baseAddress, &size, nil, 0) == 0
        }
        guard ok else { return nil }
        return Data(buf.prefix(size))
    }
}
