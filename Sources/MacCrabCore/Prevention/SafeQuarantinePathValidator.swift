// SafeQuarantinePathValidator.swift
// MacCrabCore
//
// Refuses to quarantine files whose movement would damage the user's
// machine or strand them out of their own system. Used by
// ResponseEngine.quarantineFile (auto-quarantine, root sysext) and
// ManualResponse.quarantineFile (operator-initiated, user app).
//
// Quarantining a file means MOVING it to a quarantine vault. If the
// file is a system component, an Apple framework binary, MacCrab's own
// support data, or live user data (mail, calendars, keychain), moving
// it can:
//
//   - prevent the OS from booting (kernel kexts, login chain)
//   - break code-signing system-wide (System.framework copies, OCSP
//     cache)
//   - corrupt user data (Mail/V2 envelope-index, Calendar Cache.db)
//   - lock MacCrab out of its own state (SQLite WAL, compiled rules,
//     baseline.json)
//   - require Recovery Mode to fix
//
// The validator is conservative: when in doubt, refuse. The cost of
// "I wanted to quarantine a file in /Library/Apple/ but couldn't" is
// a logged warning the operator can override by moving the file
// manually. The cost of an over-eager auto-quarantine that bricks the
// user's mail database is a support nightmare with no recovery path.

import Foundation
import os.log

public enum SafeQuarantinePathValidator {

    private static let logger = Logger(subsystem: "com.maccrab.prevention", category: "safe-quarantine-validator")

    /// Path prefixes that must NEVER be quarantined. The list is intentionally
    /// broader than `SafePIDValidator.protectedPathPrefixes` because moving a
    /// file is more catastrophic than failing to kill a process — there's no
    /// "the OS will spawn it again" recovery for a quarantined system binary.
    public static let protectedPathPrefixes: [String] = [
        // Apple system code & frameworks — moving any of these breaks code
        // signing, kext loading, recovery boot.
        "/System/",
        "/Library/Apple/",
        "/Library/Frameworks/",
        "/Library/PrivilegedHelperTools/",
        "/Library/SystemExtensions/",
        "/Library/LaunchDaemons/",
        "/Library/LaunchAgents/",
        "/Library/Extensions/",
        "/Library/Filesystems/",
        "/Library/Audio/",
        "/Library/CoreMediaIO/",
        "/Library/PreferencePanes/",
        "/Library/QuickLook/",
        "/Library/Spotlight/",
        "/Library/Updates/",
        // Apple system binaries & libexecs
        "/usr/libexec/",
        "/usr/lib/",
        "/usr/sbin/",
        "/usr/bin/",
        "/usr/share/",
        "/sbin/",
        "/bin/",
        // System databases & runtime state — moving these locks the user
        // out of auth, package management, etc.
        "/private/var/db/",
        "/var/db/",
        "/private/var/folders/",
        "/var/folders/",
        "/private/etc/",
        "/etc/",
        // Boot / kernel
        "/private/var/vm/",
        "/var/vm/",
        // MacCrab's OWN state — never quarantine ourselves
        "/Library/Application Support/MacCrab/",
        // Apple App Store apps live here, signed; quarantine breaks the
        // receipt chain. (Third-party /Applications stays quarantine-able
        // because that's where most malware-quarantine targets live.)
    ]

    /// User-data path SUFFIXES inside the user's home that must not be moved.
    /// Same reasoning as `protectedPathPrefixes` but expressed relative to
    /// `/Users/<u>/` because per-user.
    public static let protectedHomeRelativeSuffixes: [String] = [
        // Mail data — quarantining envelope-index.sqlite or mbox files
        // corrupts the entire mailbox.
        "/Library/Mail/",
        "/Library/Containers/com.apple.mail/",
        // Calendar / Contacts / Reminders — same shape
        "/Library/Calendars/",
        "/Library/Application Support/AddressBook/",
        "/Library/Application Support/CallHistoryDB/",
        "/Library/Reminders/",
        // Keychain — moving this is worse than deleting; user can't sign
        // into anything.
        "/Library/Keychains/",
        // Safari history / bookmarks
        "/Library/Safari/",
        "/Library/Containers/com.apple.Safari/",
        // iCloud sync
        "/Library/Mobile Documents/",
        // Photos library
        "/Pictures/Photos Library.photoslibrary/",
        // MacCrab's own per-user data
        "/Library/Application Support/MacCrab/",
        // Time Machine local snapshots / backup metadata
        "/Library/Application Support/com.apple.backupd/",
        // Generic Apple system preferences (per-user copy)
        "/Library/Preferences/com.apple.",
    ]

    /// Returns nil if the path is safe to quarantine, or a human-readable
    /// rejection reason otherwise. The reason is suitable for logging.
    public static func reasonToReject(path: String) -> String? {
        let trimmed = path.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.isEmpty {
            return "empty path"
        }
        // Reject relative paths — quarantine works on absolutes, and a
        // relative path could resolve unpredictably under different cwds.
        if !trimmed.hasPrefix("/") {
            return "path is not absolute: \(trimmed)"
        }

        // Resolve symlinks so an attacker who plants a symlink at /tmp/foo
        // -> /System/Library/X can't trick us into quarantining the system
        // binary. realpath returns the canonical absolute path.
        let canonical: String = {
            guard let resolved = (trimmed as NSString).resolvingSymlinksInPath as String?,
                  !resolved.isEmpty else {
                return trimmed
            }
            return resolved
        }()

        for prefix in protectedPathPrefixes {
            if canonical.hasPrefix(prefix) || trimmed.hasPrefix(prefix) {
                return "path \(canonical) is on a protected system prefix (\(prefix))"
            }
        }

        // Check user-home-relative protected suffixes. Match against any
        // `/Users/<u>/<suffix>` shape. Apply to both the original and the
        // symlink-resolved path so symlink games can't bypass.
        for suffix in protectedHomeRelativeSuffixes {
            if canonical.range(of: "/Users/[^/]+\(suffix)", options: .regularExpression) != nil {
                return "path \(canonical) is on a protected per-user data location (matches /Users/<u>\(suffix))"
            }
            if trimmed.range(of: "/Users/[^/]+\(suffix)", options: .regularExpression) != nil {
                return "path \(trimmed) is on a protected per-user data location (matches /Users/<u>\(suffix))"
            }
        }

        return nil
    }

    /// Convenience wrapper. Logs a warning on rejection so callers don't
    /// need their own log line.
    public static func isSafeToQuarantine(path: String) -> Bool {
        if let reason = reasonToReject(path: path) {
            logger.warning("Refusing to quarantine: \(reason, privacy: .public)")
            return false
        }
        return true
    }
}
