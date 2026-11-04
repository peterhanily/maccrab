// UserRuleOverlayTrust.swift
// MacCrabCore
//
// The ownership checks the engine applies to the user_rules overlay before it
// loads a file from it, for the code that shows which rule the engine applies:
// the MCP rule index behind explain_alert, and `maccrabctl why`. The engine
// keeps its own gates (DaemonSetup's `isSecureDirectory` and
// `isOverlayDirSecure` for the folder, `RuleEngine.loadRules(requireOwnerUID:)`
// for each file); these apply the same conditions, read with lstat.

import Foundation
import Darwin

public enum UserRuleOverlayTrust {
    /// The uid the engine runs as for a support directory: root for the
    /// installed engine, this process's user for a development daemon.
    public static func engineUID(forSupportDirectory supportDirectory: String) -> uid_t {
        supportDirectory == "/Library/Application Support/MacCrab" ? 0 : getuid()
    }

    /// The engine loads user rules only from a folder that is not a symlink,
    /// is owned by root or the engine's uid, and is writable by its owner
    /// alone, so a legacy root:admin 0775 folder is refused as a whole.
    public static func trustsDirectory(owner: uid_t, mode: mode_t, isSymlink: Bool, engineUID: uid_t) -> Bool {
        !isSymlink && (owner == 0 || owner == engineUID) && mode & 0o022 == 0
    }

    /// From a trusted folder, the engine loads only the files its uid owns.
    public static func trustsFile(owner: uid_t, engineUID: uid_t) -> Bool { owner == engineUID }

    /// `trustsDirectory` for the folder at `path`, read with lstat so that a
    /// symlink counts as one. Anything else that is not a directory, and a
    /// path lstat cannot read, is not trusted.
    public static func trustsDirectory(atPath path: String, engineUID: uid_t) -> Bool {
        var st = stat()
        guard lstat(path, &st) == 0 else { return false }
        let type = st.st_mode & S_IFMT
        guard type == S_IFDIR || type == S_IFLNK else { return false }
        return trustsDirectory(owner: st.st_uid, mode: st.st_mode, isSymlink: type == S_IFLNK, engineUID: engineUID)
    }

    /// `trustsFile` for the file at `path`, read with lstat. A path lstat
    /// cannot read is not trusted.
    public static func trustsFile(atPath path: String, engineUID: uid_t) -> Bool {
        var st = stat()
        guard lstat(path, &st) == 0 else { return false }
        return trustsFile(owner: st.st_uid, engineUID: engineUID)
    }
}
