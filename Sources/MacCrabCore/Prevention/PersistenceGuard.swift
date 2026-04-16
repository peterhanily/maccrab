import Foundation
import Darwin
import os.log

/// Protects persistence directories from unauthorized modification
/// using chflags system immutable flag (schg).
public actor PersistenceGuard {

    /// MITRE D3FEND defensive technique this module implements.
    public nonisolated static let d3fend = D3FENDMapping.persistenceGuard
    private let logger = Logger(subsystem: "com.maccrab.prevention", category: "persistence-guard")

    /// Directories to protect
    private static let protectedPaths = [
        "/Library/LaunchDaemons",
        "/Library/LaunchAgents",
        "/Library/Security/SecurityAgentPlugins",
        "/Library/DirectoryServices/PlugIns",
    ]

    /// User-level paths (resolved at runtime)
    private static func userProtectedPaths() -> [String] {
        let home = NSHomeDirectory()
        return [
            home + "/Library/LaunchAgents",
        ]
    }

    private var isEnabled = false
    private var protectedDirs: [String] = []

    public init() {}

    /// Lock persistence directories with system immutable flag.
    /// Only root can unlock (chflags noschg).
    public func enable() {
        protectedDirs = Self.protectedPaths + Self.userProtectedPaths()

        for dir in protectedDirs {
            guard FileManager.default.fileExists(atPath: dir) else { continue }
            // Set system immutable flag — prevents writes even by root unless flag is removed
            let result = chflags(dir, UInt32(SF_IMMUTABLE))
            if result == 0 {
                logger.info("Locked persistence directory: \(dir)")
            } else {
                logger.warning("Failed to lock \(dir): \(String(cString: strerror(errno)))")
            }
        }

        isEnabled = true
        logger.info("Persistence guard enabled: \(self.protectedDirs.count) directories locked")
    }

    /// Unlock persistence directories.
    public func disable() {
        for dir in protectedDirs {
            let _ = chflags(dir, 0)
            logger.info("Unlocked persistence directory: \(dir)")
        }
        isEnabled = false
        protectedDirs.removeAll()
        logger.info("Persistence guard disabled")
    }

    /// Temporarily unlock a directory for a legitimate operation, then re-lock.
    public func withUnlockedDirectory(_ path: String, operation: () throws -> Void) rethrows {
        let _ = chflags(path, 0)
        defer { if isEnabled { let _ = chflags(path, UInt32(SF_IMMUTABLE)) } }
        try operation()
    }

    public func stats() -> (enabled: Bool, protectedCount: Int) {
        (isEnabled, protectedDirs.count)
    }
}
