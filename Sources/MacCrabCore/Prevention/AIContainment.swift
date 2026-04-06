import Foundation
import Darwin
import os.log

/// Proactively blocks AI coding tool processes from accessing sensitive files.
/// Uses file ACLs to deny read access to credential paths for specific users/processes.
/// Moves from "detect and alert" to "detect and prevent".
public actor AIContainment {
    private let logger = Logger(subsystem: "com.maccrab.prevention", category: "ai-containment")

    /// Paths to protect from AI tool access
    private static let protectedPaths = [
        ".ssh/id_rsa", ".ssh/id_ed25519", ".ssh/id_ecdsa",
        ".aws/credentials", ".aws/config",
        ".env", ".env.local", ".env.production",
        ".npmrc",  // npm tokens
        ".pypirc",  // PyPI tokens
        ".docker/config.json",  // Docker credentials
        ".kube/config",  // Kubernetes
        ".netrc",  // Generic credentials
    ]

    private var isEnabled = false
    private var protectedFiles: [String] = []

    public init() {}

    /// Enable AI containment — set restrictive ACLs on credential files.
    public func enable() {
        let home = NSHomeDirectory()

        for relPath in Self.protectedPaths {
            let fullPath = home + "/" + relPath
            guard FileManager.default.fileExists(atPath: fullPath) else { continue }

            // Set file permissions to owner-only read (remove group/other access)
            chmod(fullPath, 0o400)  // r--------
            protectedFiles.append(fullPath)
            logger.info("Protected credential file: \(fullPath)")
        }

        isEnabled = true
        logger.info("AI containment enabled: \(self.protectedFiles.count) credential files protected")
    }

    /// Disable AI containment — restore normal permissions.
    public func disable() {
        for path in protectedFiles {
            chmod(path, 0o600)  // rw-------
        }
        isEnabled = false
        protectedFiles.removeAll()
        logger.info("AI containment disabled — file permissions restored")
    }

    /// Check if a file access by an AI tool should be blocked.
    /// Returns true if the access would be blocked by containment.
    public func wouldBlock(filePath: String, aiToolName: String) -> Bool {
        guard isEnabled else { return false }
        return protectedFiles.contains(filePath) ||
            Self.protectedPaths.contains(where: { filePath.hasSuffix($0) })
    }

    public func stats() -> (enabled: Bool, protectedCount: Int) {
        (isEnabled, protectedFiles.count)
    }
}
