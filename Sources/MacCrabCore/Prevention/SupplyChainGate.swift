import Foundation
import Darwin
import os.log

/// Blocks installation of suspiciously fresh packages by killing the
/// installer process when the package freshness check returns critical risk.
public actor SupplyChainGate {

    /// MITRE D3FEND defensive technique this module implements.
    public nonisolated static let d3fend = D3FENDMapping.supplyChainGate
    private let logger = Logger(subsystem: "com.maccrab.prevention", category: "supply-chain-gate")

    public struct BlockedInstall: Sendable {
        public let packageName: String
        public let registry: String
        public let ageHours: Double?
        public let installerPid: Int32
        public let reason: String
        public let timestamp: Date
    }

    private var isEnabled = false
    private var blockedInstalls: [BlockedInstall] = []
    private let maxAgeHours: Double  // Block packages younger than this

    public init(maxAgeHours: Double = 24) {
        self.maxAgeHours = maxAgeHours
    }

    /// Enable the supply chain gate.
    public func enable() {
        isEnabled = true
        logger.info("Supply chain gate enabled: blocking packages < \(self.maxAgeHours)h old")
    }

    /// Disable the gate.
    public func disable() {
        isEnabled = false
        logger.info("Supply chain gate disabled")
    }

    /// Check a package and kill the installer if it's too fresh.
    /// Returns a BlockedInstall if the package was blocked, nil otherwise.
    public func gate(
        packageName: String,
        registry: String,
        ageInDays: Double?,
        riskLevel: String,
        installerPid: Int32
    ) -> BlockedInstall? {
        guard isEnabled else { return nil }

        // Block if critical risk or if age is under threshold
        let shouldBlock: Bool
        let reason: String

        if riskLevel == "critical" {
            shouldBlock = true
            reason = "Critical risk package — unknown, not found, or extremely fresh"
        } else if let age = ageInDays, age * 24 < maxAgeHours {
            shouldBlock = true
            reason = "Package published \(String(format: "%.1f", age * 24)) hours ago (threshold: \(maxAgeHours)h)"
        } else {
            shouldBlock = false
            reason = ""
        }

        guard shouldBlock else { return nil }

        // SAFETY: refuse to kill PIDs that would damage the system or trap the
        // user (PID 1, WindowServer, securityd, /System/..., MacCrab itself).
        guard SafePIDValidator.isSafeToKill(pid: installerPid) else {
            logger.warning("Refused to block \(packageName, privacy: .public): installer PID \(installerPid) is on the safe-kill protect list")
            return nil
        }

        // SAFETY: verify the PID descends from a known package manager. If we
        // can't find a recognized ancestor in 5 hops, the PID was probably
        // misidentified — refuse rather than kill an unrelated user process.
        guard Self.descendsFromPackageManager(pid: installerPid) else {
            logger.warning("Refused to block \(packageName, privacy: .public): installer PID \(installerPid) does not descend from a known package manager")
            return nil
        }

        // Capture the original path so we can detect a recycled PID before
        // the delayed SIGKILL fires.
        let originalPath = Self.processPath(for: installerPid)

        // Send SIGTERM
        kill(installerPid, SIGTERM)
        logger.warning("Blocked package install: \(packageName) from \(registry). \(reason). Killed PID \(installerPid)")

        // After 2 seconds, SIGKILL — but only if the PID still resolves to
        // the same path. Otherwise the original process exited and the PID
        // was recycled to a different binary; killing it would hit the
        // wrong target.
        //
        // Use a fresh Logger inside the closure rather than capturing
        // self.logger — the closure runs 2s later on a global queue and
        // capturing actor state could outlive the actor.
        DispatchQueue.global().asyncAfter(deadline: .now() + 2) {
            let currentPath = Self.processPath(for: installerPid)
            guard currentPath == originalPath else {
                Logger(subsystem: "com.maccrab.prevention", category: "supply-chain-gate")
                    .info("Skipped SIGKILL on PID \(installerPid): process exited or PID was recycled (path drift)")
                return
            }
            kill(installerPid, SIGKILL)
        }

        let blocked = BlockedInstall(
            packageName: packageName,
            registry: registry,
            ageHours: ageInDays.map { $0 * 24 },
            installerPid: installerPid,
            reason: reason,
            timestamp: Date()
        )
        blockedInstalls.append(blocked)

        return blocked
    }

    /// Get history of blocked installs.
    public func history() -> [BlockedInstall] { blockedInstalls }

    public func stats() -> (enabled: Bool, blocked: Int) {
        (isEnabled, blockedInstalls.count)
    }

    // MARK: - Process ancestry helpers (nonisolated, used from the actor and
    // from the dispatch closure that fires the delayed SIGKILL).

    /// Recognized package-manager binary basenames. A PID descending from any
    /// of these in ≤5 hops is considered a legitimate installer target.
    /// Shells (bash, sh, zsh) are deliberately NOT included — every user
    /// process descends from a shell, so including them would defeat the check.
    static let packageManagerNames: Set<String> = [
        // macOS native
        "brew", "installer", "softwareupdate", "mas", "port",
        // Node ecosystem (node included because npm/pnpm/yarn run as node)
        "npm", "pnpm", "yarn", "npx", "node",
        // Python
        "pip", "pip3", "pip2", "python", "python3", "python2",
        "uv", "poetry", "pipenv", "conda",
        // Ruby
        "gem", "ruby", "bundle", "rake",
        // Rust / Go
        "cargo", "rustup", "go",
        // Java
        "gradle", "mvn", "sbt",
        // PHP / .NET
        "composer", "php", "dotnet", "nuget",
    ]

    /// Walk up to 5 ancestors of `pid` and return true if any has a basename
    /// in `packageManagerNames`.
    nonisolated static func descendsFromPackageManager(pid: Int32) -> Bool {
        var current = pid
        for _ in 0..<5 {
            if let name = processBasename(for: current),
               packageManagerNames.contains(name) {
                return true
            }
            let parent = parentPID(for: current)
            // Stop at PID 1 (launchd) — beyond it is the kernel.
            // Also stop on a self-loop (defensive).
            guard parent > 1, parent != current else { return false }
            current = parent
        }
        return false
    }

    /// Return the executable path of a process, or nil if proc_pidpath fails.
    nonisolated static func processPath(for pid: Int32) -> String? {
        var buffer = [CChar](repeating: 0, count: Int(MAXPATHLEN))
        let len = proc_pidpath(pid, &buffer, UInt32(buffer.count))
        guard len > 0 else { return nil }
        return String(cString: buffer)
    }

    /// Return the basename of a process, or nil if proc_pidpath fails.
    nonisolated static func processBasename(for pid: Int32) -> String? {
        guard let path = processPath(for: pid) else { return nil }
        return (path as NSString).lastPathComponent
    }

    /// Return the parent PID, or 0 if the lookup fails.
    nonisolated static func parentPID(for pid: Int32) -> Int32 {
        var bsdInfo = proc_bsdinfo()
        let size = Int32(MemoryLayout<proc_bsdinfo>.size)
        let result = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &bsdInfo, size)
        guard result == size else { return 0 }
        return Int32(bsdInfo.pbi_ppid)
    }
}
