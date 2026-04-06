import Foundation
import os.log

/// Analyzes suspicious binaries by executing them in a macOS sandbox.
/// Uses sandbox-exec (deprecated but functional on macOS 26) to restrict
/// network access, file writes, and process spawning during analysis.
public actor SandboxAnalyzer {
    private let logger = Logger(subsystem: "com.maccrab.prevention", category: "sandbox-analyzer")

    /// Analysis result
    public struct AnalysisResult: Sendable {
        public let binaryPath: String
        public let exitCode: Int32
        public let blockedOperations: [String]  // Operations the sandbox blocked
        public let output: String               // First 4KB of stdout/stderr
        public let duration: TimeInterval
        public let isSuspicious: Bool
    }

    /// Restrictive sandbox profile that allows execution but blocks dangerous operations
    private static let analysisProfile = """
    (version 1)
    (allow default)
    (deny network*)
    (deny file-write* (subpath "/Library"))
    (deny file-write* (subpath "/etc"))
    (deny file-write* (subpath "/usr"))
    (deny file-write* (subpath "/System"))
    (deny file-write* (regex #"/Users/.*/Library/LaunchAgents"))
    (deny file-write* (regex #"/Users/.*/\\.ssh"))
    (deny file-write* (regex #"/Users/.*/\\.aws"))
    (deny file-write* (regex #"/Users/.*/\\.env"))
    (deny process-exec* (subpath "/usr/bin/osascript"))
    (deny process-exec* (subpath "/usr/bin/curl"))
    (deny process-exec* (subpath "/usr/bin/wget"))
    """

    private let timeout: TimeInterval

    public init(timeout: TimeInterval = 10) {
        self.timeout = timeout
    }

    /// Analyze a binary in a restricted sandbox.
    /// Returns nil if the binary doesn't exist or can't be analyzed.
    public func analyze(binaryPath: String) -> AnalysisResult? {
        let fm = FileManager.default
        guard fm.fileExists(atPath: binaryPath),
              fm.isExecutableFile(atPath: binaryPath) else { return nil }

        // Don't analyze system binaries
        if binaryPath.hasPrefix("/System/") || binaryPath.hasPrefix("/usr/") {
            return nil
        }

        let start = Date()

        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: "/usr/bin/sandbox-exec")
        proc.arguments = ["-p", Self.analysisProfile, binaryPath]

        let outputPipe = Pipe()
        let errorPipe = Pipe()
        proc.standardOutput = outputPipe
        proc.standardError = errorPipe

        do {
            try proc.run()
        } catch {
            logger.warning("Failed to start sandbox analysis: \(error.localizedDescription)")
            return nil
        }

        // Kill after timeout
        let timer = DispatchSource.makeTimerSource()
        timer.schedule(deadline: .now() + timeout)
        timer.setEventHandler { proc.terminate() }
        timer.resume()

        proc.waitUntilExit()
        timer.cancel()

        let duration = Date().timeIntervalSince(start)

        let stdout = String(data: outputPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        let stderr = String(data: errorPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        let output = String((stdout + "\n" + stderr).prefix(4096))

        // Parse sandbox violations from stderr
        var blockedOps: [String] = []
        for line in stderr.components(separatedBy: "\n") {
            if line.contains("deny") || line.contains("sandbox") || line.contains("violation") {
                blockedOps.append(line.trimmingCharacters(in: .whitespaces))
            }
        }

        // Suspicious if it tried to do things the sandbox blocked
        let isSuspicious = !blockedOps.isEmpty || proc.terminationStatus != 0

        return AnalysisResult(
            binaryPath: binaryPath,
            exitCode: proc.terminationStatus,
            blockedOperations: blockedOps,
            output: output,
            duration: duration,
            isSuspicious: isSuspicious
        )
    }
}
