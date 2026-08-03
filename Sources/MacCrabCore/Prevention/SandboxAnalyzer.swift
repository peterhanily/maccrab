import Foundation
import os.log

/// Historical API for suspicious-binary dynamic analysis.
///
/// Dynamic execution is deliberately disabled. The only production caller is
/// the root system extension, and the old `(allow default)` sandbox-exec
/// profile re-ran an attacker-selected Downloads/tmp binary as root while
/// still allowing broad filesystem, Mach/XPC, and process access. A safe
/// replacement requires a separately signed, unprivileged, deny-default broker
/// with a measured containment probe; it cannot live in the root engine.
public actor SandboxAnalyzer {

    /// MITRE D3FEND defensive technique this module implements.
    public nonisolated static let d3fend = D3FENDMapping.sandboxAnalyzer
    private let logger = Logger(subsystem: "com.maccrab.prevention", category: "sandbox-analyzer")
    private var didLogDisabledState = false

    /// Analysis result
    public struct AnalysisResult: Sendable {
        public let binaryPath: String
        public let exitCode: Int32
        public let blockedOperations: [String]  // Operations the sandbox blocked
        public let output: String               // First 4KB of stdout/stderr
        public let duration: TimeInterval
        public let isSuspicious: Bool
    }

    /// Exposed for a guard test and diagnostics. This must remain false until
    /// the broker above exists and has a host-level escape corpus.
    public nonisolated static let dynamicExecutionEnabled = false

    public init(timeout _: TimeInterval = 10) {}

    /// Analyze a binary in a restricted sandbox.
    /// Returns nil because privileged in-process dynamic execution is retired.
    public func analyze(binaryPath: String) -> AnalysisResult? {
        if !didLogDisabledState {
            logger.notice("Unsafe in-engine dynamic execution is disabled; skipped \(binaryPath, privacy: .public)")
            didLogDisabledState = true
        }
        return nil
    }
}
