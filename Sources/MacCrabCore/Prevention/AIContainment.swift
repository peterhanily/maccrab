import Foundation
import os.log

/// Retired compatibility shell for the former "AI containment" module.
///
/// chmod/ACL permissions apply to a uid, not to one process identity. AI tools
/// normally run as the same uid as their operator, so changing a credential to
/// 0400 never prevented that tool from reading it; it only removed the owner's
/// write bit and later guessed 0600 while "restoring" metadata. Real process-
/// selective prevention requires an Endpoint Security AUTH_OPEN authorization
/// boundary. Until that exists, MacCrab detects and attributes credential reads
/// but does not claim to block them.
public actor AIContainment {

    /// Legacy source-compatibility reference. This retired module is excluded
    /// from the advertised D3FEND inventory and tactic mappings.
    @available(*, deprecated, message: "AIContainment is detection-only; no process-selective enforcement is available")
    public nonisolated static let d3fend = D3FENDMapping.aiContainment
    private let logger = Logger(subsystem: "com.maccrab.prevention", category: "ai-containment")

    public nonisolated static let enforcementAvailable = false
    public nonisolated static let retirementReason =
        "Process-selective credential blocking requires Endpoint Security AUTH_OPEN; chmod/ACL cannot distinguish same-uid AI processes."

    public init() {}

    /// Compatibility no-op. It intentionally performs no filesystem mutation
    /// and never reports the retired capability as enabled.
    public func enable() {
        logger.error("AI containment request ignored: \(Self.retirementReason, privacy: .public)")
    }

    /// Compatibility no-op; no metadata was changed by `enable()`.
    public func disable() {
        logger.info("AI containment is retired; no credential metadata to restore")
    }

    /// Always false: this actor has no authorization hook capable of blocking.
    public func wouldBlock(filePath: String, aiToolName: String) -> Bool {
        false
    }

    public func stats() -> (enabled: Bool, protectedCount: Int) {
        (false, 0)
    }
}
