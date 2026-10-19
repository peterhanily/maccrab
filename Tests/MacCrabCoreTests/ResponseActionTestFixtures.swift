import Foundation
import Testing
@testable import MacCrabCore

/// Records policy admission without addressing real PIDs, PF, files or the
/// notification service. Integration fixtures for actual owned resources do
/// not use this helper: this seam tests routing, not successful containment.
actor ResponseActionTestRecorder {
    struct Invocation: Sendable, Equatable {
        let action: ResponseActionType
        let eventID: UUID
        let processID: Int32
        let ruleID: String
    }

    private let success: Bool
    private(set) var invocations: [Invocation] = []

    init(success: Bool = true) { self.success = success }

    func execute(_ config: ResponseActionConfig, alert: Alert, event: Event) -> (target: String, success: Bool) {
        invocations.append(.init(action: config.action, eventID: event.id,
                                 processID: event.process.pid, ruleID: alert.ruleId))
        return ("fixture:\(config.action.rawValue)", success)
    }
}

func makeInertResponseEngine(
    recording recorder: ResponseActionTestRecorder,
    userConfigSnapshotProvider: @escaping ResponseEngine.UserConfigSnapshotProvider = { nil }
) -> ResponseEngine {
    let blocks = TemporaryNetworkBlocks(io: .init(
        write: { _ in Issue.record("inert response fixture reached PF writes"); return false },
        reload: { Issue.record("inert response fixture reached PF reload"); return .init(loaded: false, enforcing: false) },
        legacyStateUnverified: { false }))
    return ResponseEngine(
        quarantineDir: FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString).path,
        temporaryNetworkBlocks: blocks,
        actionExecutor: { config, alert, event in
            await recorder.execute(config, alert: alert, event: event)
        },
        userConfigSnapshotProvider: userConfigSnapshotProvider)
}
