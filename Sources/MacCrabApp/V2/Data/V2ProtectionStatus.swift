import Foundation
import MacCrabCore

/// Presentation contract shared by the menu bar, Overview, and System health.
/// A fresh file proves that a process reported; readiness proves that its
/// initialization completed. Neither implies the other.
enum V2EngineReadiness: String, Equatable {
    case starting, ready, unavailable

    init(bootPhase: String?, liveness: Bool?) {
        switch bootPhase {
        case "starting", "stores_ready", "rules_loaded", "collectors_started":
            self = .starting
        case "ready":
            self = liveness == false ? .starting : .ready
        case nil:
            self = liveness == true ? .ready : .unavailable
        default:
            // Includes storage_not_ready and any future failure phase. Unknown
            // phase names must not become a green status by default.
            self = .unavailable
        }
    }
}

enum V2ProtectionStatus: Equatable {
    case active, starting, unavailable, degraded, inactive

    static func resolve(
        providerLive: Bool,
        heartbeatPresent: Bool,
        heartbeatStale: Bool,
        readiness: V2EngineReadiness,
        degraded: Bool
    ) -> Self {
        guard heartbeatPresent else { return providerLive ? .unavailable : .inactive }
        guard !heartbeatStale else { return .degraded }
        // Startup can precede the database connection. Keep its real state
        // visible even while the provider is still waiting for the stores.
        switch readiness {
        case .starting: return .starting
        case .unavailable: return .unavailable
        case .ready: return providerLive && !degraded ? .active : .degraded
        }
    }
}

public typealias V2CollectorState = CollectorHealthState

extension CollectorHealthState {
    var label: String {
        switch self {
        case .disabled: return String(localized: "system.collectorDisabled", defaultValue: "Disabled")
        case .starting: return String(localized: "system.collectorStarting", defaultValue: "Starting")
        case .healthy: return String(localized: "system.collectorHealthy", defaultValue: "Healthy")
        case .failed: return String(localized: "system.collectorFailed", defaultValue: "Failed")
        case .stalled: return String(localized: "system.collectorStalled", defaultValue: "Stalled")
        }
    }

    var chipKind: V2ChipKind {
        switch self {
        case .disabled: return .neutral
        case .starting: return .info
        case .healthy: return .healthy
        case .failed, .stalled: return .high
        }
    }

    var sortOrder: Int {
        switch self {
        case .failed: return 0
        case .stalled: return 1
        case .starting: return 2
        case .healthy: return 3
        case .disabled: return 4
        }
    }
}

struct V2CollectorSummary: Equatable {
    let enabledCount: Int
    let healthyCount: Int
    let startingCount: Int
    let failedCount: Int
    let disabledCount: Int

    init(states: [V2CollectorState]) {
        enabledCount = states.filter { $0 != .disabled }.count
        healthyCount = states.filter { $0 == .healthy }.count
        startingCount = states.filter { $0 == .starting }.count
        failedCount = states.filter { $0 == .failed || $0 == .stalled }.count
        disabledCount = states.filter { $0 == .disabled }.count
    }

    var allEnabledHealthy: Bool { enabledCount > 0 && healthyCount == enabledCount }
}

/// Never mix a new process's liveness with an old process's collector health.
/// Rich telemetry is allowed to lag one write; it must still be fresh and
/// belong to the same boot. This is also used by AppState's richer decoder.
enum V2HeartbeatPayload {
    static func currentRich(
        _ rich: [String: Any], minimal: [String: Any], now: Date = Date()
    ) -> Bool {
        guard let written = rich["written_at_unix"] as? TimeInterval,
              written.isFinite,
              now.timeIntervalSince1970 - written >= 0,
              now.timeIntervalSince1970 - written <= V2HeartbeatSnapshot.staleThreshold,
              let identity = EngineTelemetryIdentity(heartbeat: minimal),
              EngineTelemetryIdentity(heartbeat: rich) == identity,
              written >= identity.startedAtUnix
        else { return false }
        return true
    }
}
