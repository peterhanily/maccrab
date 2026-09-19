import Foundation
import MacCrabCore

/// Presentation contract shared by the menu bar, Overview, and System health.
/// A fresh file proves that a process reported; readiness proves that its
/// initialization completed. Neither implies the other.
enum V2EngineReadiness: String, Equatable {
    case starting, ready, unavailable

    init(bootPhase: String?, liveness: Bool?) {
        switch bootPhase {
        case "starting", "upgrading_store", "stores_ready", "rules_loaded", "collectors_started":
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

/// Counts describe durable upgrade work, not live monitoring. Only the current
/// upgrading phase may display them; a ready heartbeat must discard old counts.
struct V2StoreUpgradeProgress: Equatable, Sendable {
    let sourceEvents: Int
    let migratedEvents: Int
    let remainingEvents: Int
    let expiredEvents: Int?
    let corruptPreservedEvents: Int?
    var processedEvents: Int { sourceEvents - remainingEvents }

    init?(raw: [String: Any]) {
        guard raw["boot_phase"] as? String == "upgrading_store",
              let source = raw["upgrade_source_events"] as? Int,
              let migrated = raw["upgrade_migrated_events"] as? Int,
              let remaining = raw["upgrade_remaining_events"] as? Int,
              source >= 0, migrated >= 0, remaining >= 0,
              remaining <= source, migrated <= source - remaining else { return nil }
        let expired = raw["upgrade_expired_events"] as? Int
        let corrupt = raw["upgrade_corrupt_preserved_events"] as? Int
        let settledWithoutMigration = source - remaining - migrated
        if let expired, expired < 0 || expired > settledWithoutMigration { return nil }
        if let corrupt, corrupt < 0 || corrupt > settledWithoutMigration { return nil }
        if let expired, let corrupt, corrupt != settledWithoutMigration - expired { return nil }
        sourceEvents = source
        migratedEvents = migrated
        remainingEvents = remaining
        expiredEvents = expired
        corruptPreservedEvents = corrupt
    }

    static var title: String {
        String(localized: "startup.upgrade.title", defaultValue: "Upgrading event history")
    }

    static var detail: String {
        String(localized: "startup.upgrade.detail", defaultValue: "MacCrab is preparing your existing event history. Monitoring has not started yet; protection will be confirmed when startup completes.")
    }

    var counts: String {
        String(localized: "startup.upgrade.counts", defaultValue: "\(processedEvents) of \(sourceEvents) events processed · \(remainingEvents) remaining")
    }
}

/// The menu bar runs without a dashboard window or database provider. Read its
/// own current heartbeat so opening a window is never required to see an outage.
enum V2MenuBarProtectionStatus: Equatable {
    case active, starting, upgrading, degraded, unavailable

    static func resolve(heartbeat: V2HeartbeatSnapshot?, additionalDegradation: Bool = false,
                        now: Date = Date()) -> Self {
        guard let heartbeat, heartbeat.engineIdentity != nil else { return .unavailable }
        let age = now.timeIntervalSince(heartbeat.writtenAt)
        guard age.isFinite, age >= 0, age <= V2HeartbeatSnapshot.staleThreshold else { return .unavailable }
        if heartbeat.bootPhase == "upgrading_store" { return .upgrading }
        switch heartbeat.readiness {
        case .starting: return .starting
        case .unavailable: return .unavailable
        case .ready:
            let collectors = V2CollectorSummary(states: heartbeat.collectors.map(\.resolvedState))
            return additionalDegradation || !collectors.allEnabledHealthy
                || heartbeat.rulesLoaded == 0 || heartbeat.esSensorDegraded
                || heartbeat.traceGraphStorageAdmission?.evidenceUnavailable == true
                || heartbeat.browserInventory?.degraded == true
                || heartbeat.sequenceCheckpoint?.degraded == true
                || heartbeat.timerLifecycle?.featureDegraded == true
                || (heartbeat.detectionWorkLifecycle?.detectionProtectionDegraded
                    ?? heartbeat.legacyDerivedWorkLifecycle?.featureDegraded) == true
                || heartbeat.alertEvidenceBudget?.captureDegraded == true
                || heartbeat.alertEvidenceBudget?.transitionDegraded == true
                || heartbeat.alertWritesRequireAttention ? .degraded : .active
        }
    }

    var title: String { self == .active ? "🦀" : "🦀!" }

    var label: String {
        switch self {
        case .active: return "MacCrab — protection active"
        case .starting: return "MacCrab — protection starting; monitoring not ready"
        case .upgrading: return "MacCrab — upgrading event history; monitoring not ready"
        case .degraded: return "MacCrab — protection degraded; open System health"
        case .unavailable: return "MacCrab — protection unavailable; open System health"
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
