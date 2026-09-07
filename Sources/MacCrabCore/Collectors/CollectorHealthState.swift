import Foundation

/// Fixed collector states shared by the engine heartbeat and dashboard.
public enum CollectorHealthState: String, Codable, Sendable, Hashable {
    case disabled, starting, healthy, failed, stalled

    public static func resolve(
        state: String?, enabled: Bool?, healthy: Bool, reason: String?, lastError: String?
    ) -> Self {
        if enabled == false { return .disabled }
        if let state {
            guard let value = Self(rawValue: state) else { return .failed }
            // Explicit enablement wins over a contradictory disabled state.
            if value == .disabled && enabled == true { return .failed }
            if value == .healthy && !healthy { return .failed }
            return value
        }
        if healthy { return .healthy }
        // Compatibility with older daemons. A missing start is not evidence of
        // intentional disablement; only the new explicit contract can say so.
        if reason == "started, awaiting first tick" { return .starting }
        if lastError != nil || reason == "stream ended" || reason == "errors reported"
            || reason?.hasPrefix("not started") == true { return .failed }
        return .stalled
    }

}
