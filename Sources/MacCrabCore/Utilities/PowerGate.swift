// PowerGate.swift
// MacCrabCore
//
// Battery and thermal state gating for poll-based collectors. Commercial
// EDR adoption on macOS laptops lives and dies by battery impact — a tool
// that drains 30% per day gets uninstalled no matter how good its detections
// are. PowerGate exposes a single multiplier that collectors apply to their
// base poll interval so they slow down automatically on battery or under
// thermal pressure, with zero user configuration.

import Foundation

/// Scales poll intervals based on current power and thermal state. All
/// access is through static members — `ProcessInfo.processInfo` is
/// thread-safe for reads so no actor isolation is needed.
public enum PowerGate {

    /// Multiplier applied to base poll intervals. Always ≥ 1.0 — we never
    /// speed up collectors, only slow them down when the system is stressed.
    ///
    /// Current policy:
    ///   - Low Power Mode enabled        → 3.0×   (user explicitly asked for battery savings)
    ///   - Thermal state critical/serious → 2.5×   (throttle before the OS throttles us)
    ///   - Thermal state fair             → 1.5×   (light touch; still responsive)
    ///   - AC power + nominal             → 1.0×   (normal)
    ///
    /// Tuning knob lives here intentionally: one constant change affects
    /// every collector uniformly. If we later learn a collector needs a
    /// different curve, it can override with `adjustedInterval(base:
    /// aggressiveness:)`.
    public static var pollIntervalMultiplier: Double {
        let info = Foundation.ProcessInfo.processInfo
        if info.isLowPowerModeEnabled { return 3.0 }
        switch info.thermalState {
        case .critical, .serious: return 2.5
        case .fair: return 1.5
        case .nominal: return 1.0
        @unknown default: return 1.0
        }
    }

    /// Scale a base interval by the current multiplier. Round-trip safe:
    /// passing a base of 2s on AC gives back 2s exactly.
    public static func adjustedInterval(base: TimeInterval) -> TimeInterval {
        base * pollIntervalMultiplier
    }

    /// Scale a base interval with an aggressiveness knob: 1.0 = default
    /// curve, 2.0 = double the slowdown on battery (for truly optional
    /// collectors like ClipboardMonitor / USBMonitor), 0.5 = half the
    /// slowdown (for collectors that need to stay snappy).
    ///
    /// Clamps final multiplier to ≥ 1.0 so we can't accidentally make a
    /// collector faster than it asked for.
    public static func adjustedInterval(
        base: TimeInterval,
        aggressiveness: Double
    ) -> TimeInterval {
        let scaled = 1.0 + (pollIntervalMultiplier - 1.0) * aggressiveness
        return base * max(1.0, scaled)
    }

    /// Human-readable description of the current state. Useful for the
    /// dashboard's ES Health view, or `os_log` diagnostics on why an
    /// interval has stretched.
    public static var stateDescription: String {
        let info = Foundation.ProcessInfo.processInfo
        if info.isLowPowerModeEnabled { return "low-power-mode" }
        switch info.thermalState {
        case .critical: return "thermal-critical"
        case .serious: return "thermal-serious"
        case .fair: return "thermal-fair"
        case .nominal: return "nominal"
        @unknown default: return "unknown"
        }
    }
}
