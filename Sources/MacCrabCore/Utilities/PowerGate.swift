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
import IOKit.ps

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
    /// NOTE (v1.21.5): this property is PRESSURE-ONLY (Low Power Mode + thermal).
    /// The battery term deliberately lives in `batteryAwarePollMultiplier`, which
    /// is what collectors apply — see the rationale there for why the two must
    /// stay separate.
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

    /// True when this Mac is currently drawing from battery rather than AC.
    ///
    /// v1.21.5: the type doc has claimed since v1.x that collectors "slow down
    /// automatically on battery", but nothing here ever read the power source —
    /// only Low Power Mode and thermal state. On the common laptop case
    /// (unplugged, LPM off, nominal thermals) the whole gate returned exactly
    /// 1.0×, i.e. it was inert precisely where it was supposed to earn its keep.
    ///
    /// The reading is memoised for `powerSourceCacheSeconds`: an
    /// `IOPSCopyPowerSourcesInfo` snapshot walks the IOKit registry, and the
    /// short-interval collectors (Clipboard 2 s, USB 10 s, Network 5 s) would
    /// otherwise pay for it on every tick — a perf fix must not become a perf
    /// cost. A desktop with no battery reports AC and costs one lookup per
    /// cache window.
    public static var isOnBatteryPower: Bool {
        let now = Date().timeIntervalSinceReferenceDate
        cacheLock.lock()
        if let cached = cachedOnBattery, now - cachedAt < powerSourceCacheSeconds {
            cacheLock.unlock()
            return cached
        }
        cacheLock.unlock()

        // Explicit snapshot (rather than passing nil) so the ownership is
        // unambiguous: IOPSCopyPowerSourcesInfo is a Copy (+1) → takeRetained;
        // IOPSGetProvidingPowerSourceType is a Get (+0) → takeUnretained.
        var onBattery = false
        if let blob = IOPSCopyPowerSourcesInfo()?.takeRetainedValue(),
           let providing = IOPSGetProvidingPowerSourceType(blob)?.takeUnretainedValue() {
            onBattery = (providing as String) == kIOPSBatteryPowerValue
        }

        cacheLock.lock()
        cachedOnBattery = onBattery
        cachedAt = now
        cacheLock.unlock()
        return onBattery
    }

    /// How long an `isOnBatteryPower` reading is reused before re-querying IOKit.
    private static let powerSourceCacheSeconds: TimeInterval = 15

    /// Cache backing `isOnBatteryPower`. Guarded by `cacheLock` — PowerGate is
    /// read from every collector's own task, so this is genuinely concurrent.
    private static let cacheLock = NSLock()
    nonisolated(unsafe) private static var cachedOnBattery: Bool?
    nonisolated(unsafe) private static var cachedAt: TimeInterval = 0

    /// The multiplier collectors actually apply: the worse of the pressure
    /// signal and the battery term (battery → 1.5×, matching the "fair thermal"
    /// light-touch curve).
    ///
    /// Battery is deliberately NOT folded into `pollIntervalMultiplier` itself.
    /// That property is also the gate for HEAVY BACKGROUND MAINTENANCE in
    /// DaemonTimers (`underPowerPressure = pollIntervalMultiplier > 1.0` → skip
    /// the full VACUUM and the FTS optimize). If battery raised it, a laptop
    /// that lives unplugged would never reclaim events.db and the file would grow
    /// without bound — trading a small battery win for a large disk-space and
    /// CPU-churn loss. Stretching a poll interval on battery is safe; deferring a
    /// whole-file rebuild indefinitely is not.
    public static var batteryAwarePollMultiplier: Double {
        max(pollIntervalMultiplier, isOnBatteryPower ? 1.5 : 1.0)
    }

    /// Scale a base interval by the current multiplier. Round-trip safe:
    /// passing a base of 2s on AC with nominal thermals gives back 2s exactly.
    public static func adjustedInterval(base: TimeInterval) -> TimeInterval {
        base * batteryAwarePollMultiplier
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
        let scaled = 1.0 + (batteryAwarePollMultiplier - 1.0) * aggressiveness
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
        // v1.21.5: distinguish battery from AC at nominal thermals. This string is
        // the heartbeat's `power_state` field, and reporting "nominal" while the
        // laptop ran unplugged is exactly what kept the missing battery gate
        // invisible on the dashboard's ES Health view for four releases.
        case .nominal: return isOnBatteryPower ? "battery" : "nominal"
        @unknown default: return "unknown"
        }
    }
}
