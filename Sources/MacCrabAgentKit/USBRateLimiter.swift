// USBRateLimiter.swift
// MacCrabAgentKit
//
// Per-device, per-direction USB alert throttle. Keeps non-mass-storage
// plug/unplug events from spamming the dashboard when a user moves
// between a docked and undocked setup with the same peripherals.
//
// Mass-storage events bypass the limiter (they're exfil-class signal,
// every one matters). The limiter covers hubs, HID keyboards/mice,
// YubiKey/CTK devices, audio interfaces, webcams — everything a
// normal Mac user plugs in on a loop.

import Foundation

/// In-memory 24h rate limiter keyed on "vid:pid:direction". Resets on
/// sysext restart (acceptable — a restart is infrequent enough that
/// the first replug after one is legitimate signal to surface).
actor USBRateLimiter {
    private static let window: TimeInterval = 24 * 3600
    private var lastSeen: [String: Date] = [:]

    /// Returns true when the caller should SKIP emitting the alert
    /// because this (vendor, product, direction) triple has already
    /// surfaced within the window. Updates the timestamp on pass so
    /// repeated checks renew the cooldown.
    func shouldSuppress(key: String) -> Bool {
        let now = Date()
        if let prev = lastSeen[key], now.timeIntervalSince(prev) < Self.window {
            return true
        }
        lastSeen[key] = now
        // Opportunistic cleanup — keep the dictionary bounded even on a
        // long-running daemon with many distinct devices. Cheap at this
        // cardinality (normal Mac sees <100 unique USB devices).
        if lastSeen.count > 256 {
            let cutoff = now.addingTimeInterval(-Self.window)
            lastSeen = lastSeen.filter { $0.value > cutoff }
        }
        return false
    }
}
