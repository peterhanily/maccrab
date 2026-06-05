// PreventionSafetyGateTests.swift
// MacCrabCoreTests
//
// The load-bearing gates in front of the auto-acting PF block paths. Both
// re-validate IPs against SafeBlockableIP so a poisoned threat-intel feed
// or a tampered on-disk blocklist can't PF-block DNS / the gateway and
// brick the host's network. These are pure filters; test them directly.

import Testing
import Foundation
@testable import MacCrabCore

@Suite("Prevention safety gates")
struct PreventionSafetyGateTests {

    // MARK: - Persisted blocklist re-validation (ManualResponse)

    @Test("sanitizePersistedIPs keeps only valid, non-protected IPs")
    func sanitizePersistedKeepsC2Only() {
        // A tampered dashboard_blocked_ips.txt: one real C2 + DNS + garbage.
        let poisoned = ["203.0.113.7", "8.8.8.8", "not-an-ip", "", "1.1.1.1"]
        #expect(ManualResponse.sanitizePersistedIPs(poisoned) == ["203.0.113.7"])
    }

    @Test("sanitizePersistedIPs drops a tampered IPv6 DNS-adjacent entry")
    func sanitizePersistedDropsIPv6Protected() {
        // The v1.6.21 case lives on the persisted path too — 2001:4860:4860::8889
        // must not re-inject a DNS-bricking block on re-apply.
        #expect(ManualResponse.sanitizePersistedIPs(["2001:4860:4860::8889", "2a01:4f8::1"]) == ["2a01:4f8::1"])
    }

    @Test("sanitizePersistedIPs on an empty / all-bad list yields empty")
    func sanitizePersistedEmpty() {
        #expect(ManualResponse.sanitizePersistedIPs([]).isEmpty)
        #expect(ManualResponse.sanitizePersistedIPs(["", "garbage", "127.0.0.1"]).isEmpty)
    }

    // MARK: - Threat-intel poisoned-set filter (NetworkBlocker)

    @Test("safeSubset filters protected IPs out of a poisoned threat-intel set")
    func safeSubsetFiltersProtected() async {
        let blocker = NetworkBlocker()
        let poisoned: Set<String> = ["45.77.123.45", "8.8.8.8", "1.1.1.1", "::1", "2001:4860:4860::8889"]
        let safe = await blocker.safeSubset(poisoned)
        #expect(safe == ["45.77.123.45"])
    }

    @Test("safeSubset passes a clean set through unchanged")
    func safeSubsetPassesClean() async {
        let blocker = NetworkBlocker()
        let clean: Set<String> = ["45.77.123.45", "203.0.113.7", "2a01:4f8::1"]
        #expect(await blocker.safeSubset(clean) == clean)
    }
}
