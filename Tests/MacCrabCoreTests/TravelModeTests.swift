// TravelModeTests.swift
// State/effect routing is tested with recorded effects, never live PF/DNS.
// Installed firewall enforcement remains an isolated integration-test lane.

import Testing
import Foundation
@testable import MacCrabCore

private final class TravelEffectRecorder: @unchecked Sendable {
    private let lock = NSLock()
    private var effects: [TravelMode.Effect] = []
    func record(_ effect: TravelMode.Effect) {
        lock.lock(); defer { lock.unlock() }
        effects.append(effect)
    }
    func snapshot() -> [TravelMode.Effect] {
        lock.lock(); defer { lock.unlock() }
        return effects
    }
}

@Suite("Travel Mode")
struct TravelModeTests {

    @Test("status() reports inactive by default")
    func defaultStateInactive() async {
        let effects = TravelEffectRecorder()
        let mode = TravelMode(effectExecutor: { effects.record($0) })
        let status = await mode.status()
        #expect(status.isActive == false)
        #expect(status.networkName == nil)
        #expect(status.activatedAt == nil)
        #expect(status.protections.isEmpty)
        #expect(effects.snapshot().isEmpty)
    }

    @Test("activate() flips state + records network name")
    func activateUpdatesState() async {
        let effects = TravelEffectRecorder()
        let mode = TravelMode(effectExecutor: { effects.record($0) })
        let status = await mode.activate(networkName: "HotelWiFi_Lobby")
        #expect(status.isActive == true)
        #expect(status.networkName == "HotelWiFi_Lobby")
        #expect(status.activatedAt != nil)
        // activate() returns a list of protection descriptions.
        #expect(!status.protections.isEmpty)
        #expect(effects.snapshot() == [.enableStrictFirewall, .flushDNS])
    }

    @Test("activate() without network name works")
    func activateWithoutName() async {
        let effects = TravelEffectRecorder()
        let mode = TravelMode(effectExecutor: { effects.record($0) })
        let status = await mode.activate()
        #expect(status.isActive == true)
        #expect(status.networkName == nil)
        #expect(effects.snapshot() == [.enableStrictFirewall, .flushDNS])
    }

    @Test("deactivate() clears state")
    func deactivateResets() async {
        let effects = TravelEffectRecorder()
        let mode = TravelMode(effectExecutor: { effects.record($0) })
        _ = await mode.activate(networkName: "SomeCafe")
        let status = await mode.deactivate()
        #expect(status.isActive == false)
        #expect(status.networkName == nil)
        #expect(status.activatedAt == nil)
        #expect(effects.snapshot() == [.enableStrictFirewall, .flushDNS, .removeStrictFirewall])
    }

    @Test("status() reflects activated state")
    func statusAfterActivate() async {
        let effects = TravelEffectRecorder()
        let mode = TravelMode(effectExecutor: { effects.record($0) })
        _ = await mode.activate(networkName: "AirportWifi")
        let status = await mode.status()
        #expect(status.isActive == true)
        #expect(status.networkName == "AirportWifi")
        #expect(!status.protections.isEmpty)
        #expect(effects.snapshot() == [.enableStrictFirewall, .flushDNS],
                "Reading status must not repeat external effects")
    }

    @Test("Maps to D3FEND D3-FCR (Firewall Configuration Rules)")
    func d3fendRef() {
        #expect(TravelMode.d3fend.id == "D3-FCR")
        #expect(TravelMode.d3fend.tactic == .harden)
    }

    @Test("Re-activating overwrites the previous network name")
    func reactivateUpdates() async {
        let effects = TravelEffectRecorder()
        let mode = TravelMode(effectExecutor: { effects.record($0) })
        _ = await mode.activate(networkName: "FirstNetwork")
        let second = await mode.activate(networkName: "SecondNetwork")
        #expect(second.networkName == "SecondNetwork")
        #expect(effects.snapshot() == [.enableStrictFirewall, .flushDNS,
                                      .enableStrictFirewall, .flushDNS])
    }
}
