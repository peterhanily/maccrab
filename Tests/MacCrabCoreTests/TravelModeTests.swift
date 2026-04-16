// TravelModeTests.swift
// Activation state + status queries. The pfctl paths run with
// /dev/null stdout/stderr and fail silently without root, so the actor
// state still updates correctly in tests. Full pfctl-rule verification
// lives in the integration test harness.

import Testing
import Foundation
@testable import MacCrabCore

@Suite("Travel Mode")
struct TravelModeTests {

    @Test("status() reports inactive by default")
    func defaultStateInactive() async {
        let mode = TravelMode()
        let status = await mode.status()
        #expect(status.isActive == false)
        #expect(status.networkName == nil)
        #expect(status.activatedAt == nil)
        #expect(status.protections.isEmpty)
    }

    @Test("activate() flips state + records network name")
    func activateUpdatesState() async {
        let mode = TravelMode()
        let status = await mode.activate(networkName: "HotelWiFi_Lobby")
        #expect(status.isActive == true)
        #expect(status.networkName == "HotelWiFi_Lobby")
        #expect(status.activatedAt != nil)
        // activate() returns a list of protection descriptions.
        #expect(!status.protections.isEmpty)
    }

    @Test("activate() without network name works")
    func activateWithoutName() async {
        let mode = TravelMode()
        let status = await mode.activate()
        #expect(status.isActive == true)
        #expect(status.networkName == nil)
    }

    @Test("deactivate() clears state")
    func deactivateResets() async {
        let mode = TravelMode()
        _ = await mode.activate(networkName: "SomeCafe")
        let status = await mode.deactivate()
        #expect(status.isActive == false)
        #expect(status.networkName == nil)
        #expect(status.activatedAt == nil)
    }

    @Test("status() reflects activated state")
    func statusAfterActivate() async {
        let mode = TravelMode()
        _ = await mode.activate(networkName: "AirportWifi")
        let status = await mode.status()
        #expect(status.isActive == true)
        #expect(status.networkName == "AirportWifi")
        #expect(!status.protections.isEmpty)
    }

    @Test("Maps to D3FEND D3-FCR (Firewall Configuration Rules)")
    func d3fendRef() {
        #expect(TravelMode.d3fend.id == "D3-FCR")
        #expect(TravelMode.d3fend.tactic == .harden)
    }

    @Test("Re-activating overwrites the previous network name")
    func reactivateUpdates() async {
        let mode = TravelMode()
        _ = await mode.activate(networkName: "FirstNetwork")
        let second = await mode.activate(networkName: "SecondNetwork")
        #expect(second.networkName == "SecondNetwork")
    }
}
