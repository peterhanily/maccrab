import Testing
@testable import MacCrabCore
@testable import MacCrabAgentKit

@Suite("TraceGraph startup admission observability")
struct TraceGraphStartupAdmissionStatusTests {
    @Test("footprint refusal retains cap, threshold, footprint, and startup flags")
    func footprintStatus() throws {
        let status = TraceGraphStartupAdmissionStatus(
            error: .footprintLimit(
                footprintBytes: 220_000_000,
                admissionThresholdBytes: 195_000_000,
                capBytes: 262_144_000
            ),
            configuredMaxFootprintBytes: 262_144_000,
            configuredFreeSpaceFloorBytes: 1_073_741_824
        )

        #expect(status.reason == .footprintLimit)
        #expect(status.footprintBytes == 220_000_000)
        #expect(status.admissionThresholdBytes == 195_000_000)
        #expect(status.transactionReserveBytes == 67_144_000)
        #expect(status.maxFootprintBytes == 262_144_000)

        let heartbeat = status.heartbeatDictionary
        #expect(heartbeat["enabled"] as? Bool == true)
        #expect(heartbeat["blocked"] as? Bool == true)
        #expect(heartbeat["store_available"] as? Bool == false)
        #expect(heartbeat["startup_blocked"] as? Bool == true)
        #expect(heartbeat["reason"] as? String == "footprint_limit")
    }

    @Test("low-disk refusal retains measured free space and floor")
    func lowFreeSpaceStatus() throws {
        let status = TraceGraphStartupAdmissionStatus(
            error: .lowFreeSpace(
                freeBytes: 100_000_000,
                floorBytes: 1_073_741_824,
                requiredFreeBytes: 1_140_850_688
            ),
            configuredMaxFootprintBytes: 262_144_000,
            configuredFreeSpaceFloorBytes: 1_073_741_824
        )

        #expect(status.reason == .lowFreeSpace)
        #expect(status.freeSpaceBytes == 100_000_000)
        #expect(status.freeSpaceFloorBytes == 1_073_741_824)
        #expect(status.transactionReserveBytes == 67_108_864)
        #expect(status.heartbeatDictionary["reason"] as? String == "low_free_space")
    }

    @Test("probe failures expose a stable non-sensitive reason")
    func probeFailureStatus() throws {
        let status = TraceGraphStartupAdmissionStatus(
            error: .probeFailed("free-space: /private/operator/path"),
            configuredMaxFootprintBytes: 262_144_000,
            configuredFreeSpaceFloorBytes: 1_073_741_824
        )

        #expect(status.reason == .probeFailure)
        #expect(status.heartbeatDictionary["reason"] as? String == "probe_failure")
        #expect(!(status.heartbeatDictionary["reason"] as? String ?? "").contains("operator"))
    }
}
