import Foundation
import Testing
@testable import MacCrabCore
@testable import MacCrabAgentKit

@Suite("DNS capture liveness is independent of DNS event traffic")
struct DNSCaptureLivenessTests {
    private final class Clock: @unchecked Sendable {
        private let lock = NSLock()
        private var nanos: UInt64 = 1_000_000_000_000

        func now() -> UInt64 {
            lock.lock(); defer { lock.unlock() }
            return nanos
        }

        func advance(_ seconds: UInt64) {
            lock.lock(); defer { lock.unlock() }
            nanos += seconds * 1_000_000_000
        }

        func set(_ value: UInt64) {
            lock.lock(); defer { lock.unlock() }
            nanos = value
        }
    }

    private func registry(
        _ telemetry: DNSCaptureTelemetry, enabled: Bool = true, started: Bool = true
    ) async -> CollectorRegistry {
        let registry = CollectorRegistry()
        await registry.register(
            name: "DNSCollector", expectedIntervalSeconds: 30,
            eventDriven: true, expectsContinuousTraffic: true,
            started: started, enabled: enabled,
            dnsCaptureHealth: { telemetry.snapshot() }
        )
        return registry
    }

    private func dns(_ registry: CollectorRegistry) async throws -> CollectorRegistry.Status {
        try #require(await registry.snapshot().first { $0.name == "DNSCollector" })
    }

    @Test("Successful zero-packet capture checks stay healthy during ten minutes without DNS events")
    func quietCaptureProgressDoesNotInventEvents() async throws {
        let clock = Clock()
        let telemetry = DNSCaptureTelemetry(monotonicNow: { clock.now() })
        let registry = await registry(telemetry)
        let wall = Date()
        await registry.register(name: "UnifiedLogCollector", expectedIntervalSeconds: 30,
                                eventDriven: true, expectsContinuousTraffic: true)
        telemetry.availability(.capturing(interface: "en1"))
        for _ in 0..<10 {
            clock.advance(60)
            telemetry.kernel(received: 0, dropped: 0)
            let status = try await dns(registry)
            #expect(status.state == .healthy)
            #expect(status.eventCount == 0)
            #expect(status.lastTick == nil)
        }
        let capture = telemetry.snapshot()
        #expect(capture.successfulCaptureChecksTotal == 10)
        #expect(capture.kernelReceivedTotal == 0)
        #expect(capture.streamOfferedTotal == 0)
        #expect(capture.successfulCaptureCheckAgeSeconds == 0)
        // The exception belongs only to the explicitly wired capture source.
        let other = try #require(await registry.snapshot(now: wall.addingTimeInterval(601))
            .first { $0.name == "UnifiedLogCollector" })
        #expect(other.state == .stalled)
    }

    @Test("Configuration alone expires and the existing 300-second boundary also bounds completed capture checks")
    func absentAndStaleChecksStayVisible() async throws {
        let clock = Clock()
        let telemetry = DNSCaptureTelemetry(monotonicNow: { clock.now() })
        let registry = await registry(telemetry, started: false)
        #expect(try await dns(registry).state == .starting)
        telemetry.availability(.capturing(interface: "en1"))
        // Production publishes the configured binding before its awaited
        // callback records recovery. Setup alone is not capture-loop progress.
        await registry.recordRecovery(name: "DNSCollector")
        #expect(try await dns(registry).state == .starting)
        #expect(try await dns(registry).eventCount == 0)
        clock.advance(299)
        #expect(try await dns(registry).state == .starting)
        telemetry.availability(.capturing(interface: "en1"))
        clock.advance(1)
        #expect(try await dns(registry).state == .stalled)

        telemetry.kernel(received: 0, dropped: 0)
        #expect(try await dns(registry).state == .healthy)
        clock.advance(299)
        #expect(try await dns(registry).state == .healthy)
        clock.advance(1)
        #expect(try await dns(registry).state == .stalled)
        await registry.recordTick(name: "DNSCollector")
        telemetry.availability(.capturing(interface: "en1"))
        let stillStalled = try await dns(registry)
        #expect(stillStalled.state == .stalled)
        #expect(stillStalled.eventCount == 1)
        #expect(telemetry.snapshot().successfulCaptureChecksTotal == 1)
    }

    @Test("Statistics errors fail immediately, preserve history, and require a successful check to recover")
    func statisticsFailureAndRecovery() async throws {
        let clock = Clock()
        let telemetry = DNSCaptureTelemetry(monotonicNow: { clock.now() })
        let registry = await registry(telemetry)
        telemetry.availability(.capturing(interface: "en1"))
        telemetry.kernel(received: 2, dropped: 0)
        telemetry.kernelStatisticsFailed()
        await registry.recordTick(name: "DNSCollector")
        telemetry.availability(.capturing(interface: "en1"))
        let failed = try await dns(registry)
        #expect(failed.state == .failed)
        #expect(failed.errorCount == 1)
        #expect(telemetry.snapshot().captureCheckFailureActive)
        telemetry.kernel(received: 0, dropped: 0)
        let recovered = try await dns(registry)
        #expect(recovered.state == .healthy)
        #expect(recovered.errorCount == 1)
        #expect(recovered.eventCount == 1)
        #expect(telemetry.snapshot().successfulCaptureChecksTotal == 2)
    }

    @Test("Disconnect and route changes retire the old proof without resetting lifetime counters")
    func reconnectNeedsFreshProof() async throws {
        let clock = Clock()
        let telemetry = DNSCaptureTelemetry(monotonicNow: { clock.now() })
        let registry = await registry(telemetry)
        telemetry.availability(.capturing(interface: "en1"))
        telemetry.kernel(received: 7, dropped: 1)
        telemetry.availability(.unavailable(reason: "fixture disconnect"))
        #expect(try await dns(registry).state == .failed)
        telemetry.kernel(received: 0, dropped: 0)
        #expect(try await dns(registry).state == .failed)
        #expect(telemetry.snapshot().successfulCaptureChecksTotal == 1)

        telemetry.availability(.capturing(interface: "en1"))
        #expect(try await dns(registry).state == .starting)
        #expect(telemetry.snapshot().successfulCaptureCheckAgeSeconds == nil)
        telemetry.kernel(received: 0, dropped: 0)
        #expect(try await dns(registry).state == .healthy)
        clock.advance(1)
        telemetry.availability(.capturing(interface: "en0"))
        #expect(try await dns(registry).state == .starting)
        telemetry.kernel(received: 0, dropped: 0)
        #expect(try await dns(registry).state == .healthy)
        #expect(telemetry.snapshot().successfulCaptureChecksTotal == 3)
        #expect(telemetry.snapshot().kernelReceivedTotal == 7)
        #expect(telemetry.snapshot().kernelDroppedTotal == 1)
    }

    @Test("Capture progress cannot clear independent errors or a terminated consumer")
    func independentFailurePrecedence() async throws {
        let telemetry = DNSCaptureTelemetry()
        let registry = await registry(telemetry)
        telemetry.availability(.capturing(interface: "en1"))
        telemetry.kernel(received: 0, dropped: 0)
        await registry.recordError(name: "DNSCollector", message: "fixture independent error")
        telemetry.kernel(received: 0, dropped: 0)
        #expect(try await dns(registry).state == .failed)
        await registry.recordRecovery(name: "DNSCollector")
        #expect(try await dns(registry).state == .healthy)
        #expect(try await dns(registry).errorCount == 1)
        await registry.recordStreamEnded(name: "DNSCollector")
        telemetry.kernel(received: 0, dropped: 0)
        await registry.recordRecovery(name: "DNSCollector")
        #expect(try await dns(registry).state == .failed)
        let disabled = await self.registry(telemetry, enabled: false)
        #expect(try await dns(disabled).state == .disabled)
    }

    @Test("The DNS diagnostics provider does not retain its collector through the status callback")
    func weakCollectorProviderDoesNotFormCycle() async throws {
        let registry = CollectorRegistry()
        weak var releasedCollector: DNSCollector?
        do {
            // Construct the actual actor and production callback ownership,
            // without starting BPF capture or mutating the host.
            let collector = DNSCollector { status in
                switch status {
                case .capturing:
                    await registry.recordRecovery(name: "DNSCollector")
                case .unavailable(let reason):
                    await registry.recordError(name: "DNSCollector", message: reason)
                }
            }
            releasedCollector = collector
            await registry.register(
                name: "DNSCollector", expectedIntervalSeconds: 30,
                eventDriven: true, expectsContinuousTraffic: true, started: false,
                dnsCaptureHealth: { [weak collector] in
                    collector?.captureDiagnostics ?? DNSCaptureDiagnostics()
                }
            )
            #expect(try await dns(registry).state == .starting)
        }
        #expect(releasedCollector == nil)
        // Even a late setup-recovery signal cannot make the unavailable
        // fallback diagnostics of a released collector healthy.
        await registry.recordRecovery(name: "DNSCollector")
        #expect(try await dns(registry).state == .failed)
    }

    @Test("A backward monotonic observation cannot certify capture progress")
    func invalidProgressClockStaysUnverified() async throws {
        let clock = Clock()
        let telemetry = DNSCaptureTelemetry(monotonicNow: { clock.now() })
        let registry = await registry(telemetry)
        telemetry.availability(.capturing(interface: "en1"))
        telemetry.kernel(received: 0, dropped: 0)
        clock.set(0)
        #expect(telemetry.snapshot().bindingAgeSeconds == nil)
        #expect(telemetry.snapshot().successfulCaptureCheckAgeSeconds == nil)
        #expect(try await dns(registry).state == .stalled)
        telemetry.kernel(received: 0, dropped: 0)
        #expect(try await dns(registry).state == .stalled)
        telemetry.availability(.unavailable(reason: "fixture reset"))
        telemetry.availability(.capturing(interface: "en1"))
        telemetry.kernel(received: 0, dropped: 0)
        #expect(try await dns(registry).state == .healthy)
    }
}
