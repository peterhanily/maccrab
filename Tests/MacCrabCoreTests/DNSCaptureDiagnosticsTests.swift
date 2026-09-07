import Foundation
import Testing
@testable import MacCrabCore
@testable import MacCrabAgentKit

@Suite("DNS capture availability and delivery diagnostics")
struct DNSCaptureDiagnosticsTests {
    @Test("availability changes preserve independent kernel and delivery loss history")
    func preservesLossHistory() {
        let telemetry = DNSCaptureTelemetry()
        telemetry.availability(.capturing(interface: "en1"))
        telemetry.kernel(received: 10, dropped: 2)
        telemetry.availability(.unavailable(reason: "ordinary disconnect"))
        #expect(telemetry.snapshot().available == false)
        #expect(telemetry.snapshot().kernelStatisticsAvailable == false)
        telemetry.availability(.capturing(interface: "en0"))
        #expect(telemetry.snapshot().interface == "en0")
        #expect(telemetry.snapshot().kernelStatisticsAvailable == false)
        telemetry.kernel(received: 3, dropped: 0)
        telemetry.kernelStatisticsFailed()
        let snapshot = telemetry.snapshot()
        #expect(snapshot.kernelReceivedTotal == 13)
        #expect(snapshot.kernelDroppedTotal == 2)
        #expect(snapshot.kernelStatisticsErrorsTotal == 1)
        #expect(snapshot.kernelStatisticsAvailable == false)
        #expect(snapshot.streamDroppedTotal == 0)
    }

    @Test("ordinary buffered DNS offers report eviction and stream termination separately")
    func boundedStreamCounters() {
        let telemetry = DNSCaptureTelemetry()
        let pair = AsyncStream<DnsQuery>.makeStream(bufferingPolicy: .bufferingNewest(1))
        let query = DnsQuery(queryName: "example.test", queryType: 1, responseCode: 0,
                             resolvedIPs: [], isResponse: false, timestamp: Date())
        telemetry.yielded(pair.continuation.yield(query))
        telemetry.yielded(pair.continuation.yield(query))
        pair.continuation.finish()
        telemetry.yielded(pair.continuation.yield(query))
        let snapshot = telemetry.snapshot()
        #expect(snapshot.streamOfferedTotal == 3)
        #expect(snapshot.streamDroppedTotal == 1)
        #expect(snapshot.streamTerminatedTotal == 1)
        #expect(snapshot.kernelDroppedTotal == 0)
    }

    @Test("subprocess setup recovery retains incident history and cannot revive a closed consumer",
          arguments: ["KdebugCollector", "EsloggerCollector"])
    func verifiedSubprocessRecovery(name: String) async throws {
        let registry = CollectorRegistry()
        await registry.register(name: name, expectedIntervalSeconds: 30,
                                eventDriven: true, expectsContinuousTraffic: true, started: false)
        await registry.recordSetupStatus(name: name, status: .unavailable(reason: "ordinary launch failure"))
        await registry.recordTick(name: name)
        #expect(await registry.snapshot().first?.state == .failed)
        await registry.recordSetupStatus(name: name, status: .configured)
        let recovered = try #require(await registry.snapshot().first)
        #expect(recovered.state == .healthy)
        #expect(recovered.errorCount == 1)
        #expect(recovered.eventCount == 1)
        await registry.recordStreamEnded(name: name)
        await registry.recordSetupStatus(name: name, status: .configured)
        #expect(await registry.snapshot().first?.state == .failed)
    }
}
