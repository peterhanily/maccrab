import Testing
@testable import MacCrabCore

@Suite("DNSCollector: primary interface and rebinding")
struct DNSCollectorInterfaceTests {
    private actor CaptureStatuses {
        private var values: [DNSCaptureStatus] = []
        func append(_ status: DNSCaptureStatus) { values.append(status) }
        func snapshot() -> [DNSCaptureStatus] { values }
    }

    @Test("capture status callbacks preserve failure and verified rebind order without duplicate retries")
    func reportsCaptureTransitions() async {
        let statuses = CaptureStatuses()
        var reporter = DNSCaptureStatusReporter { status in
            await statuses.append(status)
        }
        let unavailable = DNSCaptureStatus.unavailable(reason: "No primary IPv4 interface")
        let readFailure = DNSCaptureStatus.unavailable(reason: "BPF read failed; retrying capture")
        await reporter.report(unavailable)
        await reporter.report(unavailable)
        await reporter.report(.capturing(interface: "en0"))
        await reporter.report(.capturing(interface: "en0"))
        await reporter.report(readFailure)
        await reporter.report(.capturing(interface: "en0"))
        await reporter.report(.capturing(interface: "en1"))
        let received = await statuses.snapshot()
        #expect(received == [
            unavailable, .capturing(interface: "en0"), readFailure,
            .capturing(interface: "en0"), .capturing(interface: "en1"),
        ])
    }

    @Test("the primary IPv4 interface wins when two physical links are addressed")
    func primaryInterfaceWins() {
        #expect(DNSCollector.captureInterface(
            primaryInterface: "en1", addressedIPv4Interfaces: ["en0", "en1"]
        ) == "en1")
    }

    @Test("an unavailable primary does not fall back to an unrelated link")
    func noUnrelatedFallback() {
        #expect(DNSCollector.captureInterface(
            primaryInterface: "en1", addressedIPv4Interfaces: ["en0"]
        ) == nil)
        #expect(DNSCollector.captureInterface(
            primaryInterface: nil, addressedIPv4Interfaces: ["en0", "en1"]
        ) == nil)
    }

    @Test("route changes close the previous connection and bind the new primary")
    func rebindsOnRouteChanges() {
        var binding = DNSCaptureBinding()
        var operations: [String] = []
        let open: (String) -> DNSCaptureBinding.Connection? = { name in
            operations.append("open \(name)")
            return .init(descriptor: name == "en0" ? 10 : 11, bufferLength: 4096)
        }
        let close: (Int32) -> Void = { operations.append("close \($0)") }
        binding.reconcile(selectedInterface: "en0", open: open, close: close)
        binding.reconcile(selectedInterface: "en0", open: open, close: close)
        #expect(operations == ["open en0"])
        binding.reconcile(selectedInterface: "en1", open: open, close: close)
        #expect(operations == ["open en0", "close 10", "open en1"])
        #expect(binding.interface == "en1")
        #expect(binding.connection?.descriptor == 11)
        binding.reconcile(selectedInterface: nil, open: open, close: close)
        #expect(binding.connection == nil)
        #expect(operations.last == "close 11")
        binding.stop(close: close)
        #expect(operations.filter { $0 == "close 11" }.count == 1)
    }

    @Test("an initially unavailable capture can attach after the interface becomes ready")
    func retriesUnavailableConnection() {
        var binding = DNSCaptureBinding()
        var ready = false
        var attempts = 0
        let open: (String) -> DNSCaptureBinding.Connection? = { _ in
            attempts += 1
            return ready ? .init(descriptor: 20, bufferLength: 4096) : nil
        }
        binding.reconcile(selectedInterface: "en1", open: open, close: { _ in })
        #expect(binding.connection == nil)
        ready = true
        binding.reconcile(selectedInterface: "en1", open: open, close: { _ in })
        #expect(binding.interface == "en1")
        #expect(binding.connection?.descriptor == 20)
        #expect(attempts == 2)
    }
}
