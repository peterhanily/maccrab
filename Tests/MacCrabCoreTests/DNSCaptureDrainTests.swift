import Foundation
import Testing
@testable import MacCrabCore

/// The capture drain runs reads, parsing and delivery on its serial queue.
/// Pipes stand in for the BPF descriptor; no device or packet is opened.
@Suite("DNS capture drain", .serialized)
struct DNSCaptureDrainTests {
    private func makeStream() -> (AsyncStream<DnsQuery>, AsyncStream<DnsQuery>.Continuation) {
        var continuation: AsyncStream<DnsQuery>.Continuation!
        let stream = AsyncStream<DnsQuery>(bufferingPolicy: .bufferingNewest(16)) { continuation = $0 }
        return (stream, continuation)
    }

    @Test("captured records are delivered back-to-back until the interface deadline")
    func deliversUntilDeadline() async throws {
        var fds: [Int32] = [0, 0]
        try #require(pipe(&fds) == 0)
        defer { close(fds[0]) }
        let records = DNSCapturePacketFixture.bpfRecord(
            packet: DNSCapturePacketFixture.packet(), seconds: 1_700_000_000, microseconds: 0
        ) + DNSCapturePacketFixture.bpfRecord(
            packet: DNSCapturePacketFixture.packet(name: "b.example", answerType: 1),
            seconds: 1_700_000_001, microseconds: 0
        )
        let written = records.withUnsafeBytes { write(fds[1], $0.baseAddress, $0.count) }
        try #require(written == records.count)
        close(fds[1])  // then zero-byte reads, like BPF read timeouts, until the deadline
        let (stream, continuation) = makeStream()
        let buffer = UnsafeMutableRawPointer.allocate(byteCount: 4_096, alignment: 4)
        defer { buffer.deallocate() }
        let outcome = await DNSCollector.drainCapture(
            descriptor: fds[0], into: .init(pointer: buffer), length: 4_096,
            until: Foundation.ProcessInfo.processInfo.systemUptime + 0.05,
            continuation: continuation, telemetry: DNSCaptureTelemetry(),
            queue: DispatchQueue(label: "com.maccrab.test.dns-drain")
        )
        continuation.finish()
        var names: [String] = []
        for await query in stream { names.append(query.queryName) }
        #expect(outcome == .reachedDeadline)
        #expect(names == ["a.example", "b.example"])
    }

    @Test("a failed read returns its errno from the reading thread")
    func failureCarriesErrno() async {
        let (_, continuation) = makeStream()
        let buffer = UnsafeMutableRawPointer.allocate(byteCount: 64, alignment: 4)
        defer { buffer.deallocate() }
        let outcome = await DNSCollector.drainCapture(
            descriptor: -1, into: .init(pointer: buffer), length: 64,
            until: Foundation.ProcessInfo.processInfo.systemUptime + 5,
            continuation: continuation, telemetry: DNSCaptureTelemetry(),
            queue: DispatchQueue(label: "com.maccrab.test.dns-drain-error")
        )
        #expect(outcome == .failed(EBADF))
    }

    @Test("cancelling the capture task ends the drain before its deadline")
    func cancellationEndsDrain() async throws {
        var fds: [Int32] = [0, 0]
        try #require(pipe(&fds) == 0)
        close(fds[1])
        defer { close(fds[0]) }
        let (_, continuation) = makeStream()
        let buffer = UnsafeMutableRawPointer.allocate(byteCount: 64, alignment: 4)
        defer { buffer.deallocate() }
        let descriptor = fds[0]
        let pointer = DNSCollector.CaptureReadBuffer(pointer: buffer)
        let task = Task {
            await DNSCollector.drainCapture(
                descriptor: descriptor, into: pointer, length: 64,
                until: Foundation.ProcessInfo.processInfo.systemUptime + 3_600,
                continuation: continuation, telemetry: DNSCaptureTelemetry(),
                queue: DispatchQueue(label: "com.maccrab.test.dns-drain-cancel")
            )
        }
        try await Task.sleep(for: .milliseconds(20))
        task.cancel()
        #expect(await task.value == .cancelled)
    }
}
