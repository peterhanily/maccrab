import Foundation
import Darwin
import Testing
@testable import MacCrabCore
@testable import MacCrabAgentKit

@Suite("Network polling health is independent of connection events")
struct NetworkPollingHealthTests {
    private final class Clock: @unchecked Sendable {
        private let lock = NSLock()
        private var wall = Date(timeIntervalSince1970: 1_000_000)
        private var monotonic: TimeInterval = 1000
        func date() -> Date { lock.lock(); defer { lock.unlock() }; return wall }
        func uptime() -> TimeInterval { lock.lock(); defer { lock.unlock() }; return monotonic }
        func advance(_ seconds: TimeInterval, wallChange: TimeInterval? = nil) {
            lock.lock(); defer { lock.unlock() }
            monotonic += seconds
            wall = wall.addingTimeInterval(wallChange ?? seconds)
        }
    }

    /// A continuation-driven poll schedule. No wall-clock sleeps or live sockets.
    private actor Sleeper {
        private var pending: [UUID: CheckedContinuation<Void, Error>] = [:]
        private var count = 0
        private var observers: [(Int, CheckedContinuation<Void, Never>)] = []
        func sleep() async throws {
            let id = UUID()
            try await withTaskCancellationHandler {
                try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
                    guard !Task.isCancelled else {
                        continuation.resume(throwing: CancellationError()); return
                    }
                    pending[id] = continuation
                    count += 1
                    let ready = observers.filter { count >= $0.0 }
                    observers.removeAll { count >= $0.0 }
                    ready.forEach { $0.1.resume() }
                }
            } onCancel: {
                Task { await self.cancel(id) }
            }
        }
        private func cancel(_ id: UUID) {
            pending.removeValue(forKey: id)?.resume(throwing: CancellationError())
        }
        func waitForPoll(_ target: Int) async {
            if count >= target { return }
            await withCheckedContinuation { observers.append((target, $0)) }
        }
        func fire() {
            let ready = pending.values
            pending.removeAll()
            ready.forEach { $0.resume() }
        }
    }

    private actor Gate {
        private var entered = false
        private var waiter: CheckedContinuation<Void, Never>?
        private var observers: [CheckedContinuation<Void, Never>] = []
        func pause() async {
            await withCheckedContinuation { continuation in
                waiter = continuation
                entered = true
                observers.forEach { $0.resume() }
                observers.removeAll()
            }
        }
        func waitUntilEntered() async {
            if entered { return }
            await withCheckedContinuation { observers.append($0) }
        }
        func open() { waiter?.resume(); waiter = nil }
    }

    private actor Source {
        private var connections: [ConnectionKey: NetworkCollector.SocketConnectionInfo] = [:]
        private var failure: NetworkCollector.EnumerationFailure?
        private var gate: Gate?
        func set(_ value: [ConnectionKey: NetworkCollector.SocketConnectionInfo]) {
            connections = value; failure = nil
        }
        func fail() { failure = .processListUnavailable }
        func holdNext(_ value: Gate) { gate = value }
        func enumerate() async throws -> [ConnectionKey: NetworkCollector.SocketConnectionInfo] {
            let result = connections, error = failure, held = gate
            gate = nil
            if let held { await held.pause() }
            if let error { throw error }
            return result
        }
    }

    private struct Harness {
        let collector: NetworkCollector
        let registry: CollectorRegistry
        let clock: Clock
        let source: Source
        let sleeper: Sleeper
        func status() async -> CollectorRegistry.Status? {
            await registry.snapshot().first { $0.name == "NetworkCollector" }
        }
        func nextPoll(_ ordinal: Int) async {
            clock.advance(10)
            await sleeper.fire()
            await sleeper.waitForPoll(ordinal)
        }
        func stop() async { #expect(await collector.stopAndJoin(deadline: 5)) }
    }

    private func harness() async -> Harness {
        let clock = Clock(), source = Source(), sleeper = Sleeper()
        let collector = NetworkCollector(polling: .init(
            enumerate: { try await source.enumerate() },
            makeEvent: { _ in Self.event() },
            sleep: { _ in try await sleeper.sleep() },
            adjustedInterval: { $0 }, now: { clock.date() },
            monotonicNow: { clock.uptime() }
        ))
        let registry = CollectorRegistry()
        await registry.register(name: "NetworkCollector", expectedIntervalSeconds: 10,
                                pollingHealth: collector.pollingHealth)
        return Harness(collector: collector, registry: registry, clock: clock,
                       source: source, sleeper: sleeper)
    }

    private func withHarness(_ body: (Harness) async throws -> Void) async throws {
        let h = await harness()
        do { try await body(h) }
        catch {
            await h.stop()
            throw error
        }
        await h.stop()
    }

    private static func event() -> Event {
        Event(eventCategory: .network, eventType: .connection, eventAction: "connect",
              process: MacCrabCore.ProcessInfo(
                pid: 123, ppid: 1, rpid: 123, name: "fixture", executable: "/fixture/app",
                commandLine: "/fixture/app", args: [], workingDirectory: "/fixture",
                userId: 501, userName: "fixture", groupId: 20,
                startTime: Date(timeIntervalSince1970: 1)
              ))
    }

    private func connection() -> [ConnectionKey: NetworkCollector.SocketConnectionInfo] {
        let key = ConnectionKey(pid: 123, localPort: 45000, remoteIp: "192.0.2.10",
                                remotePort: 443, proto: "tcp")
        return [key: .init(key: key, pid: 123, localIp: "192.0.2.11", localPort: 45000,
                           remoteIp: "192.0.2.10", remotePort: 443, transport: "tcp",
                           socketFamily: AF_INET, tcpState: 4)]
    }

    @Test("Repeated valid empty polls remain healthy without manufacturing an event")
    func emptyPollsAreProgress() async throws {
        try await withHarness { h in
            await h.collector.start()
            await h.sleeper.waitForPoll(1)
            for ordinal in 2...8 { await h.nextPoll(ordinal) }
            let status = try #require(await h.status())
            #expect(status.state == .healthy)
            #expect(status.eventCount == 0)
            #expect(status.lastTick == nil)
            #expect(status.completedPollCount == 8)
            #expect(status.lastPoll == h.clock.date())
            #expect(h.collector.deliveryCounters.offeredByLane["priority"] == 0)
        }
    }

    @Test("Unchanged connections refresh polling health while emitting only once")
    func unchangedConnectionsAreProgress() async throws {
        try await withHarness { h in
            await h.source.set(connection())
            await h.collector.start()
            await h.sleeper.waitForPoll(1)
            // The real consumer records the one emitted event, not each later poll.
            await h.registry.recordTick(name: "NetworkCollector")
            for ordinal in 2...8 { await h.nextPoll(ordinal) }
            let status = try #require(await h.status())
            #expect(status.state == .healthy)
            #expect(status.eventCount == 1)
            #expect(status.completedPollCount == 8)
            #expect(h.collector.deliveryCounters.offeredByLane["priority"] == 1)
        }
    }

    @Test("Buffered events cannot hide stalled polling, including a backward wall-clock change")
    func eventDoesNotRefreshPollProgress() async throws {
        try await withHarness { h in
            await h.collector.start()
            await h.sleeper.waitForPoll(1)
            h.clock.advance(60, wallChange: -3600)
            await h.registry.recordTick(name: "NetworkCollector")
            let stalled = try #require(await h.status())
            #expect(stalled.state == .stalled)
            #expect(stalled.eventCount == 1)
            #expect(stalled.completedPollCount == 1)
            await h.nextPoll(2)
            #expect(await h.status()?.state == .healthy)
        }
    }

    @Test("Enumeration failure is distinct from empty success and only verified progress recovers it")
    func enumerationFailureAndRecovery() async throws {
        try await withHarness { h in
            let connections = connection()
            await h.source.set(connections)
            await h.collector.start()
            await h.sleeper.waitForPoll(1)
            await h.source.fail()
            await h.nextPoll(2)
            await h.registry.recordTick(name: "NetworkCollector")
            let failed = try #require(await h.status())
            #expect(failed.state == .failed)
            #expect(failed.errorCount == 1)
            #expect(failed.completedPollCount == 1)
            await h.source.set(connections)
            await h.nextPoll(3)
            let recovered = try #require(await h.status())
            #expect(recovered.state == .healthy)
            #expect(recovered.errorCount == 1)
            #expect(recovered.lastError == failed.lastError)
            #expect(recovered.completedPollCount == 2)
            #expect(h.collector.deliveryCounters.offeredByLane["priority"] == 1,
                    "A failed enumeration must not clear the deduplication snapshot")
            // A successful poll cannot clear an unrelated explicit registry error.
            await h.registry.recordError(name: "NetworkCollector", message: "Fixture setup error")
            await h.nextPoll(4)
            await h.registry.recordTick(name: "NetworkCollector")
            #expect(await h.status()?.state == .failed)
            #expect(await h.status()?.errorCount == 2)
        }
    }

    @Test("Stopping a held enumeration seals progress and rejects one-shot restart")
    func stopRejectsLateCompletion() async throws {
        try await withHarness { h in
            let gate = Gate()
            await h.source.set(connection())
            await h.source.holdNext(gate)
            await h.collector.start()
            await gate.waitUntilEntered()
            #expect(await h.status()?.state == .starting)
            h.clock.advance(60)
            await h.registry.recordTick(name: "NetworkCollector")
            #expect(await h.status()?.state == .stalled,
                    "Even a first sweep must complete; an event is not completion")
            await h.collector.stop()
            await h.registry.recordTick(name: "NetworkCollector")
            #expect(await h.status()?.state == .failed)
            await gate.open()
            await h.stop()
            await h.collector.start()
            let stopped = try #require(await h.status())
            #expect(stopped.state == .failed)
            #expect(stopped.completedPollCount == 0)
            #expect(stopped.lastPoll == nil)
            #expect(stopped.errorCount == 0, "Cancellation is not an enumeration fault")
            #expect(h.collector.deliveryCounters.offeredByLane["priority"] == 0)
        }
    }

    @Test("PID enumeration distinguishes success, failed initial/retry calls and a full retry")
    func pidListOutcomes() throws {
        let pids = try NetworkCollector.enumeratePIDs(initialBufferCount: 2) { buffer in
            buffer[0] = 1
            return Int32(MemoryLayout<Int32>.size)
        }
        #expect(pids == [1])
        #expect(throws: NetworkCollector.EnumerationFailure.processListUnavailable) {
            try NetworkCollector.enumeratePIDs(initialBufferCount: 2) { _ in 0 }
        }
        #expect(throws: NetworkCollector.EnumerationFailure.processListUnavailable) {
            try NetworkCollector.enumeratePIDs(initialBufferCount: 2) { buffer in
                buffer.count == 2 ? 8 : 0
            }
        }
        #expect(throws: NetworkCollector.EnumerationFailure.processListTruncated) {
            try NetworkCollector.enumeratePIDs(initialBufferCount: 2) { buffer in
                Int32(buffer.count * MemoryLayout<Int32>.size)
            }
        }
    }
}
