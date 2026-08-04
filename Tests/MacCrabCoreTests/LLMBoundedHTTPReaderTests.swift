// LLMBoundedHTTPReaderTests.swift
// MacCrabCoreTests

import Foundation
import Testing
@testable import MacCrabCore

private final class LLMHTTPReadProbe: @unchecked Sendable {
    private let lock = NSLock()
    private var readsStorage = 0
    private var cancellationsStorage = 0

    func recordRead() {
        lock.lock()
        readsStorage += 1
        lock.unlock()
    }

    func recordCancellation() {
        lock.lock()
        cancellationsStorage += 1
        lock.unlock()
    }

    var reads: Int {
        lock.lock()
        defer { lock.unlock() }
        return readsStorage
    }

    var cancellations: Int {
        lock.lock()
        defer { lock.unlock() }
        return cancellationsStorage
    }
}

private struct InjectedLLMHTTPBytes: AsyncSequence, Sendable {
    typealias Element = UInt8

    let storage: [UInt8]
    let probe: LLMHTTPReadProbe

    struct AsyncIterator: AsyncIteratorProtocol {
        let storage: [UInt8]
        let probe: LLMHTTPReadProbe
        var index = 0

        mutating func next() async -> UInt8? {
            guard index < storage.count else { return nil }
            let value = storage[index]
            index += 1
            probe.recordRead()
            return value
        }
    }

    func makeAsyncIterator() -> AsyncIterator {
        AsyncIterator(storage: storage, probe: probe)
    }
}

private actor OversizeSignallingLLMBackend: LLMBackend, BoundedLLMBackend {
    let providerName = "OversizeSignalling"
    private(set) var calls = 0

    func isAvailable() async -> Bool { true }

    func complete(
        systemPrompt: String,
        userPrompt: String,
        maxTokens: Int,
        temperature: Double
    ) async -> String? {
        await completeResult(
            systemPrompt: systemPrompt,
            userPrompt: userPrompt,
            maxTokens: maxTokens,
            temperature: temperature
        ).value
    }

    func completeResult(
        systemPrompt: String,
        userPrompt: String,
        maxTokens: Int,
        temperature: Double
    ) async -> LLMBackendCompletionResult {
        calls += 1
        return .responseOversize
    }
}

@Suite("Bounded LLM HTTP response reader")
struct LLMBoundedHTTPReaderTests {
    private var repositoryRoot: URL {
        URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
    }

    private func response(headers: [String: String]) -> HTTPURLResponse {
        HTTPURLResponse(
            url: URL(string: "https://llm.invalid/completion")!,
            statusCode: 200,
            httpVersion: "HTTP/1.1",
            headerFields: headers
        )!
    }

    private func collect(
        headers: [String: String],
        bytes: Int,
        cap: Int,
        probe: LLMHTTPReadProbe
    ) async throws -> Data {
        try await LLMBoundedHTTPReader.collect(
            response: response(headers: headers),
            bytes: InjectedLLMHTTPBytes(
                storage: Array(repeating: 0x78, count: bytes),
                probe: probe
            ),
            maximumBytes: cap,
            cancelTransfer: { probe.recordCancellation() }
        )
    }

    @Test("Oversize Content-Length cancels before reading the body")
    func fixedLengthRejectsAtHeaders() async {
        let probe = LLMHTTPReadProbe()
        var received: LLMBoundedHTTPError?
        do {
            _ = try await collect(
                headers: ["Content-Length": "6"],
                bytes: 100,
                cap: 5,
                probe: probe
            )
        } catch let error as LLMBoundedHTTPError {
            received = error
        } catch {}

        #expect(received == .responseTooLarge(limit: 5, declaredBytes: 6))
        #expect(probe.reads == 0)
        #expect(probe.cancellations == 1)
    }

    @Test("Chunked response cancels on byte cap plus one")
    func chunkedRejectsWhileStreaming() async {
        let probe = LLMHTTPReadProbe()
        var received: LLMBoundedHTTPError?
        do {
            _ = try await collect(
                headers: ["Transfer-Encoding": "chunked"],
                bytes: 100,
                cap: 5,
                probe: probe
            )
        } catch let error as LLMBoundedHTTPError {
            received = error
        } catch {}

        #expect(received == .responseTooLarge(limit: 5, declaredBytes: nil))
        #expect(probe.reads == 6)
        #expect(probe.cancellations == 1)
    }

    @Test("Response without a length cancels on byte cap plus one")
    func noLengthRejectsWhileStreaming() async {
        let probe = LLMHTTPReadProbe()
        var received: LLMBoundedHTTPError?
        do {
            _ = try await collect(
                headers: [:],
                bytes: 100,
                cap: 5,
                probe: probe
            )
        } catch let error as LLMBoundedHTTPError {
            received = error
        } catch {}

        #expect(received == .responseTooLarge(limit: 5, declaredBytes: nil))
        #expect(probe.reads == 6)
        #expect(probe.cancellations == 1)
    }

    @Test("Exact-cap response remains valid")
    func exactCapAccepted() async throws {
        let probe = LLMHTTPReadProbe()
        let data = try await collect(
            headers: ["Content-Length": "5"],
            bytes: 5,
            cap: 5,
            probe: probe
        )
        #expect(data == Data(repeating: 0x78, count: 5))
        #expect(probe.reads == 5)
        #expect(probe.cancellations == 0)
    }

    @Test("Transport oversize is a circuit failure and response_oversize outcome")
    func oversizeMapsIntoServiceSemantics() async {
        var config = LLMConfig()
        config.provider = .claude
        let backend = OversizeSignallingLLMBackend()
        let service = LLMService(
            backend: backend,
            config: config,
            minInterval: 0
        )

        #expect(await service.query(
            systemPrompt: "system",
            userPrompt: "user",
            useCache: false,
            feature: .unspecified
        ) == nil)
        #expect(await backend.calls == 1)

        let health = await service.healthSnapshot()
        let telemetry = await service.runtimeTelemetrySnapshot()
        #expect(health.consecutiveFailures == 1)
        #expect(!health.usable)
        #expect(telemetry.totals.outcomes.responseOversize == 1)
        #expect(telemetry.totals.outcomes.backendFailure == 0)
        #expect(telemetry.totals.conservationMaintained)
        #expect(telemetry.totals.backendAdmissionConservationMaintained)
    }

    @Test("Every completion backend stays on the shared streaming boundary")
    func backendSourceDriftGuard() throws {
        let names = [
            "ClaudeBackend.swift",
            "OpenAIBackend.swift",
            "GeminiBackend.swift",
            "MistralBackend.swift",
            "OllamaBackend.swift",
        ]
        for name in names {
            let url = repositoryRoot
                .appendingPathComponent("Sources/MacCrabCore/LLM")
                .appendingPathComponent(name)
            let source = try String(contentsOf: url, encoding: .utf8)
            #expect(
                !source.contains(".data(for:"),
                "\(name) must not restore whole-body URLSession buffering"
            )
            #expect(
                source.contains("LLMBoundedHTTPReader.read("),
                "\(name) must use the shared running-cap implementation"
            )
            #expect(
                source.contains("return .responseOversize"),
                "\(name) must preserve the oversize circuit/telemetry outcome"
            )
        }

        let claudeURL = repositoryRoot
            .appendingPathComponent("Sources/MacCrabCore/LLM/ClaudeBackend.swift")
        let claude = try String(contentsOf: claudeURL, encoding: .utf8)
        #expect(
            claude.components(separatedBy: "LLMBoundedHTTPReader.read(").count - 1 == 2,
            "regular and extended-thinking Claude completions both need the cap"
        )

        let serviceURL = repositoryRoot
            .appendingPathComponent("Sources/MacCrabCore/LLM/LLMService.swift")
        let service = try String(contentsOf: serviceURL, encoding: .utf8)
        #expect(service.contains("case .responseOversize:"))
        #expect(service.contains("telemetryOutcome = .responseOversize"))
    }
}
