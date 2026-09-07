import Foundation
import Testing
@testable import MacCrabCore
@testable import MacCrabAgentKit

@Suite("Runtime configuration and request contracts")
struct RuntimeControlContractTests {
    private func directory() throws -> URL {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("maccrab-runtime-contract-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        return root
    }
    private let identity = EngineTelemetryIdentity(pid: 42, startedAtUnix: 1000, version: "1.22.0", build: "fixture")

    @Test("shared keys retain type, defaults, numeric bounds and application timing")
    func sharedDefinitions() throws {
        #expect(RuntimeConfigurationContract.definitions.count == 19)
        #expect(RuntimeConfigurationContract.byKey.count == RuntimeConfigurationContract.definitions.count)
        for definition in RuntimeConfigurationContract.definitions {
            let parsed = try definition.parse(definition.defaultValue.description)
            #expect(parsed == definition.defaultValue)
            #expect(try definition.normalized(parsed, forRequest: false) == definition.defaultValue)
            if let minimum = definition.minimum, let maximum = definition.maximum {
                let low = definition.kind == .int ? RuntimeConfigValue.integer(Int(minimum)) : .number(minimum)
                let high = definition.kind == .int ? RuntimeConfigValue.integer(Int(maximum)) : .number(maximum)
                #expect(try definition.normalized(low, forRequest: false) == low)
                #expect(try definition.normalized(high, forRequest: false) == high)
            }
        }
        let unsupported = try #require(RuntimeConfigurationContract.byKey["prompt_injection_confidence"])
        #expect(throws: RuntimeConfigContractError.self) { try unsupported.normalized(.integer(40)) }
        #expect(RuntimeConfigurationContract.byKey["threat_intel_enabled"]?.application == .live)
        #expect(RuntimeConfigurationContract.byKey["usb_poll_interval"]?.application == .restart)
    }

    @Test("boot configuration reports actual source and original value alongside normalization")
    func configuredSourceAndBounds() throws {
        let root = try directory()
        defer { try? FileManager.default.removeItem(at: root) }
        try Data(#"{"usb_poll_interval":10,"usbPollInterval":20,"intent_posterior_threshold":0.9,"clipboard_poll_interval":120}"#.utf8)
            .write(to: root.appendingPathComponent("daemon_config.json"))
        let config = DaemonConfig.load(from: root.path, applyOverrides: false)
        let entries = config.effectiveRuntimeEntries()
        #expect(entries["usb_poll_interval"]?.value == .number(20))
        #expect(entries["usb_poll_interval"]?.source == "daemon_config")
        #expect(entries["clipboard_poll_interval"]?.source == "daemon_config")
        #expect(entries["clipboard_poll_interval"]?.value == .number(60))
        #expect(entries["clipboard_poll_interval"]?.configuredValue == .number(120))
        #expect(entries["rootkit_poll_interval"]?.source == "default")
        #expect(entries["prompt_injection_confidence"]?.value == nil)
        #expect(entries["intent_posterior_threshold"]?.configuredValue == .number(0.9))
    }

    @Test("accepted startup-only requests survive a reporter restart and become applied with boot evidence")
    func pendingRequestAcrossRestart() async throws {
        let root = try directory()
        defer { try? FileManager.default.removeItem(at: root) }
        let reporter = RuntimeConfigurationReporter()
        try await reporter.configure(directory: root.path, snapshot: .init(engineIdentity: identity, values: [
            "usb_poll_interval": .init(value: .number(10), configuredValue: .number(10), source: "default")
        ]))
        let id = UUID()
        try await reporter.record(.init(requestID: id, operation: "set-daemon-config", state: .accepted,
            engineIdentity: identity, key: "usb_poll_interval", requestedValue: .number(20),
            acceptedValue: .number(20), reason: "Persisted; awaiting restart"))
        let pending = try RuntimeConfigurationFiles.readReceipt(directory: root.path, requestID: id)
        #expect(pending?.state == .accepted)
        let next = RuntimeConfigurationReporter()
        let nextIdentity = EngineTelemetryIdentity(pid: 43, startedAtUnix: 2000, version: "1.22.0", build: "fixture")
        try await next.configure(directory: root.path, snapshot: .init(engineIdentity: nextIdentity, values: [
            "usb_poll_interval": .init(value: .number(20), configuredValue: .number(20), source: "daemon_config")
        ]))
        let applied = try RuntimeConfigurationFiles.readReceipt(directory: root.path, requestID: id)
        #expect(applied?.state == .applied)
        #expect(applied?.engineIdentity == nextIdentity)
        #expect(applied?.appliedGeneration == 1)
    }

    @Test("live application advances generation and preserves a durable rejected outcome")
    func liveAndRejectedOutcomes() async throws {
        let root = try directory()
        defer { try? FileManager.default.removeItem(at: root) }
        let reporter = RuntimeConfigurationReporter()
        try await reporter.configure(directory: root.path, snapshot: .init(engineIdentity: identity, values: [
            "vuln_scan_enabled": .init(value: .boolean(true), configuredValue: .boolean(true), source: "user_override")
        ]))
        let id = UUID()
        try await reporter.record(.init(requestID: id, operation: "set-daemon-config", state: .accepted,
            engineIdentity: identity, key: "vuln_scan_enabled", requestedValue: .boolean(false),
            acceptedValue: .boolean(false), reason: "Persisted"))
        try await reporter.apply(["vuln_scan_enabled": .init(value: .boolean(false), configuredValue: .boolean(false), source: "inbox")])
        let applied = try RuntimeConfigurationFiles.readReceipt(directory: root.path, requestID: id)
        #expect(applied?.state == .applied)
        #expect(applied?.appliedGeneration == 2)
        let rejectedID = UUID()
        try await reporter.record(.init(requestID: rejectedID, operation: "set-daemon-config", state: .rejected,
            engineIdentity: identity, reason: "This key has no runtime consumer"))
        let rejected = try RuntimeConfigurationFiles.readReceipt(directory: root.path, requestID: rejectedID)
        #expect(rejected?.state == .rejected)
        #expect(rejected?.appliedGeneration == nil)
    }

    @Test("reload batches acknowledge only the requests included in their completed operation")
    func reloadBatchBoundaries() async throws {
        let root = try directory()
        defer { try? FileManager.default.removeItem(at: root) }
        let reporter = RuntimeConfigurationReporter()
        try await reporter.configure(directory: root.path, snapshot: .init(engineIdentity: identity, values: [:]))
        let first = UUID(), second = UUID()
        try await reporter.record(.init(requestID: first, operation: "reload-rules", state: .accepted,
                                       engineIdentity: identity, reason: "Queued"))
        let batch = await reporter.takeReloadRequests()
        try await reporter.record(.init(requestID: second, operation: "reload-rules", state: .accepted,
                                       engineIdentity: identity, reason: "Queued later"))
        try await reporter.finishReload(batch, succeeded: true, reason: "Completed")
        let firstReceipt = try RuntimeConfigurationFiles.readReceipt(directory: root.path, requestID: first)
        let secondReceipt = try RuntimeConfigurationFiles.readReceipt(directory: root.path, requestID: second)
        #expect(firstReceipt?.state == .applied)
        #expect(secondReceipt?.state == .accepted)
        let hasQueued = await reporter.hasQueuedReloads()
        #expect(hasQueued)
    }
}
