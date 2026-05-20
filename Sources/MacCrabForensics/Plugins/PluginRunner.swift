// PluginRunner — orchestrates a single plugin invocation per
// plan §3.5.
//
//   register at app launch
//     → validate manifest
//     → register MCP tools (deferred to v1.13a-1.7)
//     → idle until invoked
//
//   invocation:
//     validate case exists; unlock DEK if encrypted   (CaseManager.openCase)
//     check TCC requirements                          (deferred — concrete collectors)
//     snapshot live DBs                                (deferred — concrete collectors)
//     open plugin_invocations row (status=running)
//     call collect / enrich / fingerprint / analyze
//     update plugin_invocations row (status=ok|partial|error|cancelled)
//
// v1.13a-1 ships Collector path only; the Enricher /
// Fingerprinter / Analyzer paths are added when their first
// real plugins land.

import Foundation

/// Invocation arguments — what the operator typed on the CLI or
/// what an MCP tool call supplied.
public struct PluginInvocationInputs: Sendable, Codable {
    public let values: [String: InputValue]

    public init(values: [String: InputValue] = [:]) {
        self.values = values
    }

    public static let empty = PluginInvocationInputs(values: [:])
}

public enum PluginRunnerError: Error, CustomStringConvertible {
    case pluginNotFound(id: String)
    case pluginKindMismatch(expected: PluginType, got: PluginType)
    case constructionFailed(id: String, message: String)
    case runtimeError(id: String, message: String)
    case inputsEncodeFailed(message: String)

    public var description: String {
        switch self {
        case .pluginNotFound(let id):
            return "PluginRunner: no plugin registered for id '\(id)'"
        case .pluginKindMismatch(let exp, let got):
            return "PluginRunner: invoked as \(exp.rawValue) but plugin is \(got.rawValue)"
        case .constructionFailed(let id, let m):
            return "PluginRunner: failed to construct plugin '\(id)': \(m)"
        case .runtimeError(let id, let m):
            return "PluginRunner: plugin '\(id)' threw at runtime: \(m)"
        case .inputsEncodeFailed(let m):
            return "PluginRunner: couldn't serialize inputs: \(m)"
        }
    }
}

public actor PluginRunner {

    private let registry: PluginRegistry

    public init(registry: PluginRegistry = .shared) {
        self.registry = registry
    }

    /// Run a Collector against a CaseHandle. Returns the
    /// CollectionResult and the plugin_invocations row id.
    @discardableResult
    public func runCollector(
        id: String,
        handle: CaseHandle,
        window: TimeWindow? = nil,
        inputs: PluginInvocationInputs = .empty
    ) async throws -> (result: CollectionResult, invocationID: Int64) {

        guard let registration = await registry.registration(forID: id) else {
            throw PluginRunnerError.pluginNotFound(id: id)
        }
        guard registration.manifest.type == .collector else {
            throw PluginRunnerError.pluginKindMismatch(
                expected: .collector,
                got: registration.manifest.type
            )
        }

        // Construct the plugin instance.
        let pluginAny: any ForensicPlugin
        do {
            pluginAny = try await registration.factory()
        } catch {
            throw PluginRunnerError.constructionFailed(
                id: id,
                message: error.localizedDescription
            )
        }
        guard let collector = pluginAny as? any Collector else {
            // Manifest said collector but the registered type
            // doesn't conform to Collector. Manifest authoring
            // bug; surface clearly.
            throw PluginRunnerError.runtimeError(
                id: id,
                message: "plugin registered as collector but does not conform to Collector protocol"
            )
        }

        // Serialize inputs for the audit log.
        let inputsJSON = try Self.encodeInputs(inputs)

        // Build the CaseContext + write-only output.
        let caseContext: CaseContext
        if let row = try await handle.store.fetchCase(id: handle.caseID) {
            caseContext = CaseContext(
                caseID: row.id,
                caseName: row.name,
                aiContentAllowed: row.aiContentAllowed,
                scheduledTrusted: row.scheduledTrusted,
                directory: handle.layout.caseDirectory,
                encryptionState: row.encryptionState
            )
        } else {
            // The CaseHandle wraps a real case; if fetchCase
            // returns nil at this point, something has gone deeply
            // wrong with the store. Surface as runtime error.
            throw PluginRunnerError.runtimeError(
                id: id,
                message: "case row absent from store at invocation"
            )
        }
        let output = StoreCollectorOutput(store: handle.store)

        // Open the plugin_invocations row.
        let invocationID = try await handle.store.recordInvocationStart(
            caseID: handle.caseID,
            pluginID: registration.manifest.id,
            pluginVersion: registration.manifest.version,
            inputsJSON: inputsJSON
        )

        // Run the collector with try/throw mapping back into the
        // invocations row.
        do {
            let result = try await collector.collect(
                case: caseContext,
                window: window,
                output: output
            )
            try await handle.store.recordInvocationEnd(
                id: invocationID,
                exitStatus: result.status.rawValue,
                artifactsCommitted: Int64(result.artifactsCommitted),
                artifactsRejected: Int64(result.artifactsRejected),
                errorMessage: nil,
                snapshotHash: nil
            )
            return (result, invocationID)
        } catch {
            try await handle.store.recordInvocationEnd(
                id: invocationID,
                exitStatus: "error",
                artifactsCommitted: 0,
                artifactsRejected: 0,
                errorMessage: error.localizedDescription,
                snapshotHash: nil
            )
            throw PluginRunnerError.runtimeError(
                id: id,
                message: error.localizedDescription
            )
        }
    }

    /// Run an Enricher against a single subject + stage. Returns
    /// the Enrichment plus the plugin_invocations row id (so the
    /// caller can attribute the enrichment to a specific run).
    ///
    /// v1.13a-2 ships only the codesign-resolve enricher; the runner
    /// supports the protocol surface but no Track 1 pipeline
    /// integration is wired yet — that's a follow-up.
    @discardableResult
    public func runEnricher(
        id: String,
        handle: CaseHandle,
        subject: EnrichmentSubject,
        stage: EnrichmentStage,
        inputs: PluginInvocationInputs = .empty
    ) async throws -> (enrichment: Enrichment, invocationID: Int64) {

        guard let registration = await registry.registration(forID: id) else {
            throw PluginRunnerError.pluginNotFound(id: id)
        }
        guard registration.manifest.type == .enricher else {
            throw PluginRunnerError.pluginKindMismatch(
                expected: .enricher,
                got: registration.manifest.type
            )
        }
        let pluginAny: any ForensicPlugin
        do {
            pluginAny = try await registration.factory()
        } catch {
            throw PluginRunnerError.constructionFailed(
                id: id,
                message: error.localizedDescription
            )
        }
        guard let enricher = pluginAny as? any Enricher else {
            throw PluginRunnerError.runtimeError(
                id: id,
                message: "plugin registered as enricher but does not conform to Enricher protocol"
            )
        }

        let inputsJSON = try Self.encodeInputs(inputs)
        let invocationID = try await handle.store.recordInvocationStart(
            caseID: handle.caseID,
            pluginID: registration.manifest.id,
            pluginVersion: registration.manifest.version,
            inputsJSON: inputsJSON
        )

        do {
            let enrichment = try await enricher.enrich(subject, stage: stage)
            try await handle.store.recordInvocationEnd(
                id: invocationID,
                exitStatus: "ok",
                artifactsCommitted: 0,
                artifactsRejected: 0,
                errorMessage: nil,
                snapshotHash: nil
            )
            return (enrichment, invocationID)
        } catch {
            try await handle.store.recordInvocationEnd(
                id: invocationID,
                exitStatus: "error",
                artifactsCommitted: 0,
                artifactsRejected: 0,
                errorMessage: error.localizedDescription,
                snapshotHash: nil
            )
            throw PluginRunnerError.runtimeError(
                id: id,
                message: error.localizedDescription
            )
        }
    }

    // MARK: - Helpers

    private static func encodeInputs(_ inputs: PluginInvocationInputs) throws -> String {
        do {
            let data = try JSONEncoder().encode(inputs)
            return String(data: data, encoding: .utf8) ?? "{}"
        } catch {
            throw PluginRunnerError.inputsEncodeFailed(
                message: error.localizedDescription
            )
        }
    }
}
