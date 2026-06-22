// TierBCollectorExecutor — the single shared entry point for running an
// INSTALLED Tier-B collector, used by the CLI (`maccrabctl plugin run`), the
// dashboard ("Run on this Mac"), and the MCP server (forensics.run_collector),
// so the two-lane dispatch + fail-closed gating live in ONE place.
//
// Dispatch (Plan §3.1, disjoint lanes):
//   1. Try the UNSANDBOXED first-party lane — a byte-match to the compiled-in
//      FirstPartyTrustRoot anchor. If it resolves, run via FirstPartyTierBRunner.
//   2. Otherwise (firstPartyExecutionRefused) → the SANDBOXED third-party lane:
//      resolveForSandboxedExecution (fail-closed if the signed trampoline is
//      unavailable — never run untrusted code uncontained) → SandboxedTierBRunner.
//   3. Any other resolve error (quarantined / verification failed / not installed)
//      propagates — fail-closed.
//
// The executor resolves + runs + cleans up the verified temp; the CALLER owns
// the case store (artifact commit via TierBArtifactBridge + invocation recording),
// because the store handle differs per surface.

import Foundation

public enum TierBExecutionLane: String, Sendable {
    case firstParty = "first-party"
    case sandboxed = "sandboxed third-party"
}

public struct TierBExecutionResult: Sendable {
    public let outcome: TierBRunOutcome
    public let manifest: TierBManifest
    public let lane: TierBExecutionLane
}

public enum TierBCollectorExecutorError: Error, CustomStringConvertible {
    case analyzerNotSupported(pluginID: String)
    public var description: String {
        switch self {
        case .analyzerNotSupported(let id):
            return "Plugin '\(id)' is a Tier-B analyzer; analyzer execution is not yet supported (collector-only runtime)."
        }
    }
}

public enum TierBCollectorExecutor {

    /// Resolve + run an installed Tier-B collector. Throws on any fail-closed
    /// condition (not first-party AND not authorized-sandboxed; quarantined;
    /// verification failed; sandbox runtime unavailable for a third-party plugin).
    ///
    /// `officialSource` / `catalogOverrideActive` are the catalog-context
    /// defense-in-depth inputs the caller knows (env-derived). A non-collector
    /// (analyzer) is refused (collector-only runtime, B1).
    public static func runInstalled(
        pluginID: String,
        scratchDir: String,
        windowStartUnix: Int64? = nil,
        windowEndUnix: Int64? = nil,
        officialSource: Bool,
        catalogOverrideActive: Bool,
        registry: TierBRegistry = TierBRegistry()
    ) async throws -> TierBExecutionResult {
        let sandboxRunner = SandboxedTierBRunner()
        let verified: TierBRegistry.VerifiedPlugin
        let sandboxed: Bool
        do {
            verified = try await registry.resolveForFirstPartyExecution(
                pluginID: pluginID, officialSource: officialSource, catalogOverrideActive: catalogOverrideActive)
            sandboxed = false
        } catch let e as TierBRegistry.RegistryError {
            guard case .firstPartyExecutionRefused = e else { throw e }   // notInstalled/quarantined/verify → propagate
            verified = try await registry.resolveForSandboxedExecution(
                pluginID: pluginID,
                sandboxRuntimeAvailable: sandboxRunner.isRuntimeAvailable,
                hasValidCuratedReceipt: false,   // operator-trust (install) authorizes the contained lane
                catalogOverrideActive: catalogOverrideActive)
            sandboxed = true
        }
        defer { registry.cleanupVerifiedBinary(verified) }

        if verified.manifest.kind == .analyzer {
            throw TierBCollectorExecutorError.analyzerNotSupported(pluginID: pluginID)
        }

        let outcome = sandboxed
            ? try sandboxRunner.run(verified: verified, scratchDir: scratchDir,
                                    windowStartUnix: windowStartUnix, windowEndUnix: windowEndUnix)
            : try FirstPartyTierBRunner().run(verified: verified, scratchDir: scratchDir,
                                              windowStartUnix: windowStartUnix, windowEndUnix: windowEndUnix)
        return TierBExecutionResult(
            outcome: outcome, manifest: verified.manifest,
            lane: sandboxed ? .sandboxed : .firstParty)
    }

    /// The catalog-context flags from the process environment (the same
    /// defense-in-depth the first-party gate uses). Shared so every surface
    /// computes them identically.
    public static func catalogContextFromEnv() -> (officialSource: Bool, catalogOverrideActive: Bool) {
        let env = ProcessInfo.processInfo.environment
        let overrideActive = !(env["MACCRAB_RAVE_CATALOG_PUB_PATH"] ?? "").isEmpty
        let base = env["MACCRAB_RAVE_BASE_URL"] ?? ""
        let official = base.isEmpty || base == "https://rave.maccrab.com" || base == "https://rave.maccrab.com/"
        return (official, overrideActive)
    }
}
