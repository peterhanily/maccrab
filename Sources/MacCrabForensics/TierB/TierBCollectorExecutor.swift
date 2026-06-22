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
    case thirdPartyExecutionDisabled
    public var description: String {
        switch self {
        case .analyzerNotSupported(let id):
            return "Plugin '\(id)' is a Tier-B analyzer; analyzer execution is not yet supported (collector-only runtime)."
        case .thirdPartyExecutionDisabled:
            return "Third-party plugin execution is disabled by the operator (kill-switch). First-party plugins still run."
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
        registry: TierBRegistry = TierBRegistry(),
        allowUnsignedTrampoline: Bool = false   // `plugin test` only (DEBUG-honored); never set in production
    ) async throws -> TierBExecutionResult {
        let sandboxRunner = SandboxedTierBRunner(allowUnsignedTrampoline: allowUnsignedTrampoline)
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

        // Operator kill-switch (S4): a fast field lever to disable the freshly-live
        // third-party lane fleet-wide without an app update. First-party (MacCrab-
        // signed) plugins are unaffected.
        if sandboxed && thirdPartyExecutionDisabled() {
            throw TierBCollectorExecutorError.thirdPartyExecutionDisabled
        }

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
        // S5: BOTH catalog-trust-root overrides void the curated authority — the
        // pub-path override AND the staging-pub override (which swaps the signer).
        let overrideActive = !(env["MACCRAB_RAVE_CATALOG_PUB_PATH"] ?? "").isEmpty
            || RaveStagingPubOverride.isActive
        let base = env["MACCRAB_RAVE_BASE_URL"] ?? ""
        let official = base.isEmpty || base == "https://rave.maccrab.com" || base == "https://rave.maccrab.com/"
        return (official, overrideActive)
    }

    /// Operator kill-switch for the third-party lane: a flag file
    /// `<supportDir>/tierb_third_party_disabled`. Operator-settable, survives
    /// restarts, no app update needed. (A signed remote-config flip is the
    /// fleet-wide version — documented for the cross-repo server work.)
    public static func thirdPartyExecutionDisabled() -> Bool {
        FileManager.default.fileExists(
            atPath: RevocationReverifyService.defaultSupportDir()
                .appendingPathComponent("tierb_third_party_disabled").path)
    }
}
