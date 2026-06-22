// RevocationReverifyService — wires the pure RevocationReverify policy into the
// installed-plugin store: it advances the freshness clock when given a
// freshly-verified revocations list, computes the runtime quarantine sweep
// (explicit revocations ∪ stale-escalated third-party), and applies it.
//
// Closes the install-once-box gap (Plan Stream 5): a long-lived host calls
// `reconcile` on a timer. With a fresh list (online) it re-verifies + clears the
// staleness escalation; with NO list (offline / periodic) it still fail-closes a
// third-party plugin whose revocation data has gone stale past the ceiling — so
// a box that never installs again cannot keep running a since-revoked plugin.

import Foundation

public enum RevocationReverifyService {

    /// Reconcile installed Tier-B plugins against the revocation state and apply
    /// the resulting quarantine. `verifiedList` is a freshly fetched +
    /// signature-verified list (online); pass nil for an offline/periodic
    /// staleness sweep. Returns the records applied. The caller owns fetch +
    /// Ed25519-verify (the trust floor); this owns reconcile + apply + freshness.
    @discardableResult
    public static func reconcile(
        verifiedList: RaveRevocationList?,
        installer: PluginInstaller,
        trustStateStore: RaveTrustStateStore,
        receiptsDir: URL,
        now: Date = Date()
    ) async throws -> [PluginInstaller.QuarantineRecord] {
        // A freshly-verified list refreshes the staleness clock (and advances the
        // monotonic serial high-water mark; recordRevocations never lowers it).
        if let list = verifiedList {
            try? trustStateStore.recordRevocations(serial: list.serial ?? 0, verifiedAt: now)
        }
        let freshness = trustStateStore.revocationFreshness(now: now)

        let installed = try await installer.list()
        var refs: [(ref: RevocationEnforcer.InstalledRef, provenance: PluginProvenance)] = []
        refs.reserveCapacity(installed.count)
        for p in installed {
            let version = (try? TierBManifest.load(fromBundlePath: p.installRoot))?.version ?? "0"
            let provenance = PluginProvenance.forInstalled(pluginID: p.pluginID, receiptsDir: receiptsDir)
            refs.append((RevocationEnforcer.InstalledRef(pluginID: p.pluginID, version: version), provenance))
        }

        // Offline → an empty list (no explicit revocations), so only the staleness
        // escalation fires; online → the verified list drives explicit revocations.
        let list = verifiedList ?? RaveRevocationList(formatVersion: "1", serial: nil, updatedAt: nil, revocations: [])
        let records = RevocationReverify.runtimeQuarantine(
            installed: refs, against: list, freshness: freshness, now: now)
        _ = try await installer.applyQuarantine(records)
        return records
    }

    /// The MacCrab support dir (`~/Library/Application Support/MacCrab`).
    public static func defaultSupportDir() -> URL {
        (FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
            ?? URL(fileURLWithPath: NSHomeDirectory() + "/Library/Application Support"))
            .appendingPathComponent("MacCrab")
    }

    /// Reconcile against the default installer / trust-state / receipts paths.
    /// The host calls this at launch (verifiedList nil → staleness self-heal) and
    /// on a timer; pass a freshly-verified list for an online re-verify.
    @discardableResult
    public static func reconcileDefaults(
        verifiedList: RaveRevocationList? = nil, now: Date = Date()
    ) async throws -> [PluginInstaller.QuarantineRecord] {
        let support = defaultSupportDir()
        return try await reconcile(
            verifiedList: verifiedList,
            installer: PluginInstaller(),
            trustStateStore: RaveTrustStateStore.default(supportDir: support.path),
            receiptsDir: support.appendingPathComponent("plugin_receipts"),
            now: now)
    }
}
