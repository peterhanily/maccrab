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

public enum RevocationReverifyServiceError: Error, LocalizedError, Sendable, Equatable {
    case rollback(stored: Int, incoming: Int)
    case serialMissing(lastAccepted: Int)

    public var errorDescription: String? {
        switch self {
        case .rollback(let stored, let incoming):
            return "Revocation reconcile rejected rollback serial \(incoming); last accepted serial is \(stored)"
        case .serialMissing(let lastAccepted):
            return "Revocation reconcile rejected a serial-less list after accepting serial \(lastAccepted)"
        }
    }
}

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
        let installed = try await installer.list()
        var refs: [(ref: RevocationEnforcer.InstalledRef, provenance: PluginProvenance)] = []
        refs.reserveCapacity(installed.count)
        for p in installed {
            let version = (try? TierBManifest.load(fromBundlePath: p.installRoot))?.version ?? "0"
            let provenance = PluginProvenance.forInstalled(pluginID: p.pluginID, receiptsDir: receiptsDir)
            refs.append((RevocationEnforcer.InstalledRef(pluginID: p.pluginID, version: version), provenance))
        }

        let records: [PluginInstaller.QuarantineRecord]
        if let list = verifiedList {
            if let serial = list.serial {
                if case .rollback(let stored, let incoming) =
                    trustStateStore.evaluateRevocations(incoming: serial) {
                    throw RevocationReverifyServiceError.rollback(
                        stored: stored, incoming: incoming)
                }
            } else if let stored = trustStateStore.currentRevocationsSerial() {
                throw RevocationReverifyServiceError.serialMissing(lastAccepted: stored)
            }
            // A caller-supplied list is freshly signature-verified, so evaluate
            // it as fresh even before the durability write below. Applying the
            // quarantine MUST precede advancing the freshness/high-water mark:
            // otherwise a crash or write failure between those operations makes
            // the next throttled sweep believe revocation enforcement landed
            // when it did not.
            records = RevocationReverify.runtimeQuarantine(
                installed: refs, against: list, freshness: .fresh(age: 0), now: now)
            _ = try await installer.applyQuarantine(records)
            if let serial = list.serial {
                try trustStateStore.recordRevocations(serial: serial, verifiedAt: now)
            }
        } else {
            // An offline/periodic sweep has no authenticated statement that a
            // prior explicit revocation was withdrawn. Treating nil as an
            // authoritative empty list erased MALWARE quarantines immediately
            // before execution. Preserve every existing record for an installed
            // plugin and add any newly-triggered staleness quarantine. Only a
            // freshly verified list may authoritatively un-quarantine.
            let emptyList = RaveRevocationList(
                formatVersion: "1", serial: nil, updatedAt: nil, revocations: [])
            let staleRecords = RevocationReverify.runtimeQuarantine(
                installed: refs,
                against: emptyList,
                freshness: trustStateStore.revocationFreshness(now: now),
                now: now)
            let installedIDs = Set(refs.map { $0.ref.pluginID })
            var merged = await installer.currentQuarantine()
                .filter { installedIDs.contains($0.key) }
            for record in staleRecords where merged[record.pluginID] == nil {
                merged[record.pluginID] = record
            }
            records = Array(merged.values)
            _ = try await installer.applyQuarantine(records)
        }
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
