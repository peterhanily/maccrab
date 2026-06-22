// RevocationReverify — the RUNTIME (not just install-time) revocation policy.
//
// Gap this closes (Plan Stream 5): today the signed revocation list is
// reconciled only when a plugin is installed (RevocationEnforcer.reconcileQuarantine
// at the install path). An install-once box that never installs again never
// re-checks, so a plugin REVOKED after it was installed keeps running, and a box
// that has been offline past the staleness ceiling cannot know whether a plugin
// was revoked since. This adds:
//
//   (1) staleAction — when the client's revocation data is older than the ceiling
//       (RaveTrustState.revocationFreshness) or was never fetched, a maybe-revoked
//       plugin may be running unknown to us. Fail-closed by trust class: a
//       third-party SIDELOAD is quarantined (we cannot confirm it is still
//       trusted); a curated STORE plugin warns (it carries the catalog vetting
//       chain); a BUILT-IN is unaffected (first-party, no remote revocation).
//
//   (2) runtimeQuarantine — the full sweep a timer applies: the union of
//       (a) plugins the verified list now revokes and (b) stale-escalated
//       third-party plugins. AUTHORITATIVE like reconcileQuarantine — a plugin
//       not in the result is (re-)allowed, so the moment a fresh list verifies,
//       the stale escalation self-heals.
//
// PURE: no I/O. The caller (a timer in the long-lived host) does fetch +
// Ed25519-verify (advancing RaveTrustState.recordRevocations → the freshness
// clock), supplies each installed plugin's PluginProvenance, and persists the
// result via PluginInstaller.applyQuarantine. The timer wiring itself is the
// deferred host integration; this is the writable, unit-tested decision core.

import Foundation

public enum RaveRevocationStaleAction: Sendable, Equatable {
    /// Revocation data is fresh — nothing to do.
    case ok
    /// Stale/never, but the plugin's trust class only warrants a warning
    /// (curated store plugin). Surface it; keep running.
    case warn(age: TimeInterval?)
    /// Stale/never AND high-risk (third-party sideload). Fail-closed: quarantine
    /// until a fresh revocation list confirms it is still trusted.
    case quarantine(age: TimeInterval?)
}

public enum RevocationReverify {

    /// Staleness escalation keyed on trust class. Fresh data → `.ok` for all.
    public static func staleAction(
        freshness: RaveRevocationFreshness,
        provenance: PluginProvenance
    ) -> RaveRevocationStaleAction {
        guard freshness.isStale else { return .ok }
        let age: TimeInterval?
        switch freshness {
        case .stale(let a): age = a
        case .never, .fresh: age = nil
        }
        switch provenance {
        case .builtIn:    return .ok                  // first-party — no remote revocation
        case .store:      return .warn(age: age)      // curated vetting chain — warn, keep running
        case .thirdParty: return .quarantine(age: age) // sideload — fail-closed when unconfirmable
        }
    }

    /// The full runtime quarantine sweep. `installed` pairs each plugin's
    /// revocation ref with its provenance. Returns the authoritative quarantine
    /// set: union of explicit revocations and stale-escalated third-party plugins
    /// (never double-listing one id).
    public static func runtimeQuarantine(
        installed: [(ref: RevocationEnforcer.InstalledRef, provenance: PluginProvenance)],
        against list: RaveRevocationList,
        freshness: RaveRevocationFreshness,
        now: Date = Date()
    ) -> [PluginInstaller.QuarantineRecord] {
        // (a) plugins the verified list explicitly revokes.
        var records = RevocationEnforcer.reconcileQuarantine(
            installed: installed.map { $0.ref }, against: list, now: now)
        let revoked = Set(records.map { $0.pluginID })

        // (b) staleness escalation for everything not already explicitly revoked.
        let stamp = ISO8601DateFormatter().string(from: now)
        for item in installed where !revoked.contains(item.ref.pluginID) {
            guard case .quarantine(let age) = staleAction(freshness: freshness, provenance: item.provenance) else {
                continue
            }
            let hours = Int((age ?? 0) / 3600)
            records.append(PluginInstaller.QuarantineRecord(
                pluginID: item.ref.pluginID,
                installedVersion: item.ref.version,
                reason: "revocation data is stale (\(hours)h old) — quarantined pending re-verify of the signed revocation list",
                code: "REVOCATION_STALE",
                advisoryURL: nil,
                revocationsSerial: list.serial,
                quarantinedAt: stamp))
        }
        return records
    }
}
