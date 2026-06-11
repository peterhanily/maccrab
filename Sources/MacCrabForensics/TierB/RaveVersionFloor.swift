// RaveVersionFloor — O3a (S2-05) version-floor policy, shared by both rave
// catalog clients (maccrabctl PluginCatalogFetch + dashboard install path) so
// the fail-closed rule has exactly one implementation, mirroring RaveSignerPin.
//
// A catalog entry's `metadata.min_maccrab_version` declares the minimum
// MacCrab version a plugin supports. The running app/CLI MUST refuse to
// install a plugin whose floor is newer than the running version — otherwise
// the operator installs a bundle that expects engine APIs / record shapes
// this build doesn't have.
//
// Fail-closed rule:
//   - floor present + running >= floor   → proceed
//   - floor present + running <  floor   → refuse (.belowFloor)
//   - floor present but UNPARSEABLE       → refuse (.unparseableFloor)
//   - running version unparseable         → refuse (.unparseableRunning)
//   - floor ABSENT                        → proceed (the catalog schema makes
//       min_maccrab_version required for entries written at/after the v1.19
//       ceremony, but pre-ceremony entries omit it; we don't block install on
//       an absent floor — the signer pin is the load-bearing trust gate).

import Foundation
import MacCrabCore

public enum RaveVersionFloorError: Error, Equatable, CustomStringConvertible {
    case belowFloor(pluginID: String, running: String, floor: String)
    case unparseableFloor(pluginID: String, floor: String)
    case unparseableRunning(running: String)

    public var description: String {
        switch self {
        case .belowFloor(let id, let running, let floor):
            return "Refusing to install \(id): it requires MacCrab \(floor) or newer, but this build is \(running). Update MacCrab, then retry."
        case .unparseableFloor(let id, let floor):
            return "Refusing to install \(id): its declared min_maccrab_version '\(floor)' is not a valid MAJOR.MINOR.PATCH version (fail-closed)."
        case .unparseableRunning(let running):
            return "Refusing to install: the running MacCrab version '\(running)' could not be parsed for the version-floor check (fail-closed)."
        }
    }
}

public enum RaveVersionFloor {

    /// Pure policy decision. `floor` is the entry's
    /// `metadata.min_maccrab_version` (nil/empty when absent); `running` is the
    /// running build's version (`MacCrabVersion.current`). Throws when the
    /// install must be refused; returns normally when it may proceed.
    public static func enforce(
        pluginID: String,
        floor: String?,
        running: String
    ) throws {
        // Absent floor → no version gate (signer pin remains the trust gate).
        guard let floor = floor, !floor.isEmpty else { return }

        // The running version must parse, or we can't make a safe decision.
        guard MacCrabSemver(running) != nil else {
            throw RaveVersionFloorError.unparseableRunning(running: running)
        }
        // An unparseable floor is a fail-closed refusal — never a silent pass.
        guard MacCrabSemver(floor) != nil else {
            throw RaveVersionFloorError.unparseableFloor(pluginID: pluginID, floor: floor)
        }
        // satisfiesFloor returns non-nil here (both parsed above).
        if MacCrabSemverCompare.satisfiesFloor(running: running, floor: floor) != true {
            throw RaveVersionFloorError.belowFloor(
                pluginID: pluginID, running: running, floor: floor
            )
        }
    }
}
