// Fingerprinter target + result types. Stubs in v1.13a; flesh out
// in v1.14 when MCFP R0 / R1 land.
//
// Plan reference: §6.

import Foundation

/// What a Fingerprinter operates on. Three forms; one Fingerprinter
/// may declare itself applicable to a subset.
public enum FingerprintTarget: Sendable {
    /// Live process PID. The fingerprinter reads ES/runtime data
    /// for the live process. R0 (plan §6.4) determines which
    /// runtime components are observable.
    case process(pid: Int32)

    /// Path on disk to a Mach-O binary. Static components
    /// (`mcfp1/static/<arch>/<lc>/<cs>/<ent>`) compute from this
    /// without launching the binary.
    case file(URL)

    /// An existing fingerprint to recompute / verify against.
    case existing(FingerprintResult)
}

/// What a Fingerprinter returns. The result is a vector of
/// components — each independently confidence-rated — rather than
/// a single canonical string. Consumers pick components matching
/// their trust requirements.
///
/// MCFP v1 components: `static.arch`, `static.lc`, `static.cs`,
/// `static.ent`, `runtime.sys`, `runtime.startup-shape`, `dyld.image-order`.
public struct FingerprintResult: Sendable, Codable {

    /// The fingerprint scheme identifier (e.g. `mcfp1`).
    public let scheme: String

    /// Components, keyed by `"namespace.component"`. Values are
    /// hex-prefix strings of the component-specific hash.
    public let components: [String: String]

    /// Per-component confidence. Same keys as `components`.
    public let confidences: [String: Confidence]

    public init(
        scheme: String,
        components: [String: String],
        confidences: [String: Confidence]
    ) {
        self.scheme = scheme
        self.components = components
        self.confidences = confidences
    }
}
