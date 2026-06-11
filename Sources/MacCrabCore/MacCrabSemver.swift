// MacCrabSemver.swift
// MacCrabCore
//
// S2-05 (O3a) — canonical semver comparator for MacCrab's own version
// string, used to enforce a plugin's `metadata.min_maccrab_version`
// floor before install.
//
// Why this lives in MacCrabCore and not MacCrabApp: Sparkle's
// SUStandardVersionComparator is only linked into MacCrabApp, but the
// maccrabctl CLI install path (PluginCatalogFetch) needs the same
// comparison — and so does the MacCrabForensics floor policy that both
// clients call. MacCrabCore is the one module every install path links,
// so the comparator goes here next to `MacCrabVersion`.
//
// Scope is deliberately narrow: parse `MAJOR.MINOR.PATCH` with an
// OPTIONAL pre-release suffix (`-rc.1`, `-rc1`, `-beta`, ...), order
// per SemVer §11 (a pre-release is LOWER precedence than the same
// core release), and ignore build metadata (`+...`) per §10.
//
// The running app/CLI version (`MacCrabVersion.current`) can carry an
// `-rc` suffix during a release cycle; the catalog's
// `min_maccrab_version` is always a bare `MAJOR.MINOR.PATCH` (schema
// pattern `^[0-9]+\.[0-9]+\.[0-9]+$`). So the common floor check is
// "is the running version >= a bare floor" — and an `-rc` of the floor
// release must compare BELOW the floor (1.19.0-rc.1 < 1.19.0), which
// the SemVer §11 ordering gives us for free.

import Foundation

/// Minimal, dependency-free SemVer value for ordering MacCrab versions.
/// Conforms to `Comparable`, so `<`, `>`, `>=`, `==` all work directly.
public struct MacCrabSemver: Equatable, Comparable, Sendable, CustomStringConvertible {
    public let major: Int
    public let minor: Int
    public let patch: Int
    /// Dot-separated pre-release identifiers (empty for a release version).
    /// e.g. `1.19.0-rc.1` → `["rc", "1"]`; `1.19.0-rc1` → `["rc1"]`.
    public let prerelease: [String]

    /// Parse a version string. Returns nil for anything that isn't a
    /// well-formed `MAJOR.MINOR.PATCH(-prerelease)?(+build)?`.
    public init?(_ raw: String) {
        // Trim a leading "v" (some callers print "v1.19.0"); harmless.
        var s = Substring(raw)
        if s.first == "v" || s.first == "V" { s = s.dropFirst() }

        // Strip build metadata (everything after the first '+'), per §10.
        let noBuild = s.split(separator: "+", maxSplits: 1, omittingEmptySubsequences: false)[0]
        // Split core from pre-release on the first '-'.
        let parts = noBuild.split(separator: "-", maxSplits: 1, omittingEmptySubsequences: false)
        let core = parts[0]
        let coreFields = core.split(separator: ".", omittingEmptySubsequences: false)
        guard coreFields.count == 3,
              let ma = Int(coreFields[0]),
              let mi = Int(coreFields[1]),
              let pa = Int(coreFields[2]),
              ma >= 0, mi >= 0, pa >= 0 else {
            return nil
        }
        self.major = ma
        self.minor = mi
        self.patch = pa
        if parts.count == 2 {
            let pre = parts[1]
                .split(separator: ".", omittingEmptySubsequences: false)
                .map(String.init)
            // A trailing/empty pre-release ("1.0.0-" / "1.0.0-rc..1") is malformed.
            if pre.contains(where: { $0.isEmpty }) { return nil }
            self.prerelease = pre
        } else {
            self.prerelease = []
        }
    }

    public var description: String {
        let core = "\(major).\(minor).\(patch)"
        return prerelease.isEmpty ? core : core + "-" + prerelease.joined(separator: ".")
    }

    public static func < (lhs: MacCrabSemver, rhs: MacCrabSemver) -> Bool {
        if lhs.major != rhs.major { return lhs.major < rhs.major }
        if lhs.minor != rhs.minor { return lhs.minor < rhs.minor }
        if lhs.patch != rhs.patch { return lhs.patch < rhs.patch }
        // Equal core. Pre-release precedence (SemVer §11):
        //   a version WITH a pre-release < the same version WITHOUT one.
        let lpre = lhs.prerelease, rpre = rhs.prerelease
        if lpre.isEmpty && rpre.isEmpty { return false }
        if lpre.isEmpty { return false }          // release > any prerelease
        if rpre.isEmpty { return true }           // prerelease < release
        // Compare identifiers left to right.
        let count = min(lpre.count, rpre.count)
        for i in 0..<count {
            let a = lpre[i], b = rpre[i]
            if a == b { continue }
            let an = Int(a), bn = Int(b)
            switch (an, bn) {
            case let (.some(x), .some(y)):
                return x < y                       // both numeric: compare values
            case (.some, .none):
                return true                        // numeric identifiers < alphanumeric
            case (.none, .some):
                return false
            case (.none, .none):
                return a < b                       // both alphanumeric: ASCII order
            }
        }
        // All shared identifiers equal: the shorter set has lower precedence.
        return lpre.count < rpre.count
    }
}

public enum MacCrabSemverCompare {
    /// True iff `running` satisfies a minimum-version `floor` — i.e.
    /// `running >= floor` under SemVer ordering. Returns nil when either
    /// string fails to parse, so the caller can decide its own fail-closed
    /// policy (an unparseable floor must NOT silently pass).
    ///
    /// `running` may carry an `-rc` suffix (`MacCrabVersion.current` during a
    /// release cycle); `floor` is a bare release from the catalog. An `-rc`
    /// of the floor release is BELOW it (1.19.0-rc.1 does not satisfy a
    /// 1.19.0 floor), which is the intended fail-closed behavior.
    public static func satisfiesFloor(running: String, floor: String) -> Bool? {
        guard let r = MacCrabSemver(running), let f = MacCrabSemver(floor) else {
            return nil
        }
        return r >= f
    }
}
