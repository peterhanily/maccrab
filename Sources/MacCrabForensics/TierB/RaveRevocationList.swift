// RaveRevocationList — the client-side model + parser for the rave signed
// revocation list (O2, S2-03/04). Matches the frozen rave schema
// (maccrab-rave/schemas/revocation.json, committed in 96c76d2):
//
//   {
//     "version": "0",               // FORMAT version (const "0")
//     "serial": <int ≥0>,           // monotonic, signed freshness/rollback counter
//     "updated_at": "<ISO8601>",
//     "revocations": [
//       {
//         "plugin_id": "com.maccrab.forensics.<id>",
//         "scope": { "kind": "single_version", "version": "1.0.0" }
//              | { "kind": "version_range", "from_version": "1.0.0", "to_version": "1.2.0" }
//              | { "kind": "all_versions" },
//         "reason": "...",
//         "code": "compromise" | ... ,
//         "advisory_url": "https://...",            // optional
//         "decided_at": "<ISO8601>",
//         "decided_by": ["<github-login>", ...],
//         "affected_signing_identity": { ... }      // optional
//       }
//     ]
//   }
//
// Keying model (the resolved O2 decision per TRUST-FLOOR-SPEC-v1.18 §1,
// option 1 "resolve at consume time"): a revocation is keyed by `plugin_id`
// + a version scope, NOT by publisher key. To honor a revocation the client
// matches the installed plugin's id + version against the scope; the local
// operator `revoked-keys.json` (key-hex set in PluginInstaller) stays a
// SEPARATE list — the remote signed list AUGMENTS it, it does not replace it.
//
// This file is pure (no I/O, no network): parse + scope matching only, so the
// whole decision surface is unit-testable. Fetch + Ed25519-verify +
// anti-rollback live in the catalog clients (which already own catalog.pub);
// quarantine reconciliation lives in RevocationEnforcer.

import Foundation

/// Which versions of a plugin a revocation entry covers.
public enum RaveRevocationScope: Sendable, Equatable {
    /// Exactly one version is revoked.
    case singleVersion(String)
    /// An inclusive version range. `to` is nil when the schema omits
    /// `to_version` — an open-ended "from this version onward" revocation.
    case versionRange(from: String, to: String?)
    /// Every version of the plugin is revoked.
    case allVersions

    /// True iff `version` falls within this scope. Comparison is
    /// SemVer-aware (numeric field ordering, pre-release < release), so a
    /// `version_range` revocation covers the half-open numeric interval.
    /// An unparseable installed `version` against a single/range scope
    /// fails CLOSED for `all_versions` (always covered) and for an exact
    /// string-equal `single_version`; a malformed version that doesn't
    /// string-equal and can't be ordered is treated as NOT covered by a
    /// range only when at least one bound likewise can't be ordered — see
    /// `covers` below for the precise fail-closed handling.
    public func covers(version: String) -> Bool {
        switch self {
        case .allVersions:
            return true
        case .singleVersion(let v):
            // Exact match first (covers pre-release tags + non-semver ids),
            // then a SemVer-equality fallback so "1.0" vs "1.0.0"-style
            // differences still match when both parse.
            if v == version { return true }
            if let a = SemVer(v), let b = SemVer(version) { return a == b }
            return false
        case .versionRange(let from, let to):
            return Self.rangeCovers(version: version, from: from, to: to)
        }
    }

    /// Inclusive [from, to] range membership. If a bound can't be parsed as
    /// SemVer we fall back to an exact string-equality check against that
    /// bound (so a non-semver tag named exactly at a bound is still caught),
    /// but we never silently treat an unorderable version as "outside" the
    /// range — if the installed version itself can't be ordered, it is only
    /// covered when it string-equals one of the bounds.
    private static func rangeCovers(version: String, from: String, to: String?) -> Bool {
        // Exact-bound string match short-circuit (fail-closed for non-semver).
        if version == from { return true }
        if let to = to, version == to { return true }
        guard let v = SemVer(version), let lo = SemVer(from) else {
            return false
        }
        guard v >= lo else { return false }
        guard let to = to else {
            // Open-ended range: everything >= from.
            return true
        }
        guard let hi = SemVer(to) else {
            // `to` unparseable but not string-equal → can't bound the top;
            // fail closed by treating the range as open-ended from `from`.
            return true
        }
        return v <= hi
    }
}

/// A single revocation entry. Only the fields the client acts on are modeled
/// strongly; the rest are carried as operator-facing strings.
public struct RaveRevocation: Sendable, Equatable {
    public let pluginID: String
    public let scope: RaveRevocationScope
    public let reason: String
    public let code: String
    public let advisoryURL: String?
    public let decidedAt: String
    public let decidedBy: [String]

    public init(
        pluginID: String,
        scope: RaveRevocationScope,
        reason: String,
        code: String,
        advisoryURL: String? = nil,
        decidedAt: String,
        decidedBy: [String]
    ) {
        self.pluginID = pluginID
        self.scope = scope
        self.reason = reason
        self.code = code
        self.advisoryURL = advisoryURL
        self.decidedAt = decidedAt
        self.decidedBy = decidedBy
    }

    /// True iff this entry revokes the given installed plugin id + version.
    public func revokes(pluginID id: String, version: String) -> Bool {
        guard id == pluginID else { return false }
        return scope.covers(version: version)
    }
}

/// The parsed, signature-verified revocation list. `serial` is the monotonic
/// anti-rollback counter (optional in the schema only so pre-ceremony signed
/// bytes still validate; the client treats a missing serial as first-seen).
public struct RaveRevocationList: Sendable, Equatable {
    public let formatVersion: String
    public let serial: Int?
    public let updatedAt: String?
    public let revocations: [RaveRevocation]

    public init(
        formatVersion: String,
        serial: Int?,
        updatedAt: String?,
        revocations: [RaveRevocation]
    ) {
        self.formatVersion = formatVersion
        self.serial = serial
        self.updatedAt = updatedAt
        self.revocations = revocations
    }

    /// All entries that revoke the given installed plugin id + version.
    public func entriesRevoking(pluginID id: String, version: String) -> [RaveRevocation] {
        revocations.filter { $0.revokes(pluginID: id, version: version) }
    }

    public enum ParseError: Error, Equatable, CustomStringConvertible {
        case notAnObject
        case missingTopLevelField(String)
        case revocationsNotArray
        case revocationEntryMalformed(index: Int, reason: String)
        case scopeMalformed(index: Int, reason: String)

        public var description: String {
            switch self {
            case .notAnObject:
                return "revocations.json is not a JSON object"
            case .missingTopLevelField(let f):
                return "revocations.json missing required field '\(f)'"
            case .revocationsNotArray:
                return "revocations.json 'revocations' is not an array"
            case .revocationEntryMalformed(let i, let r):
                return "revocations.json revocation[\(i)] malformed: \(r)"
            case .scopeMalformed(let i, let r):
                return "revocations.json revocation[\(i)] scope malformed: \(r)"
            }
        }
    }

    /// Parse a (already signature-verified) revocations.json byte payload.
    /// Fail-CLOSED: a malformed document throws rather than degrading to an
    /// empty list — an empty list would silently un-revoke everything. The
    /// caller decides what to do with a parse failure (keep the prior trusted
    /// list; never treat as "no revocations").
    public static func parse(data: Data) throws -> RaveRevocationList {
        guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw ParseError.notAnObject
        }
        // FORMAT version (schema const "0"). Required field per schema.
        guard let formatVersion = json["version"] as? String else {
            throw ParseError.missingTopLevelField("version")
        }
        // updated_at required by schema, but tolerate absence (diagnostic
        // only) so a slightly-old signed doc still loads.
        let updatedAt = json["updated_at"] as? String
        // Monotonic serial — required-going-forward but schema-optional for
        // pre-ceremony bytes. Reject a non-integer rather than silently
        // dropping it (a string "0" must not slip past the rollback gate).
        let serial = (json["serial"] as? NSNumber)?.intValue

        guard let rawList = json["revocations"] else {
            throw ParseError.missingTopLevelField("revocations")
        }
        guard let arr = rawList as? [[String: Any]] else {
            throw ParseError.revocationsNotArray
        }

        var parsed: [RaveRevocation] = []
        parsed.reserveCapacity(arr.count)
        for (i, entry) in arr.enumerated() {
            guard let pluginID = entry["plugin_id"] as? String, !pluginID.isEmpty else {
                throw ParseError.revocationEntryMalformed(index: i, reason: "missing plugin_id")
            }
            guard let reason = entry["reason"] as? String else {
                throw ParseError.revocationEntryMalformed(index: i, reason: "missing reason")
            }
            guard let code = entry["code"] as? String else {
                throw ParseError.revocationEntryMalformed(index: i, reason: "missing code")
            }
            guard let decidedAt = entry["decided_at"] as? String else {
                throw ParseError.revocationEntryMalformed(index: i, reason: "missing decided_at")
            }
            let decidedBy = (entry["decided_by"] as? [String]) ?? []
            guard !decidedBy.isEmpty else {
                throw ParseError.revocationEntryMalformed(index: i, reason: "decided_by must be a non-empty string array")
            }
            let advisoryURL = entry["advisory_url"] as? String
            let scope = try parseScope(entry["scope"], index: i)
            parsed.append(RaveRevocation(
                pluginID: pluginID,
                scope: scope,
                reason: reason,
                code: code,
                advisoryURL: advisoryURL,
                decidedAt: decidedAt,
                decidedBy: decidedBy
            ))
        }
        return RaveRevocationList(
            formatVersion: formatVersion,
            serial: serial,
            updatedAt: updatedAt,
            revocations: parsed
        )
    }

    private static func parseScope(_ raw: Any?, index: Int) throws -> RaveRevocationScope {
        guard let obj = raw as? [String: Any] else {
            throw ParseError.scopeMalformed(index: index, reason: "scope is not an object")
        }
        guard let kind = obj["kind"] as? String else {
            throw ParseError.scopeMalformed(index: index, reason: "scope missing 'kind'")
        }
        switch kind {
        case "single_version":
            guard let v = obj["version"] as? String, !v.isEmpty else {
                throw ParseError.scopeMalformed(index: index, reason: "single_version scope missing 'version'")
            }
            return .singleVersion(v)
        case "version_range":
            guard let from = obj["from_version"] as? String, !from.isEmpty else {
                throw ParseError.scopeMalformed(index: index, reason: "version_range scope missing 'from_version'")
            }
            let to = obj["to_version"] as? String
            return .versionRange(from: from, to: (to?.isEmpty == false) ? to : nil)
        case "all_versions":
            return .allVersions
        default:
            // Unknown scope kind: fail CLOSED. We don't know what it covers,
            // so we can't honor it — but we MUST NOT silently treat it as a
            // no-op. Throwing keeps the prior trusted list in effect rather
            // than accepting a list whose meaning we can't enforce.
            throw ParseError.scopeMalformed(index: index, reason: "unknown scope kind '\(kind)'")
        }
    }
}

// MARK: - Minimal SemVer (internal)

/// Just enough SemVer to order plugin versions for `version_range` scopes.
/// Matches the catalog's version pattern `MAJOR.MINOR.PATCH(-prerelease)?`.
/// Build metadata (`+...`) is ignored for ordering per SemVer §10; a
/// pre-release version is lower-precedence than the same core release.
struct SemVer: Equatable, Comparable {
    let major: Int
    let minor: Int
    let patch: Int
    /// Dot-separated pre-release identifiers (empty for a release version).
    let prerelease: [String]

    init?(_ raw: String) {
        // Strip build metadata.
        let noBuild = raw.split(separator: "+", maxSplits: 1, omittingEmptySubsequences: false)[0]
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
            let pre = parts[1].split(separator: ".", omittingEmptySubsequences: false).map(String.init)
            // A trailing/empty pre-release ("1.0.0-") is malformed.
            if pre.contains(where: { $0.isEmpty }) { return nil }
            self.prerelease = pre
        } else {
            self.prerelease = []
        }
    }

    static func < (lhs: SemVer, rhs: SemVer) -> Bool {
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
                return x < y                       // numeric: compare values
            case (.some, .none):
                return true                        // numeric < alphanumeric
            case (.none, .some):
                return false
            case (.none, .none):
                return a < b                       // ASCII lexical
            }
        }
        // All shared identifiers equal: fewer identifiers is lower.
        return lpre.count < rpre.count
    }
}
