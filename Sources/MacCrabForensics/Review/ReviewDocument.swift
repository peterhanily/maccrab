import Foundation
import CryptoKit

/// A portable review retains both sides of a comparison. Decisions are human
/// annotations bound to these facts, not signatures or software approvals.
public struct RaveReviewDocument: Codable, Equatable, Sendable {
    public var documentType = "rave-review"
    public var schemaVersion = 1
    public var mode: String
    public var snapshot: RaveSnapshot
    public var previous: RaveSnapshot?
    public var decisions: [RaveReviewDecision]
    public init(mode: String, snapshot: RaveSnapshot, previous: RaveSnapshot? = nil,
                decisions: [RaveReviewDecision] = []) {
        self.mode = mode; self.snapshot = snapshot; self.previous = previous; self.decisions = decisions
    }
    public var requiresCredentialPrivacy: Bool { ["credentials", "investigation"].contains(snapshot.domain) }
    public var findings: [RaveFinding] {
        get throws {
            switch mode {
            case "compare", "verify":
                guard let previous else { throw RaveReviewError.invalid }
                return try RaveReviewEngine.compare(previous, snapshot)
            case "recheck":
                guard let previous else { throw RaveReviewError.invalid }
                return try RaveReviewEngine.recheck(previous).added
            case "investigate": return try RaveReviewEngine.assess(snapshot).findings
            default: throw RaveReviewError.invalid
            }
        }
    }
}

public struct RaveReviewDecision: Codable, Equatable, Sendable {
    public var id: String, recordedAt: String, reviewer: String, disposition: String, note: String, reviewDigest: String
    public init(document: RaveReviewDocument, reviewer: String, disposition: String, note: String, at: Date = Date()) throws {
        self.id = UUID().uuidString.lowercased()
        self.recordedAt = ISO8601DateFormatter().string(from: at)
        self.reviewer = reviewer; self.disposition = disposition; self.note = note
        self.reviewDigest = try RaveReviewDocumentIO.digest(document)
        try RaveReviewDocumentIO.validateDecision(self, digest: reviewDigest)
    }
}

public enum RaveReviewDocumentIO {
    public static func sha256(_ bytes: Data) -> String {
        SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined()
    }
    static func canonical(_ snapshot: RaveSnapshot) throws -> Data {
        try RaveReviewEngine.validate(snapshot)
        var stable = snapshot
        stable.findings = []
        // Importing does not authenticate provenance. Exclude that display label
        // from the digest so an unsigned annotation survives a truthful import.
        stable.provenance = "unverified-import"
        stable.scope.sort(); stable.gaps.sort(); stable.facts.sort { $0.key < $1.key }
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return try encoder.encode(stable)
    }
    public static func digest(_ document: RaveReviewDocument) throws -> String {
        var fields = [document.mode, sha256(try canonical(document.snapshot))]
        fields.append(try document.previous.map { sha256(try canonical($0)) } ?? "none")
        return sha256(Data(fields.map { "\($0.utf8.count):\($0)" }.joined().utf8))
    }
    static func validateDecision(_ decision: RaveReviewDecision, digest: String) throws {
        guard UUID(uuidString: decision.id) != nil,
              decision.recordedAt.count <= 32, ISO8601DateFormatter().date(from: decision.recordedAt) != nil,
              !decision.reviewer.trimmingCharacters(in: .whitespaces).isEmpty,
              RaveReviewEngine.textOK(decision.reviewer, limit: 120),
              ["expected", "investigate", "inconclusive"].contains(decision.disposition),
              RaveReviewEngine.textOK(decision.note, limit: 2000), decision.reviewDigest == digest else { throw RaveReviewError.invalid }
    }
    public static func validate(_ document: RaveReviewDocument) throws {
        guard document.documentType == "rave-review", document.schemaVersion == 1,
              document.decisions.count <= 128,
              Set(document.decisions.map(\.id)).count == document.decisions.count else { throw RaveReviewError.invalid }
        try RaveReviewEngine.validate(document.snapshot)
        if let previous = document.previous { try RaveReviewEngine.validate(previous) }
        switch document.mode {
        case "investigate": guard document.previous == nil, document.snapshot.domain != "app" else { throw RaveReviewError.invalid }
        case "compare": guard document.snapshot.domain == "app", document.previous != nil else { throw RaveReviewError.invalid }
        case "verify": guard document.previous != nil else { throw RaveReviewError.invalid }
        case "recheck":
            guard let previous = document.previous else { throw RaveReviewError.invalid }
            let replay = try RaveReviewEngine.recheck(previous).snapshot
            guard try canonical(replay) == canonical(document.snapshot) else { throw RaveReviewError.invalid }
        default: throw RaveReviewError.invalid
        }
        _ = try document.findings
        let binding = try digest(document)
        for decision in document.decisions { try validateDecision(decision, digest: binding) }
    }
    public static func decode(_ bytes: Data, imported: Bool = true) throws -> RaveReviewDocument {
        try RaveReviewEngine.boundedJSON(bytes)
        var document = try JSONDecoder().decode(RaveReviewDocument.self, from: bytes)
        try validate(document)
        document.snapshot.findings = []
        document.previous?.findings = []
        if imported { document.snapshot.provenance = "unverified-import"; document.previous?.provenance = "unverified-import" }
        return document
    }
    public static func encode(_ document: RaveReviewDocument) throws -> Data {
        try validate(document)
        let encoder = JSONEncoder(); encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        let bytes = try encoder.encode(document)
        guard bytes.count <= RaveReviewEngine.maxBytes else { throw RaveReviewError.oversized }
        return bytes
    }
    public static func brief(_ document: RaveReviewDocument) throws -> String {
        try validate(document)
        let findings = try document.findings
        var lines = ["Rave review — " + document.mode, "Rules: \(document.snapshot.ruleVersion)",
            "Review fingerprint: " + (try digest(document)),
            "Scope: " + document.snapshot.scope.joined(separator: ", "),
            "Selected retained observations only. No new collection or containment verification.", ""]
        for finding in findings {
            lines += [finding.title, finding.explanation, "Next check: " + finding.action,
                      "Evidence: " + finding.references.joined(separator: "; "), ""]
        }
        for (label, gaps) in [("Current coverage gaps", document.snapshot.gaps), ("Earlier coverage gaps", document.previous?.gaps ?? [])] {
            lines += [label + ": " + (gaps.isEmpty ? "none reported within the supported scope" : gaps.joined(separator: "; "))]
        }
        if !document.decisions.isEmpty { lines += ["", "Operator notes (unsigned; identity is self-reported):"] }
        for decision in document.decisions {
            lines += ["\(decision.recordedAt) · \(decision.reviewer) · \(decision.disposition)", decision.note]
        }
        return lines.joined(separator: "\n")
    }
}
