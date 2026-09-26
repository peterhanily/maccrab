import Foundation

// Foundation-only replay contract, also vendored into the native host. Input
// identities and provenance are assertions unless independently authenticated.
public struct RaveFact: Codable, Equatable, Sendable {
    public var kind: String, path: String, code: String, value: String, reference: String
    public init(kind: String, path: String, code: String, value: String = "", reference: String) {
        self.kind = kind; self.path = path; self.code = code; self.value = value; self.reference = reference
    }
    public var key: String { [kind, path, code].map { "\($0.utf8.count):\($0)" }.joined() }
}
public struct RaveFinding: Codable, Equatable, Sendable {
    public var id: String, title: String, explanation: String, action: String
    public var references: [String], attention: Bool
    public init(id: String, title: String, explanation: String, action: String,
                references: [String] = [], attention: Bool = true) {
        self.id = id; self.title = title; self.explanation = explanation; self.action = action
        self.references = references; self.attention = attention
    }
}
public struct RaveSnapshot: Codable, Equatable, Sendable {
    public var schemaVersion = 1
    public var domain: String, scope: [String], facts: [RaveFact], gaps: [String]
    public var ruleVersion: Int
    public var findings: [RaveFinding]
    public var provenance: String
    public init(domain: String, scope: [String], facts: [RaveFact], gaps: [String],
                ruleVersion: Int = 2, findings: [RaveFinding] = [], provenance: String = "unverified-import") {
        self.domain = domain; self.scope = scope; self.facts = facts; self.gaps = gaps
        self.ruleVersion = ruleVersion; self.findings = findings; self.provenance = provenance
    }
}
public enum RaveReviewError: Error { case invalid, unsupported, incompatible, oversized }

public enum RaveReviewEngine {
    public static let currentRuleVersion = 2
    public static let maxBytes = 1_048_576
    public static let scriptCodes: Set<String> = ["keychain-access", "network-send", "encoded-shell",
        "download-to-shell", "quarantine-removal", "gatekeeper-change", "privilege-request"]
    public static let families: Set<String> = ["GitHub classic personal access token", "AWS secret access key"]
    public static func textOK(_ value: String, limit: Int = 2048) -> Bool {
        value.utf8.count <= limit && !value.unicodeScalars.contains {
            CharacterSet.controlCharacters.contains($0) || (0x202A...0x202E).contains($0.value) || (0x2066...0x2069).contains($0.value)
        }
    }
    public static func validate(_ snapshot: RaveSnapshot) throws {
        guard snapshot.schemaVersion == 1, ["incident", "credentials", "investigation", "app"].contains(snapshot.domain),
              (1...currentRuleVersion).contains(snapshot.ruleVersion),
              (1...64).contains(snapshot.scope.count), snapshot.facts.count <= 1000,
              snapshot.gaps.count <= 128, snapshot.findings.count <= 1024,
              Set(snapshot.scope).count == snapshot.scope.count,
              snapshot.scope.allSatisfy({ !$0.isEmpty && textOK($0) }),
              snapshot.gaps.allSatisfy({ textOK($0) }),
              ["unverified-import", "local-static-inspection"].contains(snapshot.provenance) else { throw RaveReviewError.invalid }
        for fact in snapshot.facts {
            guard !fact.path.isEmpty, textOK(fact.path), textOK(fact.reference),
                  !fact.reference.isEmpty, textOK(fact.code, limit: 100), textOK(fact.value, limit: 256) else { throw RaveReviewError.invalid }
            switch fact.kind {
            case "script": guard ["incident", "investigation"].contains(snapshot.domain), scriptCodes.contains(fact.code), fact.value.isEmpty else { throw RaveReviewError.invalid }
            case "persistence": guard ["incident", "investigation"].contains(snapshot.domain), fact.code == "launch-configuration", ["run-at-load", "configured"].contains(fact.value) else { throw RaveReviewError.invalid }
            case "credential": guard ["credentials", "investigation"].contains(snapshot.domain), families.contains(fact.code), ["project", "ai-session", "shell-history", "log"].contains(fact.value) else { throw RaveReviewError.invalid }
            case "app":
                guard snapshot.domain == "app", ["team", "sandbox", "hardened-runtime", "disable-library-validation", "signature", "sha256"].contains(fact.code) else { throw RaveReviewError.invalid }
                if fact.code == "sha256" {
                    guard fact.value.count == 64, fact.value.allSatisfy({ "0123456789abcdef".contains($0) }) else { throw RaveReviewError.invalid }
                } else if fact.code == "team" {
                    guard fact.value == "none" || (fact.value.count == 10 && fact.value.allSatisfy({ $0.isASCII && ($0.isUppercase || $0.isNumber) })) else { throw RaveReviewError.invalid }
                } else if fact.code == "signature" {
                    guard ["signed-metadata", "unsigned", "unavailable"].contains(fact.value) else { throw RaveReviewError.invalid }
                } else { guard ["true", "false", "unknown"].contains(fact.value) else { throw RaveReviewError.invalid } }
            default: throw RaveReviewError.invalid
            }
        }
        guard Set(snapshot.facts.map(\.key)).count == snapshot.facts.count else { throw RaveReviewError.invalid }
        // Saved interpretation text is untrusted. Replay reconstructs it from facts.
        for finding in snapshot.findings {
            guard textOK(finding.id), textOK(finding.title), textOK(finding.explanation, limit: 4096),
                  textOK(finding.action, limit: 4096), finding.references.count <= 1000,
                  finding.references.allSatisfy({ textOK($0) }) else { throw RaveReviewError.invalid }
        }
    }
    public static func decode(_ bytes: Data) throws -> RaveSnapshot {
        try boundedJSON(bytes)
        let result = try JSONDecoder().decode(RaveSnapshot.self, from: bytes)
        try validate(result); return result
    }
    public static func encode(_ snapshot: RaveSnapshot) throws -> Data {
        try validate(snapshot)
        let encoder = JSONEncoder(); encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        let bytes = try encoder.encode(snapshot)
        guard bytes.count <= maxBytes else { throw RaveReviewError.oversized }; return bytes
    }
    /// Bound nesting before recursive JSON decoding. Syntax is checked by the decoder.
    public static func boundedJSON(_ bytes: Data) throws {
        guard bytes.count <= maxBytes else { throw RaveReviewError.oversized }
        var depth = 0, string = false, escaped = false
        for byte in bytes {
            if string {
                if escaped { escaped = false } else if byte == 92 { escaped = true } else if byte == 34 { string = false }
            } else if byte == 34 { string = true }
            else if byte == 123 || byte == 91 { depth += 1; if depth > 24 { throw RaveReviewError.oversized } }
            else if byte == 125 || byte == 93 { depth -= 1 }
        }
    }
    public static func assess(_ input: RaveSnapshot, version: Int = currentRuleVersion) throws -> RaveSnapshot {
        try validate(input)
        guard input.domain != "app", (1...currentRuleVersion).contains(version) else { throw RaveReviewError.unsupported }
        var result = input; result.ruleVersion = version; result.findings = []
        let ordered = input.facts.sorted { $0.key < $1.key }
        for fact in ordered {
            let title: String, explanation: String, action: String
            switch fact.kind {
            case "script":
                let titles = ["keychain-access": "Review credential access", "network-send": "Review a network send operation",
                    "encoded-shell": "Review decoded shell content", "download-to-shell": "Obtain the downstream payload",
                    "quarantine-removal": "Review quarantine removal", "gatekeeper-change": "Review the requested trust-policy change",
                    "privilege-request": "Review requested administrator access"]
                title = titles[fact.code]!
                explanation = "Supported static behavior was reported at " + fact.path + ". Execution, returned data and success are not established."
                action = fact.code == "download-to-shell" ? "Obtain the payload through your evidence process; do not run the submitted command to retrieve it." : "Review the cited source and seek execution evidence for the incident window."
            case "persistence":
                title = "Review a launch configuration"
                explanation = "A supplied configuration record names " + fact.path + ". Loaded state and execution remain unknown."
                action = "Check the original configuration, referenced executable and available process records."
            case "credential":
                title = "Review a credential candidate location"
                explanation = fact.code + " candidate reported at " + fact.path + ". This does not establish validity, ownership or exposure."
                action = "Confirm the owner and provider-side response without copying credential values into the ticket."
            default: continue
            }
            result.findings.append(.init(id: "v1:" + fact.key, title: title, explanation: explanation,
                action: action, references: [fact.reference]))
        }
        if version >= 2 {
            for path in Set(ordered.filter { $0.kind == "script" }.map(\.path)).sorted() {
                let related = ordered.filter { $0.kind == "script" && $0.path == path }
                if related.contains(where: { $0.code == "keychain-access" }) && related.contains(where: { $0.code == "network-send" }) {
                    result.findings.append(.init(id: "v2:credential-and-send:" + path,
                        title: "Credential access and sending appear in the same source",
                        explanation: "Both static behaviors are reported in " + path + ". Co-occurrence is not data flow, execution or exfiltration evidence.",
                        action: "Inspect the original data flow and obtain process/network evidence before asserting that credentials were transmitted.",
                        references: related.filter { ["keychain-access", "network-send"].contains($0.code) }.map(\.reference)))
                }
            }
        }
        if !input.gaps.isEmpty {
            result.findings.append(.init(id: "coverage", title: "Evidence is incomplete",
                explanation: "Some selected evidence is unavailable or outside supported coverage.",
                action: "Review the listed gaps and acquire missing sources where possible.", attention: false))
        }
        if result.findings.isEmpty {
            result.findings.append(.init(id: "no-supported-finding", title: "No findings under these rules",
                explanation: "The retained facts produced no supported finding. This is not incident clearance.",
                action: "Confirm that the selected material covers the question you are investigating.", attention: false))
        }
        return result
    }
    public static func recheck(_ previous: RaveSnapshot) throws -> (snapshot: RaveSnapshot, added: [RaveFinding]) {
        // Never compare against arbitrary saved titles/IDs supplied by an importer.
        let old = try assess(previous, version: previous.ruleVersion)
        let current = try assess(previous)
        let priorIDs = Set(old.findings.map(\.id))
        return (current, current.findings.filter { !priorIDs.contains($0.id) })
    }
    public static func compare(_ previous: RaveSnapshot, _ current: RaveSnapshot) throws -> [RaveFinding] {
        try validate(previous); try validate(current)
        guard previous.domain == current.domain, Set(previous.scope) == Set(current.scope),
              !current.scope.contains(where: { $0.contains("unscoped:") || $0.contains("[REDACTED") }) else { throw RaveReviewError.incompatible }
        if current.domain == "app" { return appChanges(previous, current) }
        let before = Dictionary(uniqueKeysWithValues: previous.facts.map { ($0.key, $0) })
        let after = Dictionary(uniqueKeysWithValues: current.facts.map { ($0.key, $0) })
        var findings: [RaveFinding] = []
        for key in Set(before.keys).union(after.keys).sorted() {
            let old = before[key], new = after[key]
            if old?.value == new?.value, old != nil, new != nil {
                if current.domain != "app", let new {
                    findings.append(.init(id: "remains:" + key, title: "Still observed in the current selection",
                        explanation: new.path + ": " + new.code + (new.kind == "credential" ? ". Location/type matching does not identify the same credential across runs." : ". This is a retained observation, not evidence of execution."),
                        action: "Review whether this remaining condition is expected.", references: [old!.reference, new.reference]))
                }
                continue
            }
            let fact = new ?? old!
            let absenceUnknown = new == nil && (!current.gaps.isEmpty || current.provenance != previous.provenance)
            let newlyUnknown = old == nil && !previous.gaps.isEmpty
            let title = absenceUnknown ? "Previous condition could not be reassessed" :
                newlyUnknown ? "Now observed; earlier coverage was incomplete" :
                old == nil ? "Newly observed in assessed fields" :
                new == nil ? "No longer observed in assessed fields" : "Assessed value changed"
            let values = current.domain == "app" ? " Before: \(old?.value ?? "not observed"). After: \(new?.value ?? "not observed")." : ""
            findings.append(.init(id: "delta:" + key, title: title,
                explanation: fact.path + ": " + fact.code + "." + values +
                    (absenceUnknown ? " Missing evidence is not evidence of removal." : " This comparison does not prove execution, deletion, revocation or containment."),
                action: current.domain == "app" ? "Confirm whether this change is expected before recording a new review." : "Check the original source and any provider-side action required.",
                references: [old?.reference, new?.reference].compactMap { $0 }, attention: true))
        }
        if !current.gaps.isEmpty || !previous.gaps.isEmpty {
            findings.append(.init(id: "comparison-coverage", title: "Comparison coverage is incomplete",
                explanation: "Only successfully retained facts were compared. Source gaps remain visible.",
                action: "Review both coverage lists before concluding that a condition appeared or disappeared.", attention: false))
        }
        if findings.isEmpty {
            findings.append(.init(id: "unchanged", title: "No differences in assessed fields",
                explanation: "The selected facts compare equally. Unassessed behavior and runtime access remain unknown.",
                action: "Use the coverage and original evidence to decide whether further review is needed.", attention: false))
        }
        return findings
    }
    private static func appChanges(_ previous: RaveSnapshot, _ current: RaveSnapshot) -> [RaveFinding] {
        let before = Dictionary(grouping: previous.facts, by: \.path)
        let after = Dictionary(grouping: current.facts, by: \.path)
        let labels = ["signature": "Signature metadata", "team": "Declared signing team",
            "sandbox": "App Sandbox declaration", "hardened-runtime": "Hardened Runtime flag",
            "disable-library-validation": "Library validation exception", "sha256": "Executable SHA-256"]
        var output: [RaveFinding] = []
        for path in Set(before.keys).union(after.keys).sorted() {
            let old = Dictionary(uniqueKeysWithValues: (before[path] ?? []).map { ($0.code, $0.value) })
            let new = Dictionary(uniqueKeysWithValues: (after[path] ?? []).map { ($0.code, $0.value) })
            let changed = Set(old.keys).union(new.keys).filter { old[$0] != new[$0] }.sorted()
            guard !changed.isEmpty else { continue }
            let title: String
            if old.isEmpty {
                title = !previous.gaps.isEmpty ? "Component now observed; earlier coverage was incomplete" :
                    new["sandbox"] == "false" ? "New component without an App Sandbox declaration" : "New Mach-O component to review"
            } else if new.isEmpty {
                title = !current.gaps.isEmpty || previous.provenance != current.provenance ?
                    "Previous component could not be reassessed" : "Component no longer observed in assessed fields"
            } else if old["team"] != new["team"] { title = "Declared signing identity changed" }
            else if old["sandbox"] == "true" && new["sandbox"] == "false" { title = "App Sandbox declaration removed" }
            else if old["disable-library-validation"] == "false" && new["disable-library-validation"] == "true" { title = "Library validation exception added" }
            else if old["hardened-runtime"] == "true" && new["hardened-runtime"] == "false" { title = "Hardened Runtime flag removed" }
            else if changed == ["sha256"] { title = old["sha256"] == nil ? "Executable fingerprint now available" : "Executable content changed" }
            else { title = "Component metadata changed" }
            let details = changed.map { key in
                if key == "sha256" { return "Executable SHA-256: \(old[key].map { String($0.prefix(12)) } ?? "not recorded") → \(new[key].map { String($0.prefix(12)) } ?? "not recorded"). Full fingerprints are retained in the evidence." }
                return "\(labels[key] ?? key): \(old[key] ?? "not observed") → \(new[key] ?? "not observed")."
            }.joined(separator: " ")
            let refs = Array(Set((before[path] ?? []).map(\.reference) + (after[path] ?? []).map(\.reference))).sorted()
            output.append(.init(id: "component:" + path, title: title,
                explanation: path + ". " + details + " Signing declarations cover the native architecture; fingerprints cover the assessed executable bytes. Runtime access, signature validity and software safety were not assessed.",
                action: "Confirm the component and metadata changes are expected for this release, then review the original evidence.", references: refs, attention: changed != ["sha256"] || old.isEmpty || new.isEmpty))
        }
        if !previous.gaps.isEmpty || !current.gaps.isEmpty {
            output.append(.init(id: "comparison-coverage", title: "Component coverage is incomplete",
                explanation: "Some files or signing metadata could not be assessed. Missing components are not evidence of removal.",
                action: "Inspect both coverage lists and unsupported components before deciding whether the update needs further review.", attention: false))
        }
        if output.isEmpty {
            output.append(.init(id: "unchanged", title: "No differences in assessed fields",
                explanation: "Retained component fingerprints and signing fields compare equally where recorded. Unassessed files, other architectures’ signing declarations and runtime behavior remain outside this review.",
                action: "Confirm this limited scope is sufficient for your review.", attention: false))
        }
        return output
    }
}
