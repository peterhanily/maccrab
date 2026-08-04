// RuleGenerator.swift
// MacCrabCore
//
// Generates Sigma-compatible YAML detection rules from observed attack patterns.
// When a campaign or kill chain is detected, this engine extracts the key
// indicators and produces a rule that would catch similar attacks in the future.

import CryptoKit
import Foundation
import os.log

/// Generates Sigma-compatible YAML detection rules from observed attack patterns.
/// When a campaign or kill chain is detected, this engine extracts the key
/// indicators and produces a rule that would catch similar attacks in the future.
public actor RuleGenerator {
    private let logger = Logger(subsystem: "com.maccrab.detection", category: "rule-generator")

    /// A generated rule ready to be written to disk.
    public struct GeneratedRule: Sendable {
        public let yaml: String
        public let filename: String
        public let title: String
        public let description: String
        public let severity: String
        public let generatedAt: Date
    }

    /// Fixed-cardinality accounting for the review-candidate pipeline. Every
    /// offered campaign is either still current or reaches exactly one terminal
    /// outcome. LLM validation has a second conservation equation so a model
    /// timeout, invalid candidate, or persistence failure cannot disappear into
    /// an optimistic "generated" count.
    public struct Telemetry: Sendable, Equatable {
        public var offeredTotal: UInt64 = 0
        public var insufficientSignalTotal: UInt64 = 0
        public var duplicateTotal: UInt64 = 0
        public var persistedTotal: UInt64 = 0
        public var writeFailedTotal: UInt64 = 0
        public var currentOperations: UInt64 = 0

        public var llmAttemptsTotal: UInt64 = 0
        public var llmCandidateValidTotal: UInt64 = 0
        public var llmCandidateRejectedOrAbsentTotal: UInt64 = 0
        public var llmCandidatePersistedTotal: UInt64 = 0
        public var llmCandidateDuplicateTotal: UInt64 = 0
        public var llmCandidatePersistenceFailedTotal: UInt64 = 0
        public var deterministicAttemptsTotal: UInt64 = 0

        public var terminalTotal: UInt64 {
            insufficientSignalTotal + duplicateTotal + persistedTotal + writeFailedTotal
        }

        public var conservationMaintained: Bool {
            offeredTotal == terminalTotal + currentOperations
        }

        public var llmValidationConservationMaintained: Bool {
            llmAttemptsTotal == llmCandidateValidTotal
                + llmCandidateRejectedOrAbsentTotal
        }

        public var llmPersistenceConservationMaintained: Bool {
            llmCandidateValidTotal == llmCandidatePersistedTotal
                + llmCandidateDuplicateTotal
                + llmCandidatePersistenceFailedTotal
        }
    }

    private enum TerminalOutcome {
        case insufficientSignal
        case duplicate
        case persisted
        case writeFailed
    }

    private enum PersistenceOutcome {
        case persisted
        case duplicate
        case failed(String)
    }

    private let outputDir: String
    private var generatedCount: Int = 0
    private var llmService: LLMService?
    private var telemetry = Telemetry()

    public init(outputDir: String, llmService: LLMService? = nil) {
        self.outputDir = outputDir
        self.llmService = llmService
    }

    /// DaemonSetup creates the generator before it finishes constructing the
    /// optional backend. Wiring is explicit and actor-isolated so the feature
    /// cannot silently remain on its fallback path for the process lifetime.
    public func configureLLMService(_ service: LLMService?) {
        llmService = service
    }

    /// Generate a rule using LLM enhancement, falling back to template-based generation.
    public func generateFromCampaignEnhanced(
        campaignType: String,
        alerts: [(ruleId: String, ruleTitle: String, processPath: String?, tactics: Set<String>, timestamp: Date)]
    ) async -> GeneratedRule? {
        beginOperation()
        guard hasGroundedSignal(alerts) else {
            finishOperation(.insufficientSignal)
            return nil
        }

        let fingerprint = Self.campaignFingerprint(campaignType: campaignType, alerts: alerts)
        let filename = Self.candidateFilename(
            campaignType: campaignType,
            fingerprint: fingerprint
        )
        if candidateExists(filename: filename) {
            finishOperation(.duplicate)
            return nil
        }

        if let llm = llmService {
            telemetry.llmAttemptsTotal += 1
            let semanticToken = await llm.beginDownstreamValidation(
                feature: .ruleGeneration
            )
            let promptAlerts = alerts.prefix(50)
            let processInfo = promptAlerts.compactMap { $0.processPath }
                .map {
                    "  - \(Self.boundedSingleLine($0, maximumUTF8Bytes: 512))"
                }
                .joined(separator: "\n")
            let tactics = Set(promptAlerts.flatMap { $0.tactics.prefix(16) })
                .filter(Self.isSafeSigmaTag)
                .sorted()
                .prefix(64)
                .joined(separator: ", ")
            if let enhancement = await llm.query(
                systemPrompt: LLMPrompts.ruleGenerationSystem,
                userPrompt: LLMPrompts.ruleGenerationUser(
                    campaignType: Self.boundedSingleLine(
                        campaignType,
                        maximumUTF8Bytes: 128
                    ),
                    processInfo: processInfo,
                    tactics: tactics
                ),
                maxTokens: 1024, temperature: 0.4,
                feature: .ruleGeneration
            ) {
                let yaml = enhancement.response
                // LLM output is a disabled candidate, but even candidates must
                // pass a conservative structural/cost policy before touching
                // disk. Substring presence alone accepted comments, malformed
                // YAML, and universal all-events conditions.
                if Self.validateLLMCandidate(yaml) {
                    telemetry.llmCandidateValidTotal += 1
                    let generated = GeneratedRule(
                        yaml: yaml,
                        filename: filename,
                        title: Self.topLevelValue("title", in: yaml)
                            ?? "LLM-generated rule candidate",
                        description: "Review-only LLM candidate from \(Self.safeCampaignLabel(campaignType)) campaign (\(enhancement.provider))",
                        severity: Self.topLevelValue("level", in: yaml) ?? "high",
                        generatedAt: Date()
                    )
                    switch persistRule(generated) {
                    case .persisted:
                        telemetry.llmCandidatePersistedTotal += 1
                        generatedCount += 1
                        _ = await llm.finishDownstreamValidation(
                            token: semanticToken,
                            outcome: .accepted
                        )
                        finishOperation(.persisted)
                        return generated
                    case .duplicate:
                        telemetry.llmCandidateDuplicateTotal += 1
                        _ = await llm.finishDownstreamValidation(
                            token: semanticToken,
                            outcome: .finalRejection
                        )
                        finishOperation(.duplicate)
                        return nil
                    case .failed(let message):
                        telemetry.llmCandidatePersistenceFailedTotal += 1
                        _ = await llm.finishDownstreamValidation(
                            token: semanticToken,
                            outcome: .finalRejection
                        )
                        logger.error("Failed to persist validated LLM rule candidate: \(message, privacy: .public)")
                        finishOperation(.writeFailed)
                        return nil
                    }
                }
            }
            telemetry.llmCandidateRejectedOrAbsentTotal += 1
            _ = await llm.finishDownstreamValidation(
                token: semanticToken,
                outcome: .finalRejection
            )
        }
        // A deterministic candidate is useful when the optional model is
        // unavailable or its untrusted output fails admission. It is still
        // experimental, outside the runtime rule loader, and requires review.
        telemetry.deterministicAttemptsTotal += 1
        return generateDeterministicCandidate(
            campaignType: campaignType,
            alerts: alerts,
            fingerprint: fingerprint,
            filename: filename
        )
    }

    /// Conservative admission for LLM-authored Sigma candidates. The runtime
    /// consumes compiled JSON, not this YAML directory, so passing this policy
    /// does NOT enable the rule; it only makes the candidate eligible for human
    /// review and the normal compiler/replay workflow.
    static func validateLLMCandidate(_ yaml: String) -> Bool {
        guard (128...50_000).contains(yaml.utf8.count),
              !yaml.contains("```"),
              !yaml.contains("\t"),
              !yaml.unicodeScalars.contains(where: {
                  $0.value == 0 || (0x01...0x08).contains($0.value)
                      || (0x0B...0x1F).contains($0.value)
                      || (0x7F...0x9F).contains($0.value)
              }) else { return false }

        let meaningful = yaml.split(separator: "\n", omittingEmptySubsequences: false)
            .map(String.init)
            .filter { !$0.trimmingCharacters(in: .whitespaces).hasPrefix("#") }
        func topLevelIndices(_ key: String) -> [Int] {
            meaningful.indices.filter { index in
                let line = meaningful[index]
                return !line.isEmpty
                    && line.first?.isWhitespace == false
                    && line.hasPrefix("\(key):")
            }
        }
        func indentedBlock(after index: Int) -> ArraySlice<String> {
            let start = meaningful.index(after: index)
            let end = meaningful[start...].firstIndex { line in
                !line.trimmingCharacters(in: .whitespaces).isEmpty
                    && line.first?.isWhitespace == false
            } ?? meaningful.endIndex
            return meaningful[start..<end]
        }
        func directMappings(in block: ArraySlice<String>) -> [(key: String, value: String)] {
            let populated = block.filter {
                !$0.trimmingCharacters(in: .whitespaces).isEmpty
            }
            guard let indentation = populated.map({ line in
                line.prefix(while: { $0 == " " }).count
            }).filter({ $0 > 0 }).min() else { return [] }
            return populated.compactMap { line in
                guard line.prefix(while: { $0 == " " }).count == indentation,
                      let separator = line.firstIndex(of: ":") else { return nil }
                let key = line[..<separator].trimmingCharacters(in: .whitespaces)
                let value = line[line.index(after: separator)...]
                    .trimmingCharacters(in: .whitespaces)
                return (key, value)
            }
        }
        guard topLevelIndices("title").count == 1,
              topLevelIndices("id").count == 1,
              topLevelIndices("status").count == 1,
              topLevelIndices("logsource").count == 1,
              topLevelIndices("detection").count == 1,
              topLevelIndices("falsepositives").count == 1,
              topLevelIndices("level").count == 1 else { return false }

        let status = Self.topLevelValue("status", in: yaml)?.lowercased()
        guard status == "experimental" else { return false }

        guard let title = Self.topLevelValue("title", in: yaml),
              !title.isEmpty, title.utf8.count <= 512,
              let level = Self.topLevelValue("level", in: yaml)?.lowercased(),
              ["low", "medium", "high", "critical"].contains(level) else {
            return false
        }

        let idText = Self.topLevelValue("id", in: yaml) ?? ""
        guard UUID(uuidString: idText.trimmingCharacters(
            in: CharacterSet(charactersIn: "'\"")
        )) != nil else { return false }

        let logsourceIndex = topLevelIndices("logsource")[0]
        let logsource = directMappings(in: indentedBlock(after: logsourceIndex))
        guard logsource.filter({ $0.key == "category" && $0.value == "process_creation" }).count == 1,
              logsource.filter({ $0.key == "product" && $0.value == "macos" }).count == 1 else {
            return false
        }

        let detectionIndex = topLevelIndices("detection")[0]
        let detectionBlock = indentedBlock(after: detectionIndex)
        let detectionMappings = directMappings(in: detectionBlock)
        let conditions = detectionMappings.filter { $0.key == "condition" }
        guard conditions.count == 1,
              detectionMappings.filter({ $0.key == "selection" }).count == 1 else {
            return false
        }
        let conditionWords = conditions[0].value.lowercased()
            .split(whereSeparator: { $0.isWhitespace }).map(String.init)
        guard conditionWords.first == "selection", conditionWords.count >= 4 else {
            return false
        }
        let definedKeys = Set(detectionMappings.map { $0.key.lowercased() })
        var wordIndex = 1
        while wordIndex < conditionWords.count {
            guard wordIndex + 2 < conditionWords.count,
                  conditionWords[wordIndex] == "and",
                  conditionWords[wordIndex + 1] == "not",
                  conditionWords[wordIndex + 2].hasPrefix("filter"),
                  definedKeys.contains(conditionWords[wordIndex + 2]) else {
                return false
            }
            wordIndex += 3
        }

        guard let selectionIndex = detectionBlock.firstIndex(where: { line in
            line.trimmingCharacters(in: .whitespaces) == "selection:"
        }) else { return false }
        let selectionIndent = detectionBlock[selectionIndex]
            .prefix(while: { $0 == " " }).count
        let selectionTail = detectionBlock[detectionBlock.index(after: selectionIndex)...]
        let selectionBody = selectionTail.prefix { line in
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            return trimmed.isEmpty
                || line.prefix(while: { $0 == " " }).count > selectionIndent
        }
        guard selectionBody.contains(where: Self.hasConcreteSigmaValue) else {
            return false
        }

        let falsePositiveIndex = topLevelIndices("falsepositives")[0]
        guard indentedBlock(after: falsePositiveIndex)
            .contains(where: Self.hasConcreteSigmaValue) else { return false }

        let trimmed = meaningful.map { $0.trimmingCharacters(in: .whitespaces) }
        let lower = yaml.lowercased()
        guard !lower.contains("|re:"),
              !lower.contains("|regex:"),
              !lower.contains("!!"),
              !lower.contains("<<:"),
              !lower.contains(": &"),
              !lower.contains(": !"),
              !trimmed.contains("---"),
              !trimmed.contains(where: {
                  $0.hasPrefix("- *") || $0.hasPrefix("- !")
                      || $0 == "- '*'" || $0 == "- \"*\""
                      || $0.hasSuffix(": '*'") || $0.hasSuffix(": \"*\"")
              }) else { return false }
        return true
    }

    private static func topLevelValue(_ key: String, in yaml: String) -> String? {
        let prefix = "\(key):"
        guard let line = yaml.split(separator: "\n", omittingEmptySubsequences: false)
            .map(String.init)
            .first(where: { $0.first?.isWhitespace == false && $0.hasPrefix(prefix) }) else {
            return nil
        }
        return String(line.dropFirst(prefix.count))
            .trimmingCharacters(in: .whitespacesAndNewlines)
    }

    private static func hasConcreteSigmaValue(_ line: String) -> Bool {
        let trimmed = line.trimmingCharacters(in: .whitespaces)
        let emptyValues: Set<String> = ["", "''", "\"\"", "*", "'*'", "\"*\"", "[]", "{}", "null", "~"]
        if trimmed.hasPrefix("- ") {
            return !emptyValues.contains(String(trimmed.dropFirst(2)).lowercased())
        }
        guard let separator = trimmed.firstIndex(of: ":") else { return false }
        let value = trimmed[trimmed.index(after: separator)...]
            .trimmingCharacters(in: .whitespaces)
            .lowercased()
        return !emptyValues.contains(value)
    }

    private static func safeFilenameComponent(_ value: String) -> String {
        let mapped = value.lowercased().unicodeScalars.prefix(64).map { scalar -> Character in
            let isASCIIAlpha = (65...90).contains(scalar.value)
                || (97...122).contains(scalar.value)
            let isDigit = (48...57).contains(scalar.value)
            return (isASCIIAlpha || isDigit || scalar.value == 95 || scalar.value == 45)
                ? Character(String(scalar)) : "_"
        }
        let result = String(mapped).trimmingCharacters(in: CharacterSet(charactersIn: "_-"))
        return result.isEmpty ? "campaign" : result
    }

    private static func yamlSingleQuoted(
        _ value: String,
        maximumUTF8Bytes: Int
    ) -> String {
        let bounded = boundedSingleLine(value, maximumUTF8Bytes: maximumUTF8Bytes)
            .replacingOccurrences(of: "'", with: "''")
        return "'\(bounded)'"
    }

    private static func isSafeSigmaTag(_ value: String) -> Bool {
        guard !value.isEmpty, value.utf8.count <= 128 else { return false }
        return value.utf8.allSatisfy { byte in
            (65...90).contains(byte) || (97...122).contains(byte)
                || (48...57).contains(byte) || byte == 45
                || byte == 46 || byte == 95
        }
    }

    private static func boundedSingleLine(
        _ value: String,
        maximumUTF8Bytes: Int
    ) -> String {
        guard maximumUTF8Bytes > 0 else { return "" }
        var output = ""
        output.reserveCapacity(min(value.count, maximumUTF8Bytes))
        var usedBytes = 0
        for character in value {
            let unsafe = character.unicodeScalars.contains { scalar in
                switch scalar.value {
                case 0x00...0x1F, 0x7F...0x9F,
                     0x200B...0x200F, 0x202A...0x202E,
                     0x2060...0x206F, 0xFEFF, 0xE0000...0xE007F:
                    return true
                default:
                    return false
                }
            }
            let piece = unsafe ? " " : String(character)
            if piece == " ", output.last == " " { continue }
            let byteCount = piece.utf8.count
            guard usedBytes + byteCount <= maximumUTF8Bytes else { break }
            output += piece
            usedBytes += byteCount
        }
        return output.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    /// Generate a rule from a campaign detection.
    /// Returns the generated rule, or nil if the campaign lacks enough signal.
    public func generateFromCampaign(
        campaignType: String,
        alerts: [(ruleId: String, ruleTitle: String, processPath: String?, tactics: Set<String>, timestamp: Date)]
    ) -> GeneratedRule? {
        beginOperation()
        guard hasGroundedSignal(alerts) else {
            finishOperation(.insufficientSignal)
            return nil
        }

        let fingerprint = Self.campaignFingerprint(campaignType: campaignType, alerts: alerts)
        let filename = Self.candidateFilename(
            campaignType: campaignType,
            fingerprint: fingerprint
        )
        if candidateExists(filename: filename) {
            finishOperation(.duplicate)
            return nil
        }
        telemetry.deterministicAttemptsTotal += 1
        return generateDeterministicCandidate(
            campaignType: campaignType,
            alerts: alerts,
            fingerprint: fingerprint,
            filename: filename
        )
    }

    private func generateDeterministicCandidate(
        campaignType: String,
        alerts: [(ruleId: String, ruleTitle: String, processPath: String?, tactics: Set<String>, timestamp: Date)],
        fingerprint: String,
        filename: String
    ) -> GeneratedRule? {
        // `fingerprint` is intentionally part of this private contract even
        // though the filename already contains it. This makes it difficult for
        // a future caller to reintroduce sequential, restart-clobbering names.
        precondition(filename.contains(fingerprint))

        let ruleId = UUID().uuidString.lowercased()
        let timestamp = ISO8601DateFormatter().string(from: Date()).prefix(10)

        // Extract common indicators from the alerts
        let boundedAlerts = alerts.prefix(100)
        let processes = Set(boundedAlerts.compactMap { $0.processPath })
        var tactics = Set<String>()
        for alert in boundedAlerts {
            for tactic in alert.tactics.prefix(32) where tactics.count < 128 {
                tactics.insert(tactic)
            }
        }
        // Build the detection based on what we observed
        let safeCampaign = Self.safeCampaignLabel(campaignType)
        let title = "Auto-Generated: \(safeCampaign) Pattern"
        let description = Self.boundedSingleLine(
            "Automatically generated from observed \(safeCampaign) campaign with \(alerts.count) contributing alerts. Generated by MacCrab RuleGenerator on \(timestamp).",
            maximumUTF8Bytes: 4_096
        )

        var yaml = """
        title: \(Self.yamlSingleQuoted(title, maximumUTF8Bytes: 512))
        id: \(ruleId)
        status: experimental
        description: \(Self.yamlSingleQuoted(description, maximumUTF8Bytes: 4_096))
        author: MacCrab Auto-Generator
        date: \(timestamp)
        tags:

        """

        for tactic in tactics.sorted() where Self.isSafeSigmaTag(tactic) {
            yaml += "    - \(Self.yamlSingleQuoted(tactic, maximumUTF8Bytes: 128))\n"
        }

        // Generate detection based on observed process paths
        if !processes.isEmpty {
            yaml += """
            logsource:
                category: process_creation
                product: macos
            detection:
                selection:
                    Image|endswith:

            """
            for proc in processes.prefix(5) {
                let basename = "/" + (proc as NSString).lastPathComponent
                yaml += "            - \(Self.yamlSingleQuoted(basename, maximumUTF8Bytes: 512))\n"
            }
            yaml += """
                filter_system:
                    ParentImage|startswith:
                        - '/System/'
                        - '/usr/libexec/'
                        - '/usr/sbin/'
                filter_apple_signed:
                    SignerType: 'apple'
                condition: selection and not filter_system and not filter_apple_signed

            """
        }

        yaml += """
        falsepositives:
            - Legitimate use of the same tools
            - Auto-generated rule may have high false positive rate — review and tune
        level: high
        """

        let rule = GeneratedRule(
            yaml: yaml,
            filename: filename,
            title: title,
            description: "Generated from \(safeCampaign) campaign with \(alerts.count) contributing alerts",
            severity: "high",
            generatedAt: Date()
        )

        switch persistRule(rule) {
        case .persisted:
            generatedCount += 1
            finishOperation(.persisted)
            logger.info("Generated review-only rule candidate: \(title) → \(filename)")
            return rule
        case .duplicate:
            finishOperation(.duplicate)
            return nil
        case .failed(let message):
            finishOperation(.writeFailed)
            logger.error("Failed to persist generated rule candidate: \(message, privacy: .public)")
            return nil
        }
    }

    /// Persist exactly once. Stable fingerprints deduplicate across daemon
    /// restarts; atomicCreate is the carrier boundary and refuses symlinks,
    /// hard-link replacement, and clobbering an existing reviewed candidate.
    private func persistRule(_ rule: GeneratedRule) -> PersistenceOutcome {
        let fm = FileManager.default
        let autoDir = outputDir + "/auto_generated"
        let path = autoDir + "/" + rule.filename
        do {
            try fm.createDirectory(atPath: autoDir, withIntermediateDirectories: true)
            try? fm.setAttributes(
                [.posixPermissions: 0o750, .groupOwnerAccountID: 80],
                ofItemAtPath: autoDir
            )
            try SecureFileIO.atomicCreate(
                at: path,
                data: Data(rule.yaml.utf8),
                mode: 0o640
            )
            try? fm.setAttributes(
                [.posixPermissions: 0o640, .groupOwnerAccountID: 80],
                ofItemAtPath: path
            )
            return .persisted
        } catch SecureFileIO.Error.fileAlreadyExists {
            return .duplicate
        } catch {
            return .failed(String(error.localizedDescription.prefix(512)))
        }
    }

    private func beginOperation() {
        telemetry.offeredTotal += 1
        telemetry.currentOperations += 1
    }

    private func finishOperation(_ outcome: TerminalOutcome) {
        if telemetry.currentOperations > 0 {
            telemetry.currentOperations -= 1
        }
        switch outcome {
        case .insufficientSignal:
            telemetry.insufficientSignalTotal += 1
        case .duplicate:
            telemetry.duplicateTotal += 1
        case .persisted:
            telemetry.persistedTotal += 1
        case .writeFailed:
            telemetry.writeFailedTotal += 1
        }
    }

    private func hasGroundedSignal(
        _ alerts: [(ruleId: String, ruleTitle: String, processPath: String?, tactics: Set<String>, timestamp: Date)]
    ) -> Bool {
        alerts.count >= 2 && alerts.prefix(100).contains { alert in
            guard let path = alert.processPath else { return false }
            let basename = (path as NSString).lastPathComponent
                .trimmingCharacters(in: .whitespacesAndNewlines)
            return !basename.isEmpty && basename != "." && basename != "/"
        }
    }

    private func candidateExists(filename: String) -> Bool {
        FileManager.default.fileExists(
            atPath: outputDir + "/auto_generated/" + filename
        )
    }

    private static func candidateFilename(
        campaignType: String,
        fingerprint: String
    ) -> String {
        "candidate_\(safeFilenameComponent(campaignType))_\(fingerprint).yml"
    }

    /// Stable semantic identity intentionally excludes timestamps and alert
    /// multiplicity: replaying the same evidence after a restart must not grow
    /// disk or create a superficially new candidate. New rule/process/tactic
    /// evidence produces a new fingerprint and can earn a fresh review.
    private static func campaignFingerprint(
        campaignType: String,
        alerts: [(ruleId: String, ruleTitle: String, processPath: String?, tactics: Set<String>, timestamp: Date)]
    ) -> String {
        let campaign = boundedSingleLine(
            campaignType.lowercased(),
            maximumUTF8Bytes: 256
        )
        let evidence = Set(alerts.prefix(100).map { alert in
            let rule = boundedSingleLine(alert.ruleId.lowercased(), maximumUTF8Bytes: 256)
            let process = boundedSingleLine(
                alert.processPath.map { ($0 as NSString).lastPathComponent.lowercased() } ?? "-",
                maximumUTF8Bytes: 512
            )
            let tactics = alert.tactics
                .filter(isSafeSigmaTag)
                .sorted()
                .prefix(32)
                .joined(separator: ",")
            return "r=\(rule)|p=\(process)|t=\(tactics)"
        }).sorted()
        let canonical = (["campaign=\(campaign)"] + evidence).joined(separator: "\n")
        let digest = SHA256.hash(data: Data(canonical.utf8))
        return digest.prefix(12).map { String(format: "%02x", $0) }.joined()
    }

    private static func safeCampaignLabel(_ campaignType: String) -> String {
        let candidate = boundedSingleLine(
            campaignType.replacingOccurrences(of: "_", with: " ").capitalized,
            maximumUTF8Bytes: 128
        )
        return LLMService.isSafePersistedAdvisory(candidate) ? candidate : "Campaign"
    }

    /// Get count of generated rules.
    public func stats() -> Int { generatedCount }

    public func telemetrySnapshot() -> Telemetry { telemetry }
}
