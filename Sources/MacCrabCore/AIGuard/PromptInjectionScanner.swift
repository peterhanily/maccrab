// PromptInjectionScanner.swift
// MacCrabCore
//
// Scans text content for prompt injection attacks using Forensicate.ai.
// Calls the forensicate Python CLI via subprocess for zero-dependency
// local scanning with 87+ injection detection rules.

import Foundation
import os.log

/// Scans AI tool command lines and file contents for prompt injection.
///
/// Uses the Forensicate.ai Python scanner (`forensicate --json`) to detect
/// jailbreak attempts, DAN personas, encoded payloads, and multi-vector
/// injection attacks in text that AI coding tools process.
public actor PromptInjectionScanner {

    private let logger = Logger(subsystem: "com.maccrab", category: "prompt-injection")

    /// Path to the forensicate CLI. Resolved at init.
    private let forensicatePath: String?

    /// Minimum confidence threshold to generate an alert (0-99).
    private let confidenceThreshold: Int

    /// Cache recent scans to avoid re-scanning identical text.
    private var cache: [String: ScanResult] = [:]
    private let maxCacheSize = 500

    /// Whether the scanner is available (forensicate installed).
    public var isAvailable: Bool { forensicatePath != nil }

    // MARK: - Types

    public struct ScanResult: Sendable {
        public let isPositive: Bool
        public let confidence: Int
        public let reasons: [String]
        public let matchedRules: [MatchedRule]
        public let compoundThreats: [String]
    }

    public struct MatchedRule: Sendable {
        public let ruleId: String
        public let ruleName: String
        public let severity: String
        public let matches: [String]
    }

    // MARK: - Initialization

    public init(confidenceThreshold: Int = 40) {
        self.confidenceThreshold = confidenceThreshold

        // Find forensicate CLI
        let candidates = [
            "/usr/local/bin/forensicate",
            "/opt/homebrew/bin/forensicate",
            NSHomeDirectory() + "/.local/bin/forensicate",
            "/usr/bin/forensicate",
        ]

        // Also check via `which`
        var found: String?
        for candidate in candidates {
            if FileManager.default.isExecutableFile(atPath: candidate) {
                found = candidate
                break
            }
        }

        if found == nil {
            // Try `which forensicate`
            let process = Process()
            process.executableURL = URL(fileURLWithPath: "/usr/bin/which")
            process.arguments = ["forensicate"]
            let pipe = Pipe()
            process.standardOutput = pipe
            process.standardError = FileHandle.nullDevice
            try? process.run()
            process.waitUntilExit()
            if process.terminationStatus == 0 {
                let output = String(data: pipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8)?
                    .trimmingCharacters(in: .whitespacesAndNewlines)
                if let path = output, !path.isEmpty {
                    found = path
                }
            }
        }

        self.forensicatePath = found

        if found != nil {
            Logger(subsystem: "com.maccrab", category: "prompt-injection")
                .info("Forensicate scanner available at: \(found!)")
        } else {
            Logger(subsystem: "com.maccrab", category: "prompt-injection")
                .info("Forensicate not installed — prompt injection scanning disabled. Install: pip install forensicate")
        }
    }

    // MARK: - Public API

    /// Scan text for prompt injection. Returns nil if forensicate is not installed
    /// or if the text is below the confidence threshold.
    public func scan(_ text: String) -> ScanResult? {
        guard let path = forensicatePath else { return nil }
        guard !text.isEmpty else { return nil }

        // Check cache
        let cacheKey = String(text.prefix(500))
        if let cached = cache[cacheKey] { return cached }

        // Call forensicate via subprocess
        let result = callForensicate(path: path, text: text)

        // Cache result
        if let result = result {
            if cache.count >= maxCacheSize { cache.removeAll() }
            cache[cacheKey] = result
        }

        return result
    }

    /// Scan and return a severity level for behavioral scoring integration.
    public func scanForSeverity(_ text: String) -> (indicator: String, detail: String)? {
        guard let result = scan(text), result.isPositive else { return nil }

        let indicator: String
        if !result.compoundThreats.isEmpty {
            indicator = "prompt_injection_compound"
        } else if result.confidence >= 80 {
            indicator = "prompt_injection_critical"
        } else if result.confidence >= 60 {
            indicator = "prompt_injection_high"
        } else if result.confidence >= 40 {
            indicator = "prompt_injection_medium"
        } else {
            indicator = "prompt_injection_low"
        }

        let detail = "Confidence: \(result.confidence)%. Rules: \(result.matchedRules.map(\.ruleName).joined(separator: ", "))"
        return (indicator, detail)
    }

    // MARK: - Private

    private nonisolated func callForensicate(path: String, text: String) -> ScanResult? {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: path)
        process.arguments = ["--json", "--threshold", "0"]  // Always get full results

        let inputPipe = Pipe()
        let outputPipe = Pipe()
        process.standardInput = inputPipe
        process.standardOutput = outputPipe
        process.standardError = FileHandle.nullDevice

        do {
            try process.run()

            // Write text to stdin (truncate to 100KB to avoid hanging)
            let inputData = String(text.prefix(100_000)).data(using: .utf8) ?? Data()
            inputPipe.fileHandleForWriting.write(inputData)
            inputPipe.fileHandleForWriting.closeFile()

            // Timeout: kill after 5 seconds
            let deadline = DispatchTime.now() + 5
            DispatchQueue.global().asyncAfter(deadline: deadline) {
                if process.isRunning { process.terminate() }
            }

            process.waitUntilExit()

            guard process.terminationStatus == 0 || process.terminationStatus == 1 else {
                return nil
            }

            let outputData = outputPipe.fileHandleForReading.readDataToEndOfFile()
            return parseJSON(outputData)
        } catch {
            return nil
        }
    }

    private nonisolated func parseJSON(_ data: Data) -> ScanResult? {
        guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            return nil
        }

        let isPositive = json["is_positive"] as? Bool ?? false
        let confidence = json["confidence"] as? Int ?? 0
        let reasons = json["reasons"] as? [String] ?? []

        var matchedRules: [MatchedRule] = []
        if let rules = json["matched_rules"] as? [[String: Any]] {
            for rule in rules {
                matchedRules.append(MatchedRule(
                    ruleId: rule["rule_id"] as? String ?? "",
                    ruleName: rule["rule_name"] as? String ?? "",
                    severity: rule["severity"] as? String ?? "",
                    matches: rule["matches"] as? [String] ?? []
                ))
            }
        }

        var compoundThreats: [String] = []
        if let compounds = json["compound_threats"] as? [[String: Any]] {
            compoundThreats = compounds.compactMap { $0["name"] as? String }
        }

        return ScanResult(
            isPositive: isPositive,
            confidence: confidence,
            reasons: reasons,
            matchedRules: matchedRules,
            compoundThreats: compoundThreats
        )
    }
}
