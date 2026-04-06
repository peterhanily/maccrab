// CrashReportMiner.swift
// MacCrabCore
//
// Mines macOS crash reports for exploitation indicators.
// Scans DiagnosticReports for EXC_BAD_ACCESS, buffer overflows,
// ASan faults, and other signatures that indicate exploitation
// attempts or memory-safety bugs being actively triggered.

import Foundation
import os.log

/// Mines macOS crash reports for exploitation indicators.
/// Scans DiagnosticReports for EXC_BAD_ACCESS, buffer overflows,
/// and other signatures that indicate exploitation attempts.
public actor CrashReportMiner {
    private let logger = Logger(subsystem: "com.maccrab.detection", category: "crash-miner")

    public struct ExploitIndicator: Sendable {
        public let reportPath: String
        public let processName: String
        public let indicator: String
        public let excerpt: String  // Relevant lines from crash report
        public let timestamp: Date
        public let severity: Severity
    }

    /// Exploitation signatures to search for in crash reports.
    private static let exploitSignatures: [(pattern: String, name: String, severity: Severity)] = [
        ("EXC_BAD_ACCESS (SIGBUS)", "memory_corruption", .high),
        ("EXC_BAD_ACCESS (SIGSEGV)", "segfault_possible_exploit", .high),
        ("stack_buffer_overflow", "stack_overflow_exploit", .critical),
        ("heap_buffer_overflow", "heap_overflow_exploit", .critical),
        ("use_after_free", "use_after_free", .critical),
        ("double_free", "double_free", .critical),
        ("EXC_BAD_INSTRUCTION", "bad_instruction", .medium),
        ("SIGABRT", "abort_possible_exploit", .medium),
        ("__asan", "address_sanitizer_fault", .high),
        ("__ubsan", "undefined_behavior_fault", .high),
        ("heap-use-after-free", "asan_use_after_free", .critical),
        ("heap-buffer-overflow", "asan_heap_overflow", .critical),
        ("stack-buffer-overflow", "asan_stack_overflow", .critical),
        ("container-overflow", "asan_container_overflow", .high),
        ("KERN_INVALID_ADDRESS", "invalid_address_access", .high),
        ("KERN_PROTECTION_FAILURE", "protection_fault", .high),
    ]

    /// Already-processed file paths to avoid duplicate alerts.
    private var knownReports: Set<String> = []

    /// Directories where macOS stores diagnostic crash reports.
    private static let reportDirs: [String] = [
        "/Library/Logs/DiagnosticReports/",
        NSHomeDirectory() + "/Library/Logs/DiagnosticReports/",
    ]

    /// Maximum age of crash reports to scan (24 hours).
    private let maxAge: TimeInterval = 86_400

    public init() {}

    /// Scan for new crash reports with exploitation indicators.
    public func scan() -> [ExploitIndicator] {
        var results: [ExploitIndicator] = []
        let fm = FileManager.default

        for dir in Self.reportDirs {
            guard let files = try? fm.contentsOfDirectory(atPath: dir) else { continue }

            for file in files {
                guard file.hasSuffix(".crash") || file.hasSuffix(".ips") || file.hasSuffix(".panic") else {
                    continue
                }
                let path = dir + file

                // Skip already processed
                guard !knownReports.contains(path) else { continue }
                knownReports.insert(path)

                // Only scan recent reports
                guard let attrs = try? fm.attributesOfItem(atPath: path),
                      let modDate = attrs[.modificationDate] as? Date,
                      Date().timeIntervalSince(modDate) < maxAge else { continue }

                // Read and scan
                guard let content = try? String(contentsOfFile: path, encoding: .utf8) else { continue }

                // Extract process name from crash report
                let processName = extractProcessName(from: content) ?? file

                for (pattern, name, severity) in Self.exploitSignatures {
                    if content.contains(pattern) {
                        let excerpt = extractExcerpt(content: content, pattern: pattern)
                        results.append(ExploitIndicator(
                            reportPath: path,
                            processName: processName,
                            indicator: name,
                            excerpt: excerpt,
                            timestamp: modDate,
                            severity: severity
                        ))
                    }
                }
            }
        }

        return results
    }

    /// Reset the set of known reports, allowing re-scanning.
    public func resetKnownReports() {
        knownReports.removeAll()
    }

    // MARK: - Private Helpers

    private func extractProcessName(from content: String) -> String? {
        // Crash reports have "Process: <name> [pid]" near the top
        for line in content.components(separatedBy: "\n").prefix(20) {
            if line.hasPrefix("Process:") {
                let parts = line.dropFirst("Process:".count).trimmingCharacters(in: .whitespaces)
                return parts.components(separatedBy: " ").first
            }
        }
        return nil
    }

    private func extractExcerpt(content: String, pattern: String) -> String {
        let lines = content.components(separatedBy: "\n")
        for (i, line) in lines.enumerated() {
            if line.contains(pattern) {
                let start = max(0, i - 1)
                let end = min(lines.count, i + 3)
                return String(lines[start..<end].joined(separator: "\n").prefix(300))
            }
        }
        return pattern
    }
}
