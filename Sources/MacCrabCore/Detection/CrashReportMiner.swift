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

    private struct ReportDirectory: Sendable {
        let path: String
        let directoryOwnerUID: UInt32?
        let requiredEntryOwnerUID: UInt32?
    }
    private let reportDirectories: [ReportDirectory]

    /// Maximum age of crash reports to scan (24 hours).
    private let maxAge: TimeInterval = 86_400

    /// Apple crash/Jetsam reports can be substantially larger than ordinary
    /// config files, but they must never be allowed to consume memory without
    /// a ceiling in the root daemon's five-minute forensic task.
    static let maxReportBytes = 32 * 1024 * 1024

    public init() {
        let homes = RealUserHomeResolver.all()
        self.reportDirectories = [ReportDirectory(
            path: "/Library/Logs/DiagnosticReports/",
            directoryOwnerUID: 0,
            requiredEntryOwnerUID: nil
        )] + homes.map {
            ReportDirectory(
                path: $0.appending("Library/Logs/DiagnosticReports") + "/",
                directoryOwnerUID: $0.userID,
                requiredEntryOwnerUID: $0.userID
            )
        }
    }

    static func defaultReportDirectories(homes: [RealUserHome]) -> [String] {
        ["/Library/Logs/DiagnosticReports/"]
            + homes.map { $0.appending("Library/Logs/DiagnosticReports") + "/" }
    }

    /// Internal runtime seam for carrier-boundary tests. Production always
    /// uses Apple's two DiagnosticReports locations above.
    init(reportDirectories: [String]) {
        self.reportDirectories = reportDirectories.map {
            ReportDirectory(
                path: $0,
                directoryOwnerUID: nil,
                requiredEntryOwnerUID: nil
            )
        }
    }

    /// Scan for new crash reports with exploitation indicators.
    public func scan() -> [ExploitIndicator] {
        var results: [ExploitIndicator] = []
        let fm = FileManager.default

        for scope in reportDirectories {
            guard let snapshot = BoundedDirectoryLister.list(
                at: scope.path,
                maximumEntries: 65_536,
                expectedOwnerUID: scope.directoryOwnerUID
            ) else { continue }
            // Consume a bounded partial inventory when truncated; this miner
            // never publishes a "clean directory" state. System crash reports
            // can be user-owned; per-home reports remain uid-bound.
            let files = snapshot.entries.compactMap { entry -> String? in
                guard entry.kind == .regularFile,
                      scope.requiredEntryOwnerUID.map({ entry.ownerUID == $0 }) ?? true else {
                    return nil
                }
                return entry.name
            }

            for file in files {
                guard file.hasSuffix(".crash") || file.hasSuffix(".ips") || file.hasSuffix(".panic") else {
                    continue
                }
                let path = scope.path + file

                // Skip already processed
                guard !knownReports.contains(path) else { continue }

                // Cheap prefilter only. The pathname may be replaced after
                // this stat, so the security decision below uses metadata from
                // the same descriptor that supplied the stable bytes.
                guard let attrs = try? fm.attributesOfItem(atPath: path),
                      let modDate = attrs[.modificationDate] as? Date,
                      Date().timeIntervalSince(modDate) < maxAge else { continue }

                // Read and scan. DiagnosticReports is external input to the
                // daemon; reject links, FIFOs/devices, hard links, oversized
                // reports, and concurrent replacement/mutation.
                guard case .success(let snapshot) = BoundedRegularFileReader.readOutcome(
                    at: path,
                    maximumBytes: Self.maxReportBytes
                ), Date().timeIntervalSince(snapshot.modificationDate) < maxAge else {
                    continue
                }

                // Cache only after a successful stable read. A rejected FIFO,
                // link, oversize file, or concurrent mutation may later be
                // replaced at the same path by a legitimate report.
                knownReports.insert(path)
                guard let content = String(data: snapshot.data, encoding: .utf8) else {
                    continue
                }

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
                            timestamp: snapshot.modificationDate,
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
