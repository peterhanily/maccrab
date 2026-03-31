// YARAEnricher.swift
// HawkEyeCore
//
// Optional enrichment module that scans newly created files against YARA
// rules and annotates matching events with rule names and match counts.
//
// Shells out to the `yara` binary rather than linking libyara directly,
// which keeps the build simple and allows users to update YARA rules and
// the scanner independently of HawkEye.

import Foundation
import os.log

// MARK: - YARAEnricher

/// Enriches file-creation events by scanning the target file against a
/// directory of YARA rules.
///
/// The enricher is opt-in: if the `yara` binary is not found at the
/// configured path, or if the rules directory does not exist, the enricher
/// silently passes events through unmodified.
///
/// Only files created within the configured `scanPaths` prefixes are
/// scanned, and a 50 MB size cap prevents the scanner from blocking on
/// very large files.  Each scan has a 5-second timeout.
///
/// Usage:
/// ```swift
/// let yara = YARAEnricher(
///     rulesPath: "/usr/local/share/hawkeye/yara-rules",
///     scanPaths: ["/tmp/", "~/Downloads/"]
/// )
///
/// var event = await yara.enrich(event)
/// ```
public actor YARAEnricher {

    // MARK: - Properties

    /// Absolute path to the directory containing `.yar` / `.yara` rule files.
    private let rulesPath: String

    /// Absolute path to the `yara` binary.
    private let yaraPath: String

    /// Whether the enricher is enabled (rules dir and binary both exist).
    private let enabled: Bool

    /// Only scan files whose path begins with one of these prefixes.
    /// An empty array means *no* files are scanned.
    private let scanPaths: [String]

    /// Maximum file size in bytes that will be scanned (50 MB).
    private let maxFileSize: UInt64 = 50 * 1024 * 1024

    /// Maximum wall-clock time in seconds for a single YARA scan.
    private let scanTimeout: TimeInterval = 5.0

    /// Number of files scanned since initialisation.
    private var scanCount: Int = 0

    /// Number of files that had at least one YARA rule match.
    private var matchCount: Int = 0

    /// Timestamp of the last scan, used for throttling.
    private var lastScanTime: Date = .distantPast

    /// Minimum interval between consecutive scans (200ms).
    private let minScanInterval: TimeInterval = 0.2

    /// Number of scans waiting to be processed.
    private var pendingScanCount: Int = 0

    /// Maximum number of simultaneous YARA scans.
    private let maxConcurrentScans: Int = 3

    /// Number of currently running YARA scans.
    private var activeScanCount: Int = 0

    /// Logger scoped to the YARA enrichment subsystem.
    private let logger = Logger(subsystem: "com.hawkeye.core", category: "YARAEnricher")

    // MARK: - Default Scan Paths

    /// Default directories that are commonly used for malware staging,
    /// downloads, or persistence.
    private static let defaultScanPaths: [String] = {
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        return [
            "/tmp/",
            "/private/tmp/",
            "/var/folders/",
            "\(home)/Downloads/",
            "\(home)/Desktop/",
            "/Library/LaunchAgents/",
            "/Library/LaunchDaemons/",
            "\(home)/Library/LaunchAgents/",
        ]
    }()

    // MARK: - Initialisation

    /// Creates a new `YARAEnricher`.
    ///
    /// - Parameters:
    ///   - rulesPath: Absolute path to the YARA rules directory.
    ///   - yaraPath: Absolute path to the `yara` binary.
    ///     Defaults to `/usr/local/bin/yara`.
    ///   - scanPaths: File-path prefixes to restrict scanning to.
    ///     An empty array falls back to ``defaultScanPaths``.
    public init(
        rulesPath: String,
        yaraPath: String = "/usr/local/bin/yara",
        scanPaths: [String] = []
    ) {
        self.rulesPath = rulesPath
        self.yaraPath = yaraPath
        self.scanPaths = scanPaths.isEmpty ? Self.defaultScanPaths : scanPaths

        let fm = FileManager.default
        let yaraExists = fm.fileExists(atPath: yaraPath)
        let rulesExist = fm.fileExists(atPath: rulesPath)
        self.enabled = yaraExists && rulesExist

        let log = Logger(subsystem: "com.hawkeye.core", category: "YARAEnricher")
        if !yaraExists {
            log.info("YARA binary not found at \(yaraPath) — YARA enrichment disabled.")
        }
        if !rulesExist {
            log.info("YARA rules directory not found at \(rulesPath) — YARA enrichment disabled.")
        }
        if self.enabled {
            log.info("YARAEnricher initialised — rules: \(rulesPath), binary: \(yaraPath).")
        }
    }

    // MARK: - Availability

    /// Returns `true` if the YARA binary and rules directory both exist.
    public func isAvailable() -> Bool {
        enabled
    }

    // MARK: - Enrichment

    /// Enrich a file event with YARA scan results.
    ///
    /// The event is scanned only when **all** of the following conditions hold:
    /// 1. The enricher is enabled (binary + rules exist).
    /// 2. The event is a file-creation event.
    /// 3. The target file path starts with one of the `scanPaths` prefixes.
    /// 4. The file still exists on disk.
    /// 5. The file is smaller than 50 MB.
    ///
    /// If any condition fails, the event is returned unmodified.
    ///
    /// - Parameter event: The event to enrich.
    /// - Returns: A (possibly enriched) copy of the event.
    public func enrich(_ event: Event) async -> Event {
        // Gate: must be enabled.
        guard enabled else { return event }

        // Gate: must be a file-creation event with a file payload.
        guard event.eventCategory == .file,
              event.eventAction == "create" || event.eventType == .creation,
              let fileInfo = event.file else {
            return event
        }

        let filePath = fileInfo.path

        // Gate: file must be under one of the monitored directories.
        guard matchesScanPaths(filePath) else { return event }

        // Gate: file must exist and be within the size limit.
        let fm = FileManager.default
        guard fm.fileExists(atPath: filePath) else {
            logger.debug("YARA skip — file does not exist: \(filePath)")
            return event
        }

        guard let attrs = try? fm.attributesOfItem(atPath: filePath),
              let fileSize = attrs[.size] as? UInt64,
              fileSize > 0,
              fileSize <= maxFileSize else {
            logger.debug("YARA skip — file too large or unreadable: \(filePath)")
            return event
        }

        // Throttle: minimum 200ms between scans
        let now = Date()
        guard now.timeIntervalSince(lastScanTime) >= minScanInterval else {
            return event  // Skip scan, too soon
        }

        // Concurrency limit: max 3 simultaneous scans
        guard activeScanCount < maxConcurrentScans else {
            return event  // Skip scan, too many active
        }

        activeScanCount += 1
        defer { activeScanCount -= 1 }
        lastScanTime = now

        // Run the YARA scan.
        let matchedRules = await runYARAScan(filePath: filePath)
        scanCount += 1

        guard !matchedRules.isEmpty else { return event }
        matchCount += 1

        // Build an enriched copy of the event.
        var enrichedEvent = Event(
            id: event.id,
            timestamp: event.timestamp,
            eventCategory: event.eventCategory,
            eventType: event.eventType,
            eventAction: event.eventAction,
            process: event.process,
            file: event.file,
            network: event.network,
            tcc: event.tcc,
            enrichments: event.enrichments,
            severity: event.severity,
            ruleMatches: event.ruleMatches
        )

        enrichedEvent.enrichments["yara.rules"] = matchedRules.joined(separator: ", ")
        enrichedEvent.enrichments["yara.match_count"] = String(matchedRules.count)

        // Escalate severity when YARA matches are found.
        if enrichedEvent.severity < .medium {
            enrichedEvent.severity = .medium
        }

        logger.info(
            "YARA matched \(matchedRules.count) rule(s) on \(filePath): \(matchedRules.joined(separator: ", "))"
        )

        return enrichedEvent
    }

    // MARK: - Statistics

    /// Returns cumulative scan statistics since initialisation.
    ///
    /// - Returns: A tuple of (files scanned, files with at least one match).
    public func stats() -> (scanned: Int, matched: Int) {
        (scanned: scanCount, matched: matchCount)
    }

    // MARK: - Scan Path Matching

    /// Returns `true` when the file path begins with at least one configured
    /// scan-path prefix.
    private func matchesScanPaths(_ filePath: String) -> Bool {
        for prefix in scanPaths {
            if filePath.hasPrefix(prefix) {
                return true
            }
        }
        return false
    }

    // MARK: - YARA Execution

    /// Shells out to the `yara` binary to scan a single file.
    ///
    /// Command: `yara -w -s <rules_dir> <file_path>`
    ///
    /// `-w` suppresses warnings (e.g., slow rules).
    /// `-s` prints matching strings (useful for debugging; we only parse
    ///       the rule names here).
    ///
    /// Output format (one line per match):
    /// ```
    /// rule_name file_path
    /// 0x1234:$string_id: <hex or text>
    /// ```
    ///
    /// We parse only lines that contain the file path (rule-match lines)
    /// and ignore string-detail lines.
    ///
    /// The scan is run with a wall-clock timeout; if the process does not
    /// exit within `scanTimeout` seconds it is terminated.
    ///
    /// - Parameter filePath: Absolute path to the file to scan.
    /// - Returns: Array of matched YARA rule names, possibly empty.
    private func runYARAScan(filePath: String) async -> [String] {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: yaraPath)
        process.arguments = ["-w", "-s", rulesPath, filePath]

        let stdoutPipe = Pipe()
        let stderrPipe = Pipe()
        process.standardOutput = stdoutPipe
        process.standardError = stderrPipe

        // Run in a detached task so we can enforce a timeout.
        let scanResult: [String]? = await withTaskGroup(of: [String]?.self) { group in
            group.addTask {
                do {
                    try process.run()
                } catch {
                    return nil
                }

                process.waitUntilExit()

                // Read stdout after the process exits to avoid pipe deadlocks
                // on large output.
                let data = stdoutPipe.fileHandleForReading.readDataToEndOfFile()
                guard process.terminationStatus == 0,
                      let output = String(data: data, encoding: .utf8) else {
                    return []
                }

                return self.parseYARAOutput(output, filePath: filePath)
            }

            // Timeout task.
            group.addTask {
                try? await Task.sleep(nanoseconds: UInt64(self.scanTimeout * 1_000_000_000))
                if process.isRunning {
                    process.terminate()
                }
                return nil   // signals timeout
            }

            // Return whichever finishes first.
            var result: [String]?
            for await value in group {
                if let value = value {
                    result = value
                    group.cancelAll()
                    break
                }
            }

            // If both returned nil (timeout + failed launch), return empty.
            return result
        }

        if scanResult == nil {
            logger.warning("YARA scan timed out or failed for \(filePath).")
            return []
        }

        return scanResult ?? []
    }

    /// Parses the text output of a `yara -w -s` invocation.
    ///
    /// Rule-match lines have the format:
    /// ```
    /// RuleName /path/to/file
    /// ```
    ///
    /// String-match detail lines start with `0x` and are skipped.
    /// Blank lines and lines that don't reference the scanned file are
    /// also skipped.
    ///
    /// - Parameters:
    ///   - output: Raw stdout from the `yara` process.
    ///   - filePath: The file that was scanned (used to identify match lines).
    /// - Returns: Deduplicated array of matched rule names.
    private func parseYARAOutput(_ output: String, filePath: String) -> [String] {
        var rules: [String] = []
        var seen: Set<String> = []

        let lines = output.components(separatedBy: .newlines)
        for line in lines {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            guard !trimmed.isEmpty else { continue }

            // Skip string-match detail lines (e.g., "0x1234:$s1: ...")
            if trimmed.hasPrefix("0x") { continue }

            // A rule-match line looks like: "RuleName /path/to/file"
            // Split on whitespace and verify the second component matches
            // the file path.
            let components = trimmed.split(separator: " ", maxSplits: 1)
            guard components.count == 2 else { continue }

            let candidateFile = String(components[1])
            guard candidateFile == filePath else { continue }

            let ruleName = String(components[0])
            if !seen.contains(ruleName) {
                seen.insert(ruleName)
                rules.append(ruleName)
            }
        }

        return rules
    }
}
