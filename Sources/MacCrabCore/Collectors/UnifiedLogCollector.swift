// UnifiedLogCollector.swift
// MacCrabCore
//
// Collects security-relevant events from the macOS Unified Logging system
// by streaming the output of `/usr/bin/log stream` as a subprocess.
//
// Monitors 12 subsystems covering TCC, Gatekeeper, sudo, Authorization,
// securityd, MDM, loginwindow, XProtect, LaunchServices, OpenDirectory,
// sandbox, and screen sharing.

import Foundation
import os.log

// MARK: - UnifiedLogCollectorError

/// Errors that can occur when creating or running the Unified Log collector.
public enum UnifiedLogCollectorError: Error, CustomStringConvertible {
    /// The `/usr/bin/log` tool could not be found.
    case logToolNotFound
    /// The subprocess failed to launch.
    case launchFailed(String)
    /// A JSON parsing error occurred on a log line.
    case parseError(String)

    public var description: String {
        switch self {
        case .logToolNotFound:
            return "The /usr/bin/log tool was not found."
        case .launchFailed(let msg):
            return "Failed to launch log stream subprocess: \(msg)"
        case .parseError(let msg):
            return "Failed to parse log JSON: \(msg)"
        }
    }
}

// MARK: - UnifiedLogCollector

/// Collects macOS Unified Log entries from security-relevant subsystems and
/// emits normalised `Event` values through an `AsyncStream`.
///
/// Because `LoggingSupport.framework` is private API, this collector shells
/// out to `/usr/bin/log stream --style json` with a subsystem predicate and
/// parses the resulting JSON output line by line.
///
/// Usage:
/// ```swift
/// let collector = try UnifiedLogCollector()
/// for await event in collector.events {
///     // process event
/// }
/// ```
public final class UnifiedLogCollector: @unchecked Sendable {

    // MARK: - Monitored Subsystems

    /// The set of subsystems we subscribe to, covering the major macOS
    /// security-relevant log sources.
    private static let monitoredSubsystems: [String] = [
        "com.apple.TCC",
        "com.apple.Gatekeeper",
        "com.apple.sudo",
        "com.apple.Authorization",
        "com.apple.securityd",
        "com.apple.ManagedClient",
        "com.apple.loginwindow",
        "com.apple.XProtectFramework",
        "com.apple.coreservices",
        "com.apple.opendirectoryd",
        "com.apple.sandboxd",
        "com.apple.screensharing",
        "com.apple.mDNSResponder",
        "com.apple.networkd",
        // Bluetooth & AirDrop — wireless attack detection
        "com.apple.bluetooth",
        "com.apple.sharingd",
        // Wi-Fi — evil twin, deauth, rogue AP detection
        "com.apple.wifi",
        "com.apple.wifid",
    ]

    // MARK: - Properties

    private let process: Process
    private let stdoutPipe: Pipe
    private var continuation: AsyncStream<Event>.Continuation?
    private let logger = Logger(subsystem: "com.maccrab.core", category: "UnifiedLogCollector")
    private var readTask: Task<Void, Never>?

    /// The asynchronous stream of normalised events.
    public let events: AsyncStream<Event>

    // MARK: - Initialisation

    /// Creates a new `UnifiedLogCollector`, launching a `/usr/bin/log stream`
    /// subprocess with a predicate covering all monitored subsystems.
    ///
    /// - Throws: `UnifiedLogCollectorError` if the log tool cannot be found or
    ///   the subprocess fails to launch.
    public init() throws {
        let logPath = "/usr/bin/log"
        guard FileManager.default.fileExists(atPath: logPath) else {
            throw UnifiedLogCollectorError.logToolNotFound
        }

        // Build the predicate: subsystem IN {"com.apple.TCC", ...}
        let quoted = Self.monitoredSubsystems.map { "\"\($0)\"" }.joined(separator: ", ")
        let predicate = "subsystem IN {\(quoted)}"

        // Configure the subprocess
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: logPath)
        proc.arguments = ["stream", "--predicate", predicate, "--style", "json"]

        let pipe = Pipe()
        proc.standardOutput = pipe
        proc.standardError = FileHandle.nullDevice

        self.process = proc
        self.stdoutPipe = pipe

        // Build the AsyncStream and capture the continuation
        var capturedContinuation: AsyncStream<Event>.Continuation!
        self.events = AsyncStream<Event>(bufferingPolicy: .bufferingNewest(512)) { continuation in
            capturedContinuation = continuation
        }
        self.continuation = capturedContinuation

        // Launch
        do {
            try proc.run()
        } catch {
            capturedContinuation.finish()
            throw UnifiedLogCollectorError.launchFailed(error.localizedDescription)
        }

        logger.info("UnifiedLogCollector started — monitoring \(Self.monitoredSubsystems.count) subsystems.")

        // Start the background reading task
        let continuation = self.continuation!
        let log = self.logger
        let fileHandle = pipe.fileHandleForReading

        self.readTask = Task.detached {
            Self.readLoop(fileHandle: fileHandle, continuation: continuation, logger: log)
        }
    }

    deinit {
        stop()
    }

    // MARK: - Lifecycle

    /// Stops the log stream subprocess and finishes the event stream.
    public func stop() {
        readTask?.cancel()
        readTask = nil

        if process.isRunning {
            process.terminate()
            process.waitUntilExit()
            logger.info("UnifiedLogCollector stopped — subprocess terminated.")
        }

        continuation?.finish()
        continuation = nil
    }

    // MARK: - Read Loop

    /// Reads stdout from the log subprocess line-by-line, parsing JSON entries
    /// and yielding normalised `Event` values into the continuation.
    ///
    /// The `/usr/bin/log stream --style json` output is a sequence of JSON
    /// objects, one per line, with an optional leading array bracket or
    /// trailing comma that we must strip before parsing.
    private static func readLoop(
        fileHandle: FileHandle,
        continuation: AsyncStream<Event>.Continuation,
        logger: Logger
    ) {
        // Read all available data in a loop. The `log` tool outputs one JSON
        // object per line, sometimes preceded by a `[` or followed by `,`.
        var residual = Data()

        while !Task.isCancelled {
            let data = fileHandle.availableData
            guard !data.isEmpty else {
                // EOF — the subprocess has exited
                break
            }

            residual.append(data)

            // Split on newlines and process each complete line
            while let newlineRange = residual.range(of: Data([0x0A])) {
                let lineData = residual[residual.startIndex..<newlineRange.lowerBound]
                residual = Data(residual[newlineRange.upperBound...])

                guard !lineData.isEmpty else { continue }

                guard var lineString = String(data: lineData, encoding: .utf8) else {
                    continue
                }

                // Trim whitespace and strip leading/trailing JSON array syntax
                lineString = lineString.trimmingCharacters(in: .whitespacesAndNewlines)

                // Skip empty lines and array markers
                if lineString.isEmpty || lineString == "[" || lineString == "]" {
                    continue
                }

                // Strip trailing comma (the log tool outputs JSON objects
                // separated by commas inside an array)
                if lineString.hasSuffix(",") {
                    lineString = String(lineString.dropLast())
                }

                // Attempt to parse as JSON
                guard let jsonData = lineString.data(using: .utf8),
                      let json = try? JSONSerialization.jsonObject(with: jsonData) as? [String: Any] else {
                    logger.debug("Skipped non-JSON log line: \(lineString.prefix(120))")
                    continue
                }

                if let event = normalise(json: json, logger: logger) {
                    let result = continuation.yield(event)
                    if case .terminated = result {
                        return
                    }
                }
            }
        }

        continuation.finish()
    }

    // MARK: - Event Normalisation

    /// Parses a JSON dictionary from `/usr/bin/log stream --style json` and
    /// converts it into a MacCrab `Event`.
    ///
    /// JSON keys of interest:
    /// - `timestamp`: ISO 8601 timestamp string
    /// - `subsystem`: log subsystem (e.g. `"com.apple.TCC"`)
    /// - `category`: log category within the subsystem
    /// - `processImagePath`: path to the emitting process
    /// - `processID`: PID of the emitting process
    /// - `senderImagePath`: path to the library/framework that emitted the log
    /// - `messageType`: log level (Default, Info, Debug, Error, Fault)
    /// - `eventMessage`: the human-readable log message
    private static func normalise(json: [String: Any], logger: Logger) -> Event? {
        // Required fields
        guard let subsystem = json["subsystem"] as? String,
              let eventMessage = json["eventMessage"] as? String else {
            return nil
        }

        // Timestamp
        let timestamp: Date
        if let tsString = json["timestamp"] as? String {
            timestamp = parseTimestamp(tsString) ?? Date()
        } else {
            timestamp = Date()
        }

        // Process info
        let processImagePath = json["processImagePath"] as? String ?? ""
        let processID = json["processID"] as? Int ?? 0
        let senderImagePath = json["senderImagePath"] as? String ?? ""
        let category = json["category"] as? String ?? ""
        let messageType = json["messageType"] as? String ?? "Default"

        // Determine event category, type, and action from subsystem
        let (eventCategory, eventType, eventAction) = classifySubsystem(
            subsystem: subsystem,
            category: category,
            message: eventMessage
        )

        // Determine severity from message type and subsystem context
        let severity = classifySeverity(
            messageType: messageType,
            subsystem: subsystem,
            message: eventMessage
        )

        // Build the process info. We have limited data from the Unified Log
        // (just PID, image path, and process name). Enrichment fills in the rest.
        let processName = (processImagePath as NSString).lastPathComponent
        let processInfo = ProcessInfo(
            pid: Int32(processID),
            ppid: 0,
            rpid: 0,
            name: processName.isEmpty ? "unknown" : processName,
            executable: processImagePath,
            commandLine: processImagePath,
            args: [],
            workingDirectory: "/",
            userId: 0,
            userName: "",
            groupId: 0,
            startTime: timestamp
        )

        // Build optional TCC info if this is a TCC subsystem message
        let tccInfo: TCCInfo? = parseTCCInfo(
            subsystem: subsystem,
            message: eventMessage,
            category: category
        )

        // Build enrichments with log-specific metadata
        var enrichments: [String: String] = [
            "log.subsystem": subsystem,
            "log.category": category,
            "log.messageType": messageType,
            "log.senderImagePath": senderImagePath,
        ]

        // Include the raw message for downstream analysis
        enrichments["log.message"] = String(eventMessage.prefix(4096))

        return Event(
            timestamp: timestamp,
            eventCategory: eventCategory,
            eventType: eventType,
            eventAction: eventAction,
            process: processInfo,
            tcc: tccInfo,
            enrichments: enrichments,
            severity: severity
        )
    }

    // MARK: - Subsystem Classification

    /// Maps a Unified Log subsystem (and optionally category/message content)
    /// to an `EventCategory`, `EventType`, and action string.
    private static func classifySubsystem(
        subsystem: String,
        category: String,
        message: String
    ) -> (EventCategory, EventType, String) {
        switch subsystem {
        case "com.apple.TCC":
            return (.tcc, .change, "tcc_decision")

        case "com.apple.Gatekeeper":
            return (.process, .info, "gatekeeper_assessment")

        case "com.apple.sudo":
            return (.authentication, .info, "sudo_auth")

        case "com.apple.Authorization":
            return (.authentication, .info, "authorization_event")

        case "com.apple.securityd":
            return (.process, .info, "securityd_event")

        case "com.apple.ManagedClient":
            return (.process, .change, "mdm_event")

        case "com.apple.loginwindow":
            // Distinguish login from logout based on message content
            let lowerMessage = message.lowercased()
            if lowerMessage.contains("logout") || lowerMessage.contains("logged out") {
                return (.authentication, .end, "user_logout")
            } else if lowerMessage.contains("login") || lowerMessage.contains("logged in") {
                return (.authentication, .start, "user_login")
            }
            return (.authentication, .info, "loginwindow_event")

        case "com.apple.XProtectFramework":
            return (.process, .info, "xprotect_scan")

        case "com.apple.coreservices":
            return (.process, .info, "launchservices_event")

        case "com.apple.opendirectoryd":
            // Detect user creation vs. general directory service events
            let lowerMessage = message.lowercased()
            if lowerMessage.contains("create") || lowerMessage.contains("new user") {
                return (.authentication, .creation, "user_creation")
            }
            return (.authentication, .info, "directory_service_event")

        case "com.apple.sandboxd":
            return (.process, .info, "sandbox_violation")

        case "com.apple.screensharing":
            let lowerMessage = message.lowercased()
            if lowerMessage.contains("connect") || lowerMessage.contains("session started") {
                return (.authentication, .start, "screensharing_connect")
            } else if lowerMessage.contains("disconnect") || lowerMessage.contains("session ended") {
                return (.authentication, .end, "screensharing_disconnect")
            }
            return (.process, .info, "screensharing_event")

        default:
            return (.process, .info, "unified_log_event")
        }
    }

    // MARK: - Severity Classification

    /// Determines the event severity from the log message type and context.
    private static func classifySeverity(
        messageType: String,
        subsystem: String,
        message: String
    ) -> Severity {
        // Fault-level messages always indicate a serious problem
        if messageType == "Fault" {
            return .high
        }

        // Error-level messages are at least medium
        if messageType == "Error" {
            return .medium
        }

        // Subsystem-specific escalation
        switch subsystem {
        case "com.apple.sudo":
            // sudo usage is always noteworthy
            let lowerMessage = message.lowercased()
            if lowerMessage.contains("authentication failure") ||
               lowerMessage.contains("incorrect password") {
                return .high
            }
            return .medium

        case "com.apple.sandboxd":
            // Sandbox violations may indicate exploitation attempts
            return .medium

        case "com.apple.XProtectFramework":
            let lowerMessage = message.lowercased()
            if lowerMessage.contains("malware") || lowerMessage.contains("blocked") {
                return .high
            }
            return .low

        case "com.apple.Gatekeeper":
            let lowerMessage = message.lowercased()
            if lowerMessage.contains("denied") || lowerMessage.contains("blocked") {
                return .medium
            }
            return .low

        case "com.apple.TCC":
            return .low

        case "com.apple.screensharing":
            return .low

        default:
            return .informational
        }
    }

    // MARK: - TCC Message Parsing

    /// Attempts to parse TCC-specific information from a Unified Log message.
    ///
    /// TCC log messages often contain structured data about the service name,
    /// client bundle identifier, and the decision (allow/deny). The format is
    /// not formally documented so we use heuristic pattern matching.
    private static func parseTCCInfo(
        subsystem: String,
        message: String,
        category: String
    ) -> TCCInfo? {
        guard subsystem == "com.apple.TCC" else {
            return nil
        }

        // Attempt to extract the TCC service name.
        // Common patterns: "kTCCServiceAccessibility", "kTCCServiceScreenCapture"
        let service = extractPattern(
            from: message,
            prefix: "kTCCService",
            terminators: CharacterSet.whitespacesAndNewlines.union(CharacterSet(charactersIn: ",)\"'"))
        ) ?? category

        // Attempt to extract the client bundle identifier
        let client = extractBundleId(from: message) ?? "unknown"

        // Determine if the decision was allow or deny
        let lowerMessage = message.lowercased()
        let allowed = lowerMessage.contains("allow") ||
                      lowerMessage.contains("grant") ||
                      lowerMessage.contains("permitted") ||
                      lowerMessage.contains("auth_value: 2")

        // Attempt to extract the auth reason
        let authReason: String
        if lowerMessage.contains("user") && lowerMessage.contains("consent") {
            authReason = "user_consent"
        } else if lowerMessage.contains("mdm") || lowerMessage.contains("profile") {
            authReason = "mdm_policy"
        } else if lowerMessage.contains("system") && lowerMessage.contains("policy") {
            authReason = "system_policy"
        } else {
            authReason = "unknown"
        }

        return TCCInfo(
            service: service,
            client: client,
            clientPath: "",
            allowed: allowed,
            authReason: authReason
        )
    }

    // MARK: - Parsing Helpers

    /// ISO 8601 date formatter for Unified Log timestamps.
    /// The log tool outputs timestamps like `"2024-01-15 10:30:45.123456-0800"`.
    private static let timestampFormatters: [DateFormatter] = {
        let formats = [
            "yyyy-MM-dd HH:mm:ss.SSSSSSZ",
            "yyyy-MM-dd HH:mm:ss.SSSSSSZZZZ",
            "yyyy-MM-dd HH:mm:ssZ",
        ]
        return formats.map { format in
            let formatter = DateFormatter()
            formatter.dateFormat = format
            formatter.locale = Locale(identifier: "en_US_POSIX")
            return formatter
        }
    }()

    /// Parses a timestamp string from the Unified Log into a `Date`.
    private static func parseTimestamp(_ string: String) -> Date? {
        for formatter in timestampFormatters {
            if let date = formatter.date(from: string) {
                return date
            }
        }
        // Fallback: try ISO8601DateFormatter which handles various ISO formats
        let iso = ISO8601DateFormatter()
        iso.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return iso.date(from: string)
    }

    /// Extracts a token beginning with the given prefix from a message string.
    ///
    /// For example, given prefix `"kTCCService"` and message
    /// `"checking access for kTCCServiceCamera for client com.example.app"`,
    /// returns `"kTCCServiceCamera"`.
    private static func extractPattern(
        from message: String,
        prefix: String,
        terminators: CharacterSet
    ) -> String? {
        guard let prefixRange = message.range(of: prefix) else {
            return nil
        }

        let startIndex = prefixRange.lowerBound
        var endIndex = prefixRange.upperBound

        while endIndex < message.endIndex {
            if let scalar = message[endIndex...].unicodeScalars.first,
               terminators.contains(scalar) {
                break
            }
            endIndex = message.index(after: endIndex)
        }

        let result = String(message[startIndex..<endIndex])
        return result.isEmpty ? nil : result
    }

    /// Extracts a plausible bundle identifier from a log message.
    ///
    /// Looks for patterns like `"com.example.app"` or `"com.apple.something"`.
    private static func extractBundleId(from message: String) -> String? {
        // Bundle IDs follow reverse-DNS: 2+ dot-separated segments of
        // alphanumerics and hyphens.
        let pattern = #"(?:com|org|net|io)\.[a-zA-Z0-9\-]+(?:\.[a-zA-Z0-9\-]+)+"#
        guard let regex = try? NSRegularExpression(pattern: pattern),
              let match = regex.firstMatch(
                in: message,
                range: NSRange(message.startIndex..., in: message)
              ),
              let range = Range(match.range, in: message) else {
            return nil
        }
        return String(message[range])
    }
}
