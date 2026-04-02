// WebhookOutput.swift
// HawkEyeCore
//
// Sends detection alerts to a configured webhook URL as JSON POST requests.
// Supports retry with exponential backoff for transient failures.

import Foundation
import os.log

// MARK: - WebhookOutput

/// Delivers detection alerts to an external HTTP(S) endpoint as JSON payloads.
///
/// Each alert is serialised into a structured JSON envelope containing alert
/// metadata, the triggering event, and host information. Delivery is best-effort
/// with configurable retry for transient server errors (HTTP 5xx) and network
/// failures. The output is fire-and-forget by design so it does not block the
/// main detection pipeline.
///
/// Thread-safe via Swift actor isolation.
public actor WebhookOutput {

    // MARK: Properties

    /// The destination webhook URL.
    private let url: URL

    /// Additional HTTP headers sent with every request (e.g. authorization tokens).
    private let headers: [String: String]

    /// The URL session used for all outbound requests.
    private let session: URLSession

    /// Number of retry attempts for transient failures (default 2).
    private let retryCount: Int

    /// Per-request timeout in seconds (default 10).
    private let timeout: TimeInterval

    /// Running count of successfully delivered payloads.
    private var sentCount: Int = 0

    /// Running count of payloads that failed delivery after all retries.
    private var failedCount: Int = 0

    private let logger = Logger(
        subsystem: "com.hawkeye.output",
        category: "WebhookOutput"
    )

    /// ISO 8601 formatter used for all timestamp fields in the JSON payload.
    private static let iso8601Formatter: ISO8601DateFormatter = {
        let fmt = ISO8601DateFormatter()
        fmt.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return fmt
    }()

    // MARK: Initialization

    /// Creates a webhook output configured for the given endpoint.
    ///
    /// - Parameters:
    ///   - url: The destination URL for alert payloads.
    ///   - headers: Additional HTTP headers (e.g. `["Authorization": "Bearer ..."]`).
    ///   - retryCount: Number of retry attempts on transient failure (default 2).
    ///   - timeout: Per-request timeout in seconds (default 10).
    public init(
        url: URL,
        headers: [String: String] = [:],
        retryCount: Int = 2,
        timeout: TimeInterval = 10
    ) {
        self.url = url
        self.headers = headers
        self.retryCount = retryCount
        self.timeout = timeout

        let config = URLSessionConfiguration.ephemeral
        config.timeoutIntervalForRequest = timeout
        config.timeoutIntervalForResource = timeout * Double(retryCount + 1)
        config.waitsForConnectivity = false
        self.session = URLSession(configuration: config)
    }

    // MARK: - Public API

    /// Sends a single alert/event pair to the webhook.
    ///
    /// The call is non-throwing; delivery failures are logged and counted but
    /// do not propagate to the caller.
    ///
    /// - Parameters:
    ///   - alert: The detection alert to deliver.
    ///   - event: The event that triggered the alert.
    public func send(alert: Alert, event: Event) async {
        let payload = buildPayload(alert: alert, event: event)
        await deliver(payload: payload, label: alert.id)
    }

    /// Sends a batch of alert/event pairs to the webhook.
    ///
    /// Each pair is sent as an individual HTTP request. For very large batches
    /// the calls are serialised to avoid overwhelming the remote endpoint.
    ///
    /// - Parameter alerts: An array of `(Alert, Event)` tuples to deliver.
    public func sendBatch(alerts: [(Alert, Event)]) async {
        for (alert, event) in alerts {
            await send(alert: alert, event: event)
        }
    }

    /// Returns delivery statistics since this output was created.
    ///
    /// - Returns: A tuple of successfully sent and failed delivery counts.
    public func stats() -> (sent: Int, failed: Int) {
        (sent: sentCount, failed: failedCount)
    }

    // MARK: - Payload Construction

    /// Builds the JSON payload dictionary for a single alert/event pair.
    private func buildPayload(alert: Alert, event: Event) -> [String: Any] {
        let timestamp = Self.iso8601Formatter.string(from: alert.timestamp)

        // Alert block
        var alertDict: [String: Any] = [
            "id": alert.id,
            "rule_id": alert.ruleId,
            "rule_title": alert.ruleTitle,
            "severity": alert.severity.rawValue,
        ]
        if let desc = alert.description {
            alertDict["description"] = desc
        }
        if let tactics = alert.mitreTactics {
            alertDict["mitre_tactics"] = tactics
        }
        if let techniques = alert.mitreTechniques {
            alertDict["mitre_techniques"] = techniques
        }

        // Process block
        var processDict: [String: Any] = [
            "name": event.process.name,
            "path": event.process.executable,
            "pid": event.process.pid,
            "ppid": event.process.ppid,
            "command_line": CommandSanitizer.sanitize(event.process.commandLine),
        ]
        if let sig = event.process.codeSignature {
            processDict["signer"] = sig.signerType.rawValue
            if let teamId = sig.teamId {
                processDict["team_id"] = teamId
            }
            if let signingId = sig.signingId {
                processDict["signing_id"] = signingId
            }
        } else {
            processDict["signer"] = "unsigned"
        }

        // Event block
        var eventDict: [String: Any] = [
            "id": event.id.uuidString,
            "category": event.eventCategory.rawValue,
            "action": event.eventAction,
            "process": processDict,
        ]

        // File sub-block (if present)
        if let file = event.file {
            var fileDict: [String: Any] = [
                "path": file.path,
                "name": file.name,
                "directory": file.directory,
                "action": file.action.rawValue,
            ]
            if let ext = file.extension_ {
                fileDict["extension"] = ext
            }
            if let size = file.size {
                fileDict["size"] = size
            }
            if let src = file.sourcePath {
                fileDict["source_path"] = src
            }
            eventDict["file"] = fileDict
        }

        // Network sub-block (if present)
        if let net = event.network {
            var netDict: [String: Any] = [
                "source_ip": net.sourceIp,
                "source_port": net.sourcePort,
                "destination_ip": net.destinationIp,
                "destination_port": net.destinationPort,
                "direction": net.direction.rawValue,
                "transport": net.transport,
            ]
            if let hostname = net.destinationHostname {
                netDict["destination_hostname"] = hostname
            }
            eventDict["network"] = netDict
        }

        // Host block
        let hostDict: [String: Any] = [
            "hostname": Self.hostname(),
            "os_version": Self.osVersion(),
        ]

        return [
            "version": "1.0",
            "source": "hawkeye",
            "timestamp": timestamp,
            "alert": alertDict,
            "event": eventDict,
            "host": hostDict,
        ]
    }

    // MARK: - Delivery

    /// Delivers a JSON payload with retry and exponential backoff.
    private func deliver(payload: [String: Any], label: String) async {
        guard let body = try? JSONSerialization.data(withJSONObject: payload, options: []) else {
            logger.error("Failed to serialise webhook payload for alert \(label, privacy: .public)")
            failedCount += 1
            return
        }

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("HawkEye/1.0", forHTTPHeaderField: "User-Agent")
        for (key, value) in headers {
            request.setValue(value, forHTTPHeaderField: key)
        }
        request.httpBody = body

        var lastError: Error?

        for attempt in 0...retryCount {
            if attempt > 0 {
                // Exponential backoff: 1s, 2s, 4s, ...
                let delay = UInt64(pow(2.0, Double(attempt - 1))) * 1_000_000_000
                try? await Task.sleep(nanoseconds: delay)
            }

            do {
                let (_, response) = try await session.data(for: request)

                if let httpResponse = response as? HTTPURLResponse {
                    let statusCode = httpResponse.statusCode

                    if (200..<300).contains(statusCode) {
                        sentCount += 1
                        if attempt > 0 {
                            logger.info(
                                "Webhook delivery succeeded on attempt \(attempt + 1) for alert \(label, privacy: .public)"
                            )
                        }
                        return
                    }

                    if (500..<600).contains(statusCode) {
                        // Server error -- retryable.
                        lastError = WebhookError.serverError(statusCode)
                        logger.warning(
                            "Webhook returned \(statusCode) for alert \(label, privacy: .public) (attempt \(attempt + 1)/\(self.retryCount + 1))"
                        )
                        continue
                    }

                    // Client error (4xx) -- not retryable.
                    logger.error(
                        "Webhook returned \(statusCode) for alert \(label, privacy: .public); not retrying"
                    )
                    failedCount += 1
                    return
                }

                // Non-HTTP response -- should not happen, treat as failure.
                logger.error("Non-HTTP response received for alert \(label, privacy: .public)")
                failedCount += 1
                return

            } catch {
                lastError = error
                logger.warning(
                    "Webhook delivery failed for alert \(label, privacy: .public): \(error.localizedDescription) (attempt \(attempt + 1)/\(self.retryCount + 1))"
                )
                continue
            }
        }

        // All retries exhausted.
        failedCount += 1
        logger.error(
            "Webhook delivery failed permanently for alert \(label, privacy: .public) after \(self.retryCount + 1) attempts: \(lastError?.localizedDescription ?? "unknown error")"
        )
    }

    // MARK: - Host Information

    /// Returns the local hostname.
    private static func hostname() -> String {
        Foundation.ProcessInfo.processInfo.hostName
    }

    /// Returns the macOS version string (e.g. "14.3.1").
    private static func osVersion() -> String {
        let version = Foundation.ProcessInfo.processInfo.operatingSystemVersion
        return "\(version.majorVersion).\(version.minorVersion).\(version.patchVersion)"
    }
}

// MARK: - WebhookError

/// Internal error type for webhook delivery failures.
private enum WebhookError: Error, LocalizedError {
    case serverError(Int)

    var errorDescription: String? {
        switch self {
        case .serverError(let code):
            return "Server returned HTTP \(code)"
        }
    }
}
