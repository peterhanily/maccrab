// FleetClient.swift
// MacCrabCore
//
// Pushes telemetry to the fleet collector.
// Configured via MACCRAB_FLEET_URL environment variable.
// v1.21.5: outbound-only — the pull machinery (IOC aggregations, fleet
// campaigns) was removed. The prototype collector authenticates every
// caller with one shared bearer key and trusts self-reported hostIds,
// so anything it returns is trivially poisonable and must never flow
// back into endpoint state.

import CryptoKit
import Foundation
import os.log

/// Outbound-only fleet telemetry client.
///
/// Push: batches local alerts and IOC sightings, sends to collector every 60s.
public actor FleetClient {

    private let logger = Logger(subsystem: "com.maccrab", category: "fleet")

    /// Fleet collector base URL.
    private let collectorURL: URL

    /// API key for authentication.
    private let apiKey: String

    /// Pseudonymous host ID.
    private let hostId: String

    /// Buffered alerts for next push.
    private var pendingAlerts: [FleetAlertSummary] = []
    private var pendingIOCs: [FleetIOCSighting] = []

    /// Push interval (default: 60 seconds).
    private let pushInterval: TimeInterval

    /// Whether the client is active.
    private var isRunning = false

    /// Consecutive push failures (for exponential backoff).
    private var consecutivePushFailures: Int = 0

    /// Maximum backoff interval (5 minutes).
    private let maxBackoffInterval: TimeInterval = 300

    // MARK: - Initialization

    public init?(pushInterval: TimeInterval = 60) {
        // Read config from environment
        guard let urlString = Foundation.ProcessInfo.processInfo.environment["MACCRAB_FLEET_URL"],
              let url = URL(string: urlString) else {
            return nil
        }

        // v1.21.5: enforce transport security. Pushes carry a bearer key
        // plus alert summaries, so accept https to any host, or plaintext
        // http only to a loopback host (dev collector). Mirrors
        // OllamaBackend.isPlaintextRemote: LoopbackEndpoint parses the
        // host as an IP literal, so `127.0.0.1.evil.com` is remote.
        let scheme = url.scheme?.lowercased()
        let isLoopbackHTTP = scheme == "http" && LoopbackEndpoint.isLoopback(host: url.host ?? "")
        guard scheme == "https" || isLoopbackHTTP else {
            // Instance stored properties aren't initialized yet in a
            // failable init, so use a local logger.
            Logger(subsystem: "com.maccrab", category: "fleet")
                .warning("Refusing MACCRAB_FLEET_URL (scheme \(scheme ?? "?", privacy: .public), host \(url.host ?? "?", privacy: .public)): only https://, or http:// to a loopback host, is accepted. Fleet client disabled.")
            return nil
        }

        self.collectorURL = url
        self.apiKey = Foundation.ProcessInfo.processInfo.environment["MACCRAB_FLEET_KEY"] ?? ""
        self.pushInterval = pushInterval

        // Generate pseudonymous host ID
        let hostname = Foundation.ProcessInfo.processInfo.hostName
        let hwUUID = Self.hardwareUUID() ?? UUID().uuidString
        self.hostId = Self.sha256("\(hostname):\(hwUUID)")
    }

    // MARK: - Public API

    /// Start the fleet client (push-only).
    public func start() {
        self.isRunning = true

        // Push task with exponential backoff on failure
        Task {
            while isRunning {
                let interval = pushBackoffInterval()
                try? await Task.sleep(nanoseconds: UInt64(interval * 1_000_000_000))
                guard isRunning else { break }
                await push()
            }
        }

        logger.info("Fleet client started (outbound-only): \(self.collectorURL.absoluteString)")
    }

    public func stop() {
        isRunning = false
    }

    /// Buffer an alert for the next push cycle.
    public func bufferAlert(_ summary: FleetAlertSummary) {
        pendingAlerts.append(summary)
        // Cap buffer
        if pendingAlerts.count > 1000 { pendingAlerts.removeFirst(500) }
    }

    /// Buffer an IOC sighting for the next push cycle.
    public func bufferIOC(_ sighting: FleetIOCSighting) {
        pendingIOCs.append(sighting)
        if pendingIOCs.count > 500 { pendingIOCs.removeFirst(250) }
    }

    // MARK: - Push

    private func push() async {
        guard !pendingAlerts.isEmpty || !pendingIOCs.isEmpty else { return }

        let telemetry = FleetTelemetry(
            hostId: hostId,
            timestamp: Date(),
            version: "0.5.0",
            alerts: pendingAlerts,
            iocSightings: pendingIOCs,
            behaviorScores: [] // Populated by caller if needed
        )

        let url = collectorURL.appendingPathComponent("/api/telemetry")
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        if !apiKey.isEmpty {
            request.setValue("Bearer \(apiKey)", forHTTPHeaderField: "Authorization")
        }
        request.timeoutInterval = 15

        do {
            let encoder = JSONEncoder()
            encoder.dateEncodingStrategy = .iso8601
            request.httpBody = try encoder.encode(telemetry)

            let (_, response) = try await SecureURLSession.shared.data(for: request)
            if let http = response as? HTTPURLResponse, http.statusCode == 200 {
                let alertCount = pendingAlerts.count
                let iocCount = pendingIOCs.count
                pendingAlerts.removeAll()
                pendingIOCs.removeAll()
                consecutivePushFailures = 0
                logger.info("Fleet push: sent \(alertCount) alerts, \(iocCount) IOCs")
            } else {
                consecutivePushFailures += 1
                logger.warning("Fleet push failed: HTTP \((response as? HTTPURLResponse)?.statusCode ?? 0) (attempt \(self.consecutivePushFailures))")
            }
        } catch {
            consecutivePushFailures += 1
            logger.warning("Fleet push error: \(error.localizedDescription) (attempt \(self.consecutivePushFailures))")
        }
    }

    /// Calculate push interval with exponential backoff and jitter.
    /// Base interval doubles on each consecutive failure, capped at maxBackoffInterval.
    /// Random jitter (0-25%) prevents thundering herd when many nodes recover.
    private func pushBackoffInterval() -> TimeInterval {
        guard consecutivePushFailures > 0 else { return pushInterval }
        let exponential = pushInterval * pow(2.0, Double(min(consecutivePushFailures, 8)))
        let capped = min(exponential, maxBackoffInterval)
        let jitter = capped * Double.random(in: 0...0.25)
        return capped + jitter
    }

    // MARK: - Utilities

    private static func hardwareUUID() -> String? {
        guard let result = BoundedPrivilegedProcessRunner.run(
            executable: "/usr/sbin/ioreg",
            arguments: ["-rd1", "-c", "IOPlatformExpertDevice"],
            timeout: 5,
            maximumOutputBytes: 1 * 1_024 * 1_024,
            mergeStandardErrorIntoOutput: false
        ), result.succeeded else { return nil }
        let output = String(data: result.output, encoding: .utf8) ?? ""
        // Extract IOPlatformUUID
        if let range = output.range(of: "IOPlatformUUID\" = \"") {
            let start = range.upperBound
            if let end = output[start...].firstIndex(of: "\"") {
                return String(output[start..<end])
            }
        }
        return nil
    }

    private static func sha256(_ string: String) -> String {
        SHA256.hash(data: Data(string.utf8))
            .map { String(format: "%02x", $0) }
            .joined()
    }
}
