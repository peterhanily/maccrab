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

    /// Buffered telemetry carries stable local sequence numbers. HTTP success
    /// removes only the exact entries represented by that request, even if the
    /// bounded queue shed older entries or accepted new ones while awaiting.
    private struct BufferedAlert: Sendable {
        let sequence: UInt64
        let value: FleetAlertSummary
    }
    private struct BufferedIOC: Sendable {
        let sequence: UInt64
        let value: FleetIOCSighting
    }
    private var nextBufferSequence: UInt64 = 0
    private var pendingAlerts: [BufferedAlert] = []
    private var pendingIOCs: [BufferedIOC] = []

    /// Push interval (default: 60 seconds).
    private let pushInterval: TimeInterval

    /// Whether the client is active.
    private var isRunning = false
    private var pushTask: Task<Void, Never>?
    private var lifecyclePhase: CollectorLifecyclePhase = .initialized
    private var shutdownTask: Task<Bool, Never>?

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
    @discardableResult
    public func start() -> Bool {
        if lifecyclePhase == .running { return true }
        guard lifecyclePhase == .initialized, pushTask == nil else {
            return false
        }
        lifecyclePhase = .running
        self.isRunning = true

        // Push task with exponential backoff on failure
        pushTask = Task { [weak self] in
            await self?.runPushLoop()
            await self?.finishPushLoop()
        }

        logger.info("Fleet client started (outbound-only): \(self.collectorURL.absoluteString)")
        return true
    }

    private func runPushLoop() async {
        while lifecyclePhase == .running,
              isRunning,
              !Task.isCancelled {
            let interval = pushBackoffInterval()
            do {
                try await Task.sleep(
                    nanoseconds: UInt64(interval * 1_000_000_000)
                )
            } catch {
                break
            }
            guard lifecyclePhase == .running,
                  isRunning,
                  !Task.isCancelled else { break }
            await push()
        }
    }

    private func finishPushLoop() {
        guard lifecyclePhase == .running else { return }
        pushTask = nil
    }

    @discardableResult
    public func stop(deadline: TimeInterval = 1.0) async -> Bool {
        if let shutdownTask { return await shutdownTask.value }
        if lifecyclePhase == .stopped { return true }
        lifecyclePhase = .stopping
        isRunning = false
        let task = pushTask
        task?.cancel()
        let accepted = task.map { [$0] } ?? []
        let waiter = Task {
            await CollectorBoundedTaskJoin.waitForAll(
                accepted,
                deadline: deadline
            )
        }
        shutdownTask = waiter
        let joined = await waiter.value
        lifecyclePhase = .stopped
        if joined { pushTask = nil }
        return joined
    }

    /// Buffer an alert for the next push cycle.
    @discardableResult
    public func bufferAlert(_ summary: FleetAlertSummary) -> Bool {
        guard lifecyclePhase == .running, isRunning else { return false }
        nextBufferSequence &+= 1
        pendingAlerts.append(BufferedAlert(
            sequence: nextBufferSequence,
            value: summary
        ))
        // Cap buffer
        if pendingAlerts.count > 1000 { pendingAlerts.removeFirst(500) }
        return true
    }

    /// Buffer an IOC sighting for the next push cycle.
    @discardableResult
    public func bufferIOC(_ sighting: FleetIOCSighting) -> Bool {
        guard lifecyclePhase == .running, isRunning else { return false }
        nextBufferSequence &+= 1
        pendingIOCs.append(BufferedIOC(
            sequence: nextBufferSequence,
            value: sighting
        ))
        if pendingIOCs.count > 500 { pendingIOCs.removeFirst(250) }
        return true
    }

    // MARK: - Push

    private func push() async {
        guard lifecyclePhase == .running,
              isRunning,
              !Task.isCancelled else { return }
        guard !pendingAlerts.isEmpty || !pendingIOCs.isEmpty else { return }

        let alertsToSend = pendingAlerts
        let iocsToSend = pendingIOCs

        let telemetry = FleetTelemetry(
            hostId: hostId,
            timestamp: Date(),
            version: "0.5.0",
            alerts: alertsToSend.map(\.value),
            iocSightings: iocsToSend.map(\.value),
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
            guard lifecyclePhase == .running,
                  isRunning,
                  !Task.isCancelled else { return }
            if let http = response as? HTTPURLResponse, http.statusCode == 200 {
                // Remove only the sequence IDs represented by this request.
                // Telemetry buffered while HTTP was in flight belongs to the
                // next batch and must not be acknowledged accidentally.
                let sentAlertSequences = Set(
                    alertsToSend.map(\.sequence)
                )
                let sentIOCSequences = Set(
                    iocsToSend.map(\.sequence)
                )
                let alertCount = pendingAlerts.count
                pendingAlerts.removeAll {
                    sentAlertSequences.contains($0.sequence)
                }
                let acknowledgedAlerts = alertCount - pendingAlerts.count
                let iocCount = pendingIOCs.count
                pendingIOCs.removeAll {
                    sentIOCSequences.contains($0.sequence)
                }
                let acknowledgedIOCs = iocCount - pendingIOCs.count
                consecutivePushFailures = 0
                logger.info("Fleet push: acknowledged \(acknowledgedAlerts) alerts, \(acknowledgedIOCs) IOCs")
            } else {
                consecutivePushFailures += 1
                logger.warning("Fleet push failed: HTTP \((response as? HTTPURLResponse)?.statusCode ?? 0) (attempt \(self.consecutivePushFailures))")
            }
        } catch {
            guard lifecyclePhase == .running,
                  isRunning,
                  !Task.isCancelled else { return }
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
