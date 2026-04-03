// FleetClient.swift
// HawkEyeCore
//
// Pushes telemetry to and pulls aggregations from the fleet collector.
// Configured via HAWKEYE_FLEET_URL environment variable.

import Foundation
import os.log

/// Bidirectional fleet telemetry client.
///
/// Push: batches local alerts and IOC sightings, sends to collector every 60s.
/// Pull: fetches fleet-wide IOC aggregations every 5 minutes.
public actor FleetClient {

    private let logger = Logger(subsystem: "com.hawkeye", category: "fleet")

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

    /// Pull interval (default: 5 minutes).
    private let pullInterval: TimeInterval

    /// Whether the client is active.
    private var isRunning = false

    /// Last pulled aggregation.
    private var lastAggregation: FleetAggregation?

    /// Callback for processing pulled fleet data.
    public typealias FleetDataHandler = @Sendable (FleetAggregation) async -> Void
    private var dataHandler: FleetDataHandler?

    // MARK: - Initialization

    public init?(
        pushInterval: TimeInterval = 60,
        pullInterval: TimeInterval = 300
    ) {
        // Read config from environment
        guard let urlString = Foundation.ProcessInfo.processInfo.environment["HAWKEYE_FLEET_URL"],
              let url = URL(string: urlString) else {
            return nil
        }

        self.collectorURL = url
        self.apiKey = Foundation.ProcessInfo.processInfo.environment["HAWKEYE_FLEET_KEY"] ?? ""
        self.pushInterval = pushInterval
        self.pullInterval = pullInterval

        // Generate pseudonymous host ID
        let hostname = Foundation.ProcessInfo.processInfo.hostName
        let hwUUID = Self.hardwareUUID() ?? UUID().uuidString
        self.hostId = Self.sha256("\(hostname):\(hwUUID)")
    }

    // MARK: - Public API

    /// Start the fleet client with a handler for pulled fleet data.
    public func start(handler: @escaping FleetDataHandler) {
        self.dataHandler = handler
        self.isRunning = true

        // Push task
        Task {
            while isRunning {
                try? await Task.sleep(nanoseconds: UInt64(pushInterval * 1_000_000_000))
                guard isRunning else { break }
                await push()
            }
        }

        // Pull task
        Task {
            while isRunning {
                try? await Task.sleep(nanoseconds: UInt64(pullInterval * 1_000_000_000))
                guard isRunning else { break }
                await pull()
            }
        }

        logger.info("Fleet client started: \(self.collectorURL.absoluteString)")
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

    /// Get last pulled aggregation.
    public func getAggregation() -> FleetAggregation? {
        lastAggregation
    }

    // MARK: - Push

    private func push() async {
        guard !pendingAlerts.isEmpty || !pendingIOCs.isEmpty else { return }

        let telemetry = FleetTelemetry(
            hostId: hostId,
            timestamp: Date(),
            version: "0.3.0",
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

            let (_, response) = try await URLSession.shared.data(for: request)
            if let http = response as? HTTPURLResponse, http.statusCode == 200 {
                let alertCount = pendingAlerts.count
                let iocCount = pendingIOCs.count
                pendingAlerts.removeAll()
                pendingIOCs.removeAll()
                logger.info("Fleet push: sent \(alertCount) alerts, \(iocCount) IOCs")
            } else {
                logger.warning("Fleet push failed: HTTP \((response as? HTTPURLResponse)?.statusCode ?? 0)")
            }
        } catch {
            logger.warning("Fleet push error: \(error.localizedDescription)")
        }
    }

    // MARK: - Pull

    private func pull() async {
        let url = collectorURL.appendingPathComponent("/api/iocs")
        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        if !apiKey.isEmpty {
            request.setValue("Bearer \(apiKey)", forHTTPHeaderField: "Authorization")
        }
        request.timeoutInterval = 15

        do {
            let (data, response) = try await URLSession.shared.data(for: request)
            guard let http = response as? HTTPURLResponse, http.statusCode == 200 else { return }

            let decoder = JSONDecoder()
            decoder.dateDecodingStrategy = .iso8601
            let aggregation = try decoder.decode(FleetAggregation.self, from: data)
            lastAggregation = aggregation

            logger.info("Fleet pull: \(aggregation.iocs.count) IOCs, \(aggregation.hotProcesses.count) hot processes, fleet size: \(aggregation.fleetSize)")

            await dataHandler?(aggregation)
        } catch {
            // Silent failure for pull — collector may be unreachable
        }
    }

    // MARK: - Utilities

    private static func hardwareUUID() -> String? {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/sbin/ioreg")
        process.arguments = ["-rd1", "-c", "IOPlatformExpertDevice"]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = FileHandle.nullDevice
        try? process.run()
        process.waitUntilExit()
        let output = String(data: pipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
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
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/shasum")
        process.arguments = ["-a", "256"]
        let inputPipe = Pipe()
        let outputPipe = Pipe()
        process.standardInput = inputPipe
        process.standardOutput = outputPipe
        process.standardError = FileHandle.nullDevice
        try? process.run()
        inputPipe.fileHandleForWriting.write(string.data(using: .utf8)!)
        inputPipe.fileHandleForWriting.closeFile()
        process.waitUntilExit()
        let output = String(data: outputPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        return String(output.split(separator: " ").first ?? "unknown")
    }
}
