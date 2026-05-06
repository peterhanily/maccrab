// OTLPOutput.swift
// MacCrabCore
//
// OpenTelemetry Protocol (OTLP) HTTP/JSON output. Targets any OTLP-compatible
// collector — OTel Collector itself, Grafana Cloud, Honeycomb, Datadog (via
// OTLP ingest), Splunk Observability Cloud, etc.
//
// Why OTLP and not just-another-stream-format:
//   - It's the cross-vendor standard. One config wins all.
//   - Logs + Traces share a wire format — when v2.0 starts emitting trust
//     substrate trace data alongside alerts, the same sink handles both.
//   - Native severity + structured attributes mean the alert's MITRE
//     tactic / process signer / rule id arrive as queryable fields, not
//     buried in a free-text body.
//
// Wire format: OTLP/HTTP+JSON (https://opentelemetry.io/docs/specs/otlp/#otlphttp).
// We POST to {endpoint}/v1/logs with a ResourceLogs envelope. Protobuf
// transport is more compact but requires a code-generated runtime; for
// v1.8 the JSON path keeps the binary small and the code reviewable.

import Foundation
import os.log

public actor OTLPOutput: Output {

    // MARK: - Config

    public nonisolated let name = "otlp"
    private let endpoint: URL                  // e.g. https://otelcol.example.com
    private let apiKey: String?                // optional Authorization bearer
    private let serviceName: String
    private let hostName: String
    private let batchSize: Int
    private let flushIntervalSeconds: TimeInterval
    private let session: URLSession
    /// Mirrors StreamOutput / S3Output. When the configured endpoint fails
    /// the WebhookOutput SSRF gate (plaintext http:// to non-loopback,
    /// RFC1918 without opt-in, link-local 169.254.169.254 / metadata IPs),
    /// `send` short-circuits to a logged drop.
    private let policyRejected: Bool

    // MARK: - State

    private let logger = Logger(subsystem: "com.maccrab.output", category: "otlp")
    private var buffer: [(Alert, Event?)] = []
    private var stats = OutputStats()
    private var lastFlushAt = Date.distantPast

    // MARK: - Init

    /// - Parameters:
    ///   - endpoint: OTLP collector base URL. The "/v1/logs" path is appended
    ///     automatically — pass `https://otelcol.example.com`, not the full
    ///     receiver path. Custom collectors that mount OTLP at a non-default
    ///     path can pass the full URL; we only append "/v1/logs" when the
    ///     URL doesn't already end in it.
    ///   - apiKey: Optional bearer token for hosted collectors (Honeycomb,
    ///     Grafana Cloud, etc.). Sent verbatim in `Authorization: Bearer …`.
    ///   - serviceName: OTel resource attribute `service.name`. Defaults to
    ///     "maccrab"; override per-host if you want to fan out to a multi-
    ///     tenant collector.
    ///   - hostName: OTel resource attribute `host.name`. Defaults to the
    ///     macOS sysname (`uname -n`). Hostname can leak organization info
    ///     so allow override.
    ///   - batchSize: Alerts per POST. 50 is a good fit for OTLP/JSON
    ///     payloads (~30-50 KB) — small enough to stay under collector
    ///     defaults, big enough to amortize HTTP cost.
    ///   - flushIntervalSeconds: Max time before draining a partial batch.
    ///     Idle daemon → still ships every 5s when there's traffic.
    public init(
        endpoint: URL,
        apiKey: String? = nil,
        serviceName: String = "maccrab",
        hostName: String? = nil,
        batchSize: Int = 50,
        flushIntervalSeconds: TimeInterval = 5
    ) {
        self.endpoint = endpoint
        self.apiKey = apiKey
        self.serviceName = serviceName
        self.hostName = hostName ?? Self.defaultHostName()
        self.batchSize = batchSize
        self.flushIntervalSeconds = flushIntervalSeconds

        // SSRF policy: same gate as StreamOutput/S3Output. Captured into
        // `policyRejected` so `send` short-circuits — try? would silently
        // accept private IPs / cleartext.
        var rejected = false
        do {
            try WebhookOutput.validate(
                url: endpoint,
                allowPrivate: Foundation.ProcessInfo.processInfo.environment["MACCRAB_OTLP_ALLOW_PRIVATE"] == "1"
            )
        } catch {
            Logger(subsystem: "com.maccrab.output", category: "otlp")
                .error("OTLPOutput endpoint rejected by SSRF policy: \(error.localizedDescription, privacy: .public)")
            rejected = true
        }
        self.policyRejected = rejected

        // SecureURLSession pins TLS 1.2+ and disables cookie/credential
        // storage. The OTLP collector should always be HTTPS; the SSRF
        // gate above already rejects http:// for non-loopback hosts.
        self.session = SecureURLSession.makeGeneric(timeout: 15, retryBudgetFactor: 3)
    }

    // MARK: - Output protocol

    public func send(alert: Alert, event: Event?) async {
        if policyRejected {
            stats.dropped += 1
            return
        }
        buffer.append((alert, event))
        let due = Date().timeIntervalSince(lastFlushAt) >= flushIntervalSeconds
        if buffer.count >= batchSize || due {
            await flushBuffer()
        }
    }

    public func flush() async {
        if policyRejected { return }
        await flushBuffer()
    }

    public func outputStats() async -> OutputStats { stats }

    // MARK: - Private

    /// Hard ceiling per OTLP/HTTP POST body. Most collectors default to
    /// 4-10 MB; we stay well under that. Above this cap, the batch is
    /// recursively split — drop half, send half, retry the other half.
    /// Prevents a rule-storm carrying outsized investigations
    /// (llmInvestigation.evidenceChain can balloon to 5-10 MB per alert)
    /// from producing 500 MB POSTs that the collector would refuse.
    private static let maxEnvelopeBytes = 1_048_576   // 1 MB

    private func flushBuffer() async {
        guard !buffer.isEmpty else { return }
        let batch = buffer
        buffer.removeAll(keepingCapacity: true)
        lastFlushAt = Date()

        await sendBatch(batch)
    }

    /// Recursive batch splitter. Encodes once, checks size; if over the
    /// envelope cap, halves the batch and retries each half. Single-record
    /// batches that exceed the cap are dropped (logged) rather than split
    /// further — at that point the alert itself is malformed-large and
    /// rejecting it is the right call.
    private func sendBatch(_ batch: [(Alert, Event?)]) async {
        guard !batch.isEmpty else { return }

        guard let body = try? JSONSerialization.data(
            withJSONObject: buildEnvelope(for: batch),
            options: []
        ) else {
            stats.dropped += batch.count
            stats.lastError = "json encode failed"
            return
        }

        if body.count > Self.maxEnvelopeBytes {
            if batch.count == 1 {
                // A single alert that doesn't fit — drop it. Encoding a
                // truncated version would corrupt the OTLP envelope, and
                // splitting an already-singleton batch is a no-op loop.
                stats.dropped += 1
                stats.lastError = "single-alert envelope exceeded \(Self.maxEnvelopeBytes) byte cap"
                logger.warning("OTLP: dropped 1 oversize alert (\(body.count, privacy: .public) bytes)")
                return
            }
            let mid = batch.count / 2
            await sendBatch(Array(batch[..<mid]))
            await sendBatch(Array(batch[mid...]))
            return
        }

        await postEnvelope(body: body, recordCount: batch.count)
    }

    private func postEnvelope(body: Data, recordCount: Int) async {

        let url = endpoint.appendingPathComponentIfMissing("v1/logs")
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("MacCrab/\(MacCrabVersion.current)", forHTTPHeaderField: "User-Agent")
        if let apiKey {
            request.setValue("Bearer \(apiKey)", forHTTPHeaderField: "Authorization")
        }
        request.httpBody = body
        request.timeoutInterval = 15

        do {
            let (_, response) = try await session.data(for: request)
            if let http = response as? HTTPURLResponse, !(200..<300).contains(http.statusCode) {
                stats.failed += recordCount
                stats.lastError = "HTTP \(http.statusCode)"
                logger.warning("OTLP send returned \(http.statusCode, privacy: .public) for \(recordCount, privacy: .public) records")
                return
            }
            stats.sent += recordCount
            stats.lastSentAt = Date()
        } catch {
            stats.failed += recordCount
            stats.lastError = error.localizedDescription
            logger.warning("OTLP send failed: \(error.localizedDescription, privacy: .public)")
        }
    }

    /// Build the OTLP/HTTP ResourceLogs envelope for a batch. Single
    /// resource (this host) + a single InstrumentationScope ("MacCrab")
    /// + N LogRecord entries. Spec: https://opentelemetry.io/docs/specs/otlp/
    private func buildEnvelope(for batch: [(Alert, Event?)]) -> [String: Any] {
        let logRecords: [[String: Any]] = batch.map { (alert, event) in
            buildLogRecord(alert: alert, event: event)
        }
        return [
            "resourceLogs": [[
                "resource": [
                    "attributes": [
                        otelAttribute(key: "service.name", value: serviceName),
                        otelAttribute(key: "service.version", value: MacCrabVersion.current),
                        otelAttribute(key: "host.name", value: hostName),
                    ]
                ],
                "scopeLogs": [[
                    "scope": [
                        "name": "com.maccrab.detection",
                        "version": MacCrabVersion.current,
                    ],
                    "logRecords": logRecords,
                ]],
            ]],
        ]
    }

    private func buildLogRecord(alert: Alert, event: Event?) -> [String: Any] {
        // OTLP timestamps are nanoseconds since Unix epoch as strings (JSON
        // numbers can't represent the full int64 range).
        let unixNanos = Int64(alert.timestamp.timeIntervalSince1970 * 1_000_000_000)
        var attrs: [[String: Any]] = [
            otelAttribute(key: "rule.id", value: alert.ruleId),
            otelAttribute(key: "rule.title", value: alert.ruleTitle),
            otelAttribute(key: "alert.id", value: alert.id),
            otelAttribute(key: "alert.severity", value: alert.severity.rawValue),
        ]
        if let processName = alert.processName {
            attrs.append(otelAttribute(key: "process.name", value: processName))
        }
        if let processPath = alert.processPath {
            attrs.append(otelAttribute(key: "process.executable.path", value: processPath))
        }
        if let mitreTechniques = alert.mitreTechniques, !mitreTechniques.isEmpty {
            attrs.append(otelAttribute(key: "mitre.technique", value: mitreTechniques))
        }
        if let mitreTactics = alert.mitreTactics, !mitreTactics.isEmpty {
            attrs.append(otelAttribute(key: "mitre.tactic", value: mitreTactics))
        }
        if let event {
            attrs.append(otelAttribute(key: "event.category", value: event.eventCategory.rawValue))
            attrs.append(otelAttribute(key: "event.action", value: event.eventAction))
            if !event.process.commandLine.isEmpty {
                attrs.append(otelAttribute(key: "process.command_line", value: event.process.commandLine))
            }
            if let net = event.network {
                attrs.append(otelAttribute(key: "net.peer.ip", value: net.destinationIp))
                attrs.append(otelAttribute(key: "net.peer.port", value: Int(net.destinationPort)))
            }
        }

        return [
            "timeUnixNano": "\(unixNanos)",
            "observedTimeUnixNano": "\(unixNanos)",
            "severityNumber": Self.otelSeverityNumber(for: alert.severity),
            "severityText": alert.severity.rawValue.uppercased(),
            "body": ["stringValue": alert.description ?? alert.ruleTitle],
            "attributes": attrs,
        ]
    }

    /// Encode a (key, scalar value) pair as an OTLP `KeyValue`. OTLP's
    /// AnyValue is a oneof of {stringValue, intValue, doubleValue, …}; we
    /// match the type of `value` to the right branch.
    private func otelAttribute(key: String, value: Any) -> [String: Any] {
        let av: [String: Any]
        switch value {
        case let s as String:
            av = ["stringValue": s]
        case let i as Int:
            av = ["intValue": "\(i)"]   // OTLP carries int64s as strings
        case let i as Int64:
            av = ["intValue": "\(i)"]
        case let d as Double:
            av = ["doubleValue": d]
        case let b as Bool:
            av = ["boolValue": b]
        default:
            av = ["stringValue": "\(value)"]
        }
        return ["key": key, "value": av]
    }

    /// OTel severity numbers (https://opentelemetry.io/docs/specs/otel/logs/data-model/#field-severitynumber).
    /// Map MacCrab's 5-level scale onto the OTel 24-level scale at the
    /// "anchor" values per spec — TRACE=1, DEBUG=5, INFO=9, WARN=13,
    /// ERROR=17, FATAL=21.
    private static func otelSeverityNumber(for severity: Severity) -> Int {
        switch severity {
        case .informational: return 9   // INFO
        case .low:           return 13  // WARN
        case .medium:        return 13  // WARN
        case .high:          return 17  // ERROR
        case .critical:      return 21  // FATAL
        }
    }

    private static func defaultHostName() -> String {
        var nameBuffer = [CChar](repeating: 0, count: 256)
        guard gethostname(&nameBuffer, nameBuffer.count) == 0 else {
            return "maccrab-host"
        }
        return String(cString: nameBuffer)
    }
}

// MARK: - URL convenience

private extension URL {
    /// Append `path` to the URL only if the URL's existing path doesn't
    /// already end with it. Lets users pass either `https://collector` or
    /// `https://collector/v1/logs` and have it work.
    func appendingPathComponentIfMissing(_ path: String) -> URL {
        let trimmed = self.path.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        if trimmed.hasSuffix(path.trimmingCharacters(in: CharacterSet(charactersIn: "/"))) {
            return self
        }
        return self.appendingPathComponent(path)
    }
}
