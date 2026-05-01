// StreamOutput.swift
// MacCrabCore
//
// HTTP-bulk sink for SIEMs that ingest line-delimited OCSF / ECS JSON:
// Splunk HEC and Elasticsearch Bulk API in v1. Both flavours share the
// same POST + retry plumbing; the Kind enum switches URL shape and body
// framing.
//
// Per-alert POST for simplicity. A batched variant (20 alerts per flush
// on a timer) is an obvious follow-up — the Output protocol's
// flush() hook is already in place.

import Foundation
import os.log

public actor StreamOutput: Output {

    // MARK: - Kind

    public enum Kind: String, Sendable, Codable, CaseIterable {
        case splunkHEC    = "splunk_hec"
        case elasticBulk  = "elastic_bulk"
        case datadogLogs  = "datadog_logs"
        case wazuhAPI     = "wazuh_api"

        public var displayName: String {
            switch self {
            case .splunkHEC:   return "Splunk HEC"
            case .elasticBulk: return "Elasticsearch Bulk"
            case .datadogLogs: return "Datadog Logs"
            case .wazuhAPI:    return "Wazuh Manager API"
            }
        }
    }

    // MARK: - Config

    public nonisolated let name: String
    private let kind: Kind
    private let url: URL
    private let token: String?
    private let indexName: String    // Elastic index / Splunk sourcetype
    private let session: URLSession
    private let retryCount: Int
    private let timeout: TimeInterval
    /// True when the configured `url` was rejected by `WebhookOutput.validate`
    /// — typically `http://`, RFC1918 / metadata IP without an explicit opt-in,
    /// or a non-HTTP scheme. `send` short-circuits to a logged drop so a
    /// misconfigured operator can't silently leak HEC tokens or alert content.
    private let policyRejected: Bool

    // MARK: - State

    private let logger = Logger(subsystem: "com.maccrab.output", category: "stream")
    private var stats = OutputStats()

    // MARK: - Init

    /// - Parameters:
    ///   - kind: Which upstream this stream targets.
    ///   - url: Fully-qualified endpoint URL. For Splunk HEC this is the
    ///     collector path (`https://.../services/collector`). For Elastic
    ///     Bulk this is `https://.../_bulk`.
    ///   - token: HEC token for Splunk, basic auth for Elastic, API key
    ///     for Datadog. Omit for unauthenticated endpoints.
    ///   - indexName: Elastic index (default `maccrab-alerts`) or Splunk
    ///     sourcetype (default `maccrab:alert`).
    ///   - retryCount: Retries per POST on transient 5xx / network fail.
    ///   - timeout: Per-request timeout in seconds.
    public init(
        kind: Kind,
        url: URL,
        token: String?,
        indexName: String? = nil,
        retryCount: Int = 2,
        timeout: TimeInterval = 10
    ) {
        // v1.8.0: validate the URL through the same policy used by
        // WebhookOutput. Block plaintext http:// (except loopback),
        // metadata addresses (169.254.169.254 / EC2 / GCP), and
        // RFC1918 unless explicitly opted in. A misconfigured Splunk
        // HEC / Elastic Bulk / Datadog endpoint pointing at http://
        // would otherwise leak the bearer token in plaintext.
        //
        // The previous `try?` swallowed validation errors — TLS floor was
        // still enforced by SecureURLSession, but the private-IP /
        // metadata-address policy was effectively dead. Now we capture
        // the result; `send()` checks `policyRejected` and refuses.
        var rejected = false
        do {
            try WebhookOutput.validate(
                url: url,
                allowPrivate: Foundation.ProcessInfo.processInfo.environment["MACCRAB_STREAM_ALLOW_PRIVATE"] == "1"
            )
        } catch {
            Logger(subsystem: "com.maccrab.output", category: "stream")
                .error("StreamOutput URL rejected by SSRF policy: \(error.localizedDescription, privacy: .public)")
            rejected = true
        }
        self.policyRejected = rejected
        self.kind = kind
        self.name = kind.rawValue
        self.url = url
        self.token = token
        self.indexName = indexName ?? Self.defaultIndexName(for: kind)
        self.retryCount = retryCount
        self.timeout = timeout

        // v1.8.0: route through SecureURLSession so the TLS minimum is
        // pinned to TLS 1.2+ and we get the same scheme/private-IP
        // discipline as WebhookOutput. Pre-fix, this used a bare
        // `URLSessionConfiguration.ephemeral` with no `tlsMinimumSupportedProtocolVersion`
        // and no scheme check — a misconfigured `http://siem.local/_bulk`
        // would silently exfiltrate the HEC token + alert content in
        // cleartext.
        self.session = SecureURLSession.makeGeneric(
            timeout: timeout,
            retryBudgetFactor: retryCount + 1
        )
    }

    // MARK: - Output protocol

    public func send(alert: Alert, event: Event?) async {
        if policyRejected {
            stats.dropped += 1
            return
        }
        guard let body = buildBody(alert: alert, event: event) else {
            stats.dropped += 1
            return
        }
        await post(body: body)
    }

    public func outputStats() async -> OutputStats { stats }

    // MARK: - Body framing

    // Internal (not private) so unit tests can verify framing without
    // standing up an HTTP server.
    func buildBody(alert: Alert, event: Event?) -> Data? {
        let finding = OCSFMapper.mapAlert(alert, event: event)

        switch kind {
        case .splunkHEC:
            // Splunk HEC envelope:  {"time": <epoch>, "sourcetype": "...", "event": {...}}
            guard let findingJSON = try? OCSFMapper.encodeJSON(finding),
                  let findingObject = try? JSONSerialization.jsonObject(
                    with: Data(findingJSON.utf8)
                  ) else {
                return nil
            }
            let envelope: [String: Any] = [
                "time": alert.timestamp.timeIntervalSince1970,
                "sourcetype": indexName,
                "event": findingObject,
            ]
            return try? JSONSerialization.data(
                withJSONObject: envelope, options: []
            )

        case .elasticBulk:
            // Bulk API body is NDJSON pairs. For a single doc:
            //   {"index": {"_index": "..."}}\n{actual doc}\n
            guard let docJSON = try? OCSFMapper.encodeJSON(finding) else {
                return nil
            }
            let action = "{\"index\":{\"_index\":\"\(indexName)\"}}\n"
            let bulk = action + docJSON + "\n"
            return bulk.data(using: .utf8)

        case .datadogLogs:
            // Datadog Logs API accepts a JSON array. One-element array
            // per alert keeps the signature stable.
            guard let findingJSON = try? OCSFMapper.encodeJSON(finding),
                  let findingObject = try? JSONSerialization.jsonObject(
                    with: Data(findingJSON.utf8)
                  ) else {
                return nil
            }
            let envelope: [[String: Any]] = [[
                "ddsource": "maccrab",
                "service": "maccrab",
                "ddtags": "env:prod,product:maccrab",
                "message": findingObject,
            ]]
            return try? JSONSerialization.data(
                withJSONObject: envelope, options: []
            )

        case .wazuhAPI:
            // Wazuh Manager `/events` endpoint: {"events": ["<raw JSON>"]}
            // Each event is a stringified JSON payload. Single-alert
            // framing keeps the plumbing simple; bulk is a v2.2 concern.
            guard let findingJSON = try? OCSFMapper.encodeJSON(finding) else {
                return nil
            }
            let envelope: [String: Any] = [
                "events": [findingJSON],
            ]
            return try? JSONSerialization.data(
                withJSONObject: envelope, options: []
            )
        }
    }

    // MARK: - POST with retry

    private func post(body: Data) async {
        var attempt = 0
        while attempt <= retryCount {
            var request = URLRequest(url: url)
            request.httpMethod = "POST"
            request.httpBody = body
            request.setValue(contentType, forHTTPHeaderField: "Content-Type")
            if let header = authHeader(for: kind, token: token) {
                request.setValue(header.value, forHTTPHeaderField: header.key)
            }

            do {
                let (_, resp) = try await session.data(for: request)
                if let http = resp as? HTTPURLResponse {
                    if (200...299).contains(http.statusCode) {
                        stats.sent += 1
                        stats.lastSentAt = Date()
                        return
                    }
                    // Non-transient 4xx → don't retry.
                    if (400...499).contains(http.statusCode) {
                        stats.failed += 1
                        stats.lastError = "HTTP \(http.statusCode) (non-retryable)"
                        logger.warning("\(self.name) got HTTP \(http.statusCode), not retrying")
                        return
                    }
                    // 5xx and others fall through to retry.
                }
            } catch {
                stats.lastError = error.localizedDescription
            }
            attempt += 1
            if attempt <= retryCount {
                let backoff = pow(2.0, Double(attempt)) * 0.5
                try? await Task.sleep(nanoseconds: UInt64(backoff * 1_000_000_000))
            }
        }
        stats.failed += 1
        logger.error("\(self.name) exhausted retries")
    }

    // MARK: - Helpers

    private var contentType: String {
        switch kind {
        case .splunkHEC, .datadogLogs, .wazuhAPI: return "application/json"
        case .elasticBulk:                         return "application/x-ndjson"
        }
    }

    private func authHeader(for kind: Kind, token: String?) -> (key: String, value: String)? {
        guard let token, !token.isEmpty else { return nil }
        switch kind {
        case .splunkHEC:
            return ("Authorization", "Splunk \(token)")
        case .elasticBulk:
            // Elastic supports basic auth or ApiKey. Expect the caller to
            // pass "ApiKey base64token" or "Basic base64token" — we pass
            // it straight through.
            return ("Authorization", token)
        case .datadogLogs:
            return ("DD-API-KEY", token)
        case .wazuhAPI:
            // Wazuh Manager API uses JWT bearer tokens obtained from
            // /security/user/authenticate. The caller passes the JWT
            // directly in tokenEnv.
            return ("Authorization", "Bearer \(token)")
        }
    }

    private static func defaultIndexName(for kind: Kind) -> String {
        switch kind {
        case .splunkHEC:   return "maccrab:alert"
        case .elasticBulk: return "maccrab-alerts"
        case .datadogLogs: return "maccrab"
        case .wazuhAPI:    return "maccrab"
        }
    }
}
