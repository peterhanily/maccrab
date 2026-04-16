// S3Output.swift
// MacCrabCore
//
// Upload batched NDJSON alerts to an Amazon S3 (or compatible) bucket
// via a hand-rolled SigV4 signer — no AWS SDK dependency. Objects land
// at `s3://bucket/prefix/YYYY/MM/DD/HH/<uuid>.jsonl`, date-partitioned
// for downstream Athena / Snowflake / Security Lake ingest.
//
// Batching strategy: every alert is appended to an in-memory buffer.
// A PUT is issued when the buffer reaches `maxBatchBytes` OR when
// `flush()` is called (daemon shutdown, periodic timer). Keeps PUT
// cost low — S3 charges per-PUT, not per-byte.

import Foundation
import os.log

public actor S3Output: Output {

    // MARK: - Config

    public nonisolated let name = "s3"
    private let bucket: String
    private let region: String
    private let keyPrefix: String
    private let accessKey: String
    private let secretKey: String
    private let sessionToken: String?
    private let endpoint: URL          // default https://<bucket>.s3.<region>.amazonaws.com/
    private let maxBatchBytes: Int
    private let session: URLSession

    // MARK: - State

    private let logger = Logger(subsystem: "com.maccrab.output", category: "s3")
    private var buffer: Data = Data()
    private var bufferedCount: Int = 0
    private var stats = OutputStats()

    // MARK: - Init

    /// - Parameters:
    ///   - bucket: S3 bucket name.
    ///   - region: AWS region, e.g. "us-east-1".
    ///   - accessKey: AWS access-key id.
    ///   - secretKey: AWS secret-access key.
    ///   - keyPrefix: Prefix for uploaded keys. Default "maccrab/alerts".
    ///   - endpoint: Optional custom S3-compatible endpoint (MinIO, R2,
    ///     etc.). Defaults to `https://<bucket>.s3.<region>.amazonaws.com`.
    ///   - sessionToken: Optional STS session token for temporary creds.
    ///   - maxBatchBytes: Flush threshold. Default 1 MB.
    public init(
        bucket: String,
        region: String,
        accessKey: String,
        secretKey: String,
        keyPrefix: String = "maccrab/alerts",
        endpoint: URL? = nil,
        sessionToken: String? = nil,
        maxBatchBytes: Int = 1_048_576
    ) {
        self.bucket = bucket
        self.region = region
        self.accessKey = accessKey
        self.secretKey = secretKey
        self.sessionToken = sessionToken
        self.keyPrefix = keyPrefix
        self.maxBatchBytes = maxBatchBytes
        if let endpoint {
            self.endpoint = endpoint
        } else {
            self.endpoint = URL(
                string: "https://\(bucket).s3.\(region).amazonaws.com"
            )!
        }
        let config = URLSessionConfiguration.ephemeral
        config.timeoutIntervalForRequest = 30
        self.session = URLSession(configuration: config)
    }

    // MARK: - Output

    public func send(alert: Alert, event: Event?) async {
        let finding = OCSFMapper.mapAlert(alert, event: event)
        guard let json = try? OCSFMapper.encodeJSON(finding) else {
            stats.dropped += 1
            return
        }
        buffer.append(Data((json + "\n").utf8))
        bufferedCount += 1
        if buffer.count >= maxBatchBytes {
            await flushBuffer()
        }
    }

    public func flush() async {
        await flushBuffer()
    }

    public func outputStats() async -> OutputStats { stats }

    // MARK: - Private

    private func flushBuffer() async {
        guard !buffer.isEmpty else { return }
        let payload = buffer
        let count = bufferedCount
        buffer.removeAll(keepingCapacity: true)
        bufferedCount = 0

        let key = dateStampedKey()
        let url = endpoint.appendingPathComponent(key)

        let signed = SigV4Signer.sign(
            method: "PUT",
            url: url,
            headers: ["Content-Type": "application/x-ndjson"],
            body: payload,
            region: region,
            service: "s3",
            accessKey: accessKey,
            secretKey: secretKey,
            sessionToken: sessionToken
        )

        var request = URLRequest(url: url)
        request.httpMethod = "PUT"
        request.httpBody = payload
        for (k, v) in signed.headers {
            request.setValue(v, forHTTPHeaderField: k)
        }

        do {
            let (_, resp) = try await session.data(for: request)
            if let http = resp as? HTTPURLResponse,
               (200...299).contains(http.statusCode) {
                stats.sent += count
                stats.lastSentAt = Date()
            } else {
                stats.failed += count
                if let http = resp as? HTTPURLResponse {
                    stats.lastError = "HTTP \(http.statusCode)"
                }
            }
        } catch {
            stats.failed += count
            stats.lastError = error.localizedDescription
            logger.error("S3 PUT failed: \(error.localizedDescription)")
        }
    }

    /// `maccrab/alerts/2026/04/16/13/<uuid>.jsonl` — partitioned by
    /// Y/M/D/H so downstream queries can prune aggressively.
    private func dateStampedKey() -> String {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withFullDate, .withFullTime, .withTimeZone]
        let now = Date()
        let cal = Calendar(identifier: .gregorian)
        let comps = cal.dateComponents(in: TimeZone(identifier: "UTC")!, from: now)
        let y = comps.year ?? 2026
        let m = String(format: "%02d", comps.month ?? 1)
        let d = String(format: "%02d", comps.day ?? 1)
        let h = String(format: "%02d", comps.hour ?? 0)
        return "\(keyPrefix)/\(y)/\(m)/\(d)/\(h)/\(UUID().uuidString).jsonl"
    }
}
