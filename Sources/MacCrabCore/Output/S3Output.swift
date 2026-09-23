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
    /// True when the configured `endpoint` was rejected by `WebhookOutput.validate`.
    /// Both `send` and `flush` short-circuit so a misconfigured custom endpoint
    /// (`http://minio.internal/`) can't leak SigV4-signed payloads in cleartext.
    private let policyRejected: Bool

    // MARK: - State

    private let logger = Logger(subsystem: "com.maccrab.output", category: "s3")
    private var buffer: OutputBatchBuffer
    private var backoff = OutputRetryBackoff()
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
    ///   - maxRetainedBytes / maxRetainedRecords: Bound on the in-memory
    ///     batch, including batches retained after a failed PUT. Oldest
    ///     records are dropped first and counted in `OutputStats.dropped`.
    public init(
        bucket: String,
        region: String,
        accessKey: String,
        secretKey: String,
        keyPrefix: String = "maccrab/alerts",
        endpoint: URL? = nil,
        sessionToken: String? = nil,
        maxBatchBytes: Int = 1_048_576,
        maxRetainedBytes: Int = 8_388_608,
        maxRetainedRecords: Int = 10_000
    ) {
        self.bucket = bucket
        self.region = region
        self.accessKey = accessKey
        self.secretKey = secretKey
        self.sessionToken = sessionToken
        self.keyPrefix = keyPrefix
        self.maxBatchBytes = maxBatchBytes
        self.buffer = OutputBatchBuffer(
            maxRetainedBytes: maxRetainedBytes,
            maxRetainedRecords: maxRetainedRecords
        )
        if let endpoint {
            self.endpoint = endpoint
        } else {
            self.endpoint = URL(
                string: "https://\(bucket).s3.\(region).amazonaws.com"
            )!
        }
        // v1.8.0: validate endpoint through the same policy as WebhookOutput.
        // Custom endpoints (MinIO, Wasabi, Cloudflare R2 with self-signed)
        // could otherwise be `http://` and leak SigV4-signed credentials in
        // cleartext. Allow loopback http:// for local MinIO testing only.
        //
        // Captured (not swallowed via try?) so `send`/`flush` can refuse —
        // see `policyRejected` field doc.
        var rejected = false
        do {
            try WebhookOutput.validate(
                url: self.endpoint,
                allowPrivate: Foundation.ProcessInfo.processInfo.environment["MACCRAB_S3_ALLOW_PRIVATE"] == "1"
            )
        } catch {
            Logger(subsystem: "com.maccrab.output", category: "s3")
                .error("S3Output endpoint rejected by SSRF policy: \(error.localizedDescription, privacy: .public)")
            rejected = true
        }
        self.policyRejected = rejected
        // SecureURLSession pins TLS 1.2+ and disables cookie/credential storage.
        self.session = SecureURLSession.makeGeneric(timeout: 30, retryBudgetFactor: 3)
    }

    // MARK: - Output

    public func send(alert: Alert, event: Event?) async {
        if policyRejected {
            stats.dropped += 1
            return
        }
        let finding = OCSFMapper.mapAlert(alert, event: event)
        guard let json = try? OCSFMapper.encodeJSON(finding) else {
            stats.dropped += 1
            return
        }
        let overflow = buffer.append(line: Data((json + "\n").utf8))
        if overflow > 0 {
            stats.dropped += overflow
            logger.warning("S3 buffer cap reached; dropped \(overflow) oldest record(s)")
        }
        if buffer.data.count >= maxBatchBytes {
            await flushBuffer(now: Date())
        }
    }

    public func flush() async {
        if policyRejected { return }
        await flushBuffer(now: Date())
    }

    public func outputStats() async -> OutputStats { stats }

    /// Records currently buffered, including any batch retained after a
    /// failed PUT. Internal for tests.
    var bufferedRecordCount: Int { buffer.count }

    // MARK: - Private

    /// Internal so tests can drive the backoff deterministically. A failed
    /// PUT keeps its batch; the next attempt is gated by `backoff` so a
    /// size-triggered flush on every alert cannot hammer an unreachable
    /// bucket.
    func flushBuffer(now: Date) async {
        guard !buffer.isEmpty else { return }
        guard backoff.mayAttempt(now: now) else { return }
        let (payload, count) = buffer.take()

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
                stats.lastSentAt = now
                backoff.recordSuccess()
            } else {
                let detail = (resp as? HTTPURLResponse).map { "HTTP \($0.statusCode)" }
                recordFailure(payload: payload, count: count, detail: detail, now: now)
            }
        } catch {
            recordFailure(payload: payload, count: count, detail: error.localizedDescription, now: now)
            logger.error("S3 PUT failed: \(error.localizedDescription)")
        }
    }

    /// A failed PUT keeps its batch for the next flush. The retained batch
    /// goes back in front of anything buffered meanwhile (the `await` above
    /// lets `send` interleave); whatever no longer fits under the caps is
    /// dropped oldest-first and counted.
    private func recordFailure(payload: Data, count: Int, detail: String?, now: Date) {
        stats.failed += count
        if let detail { stats.lastError = detail }
        backoff.recordFailure(now: now)
        let overflow = buffer.retain(payload: payload, count: count)
        if overflow > 0 {
            stats.dropped += overflow
            logger.warning("S3 retained batch exceeded cap; dropped \(overflow) oldest record(s)")
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
