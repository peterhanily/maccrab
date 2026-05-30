// WebhookOutput.swift
// MacCrabCore
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
        subsystem: "com.maccrab.output",
        category: "WebhookOutput"
    )

    /// ISO 8601 formatter used for all timestamp fields in the JSON payload.
    private static let iso8601Formatter: ISO8601DateFormatter = {
        let fmt = ISO8601DateFormatter()
        fmt.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return fmt
    }()

    // MARK: - URL Validation

    /// Reasons a webhook URL may be rejected.
    public enum ValidationError: Error, CustomStringConvertible {
        case missingScheme
        case invalidScheme(String)
        case missingHost
        case privateHostNotAllowed(String)
        case metadataAddressBlocked(String)
        case unresolvable(String)

        public var description: String {
            switch self {
            case .missingScheme:
                return "Webhook URL must include a scheme (https://...)"
            case .invalidScheme(let s):
                return "Webhook URL scheme must be 'https' (or 'http' for localhost); got '\(s)'"
            case .missingHost:
                return "Webhook URL must include a host"
            case .privateHostNotAllowed(let h):
                return "Webhook URL points at private address '\(h)' — set MACCRAB_WEBHOOK_ALLOW_PRIVATE=1 to override"
            case .metadataAddressBlocked(let h):
                return "Webhook URL points at cloud metadata address '\(h)' — blocked unconditionally (SSRF)"
            case .unresolvable(let h):
                return "Webhook host '\(h)' could not be resolved within the timeout — blocked (fail-closed SSRF redirect guard)"
            }
        }
    }

    /// Validate a webhook URL against policy before construction.
    ///
    /// Policy:
    /// - Require `https` scheme. `http` is accepted only for loopback hosts.
    /// - Reject empty / missing host.
    /// - Reject cloud metadata IPs (169.254.169.254 AWS/GCP/Azure, fd00:ec2::254 AWS IPv6) unconditionally.
    /// - Reject RFC1918 / link-local / unique-local addresses unless `allowPrivate` is true.
    ///
    /// - Parameters:
    ///   - url: The URL to validate.
    ///   - allowPrivate: Set from `MACCRAB_WEBHOOK_ALLOW_PRIVATE=1` for intranet webhooks.
    ///   - resolve: When true, resolve the host to its IP(s) and apply the
    ///     private/metadata range check to each resolved address — closes the
    ///     gap where a DNS name resolving into RFC1918 / link-local / metadata
    ///     space would pass the IP-literal-only check. Used by the redirect
    ///     SSRF guard (`SecureURLSession`), which fails closed if resolution
    ///     fails or times out. Default is `false` so config-time validation of
    ///     a not-yet-resolvable public hostname is not blocked at startup.
    /// - Throws: `ValidationError` describing the specific failure.
    public static func validate(url: URL, allowPrivate: Bool = false, resolve: Bool = false) throws {
        guard let scheme = url.scheme?.lowercased() else {
            throw ValidationError.missingScheme
        }
        guard let host = url.host, !host.isEmpty else {
            throw ValidationError.missingHost
        }

        let isLoopbackHost = (host == "localhost" || host == "127.0.0.1" || host == "::1" || host == "[::1]")

        switch scheme {
        case "https":
            break
        case "http":
            guard isLoopbackHost else {
                throw ValidationError.invalidScheme(scheme)
            }
        default:
            throw ValidationError.invalidScheme(scheme)
        }

        // Metadata addresses are blocked regardless of allowPrivate.
        // v1.11.0 (audit security MEDIUM): extended to cover Azure
        // IMDSv2 IPv6 brackets, OCI's metadata IP, IBM Cloud's host,
        // and the all-zeroes literals (route to localhost on most
        // OSes). Alibaba is caught via the RFC1918 path below.
        let blockedMetadata: Set<String> = [
            "169.254.169.254",            // AWS / GCP / Azure / Hetzner / OCI v1
            "fd00:ec2::254",              // AWS IMDS IPv6
            "[fd00:ec2::254]",            // AWS IMDS IPv6 with brackets (Azure-style)
            "100.100.100.200",            // Alibaba ECS
            "192.0.0.192",                // OCI v2
            "metadata.softlayer.com",     // IBM Cloud (DNS host)
            "metadata.google.internal",   // GCP DNS host
            "0.0.0.0", "[::]", "::",      // any-addr → routes to localhost
        ]
        if blockedMetadata.contains(host) || blockedMetadata.contains(host.lowercased()) {
            throw ValidationError.metadataAddressBlocked(host)
        }

        if !allowPrivate && !isLoopbackHost && isPrivateAddressLiteral(host) {
            throw ValidationError.privateHostNotAllowed(host)
        }

        // Resolve-then-validate (redirect SSRF guard). The literal check above
        // misses a DNS name that resolves into private / metadata space, so the
        // redirect path passes resolve=true: resolve the host and re-apply the
        // range check to every returned IP. Metadata IP literals stay blocked
        // even when allowPrivate is set. Loopback hosts are already exempt.
        if resolve && !isLoopbackHost {
            let resolved: [String]
            do {
                resolved = try resolveHostBounded(host)
            } catch {
                // Fail OPEN on resolve failure: a host that doesn't resolve is
                // unreachable, so it carries no SSRF risk — the protection here
                // is blocking hosts that DO resolve into private/metadata space
                // (metadata IP literals are already blocked above, before this).
                // Failing closed would also drop legitimate webhooks during a
                // transient DNS outage. Let URLSession attempt (and fail) the
                // connection itself.
                return
            }
            // 169.254.169.254 etc. — the IP-literal subset of blockedMetadata,
            // matched against resolved addresses regardless of allowPrivate.
            let metadataIPs: Set<String> = [
                "169.254.169.254", "fd00:ec2::254",
                "100.100.100.200", "192.0.0.192",
            ]
            for ip in resolved {
                if metadataIPs.contains(ip) {
                    throw ValidationError.metadataAddressBlocked(host)
                }
                if !allowPrivate && isPrivateAddressLiteral(ip) {
                    throw ValidationError.privateHostNotAllowed(host)
                }
            }
        }
    }

    /// Resolves `host` to its numeric IP strings, bounded by a wall-clock
    /// timeout so a slow / hung resolver cannot stall the redirect hot path.
    ///
    /// `getaddrinfo` is blocking and has no native timeout, so it runs on a
    /// detached thread and the caller waits on a semaphore. On timeout the
    /// thread is abandoned (it finishes and exits on its own); the caller
    /// throws so the redirect guard fails closed. Returns numeric host strings
    /// suitable for `isPrivateAddressLiteral`.
    private static func resolveHostBounded(_ host: String, timeout: TimeInterval = 2.0) throws -> [String] {
        let box = ResolveBox()
        let done = DispatchSemaphore(value: 0)
        Thread.detachNewThread {
            box.set(Self.resolveHostBlocking(host))
            done.signal()
        }
        guard done.wait(timeout: .now() + timeout) == .success else {
            throw ResolveError.timedOut
        }
        let addrs = box.get()
        guard !addrs.isEmpty else { throw ResolveError.failed }
        return addrs
    }

    /// Synchronous `getaddrinfo` wrapper. Returns numeric host strings for every
    /// A / AAAA record; empty on failure.
    private static func resolveHostBlocking(_ host: String) -> [String] {
        var hints = addrinfo()
        hints.ai_family = AF_UNSPEC
        hints.ai_socktype = SOCK_STREAM
        var result: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(host, nil, &hints, &result) == 0, let head = result else {
            return []
        }
        defer { freeaddrinfo(result) }
        var out: [String] = []
        var node: UnsafeMutablePointer<addrinfo>? = head
        var buf = [CChar](repeating: 0, count: Int(NI_MAXHOST))
        while let n = node {
            if getnameinfo(
                n.pointee.ai_addr, n.pointee.ai_addrlen,
                &buf, socklen_t(buf.count),
                nil, 0,
                NI_NUMERICHOST
            ) == 0 {
                out.append(String(cString: buf))
            }
            node = n.pointee.ai_next
        }
        return out
    }

    /// Thread-safe single-writer/single-reader box for handing the resolved
    /// addresses back from the detached resolver thread.
    private final class ResolveBox: @unchecked Sendable {
        private let lock = NSLock()
        private var value: [String] = []
        func set(_ v: [String]) { lock.lock(); value = v; lock.unlock() }
        func get() -> [String] { lock.lock(); defer { lock.unlock() }; return value }
    }

    private enum ResolveError: Error { case timedOut, failed }

    /// Best-effort detection of RFC1918 / link-local / unique-local IP literals.
    /// Hostnames (DNS names) pass through — DNS rebinding is out of scope here.
    private static func isPrivateAddressLiteral(_ host: String) -> Bool {
        // Strip IPv6 brackets if present.
        let h = host.hasPrefix("[") && host.hasSuffix("]")
            ? String(host.dropFirst().dropLast())
            : host

        // IPv4 RFC1918 + link-local
        let ipv4Parts = h.split(separator: ".")
        if ipv4Parts.count == 4, let a = UInt8(ipv4Parts[0]), let b = UInt8(ipv4Parts[1]) {
            if a == 10 { return true }                              // 10.0.0.0/8
            if a == 192 && b == 168 { return true }                 // 192.168.0.0/16
            if a == 172 && (16...31).contains(b) { return true }    // 172.16.0.0/12
            if a == 169 && b == 254 { return true }                 // 169.254.0.0/16 link-local
        }

        // IPv6 unique-local (fc00::/7) and link-local (fe80::/10)
        let lower = h.lowercased()
        if lower.hasPrefix("fc") || lower.hasPrefix("fd") || lower.hasPrefix("fe8") ||
           lower.hasPrefix("fe9") || lower.hasPrefix("fea") || lower.hasPrefix("feb") {
            if lower.contains(":") { return true }
        }

        return false
    }

    // MARK: Initialization

    /// Creates a webhook output configured for the given endpoint.
    ///
    /// Callers should prefer `WebhookOutput.validate(url:allowPrivate:)` before
    /// construction to reject SSRF-prone URLs early with a specific error.
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

        // Use the hardened generic factory so webhook connections inherit the
        // same TLS 1.2+ floor and persistent-state scrubbing as our LLM /
        // threat-intel sessions. Pinning doesn't apply here (user-supplied
        // host), but everything else does.
        self.session = SecureURLSession.makeGeneric(
            timeout: timeout,
            retryBudgetFactor: retryCount + 1
        )
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
            "source": "maccrab",
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
        request.setValue("MacCrab/\(MacCrabVersion.current)", forHTTPHeaderField: "User-Agent")
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

    /// Returns the configured hostname for outbound webhook payloads.
    /// v1.12.0 RC25 (privacy): default redacts the system hostname to
    /// "maccrab-host" because webhook destinations are frequently
    /// third-party SIEMs / log aggregators that don't need to know the
    /// org's host naming convention. Operators who want their real
    /// hostname (e.g., on internal-only ELK) set `MACCRAB_WEBHOOK_HOSTNAME=$(hostname)`
    /// at daemon startup. Anything containing path-separators or
    /// non-printable bytes is rejected to keep the JSON output clean.
    private static func hostname() -> String {
        if let override = Foundation.ProcessInfo.processInfo.environment["MACCRAB_WEBHOOK_HOSTNAME"],
           !override.isEmpty,
           !override.contains("/"),
           override.allSatisfy({ $0.isASCII && !$0.isNewline }) {
            return override
        }
        return "maccrab-host"
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
