// SyslogOutput.swift
// HawkEyeCore
//
// Sends detection alerts to a syslog server via UDP or TCP using BSD sockets.
// Messages conform to RFC 5424 format with structured data for alert metadata.

#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif

import Foundation
import os.log

// MARK: - SyslogOutput

/// Delivers detection alerts to a remote syslog server over UDP or TCP.
///
/// Messages are formatted according to RFC 5424 with structured data elements
/// that carry the alert's rule ID and severity. The output uses BSD sockets
/// directly (`socket()`, `sendto()`, `connect()`/`send()`, `close()`) with no
/// external dependencies.
///
/// For UDP, each message is independently addressed via `sendto()`. For TCP, a
/// persistent connection is established with ``connect()`` and messages are
/// newline-delimited per the octet-counting / non-transparent-framing convention.
///
/// Thread-safe via Swift actor isolation.
public actor SyslogOutput {

    // MARK: Types

    /// Transport protocol for syslog delivery.
    public enum Transport: String, Sendable {
        case udp
        case tcp
    }

    // MARK: Properties

    /// Syslog server hostname or IP address.
    private let host: String

    /// Syslog server port (default 514).
    private let port: UInt16

    /// Transport protocol to use.
    private let transport: Transport

    /// Syslog facility code. Defaults to `LOG_LOCAL0` (16).
    private let facility: Int

    /// The BSD socket file descriptor, or -1 when not connected.
    private var socket: Int32 = -1

    /// Running count of successfully sent messages.
    private var sentCount: Int = 0

    /// Cached resolved socket address for the syslog server.
    private var resolvedAddr: Data?

    private let logger = Logger(
        subsystem: "com.hawkeye.output",
        category: "SyslogOutput"
    )

    /// ISO 8601 formatter for RFC 5424 timestamps.
    private static let iso8601Formatter: ISO8601DateFormatter = {
        let fmt = ISO8601DateFormatter()
        fmt.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return fmt
    }()

    // MARK: Initialization

    /// Creates a syslog output targeting the given server.
    ///
    /// - Parameters:
    ///   - host: Hostname or IP address of the syslog server.
    ///   - port: Port number (default 514).
    ///   - transport: `.udp` (default) or `.tcp`.
    public init(host: String, port: UInt16 = 514, transport: Transport = .udp) {
        self.host = host
        self.port = port
        self.transport = transport
        self.facility = 16  // LOG_LOCAL0
    }

    // MARK: - Public API

    /// Opens the socket and, for TCP, establishes the connection.
    ///
    /// For UDP this creates a datagram socket and resolves the server address.
    /// For TCP this creates a stream socket and connects to the server.
    ///
    /// - Throws: ``SyslogOutputError`` if socket creation, address resolution,
    ///   or connection fails.
    public func connect() throws {
        // Close any existing socket first.
        closeSocket()

        let resolved = try resolveAddress(host: host, port: port)

        switch transport {
        case .udp:
            let fd = Darwin.socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
            guard fd >= 0 else {
                throw SyslogOutputError.socketCreationFailed(errno: errno)
            }
            self.socket = fd
            self.resolvedAddr = resolved
            logger.info("Syslog UDP socket created for \(self.host, privacy: .public):\(self.port)")

        case .tcp:
            let fd = Darwin.socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)
            guard fd >= 0 else {
                throw SyslogOutputError.socketCreationFailed(errno: errno)
            }

            // Set TCP_NODELAY for low-latency delivery.
            var flag: Int32 = 1
            setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &flag, socklen_t(MemoryLayout<Int32>.size))

            let connectResult = resolved.withUnsafeBytes { buffer in
                let addrPtr = buffer.baseAddress!.assumingMemoryBound(to: sockaddr.self)
                return Darwin.connect(fd, addrPtr, socklen_t(resolved.count))
            }

            guard connectResult == 0 else {
                Darwin.close(fd)
                throw SyslogOutputError.connectionFailed(
                    host: host,
                    port: port,
                    errno: errno
                )
            }

            self.socket = fd
            self.resolvedAddr = resolved
            logger.info("Syslog TCP connected to \(self.host, privacy: .public):\(self.port)")
        }
    }

    /// Formats and sends an alert as an RFC 5424 syslog message.
    ///
    /// If the socket is not open, the message is silently dropped with a
    /// warning log.
    ///
    /// - Parameter alert: The detection alert to send.
    public func send(alert: Alert) async {
        guard socket >= 0 else {
            logger.warning("Syslog socket not connected; dropping alert \(alert.id, privacy: .public)")
            return
        }

        let message = formatRFC5424(alert: alert)
        let success: Bool

        switch transport {
        case .udp:
            success = sendUDP(message: message)
        case .tcp:
            success = sendTCP(message: message)
        }

        if success {
            sentCount += 1
        } else {
            logger.error(
                "Failed to send syslog message for alert \(alert.id, privacy: .public)"
            )
        }
    }

    /// Closes the socket and releases resources.
    public func disconnect() {
        closeSocket()
        logger.info("Syslog output disconnected (sent \(self.sentCount) messages)")
    }

    /// Returns the number of messages successfully sent.
    public func stats() -> Int {
        sentCount
    }

    // MARK: - RFC 5424 Formatting

    /// Formats an alert into an RFC 5424 syslog message.
    ///
    /// Format: `<PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID [SD] MSG`
    ///
    /// The PRI value encodes the facility and severity:
    /// `PRI = facility * 8 + severity_code`
    private func formatRFC5424(alert: Alert) -> String {
        let syslogSeverity = mapSeverity(alert.severity)
        let pri = facility * 8 + syslogSeverity
        let timestamp = Self.iso8601Formatter.string(from: alert.timestamp)
        let hostname = sanitizeSDValue(ProcessInfo.processInfo.hostName)

        // Structured data element with alert metadata.
        let ruleIdSD = sanitizeSDValue(alert.ruleId)
        let severitySD = sanitizeSDValue(alert.severity.rawValue)
        var sdParams = "ruleId=\"\(ruleIdSD)\" severity=\"\(severitySD)\""
        if let tactics = alert.mitreTactics {
            sdParams += " mitreTactics=\"\(sanitizeSDValue(tactics))\""
        }
        if let techniques = alert.mitreTechniques {
            sdParams += " mitreTechniques=\"\(sanitizeSDValue(techniques))\""
        }
        let structuredData = "[alert \(sdParams)]"

        // Free-form message: rule title | process info
        var msg = alert.ruleTitle
        if let path = alert.processPath {
            msg += " | \(path)"
        }
        if let name = alert.processName, alert.processPath == nil {
            msg += " | \(name)"
        }

        // Sanitize the message to strip any credentials that may appear
        // in process paths or names (defensive; command lines are the
        // primary vector but future changes could introduce others).
        msg = CommandSanitizer.sanitize(msg)

        return "<\(pri)>1 \(timestamp) \(hostname) hawkeye - - \(structuredData) \(msg)"
    }

    /// Maps HawkEye severity to RFC 5424 syslog severity codes.
    ///
    /// - critical    -> LOG_CRIT    (2)
    /// - high        -> LOG_ERR     (3)
    /// - medium      -> LOG_WARNING (4)
    /// - low         -> LOG_NOTICE  (5)
    /// - informational -> LOG_INFO  (6)
    private func mapSeverity(_ severity: Severity) -> Int {
        switch severity {
        case .critical:      return 2  // LOG_CRIT
        case .high:          return 3  // LOG_ERR
        case .medium:        return 4  // LOG_WARNING
        case .low:           return 5  // LOG_NOTICE
        case .informational: return 6  // LOG_INFO
        }
    }

    /// Escapes characters that are special in RFC 5424 structured data values.
    ///
    /// Per RFC 5424 section 6.3.3, the characters `"`, `\`, and `]` must be
    /// escaped with a backslash inside SD-VALUE.
    private func sanitizeSDValue(_ value: String) -> String {
        value
            .replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"")
            .replacingOccurrences(of: "]", with: "\\]")
    }

    // MARK: - Socket I/O

    /// Sends a message via UDP using `sendto()`.
    private func sendUDP(message: String) -> Bool {
        guard let addrData = resolvedAddr else {
            logger.error("No resolved address for UDP sendto()")
            return false
        }

        let bytes = Array(message.utf8)
        let result = bytes.withUnsafeBufferPointer { buffer in
            addrData.withUnsafeBytes { addrBuffer in
                let addrPtr = addrBuffer.baseAddress!.assumingMemoryBound(to: sockaddr.self)
                return Darwin.sendto(
                    socket,
                    buffer.baseAddress,
                    buffer.count,
                    0,
                    addrPtr,
                    socklen_t(addrData.count)
                )
            }
        }

        if result < 0 {
            logger.error("sendto() failed: \(String(cString: strerror(errno)), privacy: .public)")
            return false
        }
        return true
    }

    /// Sends a message via TCP using `send()`, appending a newline delimiter.
    private func sendTCP(message: String) -> Bool {
        let delimited = message + "\n"
        let bytes = Array(delimited.utf8)
        var totalSent = 0

        while totalSent < bytes.count {
            let result = bytes.withUnsafeBufferPointer { buffer in
                Darwin.send(
                    socket,
                    buffer.baseAddress! + totalSent,
                    bytes.count - totalSent,
                    0
                )
            }

            if result <= 0 {
                if result < 0 {
                    logger.error("send() failed: \(String(cString: strerror(errno)), privacy: .public)")
                }
                // Connection may have been reset; close the socket so callers
                // know to reconnect.
                closeSocket()
                return false
            }
            totalSent += result
        }

        return true
    }

    /// Closes the socket if it is currently open.
    private func closeSocket() {
        if socket >= 0 {
            Darwin.close(socket)
            socket = -1
            resolvedAddr = nil
        }
    }

    // MARK: - Address Resolution

    /// Resolves a hostname and port to a sockaddr structure using `getaddrinfo`.
    ///
    /// Returns the raw bytes of the first resolved `sockaddr_in` (IPv4) or
    /// `sockaddr_in6` (IPv6) address.
    private func resolveAddress(host: String, port: UInt16) throws -> Data {
        var hints = addrinfo()
        hints.ai_family = AF_UNSPEC
        hints.ai_socktype = transport == .udp ? SOCK_DGRAM : SOCK_STREAM

        var result: UnsafeMutablePointer<addrinfo>?
        let portString = String(port)
        let status = getaddrinfo(host, portString, &hints, &result)

        guard status == 0, let addrInfo = result else {
            let errorStr: String
            if let cStr = gai_strerror(status) {
                errorStr = String(cString: cStr)
            } else {
                errorStr = "unknown error"
            }
            throw SyslogOutputError.addressResolutionFailed(host: host, detail: errorStr)
        }

        defer { freeaddrinfo(result) }

        let addrData = Data(
            bytes: addrInfo.pointee.ai_addr,
            count: Int(addrInfo.pointee.ai_addrlen)
        )
        return addrData
    }
}

// MARK: - SyslogOutputError

/// Errors that can occur during syslog output operations.
public enum SyslogOutputError: Error, LocalizedError {
    case socketCreationFailed(errno: Int32)
    case connectionFailed(host: String, port: UInt16, errno: Int32)
    case addressResolutionFailed(host: String, detail: String)

    public var errorDescription: String? {
        switch self {
        case .socketCreationFailed(let errno):
            return "Failed to create socket: \(String(cString: strerror(errno)))"
        case .connectionFailed(let host, let port, let errno):
            return "Failed to connect to \(host):\(port): \(String(cString: strerror(errno)))"
        case .addressResolutionFailed(let host, let detail):
            return "Failed to resolve address for \(host): \(detail)"
        }
    }
}
