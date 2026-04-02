// NetworkCollector.swift
// HawkEyeCore
//
// Collects network connection events by periodically enumerating process
// sockets via libproc (proc_pidinfo / proc_pidfdinfo).
//
// This approach mirrors Objective-See's Netiquette and avoids the high
// volume of ES_EVENT_TYPE_NOTIFY_CONNECT events from the Endpoint Security
// framework. Instead, we poll at a configurable interval, track known
// connections, and emit events only for newly observed connections.

import Foundation
import Darwin
import Darwin.POSIX
import os.log

// MARK: - ConnectionKey

/// Uniquely identifies a network connection for deduplication between polls.
///
/// Two snapshots that share the same key are considered the same logical
/// connection, so we only emit an event the first time a key appears.
struct ConnectionKey: Hashable, Sendable {
    let pid: Int32
    let localPort: UInt16
    let remoteIp: String
    let remotePort: UInt16
    let proto: String          // "tcp" or "udp"
}

// MARK: - NetworkCollector

/// Collects macOS network connection events by enumerating process sockets
/// via the `libproc` C API and emitting `Event` values for newly observed
/// connections.
///
/// Usage:
/// ```swift
/// let collector = NetworkCollector(pollInterval: 5.0)
/// await collector.start()
/// for await event in collector.events {
///     // handle event
/// }
/// ```
public actor NetworkCollector {

    // MARK: - Properties

    /// The asynchronous stream of normalised network events.
    public nonisolated let events: AsyncStream<Event>

    /// Poll interval in seconds between socket enumeration sweeps.
    private let pollInterval: TimeInterval

    /// Set of connection keys observed on the previous sweep.  New events are
    /// only emitted for keys that are *not* already in this set.
    private var knownConnections: Set<ConnectionKey> = []

    /// Background polling task; `nil` when the collector is stopped.
    private var pollTask: Task<Void, Never>?

    /// Continuation for yielding events into the `events` stream.
    private var continuation: AsyncStream<Event>.Continuation?

    /// Logger scoped to the network collector subsystem.
    private let logger = Logger(subsystem: "com.hawkeye.core", category: "NetworkCollector")

    // MARK: - Constants

    /// Maximum number of PIDs we expect on the system.  The buffer is sized
    /// to this count; if the system has more, we grow on the next sweep.
    private static let initialPIDBufferCount = 4096

    /// Maximum path length returned by `proc_pidpath`.
    private static let maxPathLength = Int(MAXPATHLEN)

    // MARK: - Initialisation

    /// Creates a new `NetworkCollector`.
    ///
    /// - Parameter pollInterval: Seconds between socket enumeration sweeps.
    ///   Defaults to 5 seconds.
    public init(pollInterval: TimeInterval = 5.0) {
        self.pollInterval = pollInterval

        var capturedContinuation: AsyncStream<Event>.Continuation!
        self.events = AsyncStream<Event>(bufferingPolicy: .bufferingNewest(512)) { continuation in
            capturedContinuation = continuation
        }
        self.continuation = capturedContinuation
    }

    // MARK: - Lifecycle

    /// Begins periodic socket enumeration.
    ///
    /// Safe to call multiple times; subsequent calls are no-ops while the
    /// collector is already running.
    public func start() {
        guard pollTask == nil else {
            logger.warning("NetworkCollector.start() called but collector is already running.")
            return
        }

        logger.info("NetworkCollector starting — poll interval \(self.pollInterval)s.")

        pollTask = Task { [weak self] in
            guard let self else { return }
            // Perform an initial sweep immediately.
            await self.sweep()

            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: UInt64(self.pollInterval * 1_000_000_000))
                guard !Task.isCancelled else { break }
                await self.sweep()
            }
        }
    }

    /// Stops polling and finishes the event stream.
    public func stop() {
        pollTask?.cancel()
        pollTask = nil
        continuation?.finish()
        continuation = nil
        logger.info("NetworkCollector stopped.")
    }

    // MARK: - Sweep

    /// Performs a single enumeration of all process sockets, emitting events
    /// for newly discovered connections and pruning stale entries from the
    /// known set.
    private func sweep() {
        let currentConnections = enumerateAllConnections()

        var newKeys = Set<ConnectionKey>()
        for (key, info) in currentConnections {
            newKeys.insert(key)

            // Only emit an event if this connection was not seen on the
            // previous sweep.
            if !knownConnections.contains(key) {
                let event = buildEvent(from: info)
                continuation?.yield(event)
            }
        }

        // Update known connections — stale entries are implicitly removed
        // because we replace the entire set.
        knownConnections = newKeys
    }

    // MARK: - PID Enumeration

    /// Returns an array of all active PIDs on the system.
    private func listAllPIDs() -> [Int32] {
        var bufferSize = Self.initialPIDBufferCount
        var pids = [Int32](repeating: 0, count: bufferSize)

        let byteCount = proc_listpids(
            UInt32(PROC_ALL_PIDS),
            0,
            &pids,
            Int32(bufferSize * MemoryLayout<Int32>.size)
        )

        guard byteCount > 0 else { return [] }

        let pidCount = Int(byteCount) / MemoryLayout<Int32>.size
        // If we filled the buffer, the system may have more PIDs.  Grow and
        // retry once.
        if pidCount >= bufferSize {
            bufferSize = pidCount * 2
            pids = [Int32](repeating: 0, count: bufferSize)
            let retryBytes = proc_listpids(
                UInt32(PROC_ALL_PIDS),
                0,
                &pids,
                Int32(bufferSize * MemoryLayout<Int32>.size)
            )
            let retryCount = retryBytes > 0
                ? Int(retryBytes) / MemoryLayout<Int32>.size
                : pidCount
            return Array(pids.prefix(retryCount)).filter { $0 > 0 }
        }

        return Array(pids.prefix(pidCount)).filter { $0 > 0 }
    }

    // MARK: - Socket Enumeration

    /// Information about a single observed socket, used to build an `Event`.
    private struct SocketConnectionInfo {
        let key: ConnectionKey
        let pid: Int32
        let localIp: String
        let localPort: UInt16
        let remoteIp: String
        let remotePort: UInt16
        let transport: String            // "tcp" or "udp"
        let socketFamily: Int32          // AF_INET or AF_INET6
        let tcpState: Int32?             // TCP state (only for TCP sockets)
    }

    /// Enumerates all non-loopback, non-listening connections across every
    /// process on the system.
    ///
    /// - Returns: Dictionary keyed by `ConnectionKey` for deduplication.
    private func enumerateAllConnections() -> [ConnectionKey: SocketConnectionInfo] {
        let pids = listAllPIDs()
        var results: [ConnectionKey: SocketConnectionInfo] = [:]

        for pid in pids {
            // Skip kernel (0) and launchd (1) unless you have a reason.
            if pid <= 1 { continue }

            let connections = enumerateSocketsForPID(pid)
            for conn in connections {
                results[conn.key] = conn
            }
        }

        return results
    }

    /// Enumerates all socket file descriptors for a single PID.
    ///
    /// Steps:
    /// 1. `proc_pidinfo(PROC_PIDLISTFDS)` to get all file descriptors.
    /// 2. Filter to socket FDs (`PROX_FDTYPE_SOCKET`).
    /// 3. `proc_pidfdinfo(PROC_PIDFDSOCKETINFO)` to get socket details.
    /// 4. Extract IP/port/protocol and filter out loopback and listeners.
    private func enumerateSocketsForPID(_ pid: Int32) -> [SocketConnectionInfo] {
        // Step 1: Get the list of file descriptors for this process.
        let fdInfoSize = Int32(MemoryLayout<proc_fdinfo>.size)
        let bufferSize = proc_pidinfo(
            pid,
            PROC_PIDLISTFDS,
            0,
            nil,
            0
        )
        guard bufferSize > 0 else { return [] }

        let fdCount = Int(bufferSize) / MemoryLayout<proc_fdinfo>.size
        var fdInfoBuffer = [proc_fdinfo](repeating: proc_fdinfo(), count: fdCount)

        let actualSize = proc_pidinfo(
            pid,
            PROC_PIDLISTFDS,
            0,
            &fdInfoBuffer,
            bufferSize
        )
        guard actualSize > 0 else { return [] }

        let actualCount = Int(actualSize) / MemoryLayout<proc_fdinfo>.size
        var connections: [SocketConnectionInfo] = []

        // Step 2 & 3: Iterate over FDs, filter to sockets, and extract info.
        for i in 0..<actualCount {
            let fdInfo = fdInfoBuffer[i]

            // Only interested in socket file descriptors.
            guard fdInfo.proc_fdtype == PROX_FDTYPE_SOCKET else { continue }

            var socketInfo = socket_fdinfo()
            let socketInfoSize = Int32(MemoryLayout<socket_fdinfo>.size)

            let result = proc_pidfdinfo(
                pid,
                fdInfo.proc_fd,
                PROC_PIDFDSOCKETINFO,
                &socketInfo,
                socketInfoSize
            )
            guard result == socketInfoSize else { continue }

            // Only care about internet sockets (IPv4 / IPv6).
            let family = Int32(socketInfo.psi.soi_family)
            guard family == AF_INET || family == AF_INET6 else { continue }

            // Determine protocol.
            let kind = Int32(socketInfo.psi.soi_kind)
            let transport: String
            let tcpState: Int32?

            if kind == SOCKINFO_TCP {
                transport = "tcp"
                tcpState = socketInfo.psi.soi_proto.pri_tcp.tcpsi_state
            } else if kind == SOCKINFO_IN {
                transport = "udp"
                tcpState = nil
            } else {
                continue
            }

            // Step 4: Extract local and remote addresses.
            let localIp: String
            let localPort: UInt16
            let remoteIp: String
            let remotePort: UInt16

            if kind == SOCKINFO_TCP {
                let tcpInfo = socketInfo.psi.soi_proto.pri_tcp
                localPort = UInt16(bigEndian: UInt16(tcpInfo.tcpsi_ini.insi_lport))
                remotePort = UInt16(bigEndian: UInt16(tcpInfo.tcpsi_ini.insi_fport))
                localIp = extractIPAddress(
                    addr4: tcpInfo.tcpsi_ini.insi_laddr.ina_46.i46a_addr4,
                    addr6: tcpInfo.tcpsi_ini.insi_laddr.ina_6,
                    family: family
                )
                remoteIp = extractIPAddress(
                    addr4: tcpInfo.tcpsi_ini.insi_faddr.ina_46.i46a_addr4,
                    addr6: tcpInfo.tcpsi_ini.insi_faddr.ina_6,
                    family: family
                )
            } else {
                // UDP: use soi_proto.pri_in
                let inInfo = socketInfo.psi.soi_proto.pri_in
                localPort = UInt16(bigEndian: UInt16(inInfo.insi_lport))
                remotePort = UInt16(bigEndian: UInt16(inInfo.insi_fport))
                localIp = extractIPAddress(
                    addr4: inInfo.insi_laddr.ina_46.i46a_addr4,
                    addr6: inInfo.insi_laddr.ina_6,
                    family: family
                )
                remoteIp = extractIPAddress(
                    addr4: inInfo.insi_faddr.ina_46.i46a_addr4,
                    addr6: inInfo.insi_faddr.ina_6,
                    family: family
                )
            }

            // Filter: skip listening sockets (no remote address / port 0).
            if remotePort == 0 && (remoteIp == "0.0.0.0" || remoteIp == "::" || remoteIp.isEmpty) {
                continue
            }

            // Filter: skip loopback connections.
            if isLoopback(remoteIp) && isLoopback(localIp) {
                continue
            }

            let key = ConnectionKey(
                pid: pid,
                localPort: localPort,
                remoteIp: remoteIp,
                remotePort: remotePort,
                proto: transport
            )

            let conn = SocketConnectionInfo(
                key: key,
                pid: pid,
                localIp: localIp,
                localPort: localPort,
                remoteIp: remoteIp,
                remotePort: remotePort,
                transport: transport,
                socketFamily: family,
                tcpState: tcpState
            )
            connections.append(conn)
        }

        return connections
    }

    // MARK: - IP Address Extraction

    /// Extracts a human-readable IP address string from the IPv4/IPv6 address
    /// components using `inet_ntop`.
    ///
    /// - Parameters:
    ///   - addr4: The `in_addr` (IPv4) component from the socket info structure.
    ///   - addr6: The `in6_addr` (IPv6) component from the socket info structure.
    ///   - family: `AF_INET` or `AF_INET6`.
    /// - Returns: Dotted-decimal (IPv4) or colon-hex (IPv6) string.
    private func extractIPAddress(addr4: in_addr, addr6: in6_addr, family: Int32) -> String {
        if family == AF_INET {
            var addr4 = addr4
            var buffer = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
            guard let result = inet_ntop(
                AF_INET,
                &addr4,
                &buffer,
                socklen_t(INET_ADDRSTRLEN)
            ) else {
                return "0.0.0.0"
            }
            return String(cString: result)
        } else {
            var addr6 = addr6
            var buffer = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
            guard let result = inet_ntop(
                AF_INET6,
                &addr6,
                &buffer,
                socklen_t(INET6_ADDRSTRLEN)
            ) else {
                return "::"
            }
            return String(cString: result)
        }
    }

    // MARK: - Loopback Detection

    /// Returns `true` when the address is a loopback address.
    private func isLoopback(_ ip: String) -> Bool {
        if ip == "::1" { return true }
        if ip.hasPrefix("127.") { return true }
        if ip == "0.0.0.0" || ip == "::" { return true }
        return false
    }

    // MARK: - Process Info Helpers

    /// Retrieves the executable path for a PID using `proc_pidpath`.
    private func executablePath(for pid: Int32) -> String {
        var pathBuffer = [CChar](repeating: 0, count: Self.maxPathLength)
        let length = proc_pidpath(pid, &pathBuffer, UInt32(Self.maxPathLength))
        guard length > 0 else { return "" }
        return String(cString: pathBuffer)
    }

    /// Retrieves the process name (basename of the executable path).
    private func processName(for pid: Int32) -> String {
        let path = executablePath(for: pid)
        guard !path.isEmpty else {
            // Fallback: use proc_name
            var nameBuffer = [CChar](repeating: 0, count: Int(MAXCOMLEN) + 1)
            proc_name(pid, &nameBuffer, UInt32(MAXCOMLEN))
            let name = String(cString: nameBuffer)
            return name.isEmpty ? "unknown" : name
        }
        return (path as NSString).lastPathComponent
    }

    /// Retrieves the parent PID for a process using `proc_pidinfo`.
    private func parentPID(for pid: Int32) -> Int32 {
        var bsdInfo = proc_bsdinfo()
        let size = Int32(MemoryLayout<proc_bsdinfo>.size)
        let result = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &bsdInfo, size)
        guard result == size else { return 0 }
        return Int32(bsdInfo.pbi_ppid)
    }

    /// Retrieves the UID for a process using `proc_pidinfo`.
    private func processUID(for pid: Int32) -> UInt32 {
        var bsdInfo = proc_bsdinfo()
        let size = Int32(MemoryLayout<proc_bsdinfo>.size)
        let result = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &bsdInfo, size)
        guard result == size else { return 0 }
        return bsdInfo.pbi_uid
    }

    // MARK: - Direction Heuristic

    /// Determines the direction of a connection based on port numbers.
    ///
    /// Uses a simple heuristic: if the remote port is a well-known port
    /// (< 1024) or a common service port, the connection is likely outbound.
    /// If the local port is well-known, it is likely inbound.
    private func inferDirection(localPort: UInt16, remotePort: UInt16) -> NetworkDirection {
        let wellKnownPorts: Set<UInt16> = [
            20, 21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995,
            3306, 5432, 6379, 8080, 8443, 9200,
        ]

        if wellKnownPorts.contains(localPort) && !wellKnownPorts.contains(remotePort) {
            return .inbound
        }
        // Default: treat as outbound (process initiated the connection).
        return .outbound
    }

    // MARK: - Event Building

    /// Builds a HawkEye `Event` from an observed socket connection.
    private func buildEvent(from conn: SocketConnectionInfo) -> Event {
        let pid = conn.pid
        let exePath = executablePath(for: pid)
        let procName = processName(for: pid)
        let ppid = parentPID(for: pid)
        let uid = processUID(for: pid)

        // Resolve the user name from the UID.  getpwuid is not async-safe
        // in the strictest sense, but is fine for our polling context.
        let userName: String
        if let pw = getpwuid(uid) {
            userName = String(cString: pw.pointee.pw_name)
        } else {
            userName = String(uid)
        }

        let processInfo = ProcessInfo(
            pid: pid,
            ppid: ppid,
            rpid: pid,
            name: procName,
            executable: exePath,
            commandLine: exePath,
            args: [],
            workingDirectory: "/",
            userId: uid,
            userName: userName,
            groupId: 0,
            startTime: Date()      // Approximate; true start time requires sysctl
        )

        let direction = inferDirection(
            localPort: conn.localPort,
            remotePort: conn.remotePort
        )

        let networkInfo = NetworkInfo(
            sourceIp: conn.localIp,
            sourcePort: conn.localPort,
            destinationIp: conn.remoteIp,
            destinationPort: conn.remotePort,
            direction: direction,
            transport: conn.transport
        )

        // Determine severity: connections to non-private IPs on unusual ports
        // are slightly more interesting.
        let severity: Severity
        if !networkInfo.destinationIsPrivate {
            severity = .low
        } else {
            severity = .informational
        }

        // Enrichments with socket-level metadata.
        var enrichments: [String: String] = [
            "network.socket_family": conn.socketFamily == AF_INET ? "ipv4" : "ipv6",
        ]
        if let tcpState = conn.tcpState {
            enrichments["network.tcp_state"] = tcpStateName(tcpState)
        }

        return Event(
            timestamp: Date(),
            eventCategory: .network,
            eventType: .connection,
            eventAction: "connect",
            process: processInfo,
            network: networkInfo,
            enrichments: enrichments,
            severity: severity
        )
    }

    // MARK: - TCP State Names

    /// Human-readable name for a TCP state constant from `<netinet/tcp_fsm.h>`.
    private func tcpStateName(_ state: Int32) -> String {
        switch state {
        case 0:  return "CLOSED"
        case 1:  return "LISTEN"
        case 2:  return "SYN_SENT"
        case 3:  return "SYN_RECEIVED"
        case 4:  return "ESTABLISHED"
        case 5:  return "CLOSE_WAIT"
        case 6:  return "FIN_WAIT_1"
        case 7:  return "CLOSING"
        case 8:  return "LAST_ACK"
        case 9:  return "FIN_WAIT_2"
        case 10: return "TIME_WAIT"
        default: return "UNKNOWN(\(state))"
        }
    }
}
