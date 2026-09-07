// DNSCollector.swift
// MacCrabCore
//
// Captures DNS queries and responses via BPF packet capture on port 53.
// Provides domain name visibility for C2 detection, DGA identification,
// DNS tunneling, and DNS-to-IP correlation for network event enrichment.

import Foundation
import os.log
import Darwin
import SystemConfiguration

// BPF ioctl constants not exposed in Swift's Darwin module
private let BIOCSETIF: UInt = 0x8020426c
private let BIOCSETF: UInt = 0x80104267
private let BIOCIMMEDIATE: UInt = 0x80044270
private let BIOCGBLEN: UInt = 0x40044266
private let BIOCGDLT: UInt = 0x4004426a
private let BIOCGSTATS: UInt = 0x4008426f // _IOR('B',111,struct bpf_stat), two UInt32 fields
private struct bpf_stat { var received: UInt32 = 0; var dropped: UInt32 = 0 }
private let ethernetDataLinkType: UInt32 = 1 // DLT_EN10MB, <net/bpf.h>
// _IOW('B', 109, struct timeval); timeval is 16 bytes on 64-bit macOS
private let BIOCSRTIMEOUT: UInt = 0x8010426d

// bpf_insn structure
private struct bpf_insn {
    var code: UInt16
    var jt: UInt8
    var jf: UInt8
    var k: UInt32
}

// bpf_program structure
private struct bpf_program {
    var bf_len: UInt32
    var bf_insns: UnsafeMutablePointer<bpf_insn>?
}

// bpf_hdr structure.
//
// v1.21.6-rc.38 ABI FIX. This declared `bh_tstamp` as `timeval`, which is
// WRONG on every 64-bit Mac. `<net/bpf.h>` uses:
//
//     #ifdef __LP64__
//     #define BPF_TIMEVAL struct timeval32     // 8 bytes
//     #else
//     #define BPF_TIMEVAL struct timeval
//     #endif
//
// On LP64 `struct timeval` is 16 bytes (Int64 tv_sec + Int32 tv_usec + pad)
// while `timeval32` is 8 (two Int32). Measured against the real system header
// on an arm64 Mac:
//
//     real  sizeof(struct bpf_hdr) = 20, offsetof(bh_caplen) = 8
//     this  struct as declared     = 28, offsetof(bh_caplen) = 16
//
// So every field was read from the wrong offset and the read loop advanced by
// the wrong stride. `bh_caplen` picked up timestamp bytes, the `packetStart +
// packetLen <= bytesRead` bounds check then rejected the frame, and DNSCollector
// yielded ZERO packets on every 64-bit Mac since it shipped — the collector has
// never worked, which is why its live event_count is 0 with no error logged.
//
// The fields are spelled out rather than using `timeval32` so the layout is
// explicit and cannot silently follow a platform typedef again.
private struct bpf_hdr {
    var bh_tstamp_sec: Int32
    var bh_tstamp_usec: Int32
    var bh_caplen: UInt32
    var bh_datalen: UInt32
    var bh_hdrlen: UInt16

    var timestamp: Date {
        Date(
            timeIntervalSince1970: Double(bh_tstamp_sec)
                + Double(bh_tstamp_usec) / 1_000_000
        )
    }
}

/// Owns the current BPF connection. Route changes retire the old descriptor
/// before opening its replacement; a failed open remains retryable.
struct DNSCaptureBinding {
    struct Connection: Equatable {
        let descriptor: Int32
        let bufferLength: Int
    }

    private(set) var interface: String?
    private(set) var connection: Connection?

    mutating func reconcile(
        selectedInterface: String?,
        open: (String) -> Connection?,
        close: (Int32) -> Void
    ) {
        if selectedInterface == interface, connection != nil { return }
        stop(close: close)
        guard let selectedInterface, let next = open(selectedInterface) else { return }
        interface = selectedInterface
        connection = next
    }

    mutating func stop(close: (Int32) -> Void) {
        if let connection { close(connection.descriptor) }
        connection = nil
        interface = nil
    }
}

/// Capture availability is separate from DNS traffic. A configured BPF session
/// proves setup succeeded; it does not claim that a DNS event was observed.
public enum DNSCaptureStatus: Sendable, Equatable {
    case capturing(interface: String)
    case unavailable(reason: String)
}

/// The capture loop owns this reporter and awaits each transition, preserving
/// failure/recovery order without a separate queue or unstructured tasks.
struct DNSCaptureStatusReporter {
    private var previous: DNSCaptureStatus?
    private let handler: @Sendable (DNSCaptureStatus) async -> Void

    init(handler: @escaping @Sendable (DNSCaptureStatus) async -> Void) {
        self.handler = handler
    }

    @discardableResult
    mutating func report(_ status: DNSCaptureStatus) async -> Bool {
        guard status != previous else { return false }
        previous = status
        await handler(status)
        return true
    }
}

/// DNS query/response data extracted from captured packets.
public struct DnsQuery: Sendable {
    /// The queried domain name.
    public let queryName: String
    /// DNS record type (A=1, AAAA=28, MX=15, TXT=16, CNAME=5, etc.)
    public let queryType: UInt16
    /// DNS response code (0=NOERROR, 2=SERVFAIL, 3=NXDOMAIN, etc.)
    public let responseCode: UInt16
    /// Resolved IP addresses (from A/AAAA response records).
    public let resolvedIPs: [String]
    /// Whether this is a response (true) or query (false).
    public let isResponse: Bool
    /// Timestamp of capture.
    public let timestamp: Date

    /// Human-readable query type name.
    public var queryTypeName: String {
        switch queryType {
        case 1:  return "A"
        case 28: return "AAAA"
        case 5:  return "CNAME"
        case 15: return "MX"
        case 16: return "TXT"
        case 2:  return "NS"
        case 6:  return "SOA"
        case 12: return "PTR"
        case 33: return "SRV"
        case 65: return "HTTPS"
        default: return "TYPE\(queryType)"
        }
    }
}

/// Captures DNS traffic via BPF and emits DnsQuery events.
///
/// Uses `/dev/bpf*` to capture Ethernet/IPv4 UDP packets on port 53 from
/// the system's primary IPv4 interface. Parses DNS wire format to extract
/// query names, types, and response IPs. Maintains a
/// reverse lookup cache (IP → domain) for enriching network events.
public actor DNSCollector {

    private let logger = Logger(subsystem: "com.maccrab", category: "dns-collector")

    /// Recent DNS resolutions: IP address → domain name.
    /// Used to enrich NetworkCollector events with domain names.
    private var reverseLookup: [String: String] = [:]
    private let maxReverseLookupSize = 10_000

    /// Async stream of DNS events.
    public nonisolated let events: AsyncStream<DnsQuery>
    private var continuation: AsyncStream<DnsQuery>.Continuation?
    private var captureTask: Task<Void, Never>?
    private var lifecyclePhase: CollectorLifecyclePhase = .initialized
    private let captureStatusHandler: @Sendable (DNSCaptureStatus) async -> Void
    private nonisolated let telemetry = DNSCaptureTelemetry()
    public nonisolated var captureDiagnostics: DNSCaptureDiagnostics { telemetry.snapshot() }

    // MARK: - Initialization

    public init(
        captureStatusHandler: @escaping @Sendable (DNSCaptureStatus) async -> Void = { _ in }
    ) {
        self.captureStatusHandler = captureStatusHandler
        var capturedContinuation: AsyncStream<DnsQuery>.Continuation!
        self.events = AsyncStream(bufferingPolicy: .bufferingNewest(256)) { continuation in
            capturedContinuation = continuation
        }
        self.continuation = capturedContinuation
    }

    // MARK: - Public API

    /// Start capturing DNS packets. Requires root for BPF access.
    public func start() {
        guard lifecyclePhase == .initialized else {
            logger.warning("DNS collector start rejected after its one-shot lifecycle advanced")
            return
        }
        lifecyclePhase = .running

        let continuation = self.continuation!
        let logger = self.logger
        let captureStatusHandler = self.captureStatusHandler
        let telemetry = self.telemetry

        captureTask = Task.detached {
            await Self.captureLoop(
                continuation: continuation, logger: logger,
                captureStatusHandler: captureStatusHandler, telemetry: telemetry
            )
        }

        logger.info("DNS collector started")
    }

    /// Stop capturing.
    public func stop() {
        _ = beginStop()
    }

    /// Join the BPF capture task. The BPF fd has a one-second read
    /// timeout, so a healthy worker observes cancellation within this bound.
    @discardableResult
    public func stopAndJoin(deadline: TimeInterval = 1.25) async -> Bool {
        let task = beginStop()
        let joined = await CollectorBoundedTaskJoin.waitForAll(
            task.map { [$0] } ?? [],
            deadline: deadline
        )
        if joined {
            captureTask = nil
            lifecyclePhase = .stopped
            logger.info("DNS collector stopped cleanly")
        } else {
            logger.error("DNS collector stop deadline expired with capture work active")
        }
        return joined
    }

    private func beginStop() -> Task<Void, Never>? {
        if lifecyclePhase == .stopped { return nil }
        lifecyclePhase = .stopping
        let task = captureTask
        captureTask?.cancel()
        continuation?.finish()
        continuation = nil
        return task
    }

    /// Look up the domain name for an IP address from recent DNS resolutions.
    public func domainForIP(_ ip: String) -> String? {
        reverseLookup[ip]
    }

    /// Get all recent reverse lookup entries.
    public func allReverseLookups() -> [String: String] {
        reverseLookup
    }

    /// Record a DNS resolution (called internally and can be called from outside).
    public func recordResolution(domain: String, ips: [String]) {
        for ip in ips {
            if reverseLookup.count >= maxReverseLookupSize {
                // Evict ~10% of oldest entries
                let toRemove = reverseLookup.count / 10
                for key in reverseLookup.keys.prefix(toRemove) {
                    reverseLookup.removeValue(forKey: key)
                }
            }
            reverseLookup[ip] = domain
        }
    }

    // MARK: - Interface selection

    /// Only the system's primary IPv4 interface is eligible. A different
    /// addressed interface is not evidence that it carries the resolver route.
    /// Scoped/VPN routes and IPv6 transport need separate capture support.
    static func captureInterface(
        primaryInterface: String?, addressedIPv4Interfaces: Set<String>
    ) -> String? {
        guard let primaryInterface,
              addressedIPv4Interfaces.contains(primaryInterface) else { return nil }
        return primaryInterface
    }

    private static func currentCaptureInterface() -> String? {
        let key = SCDynamicStoreKeyCreateNetworkGlobalEntity(
            nil, kSCDynamicStoreDomainState, kSCEntNetIPv4
        )
        let state = SCDynamicStoreCopyValue(nil, key) as? [String: Any]
        let primary = state?[kSCDynamicStorePropNetPrimaryInterface as String] as? String
        var addressed: Set<String> = []
        var head: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&head) == 0, let first = head else { return nil }
        defer { freeifaddrs(head) }
        for ptr in sequence(first: first, next: { $0.pointee.ifa_next }) {
            let flags = Int32(ptr.pointee.ifa_flags)
            guard flags & IFF_UP == IFF_UP,
                  flags & IFF_RUNNING == IFF_RUNNING,
                  flags & IFF_LOOPBACK == 0,
                  ptr.pointee.ifa_addr?.pointee.sa_family == UInt8(AF_INET) else { continue }
            addressed.insert(String(cString: ptr.pointee.ifa_name))
        }
        return captureInterface(primaryInterface: primary, addressedIPv4Interfaces: addressed)
    }

    // MARK: - BPF Capture Loop

    private static func captureLoop(
        continuation: AsyncStream<DnsQuery>.Continuation,
        logger: Logger,
        captureStatusHandler: @escaping @Sendable (DNSCaptureStatus) async -> Void,
        telemetry: DNSCaptureTelemetry
    ) async {
        var binding = DNSCaptureBinding()
        var buffer: UnsafeMutableRawPointer?
        var allocatedLength = 0
        var nextInterfaceCheck: TimeInterval = 0
        var statusReporter = DNSCaptureStatusReporter(handler: captureStatusHandler)
        var lastKernel = bpf_stat()
        func sampleKernelStatistics() {
            guard let connection = binding.connection else { return }
            var current = bpf_stat()
            if ioctl(connection.descriptor, BIOCGSTATS, &current) == 0 {
                telemetry.kernel(received: current.received &- lastKernel.received,
                                 dropped: current.dropped &- lastKernel.dropped)
                lastKernel = current
            } else { telemetry.kernelStatisticsFailed() }
        }
        defer {
            sampleKernelStatistics()
            binding.stop { _ = Darwin.close($0) }
            telemetry.availability(.unavailable(reason: "capture stopped"))
            buffer?.deallocate()
        }
        while !Task.isCancelled {
            let now = Foundation.ProcessInfo.processInfo.systemUptime
            if now >= nextInterfaceCheck {
                nextInterfaceCheck = now + 1
                let selected = currentCaptureInterface()
                sampleKernelStatistics()
                var openingFailure: String?
                binding.reconcile(selectedInterface: selected, open: { interface in
                    lastKernel = bpf_stat() // New descriptor counters start at zero.
                    let result = openCapture(interface: interface)
                    openingFailure = result.failure
                    return result.connection
                }, close: { _ = Darwin.close($0) })
                let status: DNSCaptureStatus
                if let interface = binding.interface {
                    status = .capturing(interface: interface)
                } else {
                    status = .unavailable(reason: openingFailure
                        ?? "No primary IPv4 interface is available for supported BPF capture")
                }
                if await statusReporter.report(status) {
                    telemetry.availability(status)
                    switch status {
                    case .capturing(let interface):
                        logger.info("DNS collector: capturing Ethernet/IPv4 DNS on \(interface, privacy: .public)")
                    case .unavailable(let reason):
                        logger.warning("DNS collector: \(reason, privacy: .public)")
                    }
                }
            }
            guard let connection = binding.connection else {
                try? await Task.sleep(nanoseconds: 1_000_000_000)
                continue
            }
            if allocatedLength != connection.bufferLength {
                buffer?.deallocate()
                buffer = UnsafeMutableRawPointer.allocate(
                    byteCount: connection.bufferLength, alignment: MemoryLayout<UInt32>.alignment
                )
                allocatedLength = connection.bufferLength
            }
            guard let buffer else { return }
            let bytesRead = read(connection.descriptor, buffer, connection.bufferLength)
            if bytesRead < 0 {
                if errno == EINTR { continue }
                if errno == EAGAIN { continue }
                let reason = "BPF read failed (errno \(errno)); retrying capture"
                sampleKernelStatistics()
                binding.stop { _ = Darwin.close($0) }
                telemetry.availability(.unavailable(reason: reason))
                if await statusReporter.report(.unavailable(reason: reason)) {
                    logger.warning("DNS collector: \(reason, privacy: .public)")
                }
                continue
            }
            if bytesRead == 0 { continue }
            forEachCapturedDNS(in: UnsafeRawBufferPointer(start: buffer, count: bytesRead)) {
                telemetry.yielded(continuation.yield($0))
            }
        }
    }

    /// Configure every new binding completely before it can enter the read loop.
    /// Ethernet offsets cannot be used on loopback or utun data-link formats.
    private static func openCapture(interface: String) -> (
        connection: DNSCaptureBinding.Connection?, failure: String?
    ) {
        var bpfFd: Int32 = -1
        for index in 0..<20 {
            bpfFd = Darwin.open("/dev/bpf\(index)", O_RDONLY)
            if bpfFd >= 0 { break }
        }
        guard bpfFd >= 0 else {
            return (nil, "BPF unavailable (errno \(errno)); capture requires root")
        }
        var keepOpen = false
        defer { if !keepOpen { _ = Darwin.close(bpfFd) } }
        var ifr = ifreq()
        guard interface.utf8.count < MemoryLayout.size(ofValue: ifr.ifr_name) else {
            return (nil, "Primary interface name does not fit the platform interface request")
        }
        withUnsafeMutablePointer(to: &ifr.ifr_name) { name in
            _ = interface.withCString { memcpy(name, $0, interface.utf8.count + 1) }
        }
        guard ioctl(bpfFd, BIOCSETIF, &ifr) == 0 else {
            return (nil, "Cannot bind BPF to \(interface) (errno \(errno))")
        }
        var dataLinkType: UInt32 = 0
        guard ioctl(bpfFd, BIOCGDLT, &dataLinkType) == 0 else {
            return (nil, "Cannot read BPF data-link type (errno \(errno))")
        }
        guard dataLinkType == ethernetDataLinkType else {
            return (nil, "Unsupported BPF data-link type \(dataLinkType) on \(interface); Ethernet/IPv4 required")
        }
        // Set BPF filter for UDP port 53
        // BPF filter: ip and udp and (port 53)
        var bpfProgram = bpf_program(bf_len: 0, bf_insns: nil)
        let filterInstructions: [bpf_insn] = [
            bpf_insn(code: 0x28, jt: 0, jf: 0, k: 12),   // ldh [12] (ethertype)
            bpf_insn(code: 0x15, jt: 0, jf: 8, k: 0x0800), // jeq #0x0800 (IPv4)
            bpf_insn(code: 0x30, jt: 0, jf: 0, k: 23),   // ldb [23] (protocol)
            bpf_insn(code: 0x15, jt: 0, jf: 6, k: 17),   // jeq #17 (UDP)
            bpf_insn(code: 0x28, jt: 0, jf: 0, k: 20),   // ldh [20] (flags+frag)
            bpf_insn(code: 0x45, jt: 4, jf: 0, k: 0x1fff), // jset #0x1fff (frag?)
            bpf_insn(code: 0xb1, jt: 0, jf: 0, k: 14),   // ldxb 4*([14]&0xf)
            bpf_insn(code: 0x48, jt: 0, jf: 0, k: 14),   // ldh [x+14] (src port)
            bpf_insn(code: 0x15, jt: 1, jf: 0, k: 53),   // jeq #53
            bpf_insn(code: 0x48, jt: 0, jf: 0, k: 16),   // ldh [x+16] (dst port)
            bpf_insn(code: 0x15, jt: 0, jf: 1, k: 53),   // jeq #53
            bpf_insn(code: 0x06, jt: 0, jf: 0, k: 65535), // ret #65535
            bpf_insn(code: 0x06, jt: 0, jf: 0, k: 0),    // ret #0
        ]

        let filterResult = filterInstructions.withUnsafeBufferPointer { ptr -> Int32 in
            bpfProgram.bf_len = UInt32(ptr.count)
            bpfProgram.bf_insns = UnsafeMutablePointer(mutating: ptr.baseAddress!)
            return ioctl(bpfFd, BIOCSETF, &bpfProgram)
        }
        guard filterResult == 0 else {
            return (nil, "Cannot install DNS BPF filter (errno \(errno))")
        }
        var enable: UInt32 = 1
        guard ioctl(bpfFd, BIOCIMMEDIATE, &enable) == 0 else {
            return (nil, "Cannot enable immediate BPF reads (errno \(errno))")
        }
        // Bound idle reads so route changes and cancellation are observed.
        var readTimeout = timeval(tv_sec: 1, tv_usec: 0)
        guard ioctl(bpfFd, BIOCSRTIMEOUT, &readTimeout) == 0 else {
            return (nil, "Cannot bound BPF read timeout (errno \(errno))")
        }
        var bufferLength: UInt32 = 0
        guard ioctl(bpfFd, BIOCGBLEN, &bufferLength) == 0, bufferLength > 0 else {
            return (nil, "Cannot read BPF buffer length (errno \(errno))")
        }
        keepOpen = true
        return (.init(descriptor: bpfFd, bufferLength: Int(bufferLength)), nil)
    }

    /// Iterate the production BPF records using the macOS <net/bpf.h> ABI.
    /// BPF_ALIGNMENT is sizeof(int32_t), including on LP64 platforms.
    static func forEachCapturedDNS(
        in buffer: UnsafeRawBufferPointer, consume: (DnsQuery) -> Void
    ) {
        var offset = 0
        while offset + MemoryLayout<bpf_hdr>.size <= buffer.count {
            let header = buffer.loadUnaligned(fromByteOffset: offset, as: bpf_hdr.self)
            let headerLength = Int(header.bh_hdrlen)
            let packetLength = Int(header.bh_caplen)
            guard headerLength >= MemoryLayout<bpf_hdr>.size,
                  headerLength <= buffer.count - offset,
                  packetLength <= buffer.count - offset - headerLength else { return }
            let packetStart = offset + headerLength
            let packet = Data(buffer[packetStart..<(packetStart + packetLength)])
            if let query = parseDNSPacket(packet, timestamp: header.timestamp) { consume(query) }
            offset += bpfWordAlign(headerLength + packetLength)
        }
    }

    // MARK: - DNS Wire Format Parser

    /// Parse one standard DNS question over Ethernet/IPv4/UDP. Compression
    /// offsets are relative to the DNS message, never to the Ethernet frame.
    static func parseDNSPacket(_ packet: Data, timestamp: Date = Date()) -> DnsQuery? {
        guard packet.count >= 14 + 20 + 8 + 12,
              packet[12] == 0x08, packet[13] == 0x00 else { return nil }
        let ipStart = 14
        let ipHeaderLength = Int(packet[ipStart] & 0x0F) * 4
        guard packet[ipStart] >> 4 == 4, ipHeaderLength >= 20,
              packet[ipStart + 9] == 17 else { return nil }
        let ipLength = Int(packet[ipStart + 2]) << 8 | Int(packet[ipStart + 3])
        let fragment = UInt16(packet[ipStart + 6]) << 8 | UInt16(packet[ipStart + 7])
        guard fragment & 0x3FFF == 0,
              ipLength >= ipHeaderLength + 8 + 12,
              ipLength <= packet.count - ipStart else { return nil }
        let udpStart = ipStart + ipHeaderLength
        let sourcePort = UInt16(packet[udpStart]) << 8 | UInt16(packet[udpStart + 1])
        let destinationPort = UInt16(packet[udpStart + 2]) << 8 | UInt16(packet[udpStart + 3])
        let udpLength = Int(packet[udpStart + 4]) << 8 | Int(packet[udpStart + 5])
        guard sourcePort == 53 || destinationPort == 53,
              udpLength >= 8 + 12,
              udpLength <= ipLength - ipHeaderLength else { return nil }
        // Data(...) rebases indices to zero; padding after the UDP datagram is
        // not part of the DNS message or its compression-pointer address space.
        let data = Data(packet[(udpStart + 8)..<(udpStart + udpLength)])
        let dnsStart = 0

        // DNS header (12 bytes)
        let flags = UInt16(data[dnsStart + 2]) << 8 | UInt16(data[dnsStart + 3])
        let isResponse = (flags & 0x8000) != 0
        let responseCode = flags & 0x000F
        let qdCount = UInt16(data[dnsStart + 4]) << 8 | UInt16(data[dnsStart + 5])
        let anCount = UInt16(data[dnsStart + 6]) << 8 | UInt16(data[dnsStart + 7])

        guard qdCount == 1 else { return nil }

        // Parse question section
        var offset = dnsStart + 12
        guard let (queryName, bytesConsumed) = parseDomainName(data, offset: offset) else { return nil }
        offset += bytesConsumed

        guard offset + 4 <= data.count else { return nil }
        let queryType = UInt16(data[offset]) << 8 | UInt16(data[offset + 1])
        offset += 4 // type + class

        // Parse answer section for resolved IPs
        var resolvedIPs: [String] = []
        if isResponse && anCount > 0 {
            for _ in 0..<min(anCount, 10) {
                guard offset < data.count else { break }

                // Skip name (might be compressed)
                if let (_, nameLen) = parseDomainName(data, offset: offset) {
                    offset += nameLen
                } else {
                    break
                }

                guard offset + 10 <= data.count else { break }
                let rrType = UInt16(data[offset]) << 8 | UInt16(data[offset + 1])
                let rdLength = UInt16(data[offset + 8]) << 8 | UInt16(data[offset + 9])
                offset += 10

                if rrType == 1 && rdLength == 4 && offset + 4 <= data.count {
                    // A record
                    let ip = "\(data[offset]).\(data[offset+1]).\(data[offset+2]).\(data[offset+3])"
                    resolvedIPs.append(ip)
                } else if rrType == 28 && rdLength == 16 && offset + 16 <= data.count {
                    // AAAA record
                    var parts: [String] = []
                    for i in stride(from: offset, to: offset + 16, by: 2) {
                        let word = UInt16(data[i]) << 8 | UInt16(data[i + 1])
                        parts.append(String(word, radix: 16))
                    }
                    resolvedIPs.append(parts.joined(separator: ":"))
                }

                offset += Int(rdLength)
            }
        }

        // Filter out noise (PTR queries for local addresses, mDNS)
        if queryName.hasSuffix(".local") || queryName.hasSuffix(".arpa") {
            return nil
        }

        return DnsQuery(
            queryName: queryName,
            queryType: queryType,
            responseCode: responseCode,
            resolvedIPs: resolvedIPs,
            isResponse: isResponse,
            timestamp: timestamp
        )
    }

    /// Parse a DNS domain name from wire format (handles compression pointers).
    /// The buffer starts at the DNS header, so compression pointers retain
    /// their RFC 1035 message-relative meaning.
    static func parseDomainName(_ data: Data, offset: Int) -> (String, Int)? {
        var labels: [String] = []
        var pos = offset
        var bytesConsumed = 0
        var jumped = false
        var jumpCount = 0  // Detect pointer cycles

        while pos < data.count {
            jumpCount += jumped ? 1 : 0
            guard jumpCount < 20 else { return nil } // Pointer cycle protection
            let len = Int(data[pos])

            if len == 0 {
                if !jumped { bytesConsumed = pos - offset + 1 }
                break
            }

            // Compression pointer
            if len & 0xC0 == 0xC0 {
                guard pos + 1 < data.count else { return nil }
                let pointer = Int(len & 0x3F) << 8 | Int(data[pos + 1])
                if !jumped { bytesConsumed = pos - offset + 2 }
                pos = pointer
                jumped = true
                continue
            }

            // Regular label (RFC 1035: max 63 chars per label)
            guard len <= 63 else { return nil }
            guard pos + 1 + len <= data.count else { return nil }
            guard let label = String(data: data[(pos + 1)..<(pos + 1 + len)], encoding: .utf8),
                  !label.isEmpty else { return nil }
            labels.append(label)
            // Guard total name length (RFC 1035: max 253 chars)
            if labels.joined(separator: ".").count > 253 { return nil }
            pos += 1 + len
        }

        if bytesConsumed == 0 && !jumped {
            bytesConsumed = pos - offset + 1
        }

        let name = labels.joined(separator: ".")
        return name.isEmpty ? nil : (name, bytesConsumed)
    }

    /// macOS BPF_WORDALIGN, whose alignment is four bytes even on LP64.
    static func bpfWordAlign(_ byteCount: Int) -> Int {
        let alignment = MemoryLayout<Int32>.size
        return (byteCount + alignment - 1) & ~(alignment - 1)
    }
}
