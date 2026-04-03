// DNSCollector.swift
// HawkEyeCore
//
// Captures DNS queries and responses via BPF packet capture on port 53.
// Provides domain name visibility for C2 detection, DGA identification,
// DNS tunneling, and DNS-to-IP correlation for network event enrichment.

import Foundation
import os.log
import Darwin

// BPF ioctl constants not exposed in Swift's Darwin module
private let BIOCSETIF: UInt = 0x8020426c
private let BIOCSETF: UInt = 0x80104267
private let BIOCIMMEDIATE: UInt = 0x80044270
private let BIOCGBLEN: UInt = 0x40044266

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

// bpf_hdr structure
private struct bpf_hdr {
    var bh_tstamp: timeval
    var bh_caplen: UInt32
    var bh_datalen: UInt32
    var bh_hdrlen: UInt16
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
/// Uses `/dev/bpf*` to capture UDP packets on port 53. Parses DNS wire
/// format to extract query names, types, and response IPs. Maintains a
/// reverse lookup cache (IP → domain) for enriching network events.
public actor DNSCollector {

    private let logger = Logger(subsystem: "com.hawkeye", category: "dns-collector")

    /// Recent DNS resolutions: IP address → domain name.
    /// Used to enrich NetworkCollector events with domain names.
    private var reverseLookup: [String: String] = [:]
    private let maxReverseLookupSize = 10_000

    /// Async stream of DNS events.
    public nonisolated let events: AsyncStream<DnsQuery>
    private var continuation: AsyncStream<DnsQuery>.Continuation?
    private var captureTask: Task<Void, Never>?
    private var isRunning = false

    // MARK: - Initialization

    public init() {
        var capturedContinuation: AsyncStream<DnsQuery>.Continuation!
        self.events = AsyncStream(bufferingPolicy: .bufferingNewest(256)) { continuation in
            capturedContinuation = continuation
        }
        self.continuation = capturedContinuation
    }

    // MARK: - Public API

    /// Start capturing DNS packets. Requires root for BPF access.
    public func start() {
        guard !isRunning else { return }
        isRunning = true

        let continuation = self.continuation!
        let logger = self.logger

        captureTask = Task.detached {
            await Self.captureLoop(continuation: continuation, logger: logger)
        }

        logger.info("DNS collector started")
    }

    /// Stop capturing.
    public func stop() {
        isRunning = false
        captureTask?.cancel()
        captureTask = nil
        continuation?.finish()
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

    // MARK: - BPF Capture Loop

    private static func captureLoop(
        continuation: AsyncStream<DnsQuery>.Continuation,
        logger: Logger
    ) async {
        // Try to open a BPF device
        var bpfFd: Int32 = -1
        for i in 0..<20 {
            let path = "/dev/bpf\(i)"
            bpfFd = open(path, O_RDONLY)
            if bpfFd >= 0 {
                logger.info("Opened BPF device: /dev/bpf\(i)")
                break
            }
        }

        guard bpfFd >= 0 else {
            logger.warning("DNS collector: cannot open any BPF device (requires root). Using passive mode.")
            // Fall back to passive DNS collection via log parsing
            await passiveDNSLoop(continuation: continuation, logger: logger)
            return
        }

        defer { close(bpfFd) }

        // Attach to loopback interface first (for local DNS resolver), then en0
        var ifr = ifreq()
        let interfaces = ["en0", "lo0"]
        var attached = false

        for iface in interfaces {
            withUnsafeMutablePointer(to: &ifr.ifr_name) { ptr in
                let raw = UnsafeMutableRawPointer(ptr)
                _ = iface.withCString { src in
                    memcpy(raw, src, min(iface.count, 15))
                }
            }
            if ioctl(bpfFd, BIOCSETIF, &ifr) == 0 {
                logger.info("BPF attached to interface: \(iface)")
                attached = true
                break
            }
        }

        guard attached else {
            logger.error("DNS collector: failed to attach BPF to any interface")
            close(bpfFd)
            return
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

        filterInstructions.withUnsafeBufferPointer { ptr in
            bpfProgram.bf_len = UInt32(ptr.count)
            bpfProgram.bf_insns = UnsafeMutablePointer(mutating: ptr.baseAddress!)
            ioctl(bpfFd, BIOCSETF, &bpfProgram)
        }

        // Set immediate mode
        var enable: UInt32 = 1
        ioctl(bpfFd, BIOCIMMEDIATE, &enable)

        // Get buffer size
        var bufLen: UInt32 = 0
        ioctl(bpfFd, BIOCGBLEN, &bufLen)
        if bufLen == 0 { bufLen = 4096 }

        let buffer = UnsafeMutableRawPointer.allocate(byteCount: Int(bufLen), alignment: 1)
        defer { buffer.deallocate() }

        logger.info("DNS BPF capture active (buffer: \(bufLen) bytes)")

        // Read loop
        while !Task.isCancelled {
            let bytesRead = read(bpfFd, buffer, Int(bufLen))
            guard bytesRead > 0 else {
                if bytesRead < 0 && errno == EINTR { continue }
                try? await Task.sleep(nanoseconds: 100_000_000)
                continue
            }

            // Parse BPF packets
            var offset = 0
            while offset < bytesRead {
                let hdr = buffer.advanced(by: offset).assumingMemoryBound(to: bpf_hdr.self).pointee
                let packetStart = offset + Int(hdr.bh_hdrlen)
                let packetLen = Int(hdr.bh_caplen)

                if packetLen > 42 { // Minimum: 14 (eth) + 20 (IP) + 8 (UDP) + DNS header
                    let packetData = Data(bytes: buffer.advanced(by: packetStart), count: packetLen)
                    if let query = parseDNSPacket(packetData) {
                        continuation.yield(query)
                    }
                }

                // Advance to next BPF packet (aligned)
                offset += BPF_WORDALIGN(Int(hdr.bh_hdrlen) + Int(hdr.bh_caplen))
            }
        }
    }

    // MARK: - Passive DNS (fallback when BPF not available)

    /// Passive DNS collection via `log stream` watching mDNSResponder.
    private static func passiveDNSLoop(
        continuation: AsyncStream<DnsQuery>.Continuation,
        logger: Logger
    ) async {
        logger.info("DNS collector in passive mode (Unified Log mDNSResponder)")
        // In passive mode, DNS events come through UnifiedLogCollector
        // This task just keeps the collector alive
        while !Task.isCancelled {
            try? await Task.sleep(nanoseconds: 60_000_000_000)
        }
    }

    // MARK: - DNS Wire Format Parser

    /// Parse a DNS packet from Ethernet frame data.
    private static func parseDNSPacket(_ data: Data) -> DnsQuery? {
        guard data.count > 42 else { return nil }

        // Skip Ethernet header (14 bytes)
        let ipStart = 14
        let ipHeaderLen = Int(data[ipStart] & 0x0F) * 4
        let udpStart = ipStart + ipHeaderLen

        guard udpStart + 8 < data.count else { return nil }

        // UDP payload starts after 8-byte UDP header
        let dnsStart = udpStart + 8
        guard dnsStart + 12 < data.count else { return nil }

        // DNS header (12 bytes)
        let flags = UInt16(data[dnsStart + 2]) << 8 | UInt16(data[dnsStart + 3])
        let isResponse = (flags & 0x8000) != 0
        let responseCode = flags & 0x000F
        let qdCount = UInt16(data[dnsStart + 4]) << 8 | UInt16(data[dnsStart + 5])
        let anCount = UInt16(data[dnsStart + 6]) << 8 | UInt16(data[dnsStart + 7])

        guard qdCount >= 1 else { return nil }

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
            timestamp: Date()
        )
    }

    /// Parse a DNS domain name from wire format (handles compression pointers).
    private static func parseDomainName(_ data: Data, offset: Int) -> (String, Int)? {
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

    /// BPF alignment macro equivalent.
    private static func BPF_WORDALIGN(_ x: Int) -> Int {
        (x + (MemoryLayout<Int>.size - 1)) & ~(MemoryLayout<Int>.size - 1)
    }
}
