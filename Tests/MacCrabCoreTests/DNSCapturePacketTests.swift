import Foundation
import Testing
@testable import MacCrabCore

/// Ordinary Ethernet/IPv4 UDP DNS exchanges. No socket or BPF device is opened.
enum DNSCapturePacketFixture {
    static func networkBytes(_ value: UInt16) -> [UInt8] {
        [UInt8(value >> 8), UInt8(value & 0xff)]
    }

    static func packet(name: String = "a.example", answerType: UInt16? = nil) -> Data {
        let questionType = answerType ?? 1
        var dns: [UInt8] = [0x12, 0x34]
        dns += networkBytes(answerType == nil ? 0x0100 : 0x8180)
        dns += [0, 1, 0, answerType == nil ? 0 : 1, 0, 0, 0, 0]
        for label in name.split(separator: ".") {
            dns.append(UInt8(label.utf8.count))
            dns += Array(label.utf8)
        }
        dns += [0] + networkBytes(questionType) + [0, 1]
        if let answerType {
            // The owner name repeats the question at DNS-message offset 12.
            dns += [0xc0, 0x0c] + networkBytes(answerType) + [0, 1, 0, 0, 0, 60]
            let address: [UInt8] = answerType == 28
                ? [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
                : [192, 0, 2, 1]
            dns += networkBytes(UInt16(address.count)) + address
        }
        let udpLength = UInt16(8 + dns.count)
        let sourcePort: UInt16 = answerType == nil ? 49152 : 53
        let destinationPort: UInt16 = answerType == nil ? 53 : 49152
        let udp = networkBytes(sourcePort) + networkBytes(destinationPort)
            + networkBytes(udpLength) + [0, 0] // UDP checksum is optional over IPv4.
        var ip: [UInt8] = [0x45, 0] + networkBytes(20 + udpLength)
            + [0xbe, 0xef, 0x40, 0, 64, 17, 0, 0, 192, 0, 2, 10, 192, 0, 2, 53]
        var checksum: UInt32 = 0
        for offset in stride(from: 0, to: ip.count, by: 2) {
            checksum += UInt32(ip[offset]) << 8 | UInt32(ip[offset + 1])
        }
        while checksum > 0xffff { checksum = (checksum & 0xffff) + (checksum >> 16) }
        let checksumBytes = networkBytes(~UInt16(checksum))
        ip[10] = checksumBytes[0]
        ip[11] = checksumBytes[1]
        let ethernet: [UInt8] = [2, 0, 0, 0, 0, 1, 2, 0, 0, 0, 0, 2, 8, 0]
        return Data(ethernet + ip + udp + dns)
    }

    static func bpfRecord(packet: Data, seconds: Int32, microseconds: Int32) -> Data {
        func nativeBytes<T>(_ value: T) -> [UInt8] {
            var value = value
            return withUnsafeBytes(of: &value) { Array($0) }
        }
        // net/bpf.h: timeval32 at 0, caplen at 8, datalen at 12, hdrlen at 16.
        // Ethernet alignment adds four padding bytes after the 18-byte fields.
        var bytes = nativeBytes(seconds) + nativeBytes(microseconds)
        bytes += nativeBytes(UInt32(packet.count)) + nativeBytes(UInt32(packet.count))
        bytes += nativeBytes(UInt16(22)) + [0, 0, 0, 0]
        bytes += Array(packet)
        while bytes.count % 4 != 0 { bytes.append(0) }
        return Data(bytes)
    }
}

@Suite("DNS Ethernet/IPv4 packet parsing")
struct DNSCapturePacketTests {
    @Test("a normal query preserves its question and supplied capture timestamp")
    func query() throws {
        let timestamp = Date(timeIntervalSince1970: 1_700_000_000)
        let query = try #require(DNSCollector.parseDNSPacket(
            DNSCapturePacketFixture.packet(), timestamp: timestamp
        ))
        #expect(query.queryName == "a.example")
        #expect(query.queryType == 1)
        #expect(!query.isResponse)
        #expect(query.resolvedIPs.isEmpty)
        #expect(query.timestamp == timestamp)
    }

    @Test("compressed A and AAAA answer owners use DNS-message-relative offsets")
    func compressedAnswers() throws {
        for (type, expectedIP) in [
            (UInt16(1), "192.0.2.1"), (UInt16(28), "2001:db8:0:0:0:0:0:1"),
        ] {
            let query = try #require(DNSCollector.parseDNSPacket(
                DNSCapturePacketFixture.packet(answerType: type)
            ))
            #expect(query.queryName == "a.example")
            #expect(query.queryType == type)
            #expect(query.isResponse)
            #expect(query.responseCode == 0)
            #expect(query.resolvedIPs == [expectedIP])
        }
    }
}
