// BrokerClientTests — the plugin-side broker client (maccrab_tierb_broker_open +
// MacCrabPluginKit.TierBBroker). Proves a store plugin's declared read is served
// over the fd-3 broker end to end, and that a denial yields no descriptor.

import Testing
import Foundation
import CTierBBroker
@testable import MacCrabPluginKit

@Suite("TierB broker client (plugin-side SDK)")
struct BrokerClientTests {

    private func socketPair() -> (client: Int32, host: Int32) {
        var fds: [Int32] = [-1, -1]
        _ = socketpair(AF_UNIX, SOCK_STREAM, 0, &fds)
        return (fds[0], fds[1])
    }

    /// Mock host: read the 2-byte-BE-length + path frame, then invoke `respond`.
    @discardableResult
    private func mockHost(_ host: Int32, _ respond: @escaping (String, Int32) -> Void) -> Thread {
        let t = Thread {
            var hdr = [UInt8](repeating: 0, count: 2)
            guard read(host, &hdr, 2) == 2 else { return }
            let len = Int(hdr[0]) << 8 | Int(hdr[1])
            var pathBuf = [UInt8](repeating: 0, count: max(len, 1))
            let got = pathBuf.withUnsafeMutableBytes { read(host, $0.baseAddress, len) }
            let path = String(decoding: pathBuf[0..<max(0, got)], as: UTF8.self)
            respond(path, host)
        }
        t.start()
        return t
    }

    @Test("served: the broker passes a read-only fd → the client reads the file")
    func servedFd() throws {
        let (client, host) = socketPair()
        defer { close(client); close(host) }
        let tmp = NSTemporaryDirectory() + "brk-\(UUID().uuidString)"
        try "hello-broker".write(toFile: tmp, atomically: true, encoding: .utf8)
        defer { try? FileManager.default.removeItem(atPath: tmp) }

        mockHost(host) { requested, hostSock in
            #expect(requested == "/Library/LaunchDaemons")
            let servedFd = open(tmp, O_RDONLY)
            _ = maccrab_tierb_send_fd(hostSock, servedFd, 0)   // status 0 = ok
            close(servedFd)
        }

        let fd = "/Library/LaunchDaemons".withCString { maccrab_tierb_broker_open(client, $0) }
        #expect(fd >= 0)
        if fd >= 0 {
            var buf = [UInt8](repeating: 0, count: 32)
            let n = read(fd, &buf, 32)
            close(fd)
            #expect(String(decoding: buf[0..<max(0, n)], as: UTF8.self) == "hello-broker")
        }
    }

    @Test("denied: host sends a status byte with no descriptor → client gets -1")
    func denied() {
        let (client, host) = socketPair()
        defer { close(client); close(host) }
        mockHost(host) { _, hostSock in
            _ = maccrab_tierb_send_status(hostSock, 1)   // 1 = denied, no fd
        }
        let fd = "/etc/not-declared".withCString { maccrab_tierb_broker_open(client, $0) }
        #expect(fd == -1)
    }

    @Test("first-party lane (no broker env): readDeclared reads directly")
    func firstPartyDirect() throws {
        // No MACCRAB_TIERB_BROKER_FD in the test env → SDK takes the direct path.
        #expect(TierBBroker.brokerFD == nil)
        #expect(TierBBroker.isSandboxed == false)
        let tmp = NSTemporaryDirectory() + "fp-\(UUID().uuidString)"
        try "direct-read".write(toFile: tmp, atomically: true, encoding: .utf8)
        defer { try? FileManager.default.removeItem(atPath: tmp) }
        let data = TierBBroker.readDeclared(tmp)
        #expect(data.flatMap { String(data: $0, encoding: .utf8) } == "direct-read")
    }
}
