import Testing
import Foundation
@testable import MacCrabCore

/// Regression guard for the audit finding that DNSCollector bound BPF to a
/// hardcoded `en0`. `BIOCSETIF` succeeds on any interface that merely exists,
/// so on a Mac whose uplink is en1 the capture attached to an unaddressed link
/// and produced zero DNS events for the life of the install — voiding every
/// domain-based threat-intel comparison, DGA detection, and the DNS sinkhole.
@Suite("DNSCollector: BPF interface selection")
struct DNSCollectorInterfaceTests {

    @Test("selection is never empty and always ends with loopback as a fallback")
    func alwaysHasLoopbackFallback() {
        let ifaces = DNSCollector.captureCandidateInterfaces()
        #expect(!ifaces.isEmpty)
        #expect(ifaces.last == "lo0", "lo0 must remain the last-resort candidate")
    }

    @Test("no unaddressed interface is offered as a candidate")
    func onlyAddressedInterfaces() {
        // Rebuild the addressed set independently via getifaddrs and assert the
        // collector's candidates (minus the lo0 fallback) are a subset.
        var addressed: Set<String> = []
        var head: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&head) == 0, let first = head else { return }
        defer { freeifaddrs(head) }
        for p in sequence(first: first, next: { $0.pointee.ifa_next }) {
            let flags = Int32(p.pointee.ifa_flags)
            guard flags & IFF_UP == IFF_UP, flags & IFF_RUNNING == IFF_RUNNING,
                  flags & IFF_LOOPBACK == 0, let a = p.pointee.ifa_addr else { continue }
            let fam = a.pointee.sa_family
            guard fam == UInt8(AF_INET) || fam == UInt8(AF_INET6) else { continue }
            addressed.insert(String(cString: p.pointee.ifa_name))
        }

        let candidates = DNSCollector.captureCandidateInterfaces().filter { $0 != "lo0" }
        for c in candidates {
            #expect(addressed.contains(c),
                    "candidate \(c) has no address — this is the en0 bug reappearing")
        }
    }

    @Test("physical en* uplinks are ranked ahead of virtual links")
    func physicalUplinksRankFirst() {
        let ifaces = DNSCollector.captureCandidateInterfaces().filter { $0 != "lo0" }
        guard let firstVirtual = ifaces.firstIndex(where: { !$0.hasPrefix("en") }) else { return }
        let lastPhysical = ifaces.lastIndex(where: { $0.hasPrefix("en") })
        if let lastPhysical {
            #expect(lastPhysical < firstVirtual,
                    "an en* interface must not be ordered after a utun/bridge/awdl link")
        }
    }
}
