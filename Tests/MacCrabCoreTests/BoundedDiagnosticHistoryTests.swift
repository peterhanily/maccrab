import Foundation
import Testing
@testable import MacCrabCore

@Suite("Bounded diagnostic and discovery history")
struct BoundedDiagnosticHistoryTests {
    @Test("audit history retains the newest records in order through repeated wraparound",
          arguments: [0, 1, 3])
    func auditTailStaysBounded(capacity: Int) {
        var history = BoundedRecentHistory<Int>(capacity: capacity)
        for value in 0..<100 {
            let forgotten = history.append(value)
            let expected = Array(0...value).suffix(capacity)
            #expect(history.elements == Array(expected))
            #expect(history.count == expected.count)
            if value >= capacity {
                #expect(forgotten == value - capacity)
            } else {
                #expect(forgotten == nil)
            }
        }
    }

    @Test("dedup evicts oldest first and allows a later repeated discovery")
    func forgottenDiscoveryCanBeReportedAgain() {
        var reported = BoundedRecentSet<String>(capacity: 3)
        let a = reported.insert("a")
        let b = reported.insert("b")
        let c = reported.insert("c")
        #expect(a && b && c)
        let duplicate = reported.insert("a")
        #expect(!duplicate)
        let d = reported.insert("d")
        #expect(d)
        #expect(reported.count == 3)
        #expect(!reported.contains("a"))
        #expect(reported.contains("b"))

        let repeated = reported.insert("a")
        #expect(repeated)
        #expect(reported.count == 3)
        #expect(!reported.contains("b"))
        #expect(reported.contains("c"))
        #expect(reported.contains("d"))
        #expect(reported.contains("a"))
    }

    @Test("current inventory reconciliation forgets removed paths and preserves retained FIFO order")
    func inventoryRemovalRearmsOnlyForgottenPaths() {
        var reported = BoundedRecentSet<String>(capacity: 3)
        for path in ["/profiles/a", "/profiles/b", "/profiles/c"] {
            reported.insert(path)
        }
        let current = Set(["/profiles/a", "/profiles/c"])
        reported.retain { current.contains($0) }
        #expect(reported.count == 2)
        #expect(!reported.contains("/profiles/b"))
        let retained = reported.insert("/profiles/c")
        #expect(!retained)
        let reinstalled = reported.insert("/profiles/b")
        #expect(reinstalled)
        reported.insert("/profiles/d")
        #expect(!reported.contains("/profiles/a"))
        #expect(reported.contains("/profiles/c"))
        #expect(reported.count == 3)

        reported.retain { _ in false }
        #expect(reported.count == 0)
        let newInventory = reported.insert("/profiles/c")
        #expect(newInventory)
    }

    @Test("zero dedup capacity retains nothing without suppressing observations")
    func noDedupRetentionStillReports() {
        var reported = BoundedRecentSet<String>(capacity: 0)
        let first = reported.insert("ordinary-item")
        let second = reported.insert("ordinary-item")
        #expect(first && second)
        #expect(reported.count == 0)
        #expect(!reported.contains("ordinary-item"))
    }

    @Test("audit records preserve duplicates independently of discovery dedup")
    func duplicateAuditRecordsRemainSeparate() {
        var history = BoundedRecentHistory<String>(capacity: 3)
        history.append("same-package")
        history.append("same-package")
        history.append("other-package")
        #expect(history.elements == ["same-package", "same-package", "other-package"])
        history.append("last-package")
        #expect(history.elements == ["same-package", "other-package", "last-package"])
    }

    @Test("supply-chain audit tail does not replace lifetime blocked totals or enable prevention",
          arguments: [0, 3])
    func supplyChainAuditRetentionIsSeparateFromPolicy(capacity: Int) async {
        let gate = SupplyChainGate(maxAgeHours: 24, historyCapacity: capacity)
        for index in 0..<8 {
            // This records fixture decisions only. It never calls gate(),
            // ancestry discovery, process validation or a termination API.
            await gate.recordBlockedInstall(.init(
                packageName: "ordinary-package-\(index)",
                registry: "fixture",
                ageHours: 1,
                installerPid: Int32(10_000 + index),
                reason: "fixture decision",
                timestamp: Date(timeIntervalSince1970: Double(index))
            ))
        }
        let history = await gate.history()
        #expect(history.map { $0.packageName } == (0..<8).suffix(capacity).map {
            "ordinary-package-\($0)"
        })
        let statistics = await gate.stats()
        #expect(statistics.blocked == 8)
        #expect(!statistics.enabled)
    }
}
