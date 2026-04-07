import Foundation
import Darwin
import MacCrabCore

extension MacCrabCtl {
    static func extractCDHash(pid: Int32) async {
        let extractor = CDHashExtractor()
        if let hash = await extractor.extractCDHash(pid: pid) {
            print("PID \(pid): \(hash)")
        } else {
            print("PID \(pid): no CDHash available (process may not exist or may be unsigned)")
        }
    }

    static func extractAllCDHashes() async {
        print("Extracting CDHashes for all running processes...")
        print("══════════════════════════════════════════════════════════════")
        print(String(format: "%-8s %s", "PID", "CDHash"))
        print(String(repeating: "─", count: 60))

        // Get all PIDs using proc_listallpids
        let count = proc_listallpids(nil, 0)
        guard count > 0 else {
            print("Failed to enumerate processes.")
            return
        }
        var pids = [Int32](repeating: 0, count: Int(count) + 100)
        let actual = proc_listallpids(&pids, Int32(pids.count * MemoryLayout<Int32>.size))
        guard actual > 0 else {
            print("Failed to enumerate processes.")
            return
        }

        let validPids = pids.prefix(Int(actual)).filter { $0 > 0 }.sorted()
        let extractor = CDHashExtractor()
        let results = await extractor.extractBatch(pids: Array(validPids))

        for pid in validPids {
            if let hash = results[pid] {
                print(String(format: "%-8d %@", pid, hash))
            }
        }

        print(String(repeating: "─", count: 60))
        print("\(results.count) of \(validPids.count) processes have CDHashes")
    }
}
