import Foundation
import MacCrabCore

extension MacCrabCtl {
    static func tailEvents(limit: Int) async {
        do {
            let store = try EventStore(directory: maccrabDataDir())
            let events = try await store.events(since: Date.distantPast, category: nil, limit: limit)

            print("Last \(events.count) events:")
            print(String(repeating: "─", count: 100))

            for event in events {
                let time = formatDate(event.timestamp)
                let action = event.eventAction
                let proc = "\(event.process.name)(\(event.process.pid))"
                let detail: String
                if let file = event.file {
                    detail = file.path
                } else if let net = event.network {
                    detail = "\(net.destinationIp):\(net.destinationPort)"
                } else {
                    detail = event.process.executable
                }

                print("\(time) [\(action)] \(proc) → \(detail)")
            }
        } catch {
            print("Error reading events: \(error)")
        }
    }

    static func searchEvents(query: String) async {
        do {
            let store = try EventStore(directory: maccrabDataDir())
            let events = try await store.search(text: query, limit: 50)

            print("Search results for '\(query)' (\(events.count) matches):")
            print(String(repeating: "─", count: 100))

            for event in events {
                let time = formatDate(event.timestamp)
                let proc = "\(event.process.name)(\(event.process.pid))"
                print("\(time) [\(event.eventAction)] \(proc) | \(event.process.executable)")
            }
        } catch {
            print("Error searching events: \(error)")
        }
    }

    static func eventStats() async {
        do {
            let store = try EventStore(directory: maccrabDataDir())
            let totalCount = try await store.count()
            let last24h = try await store.events(since: Date().addingTimeInterval(-86400), limit: 1_000_000)
            print("Event Statistics:")
            print("══════════════════════════════════════")
            print("  Total events:     \(totalCount)")
            print("  Events (last 24h): \(last24h.count)")
        } catch {
            print("Error reading stats: \(error)")
        }
    }
}
