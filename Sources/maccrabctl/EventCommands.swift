import Foundation
import MacCrabCore

extension MacCrabCtl {
    static func tailEvents(limit: Int, hours: Double? = nil, category: EventCategory? = nil) async {
        do {
            let store = try openEventStoreForReading(directory: maccrabDataDir())
            let since = hours.map { Date().addingTimeInterval(-$0 * 3600) } ?? Date.distantPast
            let snapshot = try await store.exactEventsSnapshot(
                since: since,
                category: category,
                limit: limit
            )
            guard snapshot.isComplete else {
                throw EventStoreError.exactEvidenceGap(
                    poisonRecords: snapshot.poisonRecords.count,
                    corruptLegacyRecords: snapshot.corruptLegacyRecords,
                    inheritedLegacyLossRecords:
                        snapshot.inheritedLegacyLossRecords,
                    resourceLimitedRecords: snapshot.resourceLimitedRecords
                )
            }
            let events = snapshot.events

            let timeLabel = hours.map { " (last \(Int($0))h)" } ?? ""
            let catLabel = category.map { " [\($0.rawValue)]" } ?? ""
            print("\(events.count) event(s)\(timeLabel)\(catLabel):")
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
            withExtendedLifetime(snapshot) {}
        } catch {
            print("Error reading events: \(error)"); exit(1)
        }
    }

    static func searchEvents(query: String) async {
        do {
            let store = try openEventStoreForReading(directory: maccrabDataDir())
            let snapshot = try await store.searchSnapshot(
                text: query,
                limit: 50
            )
            let events = snapshot.events

            print("Search results for '\(query)' (\(events.count) projected matches):")
            if !snapshot.isComplete {
                print(
                    "WARNING: Search coverage is incomplete "
                        + "(\(snapshot.projectionOmitted) retained events omitted "
                        + "from the search projection; \(snapshot.gaps.total) "
                        + "exact-evidence gaps). An empty or partial result is "
                        + "not proof of absence."
                )
            }
            print(String(repeating: "─", count: 100))

            for event in events {
                let time = formatDate(event.timestamp)
                let proc = "\(event.process.name)(\(event.process.pid))"
                print("\(time) [\(event.eventAction)] \(proc) | \(event.process.executable)")
            }
            withExtendedLifetime(snapshot) {}
        } catch {
            print("Error searching events: \(error)")
        }
    }

    static func eventStats() async {
        do {
            let store = try openEventStoreForReading(directory: maccrabDataDir())
            let totalCount = try await store.count()
            let requestedUntil = Date()
            let requestedSince = requestedUntil.addingTimeInterval(-86_400)
            let snapshot = try await store.eventCategoryCountSnapshot(
                since: requestedSince,
                until: requestedUntil
            )
            let observedCount = snapshot.counts.values.reduce(0) {
                partial, value in
                let next = partial.addingReportingOverflow(max(0, value))
                return next.overflow ? Int.max : next.partialValue
            }
            let effectiveSeconds = max(
                0,
                Int(snapshot.effectiveUntil.timeIntervalSince(
                    snapshot.effectiveSince
                ))
            )
            print("Event Statistics:")
            print("══════════════════════════════════════")
            print("  Retained exact events: \(totalCount)")
            if snapshot.isComplete {
                print("  Events (last 24h):     \(observedCount)")
            } else {
                print(
                    "  Events (provable retained \(effectiveSeconds)s): "
                        + "\(observedCount)"
                )
                print(
                    "  WARNING: The full 24-hour window is not retained "
                        + "or has \(snapshot.gaps.total) evidence gaps; "
                        + "missing time is unknown, not zero."
                )
            }
        } catch {
            print("Error reading stats: \(error)"); exit(1)
        }
    }
}
