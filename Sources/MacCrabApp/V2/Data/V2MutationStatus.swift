import Foundation
import MacCrabCore

public struct V2MutationRequest: Hashable, Sendable, Identifiable {
    public enum Operation: String, Hashable, Sendable {
        case suppressAlert, unsuppressAlert, deleteAlert
        case suppressCampaign, unsuppressCampaign, liftSuppression

        var label: String {
            switch self {
            case .suppressAlert: return String(localized: "mutation.suppressAlert", defaultValue: "Suppress alert")
            case .unsuppressAlert: return String(localized: "mutation.restoreAlert", defaultValue: "Restore alert")
            case .deleteAlert: return String(localized: "mutation.deleteAlert", defaultValue: "Delete alert")
            case .suppressCampaign: return String(localized: "mutation.suppressCampaign", defaultValue: "Suppress campaign")
            case .unsuppressCampaign: return String(localized: "mutation.restoreCampaign", defaultValue: "Restore campaign")
            case .liftSuppression: return String(localized: "mutation.liftSuppression", defaultValue: "Lift suppression")
            }
        }
    }

    public let id: UUID
    public let operation: Operation
    public let targetID: String
    public let title: String
    public let scope: String

    public init(operation: Operation, targetID: String, title: String, scope: String = "any") {
        id = UUID()
        self.operation = operation
        self.targetID = targetID
        self.title = title
        self.scope = scope
    }

    var entityKey: String {
        switch operation {
        case .suppressAlert, .unsuppressAlert, .deleteAlert: return "alert:\(targetID)"
        case .suppressCampaign, .unsuppressCampaign: return "campaign:\(targetID)"
        case .liftSuppression: return "suppression:\(targetID):\(scope)"
        }
    }
}

public enum V2MutationSubmission: Equatable, Sendable {
    case applied
    case queued
    case failed(String)
}

public enum V2MutationConfirmation: Equatable, Sendable {
    case applied
    case pending
    case unavailable(String)
}

/// Request state never replaces an alert/campaign's stored state. A timeout is
/// unconfirmed, not proof of failure: the engine may still process its inbox.
struct V2MutationTracker: Equatable {
    enum Status: Equatable {
        case submitting, queued, applied, failed(String), unconfirmed

        var label: String {
            switch self {
            case .submitting: return String(localized: "mutation.submitting", defaultValue: "Sending request")
            case .queued: return String(localized: "mutation.queued", defaultValue: "Awaiting confirmation")
            case .applied: return String(localized: "mutation.applied", defaultValue: "Saved state confirmed")
            case .failed: return String(localized: "mutation.failed", defaultValue: "Request failed")
            case .unconfirmed: return String(localized: "mutation.unconfirmed", defaultValue: "Not confirmed — may still apply")
            }
        }

        var terminal: Bool {
            switch self {
            case .submitting, .queued: return false
            case .applied, .failed, .unconfirmed: return true
            }
        }

        var chipKind: V2ChipKind {
            switch self {
            case .submitting, .queued: return .info
            case .applied: return .healthy
            case .failed: return .high
            case .unconfirmed: return .warning
            }
        }
    }

    struct Entry: Identifiable, Equatable {
        let request: V2MutationRequest
        let startedAt: Date
        var status: Status
        var lastObservedAt: Date? = nil
        var id: UUID { request.id }
    }

    static let confirmationTimeout: TimeInterval = 120
    private(set) var entries: [Entry] = []
    var pending: [Entry] { entries.filter { !$0.status.terminal } }
    var queued: [Entry] { entries.filter { $0.status == .queued } }
    var confirmationBatch: [Entry] {
        Array(queued.sorted {
            ($0.lastObservedAt ?? .distantPast) < ($1.lastObservedAt ?? .distantPast)
        }.prefix(100))
    }

    mutating func begin(_ request: V2MutationRequest, now: Date = Date()) -> Bool {
        guard pending.count < 1_000,
              !pending.contains(where: { $0.request.entityKey == request.entityKey }) else { return false }
        entries.append(Entry(request: request, startedAt: now, status: .submitting))
        trimHistory()
        return true
    }

    mutating func submitted(_ request: V2MutationRequest, result: V2MutationSubmission) {
        guard let index = entries.firstIndex(where: { $0.id == request.id }),
              entries[index].status == .submitting else { return }
        switch result {
        case .applied: entries[index].status = .applied
        case .queued: entries[index].status = .queued
        case .failed(let detail): entries[index].status = .failed(detail)
        }
        trimHistory()
    }

    mutating func observed(_ request: V2MutationRequest, confirmation: V2MutationConfirmation,
                           now: Date = Date()) {
        guard let index = entries.firstIndex(where: { $0.id == request.id }),
              entries[index].status == .queued else { return }
        entries[index].lastObservedAt = now
        if confirmation == .applied {
            entries[index].status = .applied
        } else if now.timeIntervalSince(entries[index].startedAt) >= Self.confirmationTimeout {
            entries[index].status = .unconfirmed
        }
        trimHistory()
    }

    mutating func expire(now: Date = Date()) {
        for index in entries.indices where !entries[index].status.terminal
            && now.timeIntervalSince(entries[index].startedAt) >= Self.confirmationTimeout {
            entries[index].status = .unconfirmed
        }
        trimHistory()
    }

    mutating func dismissCompleted() { entries.removeAll { $0.status.terminal } }

    func allApplied(_ requests: [V2MutationRequest]) -> Bool {
        guard !requests.isEmpty else { return false }
        let statuses = Dictionary(uniqueKeysWithValues: entries.map { ($0.id, $0.status) })
        return requests.allSatisfy { statuses[$0.id] == .applied }
    }

    mutating func invalidatePending() {
        for index in entries.indices where !entries[index].status.terminal {
            entries[index].status = .unconfirmed
        }
        trimHistory()
    }

    private mutating func trimHistory() {
        // Retain enough confirmations for the dashboard's maximum 1,000-row
        // bulk operation to offer an honest Undo after the whole batch lands.
        let old = entries.filter { $0.status.terminal }.dropLast(1_000).map(\.id)
        let oldIDs = Set(old)
        entries.removeAll { oldIDs.contains($0.id) }
    }
}

/// Point reads cannot confuse a filtered-out row with a completed deletion.
/// These observations confirm saved state, not who changed it. Campaign
/// confirmation covers the campaign row and its retained contributing alerts.
enum V2MutationConfirmationReader {
    static func confirm(_ request: V2MutationRequest, alertStore: AlertStore?,
                        campaignStore: CampaignStore?, dataDir: String?) async -> V2MutationConfirmation {
        do {
            switch request.operation {
            case .suppressAlert, .unsuppressAlert, .deleteAlert:
                guard let alertStore else { return .unavailable("Alert store unavailable") }
                let alert = try await alertStore.alert(id: request.targetID)
                if request.operation == .deleteAlert { return alert == nil ? .applied : .pending }
                guard let alert else { return .unavailable("The alert is no longer available") }
                return alert.suppressed == (request.operation == .suppressAlert) ? .applied : .pending
            case .suppressCampaign, .unsuppressCampaign:
                guard let campaignStore, let alertStore else { return .unavailable("Campaign store unavailable") }
                guard let campaign = try await campaignStore.get(id: request.targetID) else {
                    return .unavailable("The campaign is no longer available")
                }
                let desired = request.operation == .suppressCampaign
                guard campaign.suppressed == desired else { return .pending }
                return try await alertStore.campaignSuppressionMatches(
                    campaignId: campaign.id, suppressed: desired) ? .applied : .pending
            case .liftSuppression:
                guard let dataDir else { return .unavailable("Suppression store unavailable") }
                guard UUID(uuidString: request.targetID) != nil else { return .unavailable("Invalid suppression identifier") }
                guard let document = try SuppressionFile.read(at: URL(fileURLWithPath: dataDir + "/suppressions_snapshot.json")) else {
                    return .unavailable("Suppression snapshot unavailable")
                }
                return document.entries.contains { $0.id == request.targetID } ? .pending : .applied
            }
        } catch {
            return .unavailable(error.localizedDescription)
        }
    }

    static func confirmSuppression(_ request: V2MutationRequest, data: Data) -> V2MutationConfirmation {
        guard UUID(uuidString: request.targetID) != nil,
              let document = try? SuppressionFile.decode(data: data) else {
            return .unavailable("Suppression state could not be read")
        }
        return document.entries.contains { $0.id == request.targetID } ? .pending : .applied
    }
}
