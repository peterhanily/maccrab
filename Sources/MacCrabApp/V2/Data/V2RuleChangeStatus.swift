import Foundation
import MacCrabCore

/// Confirmation describes saved configuration, never merely inbox acceptance
/// and never an unobserved detector reload.
struct V2RuleChange: Identifiable, Equatable, Sendable {
    enum Expected: Equatable, Sendable { case enabled(Bool), severity(String?), overrideRemoved, yaml(String) }
    enum Status: Equatable, Sendable { case queued, saved, unconfirmed }
    let id: UUID
    let ruleID: String
    let title: String
    let builtin: Bool
    let expected: Expected
    let requestedAt: Date
    var status: Status

    var statusText: String {
        switch status {
        case .queued: return String(localized: "rules.change.queued", defaultValue: "Queued — waiting for saved configuration")
        case .saved: return String(localized: "rules.change.saved", defaultValue: "Saved configuration confirmed; engine reload may still be pending")
        case .unconfirmed: return String(localized: "rules.change.unconfirmed", defaultValue: "Confirmation timed out. The request may still apply; review the current rule before retrying.")
        }
    }

    func savedStateMatches(directory: String) -> Bool? {
        let fm = FileManager.default
        if builtin {
            let path = directory + "/" + BuiltinRuleSettings.fileName
            guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)),
                  let settings = try? JSONDecoder().decode(BuiltinRuleSettings.self, from: data) else { return nil }
            let setting = settings.setting(forRuleId: ruleID)
            switch expected {
            case .enabled(let enabled): return (setting?.enabled ?? true) == enabled
            case .severity(let severity): return setting?.severityOverride?.rawValue == severity
            case .overrideRemoved, .yaml: return false
            }
        }
        if case .yaml(let expected) = self.expected {
            guard let saved = try? String(contentsOfFile: directory + "/user_rules/" + ruleID + ".yml", encoding: .utf8) else { return nil }
            return saved == expected
        }
        let path = directory + "/user_rules/" + ruleID + ".json"
        if expected == .overrideRemoved {
            // A read failure cannot establish absence.
            guard let files = try? fm.contentsOfDirectory(atPath: directory + "/user_rules") else { return nil }
            return !files.contains(ruleID + ".json")
        }
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)),
              let rule = try? JSONDecoder().decode(CompiledRule.self, from: data), rule.id == ruleID else { return nil }
        switch expected {
        case .enabled(let enabled): return rule.enabled == enabled
        case .severity(let severity): return rule.level.rawValue == severity
        case .overrideRemoved, .yaml: return false
        }
    }
}

struct V2RuleChangeTracker: Equatable, Sendable {
    private(set) var entries: [V2RuleChange] = []
    var pending: [V2RuleChange] { entries.filter { $0.status == .queued } }
    func canSubmit(ruleID: String) -> Bool { !pending.contains { $0.ruleID == ruleID } }

    mutating func queued(ruleID: String, title: String, builtin: Bool,
                         expected: V2RuleChange.Expected, now: Date = Date()) {
        guard canSubmit(ruleID: ruleID) else { return }
        entries.removeAll { $0.ruleID == ruleID && $0.status != .queued }
        entries.append(.init(id: UUID(), ruleID: ruleID, title: title, builtin: builtin,
                             expected: expected, requestedAt: now, status: .queued))
    }

    mutating func observe(id: UUID, saved: Bool?, now: Date = Date()) {
        guard let index = entries.firstIndex(where: { $0.id == id && $0.status == .queued }) else { return }
        if saved == true { entries[index].status = .saved }
        else if now.timeIntervalSince(entries[index].requestedAt) >= 120 { entries[index].status = .unconfirmed }
    }

    mutating func dismissCompleted() { entries.removeAll { $0.status != .queued } }
}
