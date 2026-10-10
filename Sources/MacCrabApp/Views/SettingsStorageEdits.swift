import Foundation
import CoreFoundation
import MacCrabCore

/// Only a control's explicit setter may create a storage override. Loading a
/// view or migrating its local preferences must not acquire policy ownership.
enum SettingsStorageField: String, CaseIterable {
    case eventsHotTierMinutes, eventsMaxSizeMB
    case alertsRetentionDays, alertsMaxSizeMB, evidenceMaxSizeMB
    case campaignsRetentionDays, campaignsMaxSizeMB

    var preferenceKey: String { "storage." + rawValue }

    var alias: String {
        switch self {
        case .eventsHotTierMinutes: return "events_hot_tier_minutes"
        case .eventsMaxSizeMB: return "events_max_size_mb"
        case .alertsRetentionDays: return "alerts_retention_days"
        case .alertsMaxSizeMB: return "alerts_max_size_mb"
        case .evidenceMaxSizeMB: return "evidence_max_size_mb"
        case .campaignsRetentionDays: return "campaigns_retention_days"
        case .campaignsMaxSizeMB: return "campaigns_max_size_mb"
        }
    }

    func normalized(_ value: Int, envelope: Int) -> Int {
        let range: ClosedRange<Int>
        switch self {
        case .eventsHotTierMinutes: range = 15...1440
        case .eventsMaxSizeMB: range = 162...2000
        case .alertsRetentionDays, .campaignsRetentionDays: range = 30...1095
        case .alertsMaxSizeMB: range = 50...500
        case .campaignsMaxSizeMB: range = 25...200
        case .evidenceMaxSizeMB:
            range = 50...min(500, max(162, envelope) - 112)
        }
        return min(range.upperBound, max(range.lowerBound, value))
    }
}

enum SettingsStorageEdits {
    enum Failure: Error { case unreadableOverrides, malformedOverrides }
    enum SaveResult: Equatable { case reloadQueued, savedAwaitingReload }

    static let maximumBytes = 1 * 1024 * 1024
    static var overridesURL: URL {
        URL(fileURLWithPath: NSHomeDirectory())
            .appendingPathComponent("Library/Application Support/MacCrab/user_overrides.json")
    }

    /// Shared by local preference migration and override hydration. Clamp hours
    /// before multiplication so even extreme legacy integers remain nontrapping.
    static func displayMinutes(fromLegacyHours hours: Int) -> Int {
        max(15, min(24, max(0, hours)) * 60)
    }

    private static func integer(_ value: Any) throws -> Int {
        guard let number = value as? NSNumber,
              CFGetTypeID(number) != CFBooleanGetTypeID(),
              let integer = value as? Int else { throw Failure.malformedOverrides }
        return integer
    }

    static func read(at url: URL) throws -> [String: Any] {
        switch BoundedRegularFileReader.readOutcome(at: url.path, maximumBytes: maximumBytes) {
        case .rejected(.notFound): return [:]
        case .rejected: throw Failure.unreadableOverrides
        case .success(let snapshot):
            guard let object = try? JSONSerialization.jsonObject(with: snapshot.data)
                    as? [String: Any],
                  object["storage"] == nil || object["storage"] is [String: Any] else {
                throw Failure.malformedOverrides
            }
            return object
        }
    }

    /// Match the daemon's exact legacy-generated classifier. Editing a sibling
    /// key must not turn its previously inherited envelope into an explicit 420.
    private static func hasGeneratedEnvelope(_ object: [String: Any]) -> Bool {
        guard object["maxDatabaseSizeMB"] == nil,
              object["max_database_size_mb"] == nil,
              let storage = object["storage"] as? [String: Any],
              Set(storage.keys) == Set(SettingsStorageField.allCases.map(\.rawValue)) else {
            return false
        }
        let old = SettingsStorageDefaultsSnapshot.generatedBeforeEnvelopeRebaseline
        let expected: [SettingsStorageField: Int] = [
            .eventsHotTierMinutes: old.eventsHotTierMinutes,
            .eventsMaxSizeMB: old.eventsMaxSizeMB,
            .alertsRetentionDays: old.alertsRetentionDays,
            .alertsMaxSizeMB: old.alertsMaxSizeMB,
            .evidenceMaxSizeMB: old.evidenceMaxSizeMB,
            .campaignsRetentionDays: old.campaignsRetentionDays,
            .campaignsMaxSizeMB: old.campaignsMaxSizeMB,
        ]
        return expected.allSatisfy { field, value in
            storage[field.rawValue].flatMap { try? integer($0) } == value
        }
    }

    static func explicitValues(in object: [String: Any]) throws -> [SettingsStorageField: Int] {
        let storage = object["storage"] as? [String: Any] ?? [:]
        var result: [SettingsStorageField: Int] = [:]
        for field in SettingsStorageField.allCases {
            if let value = storage[field.rawValue] {
                result[field] = try integer(value)
            }
        }
        // DaemonConfig folds top-level legacy camel-case values BEFORE the
        // nested snake-case aliases. A newer nested camel-case value wins all.
        if result[.eventsMaxSizeMB] == nil, let value = object["maxDatabaseSizeMB"] {
            result[.eventsMaxSizeMB] = try integer(value)
        }
        if let value = object["retentionDays"] {
            let days = try integer(value)
            if result[.alertsRetentionDays] == nil { result[.alertsRetentionDays] = days }
            if result[.campaignsRetentionDays] == nil { result[.campaignsRetentionDays] = days }
        }
        for field in SettingsStorageField.allCases where result[field] == nil {
            if let value = storage[field.alias] { result[field] = try integer(value) }
        }
        if result[.eventsHotTierMinutes] == nil,
           let rawHours = storage["eventsHotTierHours"] ?? storage["events_hot_tier_hours"] {
            let hours = try integer(rawHours)
            result[.eventsHotTierMinutes] = displayMinutes(fromLegacyHours: hours)
        }
        if hasGeneratedEnvelope(object) { result.removeValue(forKey: .eventsMaxSizeMB) }
        return result
    }

    private static func updateDisplayPreferences(
        _ explicit: [SettingsStorageField: Int], preferences: UserDefaults,
        inheritedEnvelopeMiB: Int? = nil, inheritedEvidenceMiB: Int? = nil
    ) {
        var values = explicit
        let envelope = SettingsStorageField.eventsMaxSizeMB.normalized(
            values[.eventsMaxSizeMB] ?? inheritedEnvelopeMiB
                ?? (preferences.object(forKey: "storage.eventsMaxSizeMB") as? Int) ?? 476,
            envelope: 476
        )
        values[.eventsMaxSizeMB] = envelope
        values[.evidenceMaxSizeMB] = values[.evidenceMaxSizeMB] ?? inheritedEvidenceMiB
            ?? (preferences.object(forKey: "storage.evidenceMaxSizeMB") as? Int) ?? 100
        for (field, value) in values {
            // Preserve raw override bytes, including advanced operator values,
            // while keeping the editable controls and their arithmetic bounded.
            preferences.set(field.normalized(value, envelope: envelope), forKey: field.preferenceKey)
        }
    }

    /// Hydration changes local display preferences only. An absent override
    /// stays absent, even when a fresh engine supplies its inherited value.
    static func hydrate(
        preferences: UserDefaults, at url: URL,
        inheritedEnvelopeMiB: Int? = nil, inheritedEvidenceMiB: Int? = nil
    ) throws {
        let values = try explicitValues(in: read(at: url))
        updateDisplayPreferences(
            values, preferences: preferences,
            inheritedEnvelopeMiB: inheritedEnvelopeMiB, inheritedEvidenceMiB: inheritedEvidenceMiB
        )
    }

    static func save(
        field: SettingsStorageField, value: Int, displayedEnvelopeMiB: Int,
        preferences: UserDefaults, at url: URL,
        persist: (Data, URL) throws -> Void = { try $0.write(to: $1, options: .atomic) },
        queueReload: () -> Bool
    ) throws -> SaveResult {
        var object = try read(at: url)
        let priorValues = try explicitValues(in: object)
        var storage = object["storage"] as? [String: Any] ?? [:]
        if hasGeneratedEnvelope(object) { storage.removeValue(forKey: "eventsMaxSizeMB") }
        let envelope = priorValues[.eventsMaxSizeMB] ?? displayedEnvelopeMiB
        var changed = [field: field.normalized(value, envelope: envelope)]
        if field == .eventsMaxSizeMB,
           let evidence = priorValues[.evidenceMaxSizeMB],
           let newEnvelope = changed[.eventsMaxSizeMB], newEnvelope < envelope,
           evidence > newEnvelope - 112 {
            changed[.evidenceMaxSizeMB] = newEnvelope - 112
        }
        for (changedField, changedValue) in changed { storage[changedField.rawValue] = changedValue }
        storage[SettingsStorageDefaultMigration.overrideGenerationKey] =
            SettingsStorageDefaultMigration.currentGeneration
        object["storage"] = storage
        let data = try JSONSerialization.data(withJSONObject: object, options: [.prettyPrinted, .sortedKeys])
        guard data.count <= maximumBytes else { throw Failure.malformedOverrides }
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        // Atomic file replacement is not a transaction with UserDefaults or
        // external config writers. Keep the durable policy first, then its UI.
        try persist(data, url)
        // A failed file write must not move local preferences ahead of policy.
        updateDisplayPreferences(
            priorValues.merging(changed, uniquingKeysWith: { _, edit in edit }),
            preferences: preferences, inheritedEnvelopeMiB: displayedEnvelopeMiB
        )
        return queueReload() ? .reloadQueued : .savedAwaitingReload
    }
}
