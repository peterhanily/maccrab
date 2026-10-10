import Foundation
import Testing
import SwiftUI
@testable import MacCrabApp

@Suite("Storage settings explicit edits")
struct StorageSettingsEditTests {
    private final class Fixture {
        let directory: URL
        let url: URL
        let suite = "maccrab-storage-settings-\(UUID())"
        let preferences: UserDefaults
        var reloads = 0

        init() throws {
            directory = FileManager.default.temporaryDirectory.resolvingSymlinksInPath()
                .appendingPathComponent("maccrab-storage-settings-\(UUID())")
            url = directory.appendingPathComponent("user_overrides.json")
            preferences = try #require(UserDefaults(suiteName: suite))
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        }

        deinit {
            preferences.removePersistentDomain(forName: suite)
            try? FileManager.default.removeItem(at: directory)
        }

        func write(_ object: [String: Any]) throws {
            try JSONSerialization.data(withJSONObject: object).write(to: url)
        }

        func storage() throws -> [String: Any] {
            try #require(SettingsStorageEdits.read(at: url)["storage"] as? [String: Any])
        }

        @discardableResult
        func save(_ field: SettingsStorageField, _ value: Int, displayedEnvelope: Int = 420,
                  queued: Bool = true) throws -> SettingsStorageEdits.SaveResult {
            try SettingsStorageEdits.save(
                field: field, value: value, displayedEnvelopeMiB: displayedEnvelope,
                preferences: preferences, at: url,
                queueReload: { self.reloads += 1; return queued }
            )
        }
    }

    private var generatedStorage: [String: Any] {
        ["eventsHotTierMinutes": 30, "eventsMaxSizeMB": 420,
         "alertsRetentionDays": 365, "alertsMaxSizeMB": 100,
         "evidenceMaxSizeMB": 100, "campaignsRetentionDays": 365,
         "campaignsMaxSizeMB": 50]
    }

    @Test("appearance does not materialize inherited policy or request a reload")
    func missingOverridesRemainAbsent() throws {
        let fixture = try Fixture()
        fixture.preferences.set(420, forKey: "storage.eventsMaxSizeMB")
        for _ in 0..<3 {
            try SettingsStorageEdits.hydrate(
                preferences: fixture.preferences, at: fixture.url,
                inheritedEnvelopeMiB: 2000, inheritedEvidenceMiB: 100
            )
        }
        #expect(fixture.preferences.integer(forKey: "storage.eventsMaxSizeMB") == 2000)
        #expect(!FileManager.default.fileExists(atPath: fixture.url.path))
        #expect(fixture.reloads == 0)
    }

    @Test("read-only hydration leaves a partial override byte-for-byte unchanged")
    func appearancePreservesPartialOverrides() throws {
        let fixture = try Fixture()
        try fixture.write(["storage": ["eventsHotTierMinutes": 15, "settingsDefaultsGeneration": 1]])
        let before = try Data(contentsOf: fixture.url)
        let beforeDate = try FileManager.default.attributesOfItem(atPath: fixture.url.path)[.modificationDate] as? Date
        fixture.preferences.set(420, forKey: "storage.eventsMaxSizeMB")
        for _ in 0..<3 {
            try SettingsStorageEdits.hydrate(
                preferences: fixture.preferences, at: fixture.url, inheritedEnvelopeMiB: 2000
            )
        }
        #expect(try Data(contentsOf: fixture.url) == before)
        let afterDate = try FileManager.default.attributesOfItem(atPath: fixture.url.path)[.modificationDate] as? Date
        #expect(afterDate == beforeDate)
        #expect(fixture.preferences.integer(forKey: "storage.eventsMaxSizeMB") == 2000)
        #expect(fixture.reloads == 0)
    }

    @Test("saved explicit cap beats stale UI preferences and older effective readback")
    func hydrationRespectsExplicitChoice() throws {
        let fixture = try Fixture()
        fixture.preferences.set(420, forKey: "storage.eventsMaxSizeMB")
        try fixture.write(["storage": ["eventsMaxSizeMB": 2000]])
        try SettingsStorageEdits.hydrate(
            preferences: fixture.preferences, at: fixture.url, inheritedEnvelopeMiB: 420
        )
        #expect(fixture.preferences.integer(forKey: "storage.eventsMaxSizeMB") == 2000)
        try fixture.write(["storage": ["eventsMaxSizeMB": 420]])
        try SettingsStorageEdits.hydrate(
            preferences: fixture.preferences, at: fixture.url, inheritedEnvelopeMiB: 2000
        )
        #expect(fixture.preferences.integer(forKey: "storage.eventsMaxSizeMB") == 420)
        #expect(fixture.reloads == 0)
    }

    @Test("an unrelated edit preserves explicit cap, unknown storage keys and top-level neighbors")
    func nestedMergePreservesOtherPolicy() throws {
        let fixture = try Fixture()
        try fixture.write([
            "storage": ["eventsMaxSizeMB": 2000, "evidenceMaxSizeMB": 100,
                        "processEventsFloorMinutes": 25, "tracesMaxSizeMB": 300,
                        "futureKnob": ["enabled": true]],
            "threatIntelEnabled": false, "futureTopLevel": ["version": 8],
        ])
        fixture.preferences.set(420, forKey: "storage.eventsMaxSizeMB")
        #expect(try fixture.save(.alertsRetentionDays, 395) == .reloadQueued)
        let object = try SettingsStorageEdits.read(at: fixture.url)
        let storage = try fixture.storage()
        #expect(storage["eventsMaxSizeMB"] as? Int == 2000)
        #expect(storage["alertsRetentionDays"] as? Int == 395)
        #expect(storage["evidenceMaxSizeMB"] as? Int == 100)
        #expect(storage["processEventsFloorMinutes"] as? Int == 25)
        #expect(storage["tracesMaxSizeMB"] as? Int == 300)
        #expect((storage["futureKnob"] as? [String: Bool])?["enabled"] == true)
        #expect(object["threatIntelEnabled"] as? Bool == false)
        #expect((object["futureTopLevel"] as? [String: Int])?["version"] == 8)
        #expect(fixture.reloads == 1)
    }

    @Test("an unrelated edit does not create an inherited events override")
    func explicitEditKeepsAbsentKeysAbsent() throws {
        let fixture = try Fixture()
        fixture.preferences.set(420, forKey: "storage.eventsMaxSizeMB")
        try fixture.save(.alertsRetentionDays, 395)
        let storage = try fixture.storage()
        #expect(Set(storage.keys) == ["alertsRetentionDays", "settingsDefaultsGeneration"])
        #expect(storage["eventsMaxSizeMB"] == nil)
        #expect(storage["evidenceMaxSizeMB"] == nil)
    }

    @Test("intentional 420 choices survive companion edits and current generation")
    func explicit420IsNotReclassified() throws {
        let fixture = try Fixture()
        var storage = generatedStorage
        storage["settingsDefaultsGeneration"] = 1
        try fixture.write(["storage": storage])
        try fixture.save(.alertsRetentionDays, 395, displayedEnvelope: 2000)
        #expect(try fixture.storage()["eventsMaxSizeMB"] as? Int == 420)
        try fixture.save(.eventsMaxSizeMB, 420, displayedEnvelope: 2000)
        #expect(try fixture.storage()["eventsMaxSizeMB"] as? Int == 420)
        #expect(fixture.preferences.integer(forKey: "storage.eventsMaxSizeMB") == 420)
    }

    @Test("a sibling edit preserves inheritance of the exact legacy-generated tuple")
    func generatedLegacyEnvelopeStaysInherited() throws {
        let fixture = try Fixture()
        try fixture.write(["storage": generatedStorage])
        try SettingsStorageEdits.hydrate(
            preferences: fixture.preferences, at: fixture.url, inheritedEnvelopeMiB: 2000
        )
        #expect(fixture.preferences.integer(forKey: "storage.eventsMaxSizeMB") == 2000)
        #expect(try fixture.storage()["eventsMaxSizeMB"] as? Int == 420)
        try fixture.save(.alertsRetentionDays, 395, displayedEnvelope: 2000)
        let storage = try fixture.storage()
        #expect(storage["eventsMaxSizeMB"] == nil)
        #expect(storage["alertsRetentionDays"] as? Int == 395)
        #expect(storage["evidenceMaxSizeMB"] as? Int == 100)
    }

    @Test("legacy explicit-cap provenance prevents generated-tuple reclassification")
    func legacyExplicitCapRemainsExplicit() throws {
        let fixture = try Fixture()
        try fixture.write(["storage": generatedStorage, "maxDatabaseSizeMB": 2000])
        try fixture.save(.alertsRetentionDays, 395, displayedEnvelope: 2000)
        #expect(try fixture.storage()["eventsMaxSizeMB"] as? Int == 420)
        #expect(try SettingsStorageEdits.read(at: fixture.url)["maxDatabaseSizeMB"] as? Int == 2000)
    }

    @Test("raising the envelope preserves evidence and updates both persistent surfaces")
    func envelopeIncreaseDoesNotChangeEvidence() throws {
        let fixture = try Fixture()
        try fixture.write(["storage": ["eventsMaxSizeMB": 420, "evidenceMaxSizeMB": 100]])
        fixture.preferences.set(420, forKey: "storage.eventsMaxSizeMB")
        fixture.preferences.set(100, forKey: "storage.evidenceMaxSizeMB")
        try fixture.save(.eventsMaxSizeMB, 2000)
        #expect(try fixture.storage()["eventsMaxSizeMB"] as? Int == 2000)
        #expect(try fixture.storage()["evidenceMaxSizeMB"] as? Int == 100)
        #expect(fixture.preferences.integer(forKey: "storage.eventsMaxSizeMB") == 2000)
        #expect(fixture.preferences.integer(forKey: "storage.evidenceMaxSizeMB") == 100)
    }

    @Test("an envelope reduction clamps only an explicit evidence value that no longer fits")
    func necessaryCoupledClamp() throws {
        let fixture = try Fixture()
        try fixture.write(["storage": ["eventsMaxSizeMB": 2000, "evidence_max_size_mb": 500,
                                       "eventsHotTierMinutes": 15]])
        try fixture.save(.eventsMaxSizeMB, 0, displayedEnvelope: 2000)
        let storage = try fixture.storage()
        #expect(storage["eventsMaxSizeMB"] as? Int == 162)
        #expect(storage["evidenceMaxSizeMB"] as? Int == 50)
        #expect(storage["eventsHotTierMinutes"] as? Int == 15)
        #expect(fixture.preferences.integer(forKey: "storage.evidenceMaxSizeMB") == 50)
    }

    @Test("inherited evidence stays absent and a feasible advanced evidence override is preserved")
    func noUnnecessaryEvidenceOverride() throws {
        let fixture = try Fixture()
        try fixture.write(["storage": ["eventsMaxSizeMB": 2000]])
        try fixture.save(.eventsMaxSizeMB, 162, displayedEnvelope: 2000)
        #expect(try fixture.storage()["evidenceMaxSizeMB"] == nil)
        try fixture.write(["storage": ["eventsMaxSizeMB": 1800, "evidenceMaxSizeMB": 700]])
        try fixture.save(.eventsMaxSizeMB, 2000, displayedEnvelope: 1800)
        #expect(try fixture.storage()["evidenceMaxSizeMB"] as? Int == 700)
    }

    @Test("evidence editing uses persisted envelope rather than a stale displayed envelope")
    func evidenceEditUsesStoredEnvelope() throws {
        let fixture = try Fixture()
        try fixture.write(["storage": ["events_max_size_mb": 2000, "evidenceMaxSizeMB": 100]])
        try fixture.save(.evidenceMaxSizeMB, 900, displayedEnvelope: 420)
        let storage = try fixture.storage()
        #expect(storage["evidenceMaxSizeMB"] as? Int == 500)
        #expect(storage["events_max_size_mb"] as? Int == 2000)
        #expect(storage["eventsMaxSizeMB"] == nil)
    }

    @Test("legacy top-level values precede nested aliases, matching daemon migration")
    func mixedLegacyAliasPrecedence() throws {
        let fixture = try Fixture()
        try fixture.write([
            "maxDatabaseSizeMB": 420, "retentionDays": 400,
            "storage": ["events_max_size_mb": 2000, "alerts_retention_days": 500,
                        "campaigns_retention_days": 600, "evidenceMaxSizeMB": 100],
        ])
        try SettingsStorageEdits.hydrate(preferences: fixture.preferences, at: fixture.url)
        #expect(fixture.preferences.integer(forKey: "storage.eventsMaxSizeMB") == 420)
        #expect(fixture.preferences.integer(forKey: "storage.alertsRetentionDays") == 400)
        #expect(fixture.preferences.integer(forKey: "storage.campaignsRetentionDays") == 400)
        try fixture.save(.evidenceMaxSizeMB, 500, displayedEnvelope: 2000)
        #expect(try fixture.storage()["evidenceMaxSizeMB"] as? Int == 308)

        try fixture.write([
            "maxDatabaseSizeMB": 420, "retentionDays": 400,
            "storage": ["eventsMaxSizeMB": 2000, "events_max_size_mb": 162,
                        "alertsRetentionDays": 700, "alerts_retention_days": 500],
        ])
        try SettingsStorageEdits.hydrate(preferences: fixture.preferences, at: fixture.url)
        #expect(fixture.preferences.integer(forKey: "storage.eventsMaxSizeMB") == 2000)
        #expect(fixture.preferences.integer(forKey: "storage.alertsRetentionDays") == 700)
        try fixture.save(.evidenceMaxSizeMB, 500, displayedEnvelope: 420)
        #expect(try fixture.storage()["evidenceMaxSizeMB"] as? Int == 500)
    }

    @Test("display hydration bounds extreme operator numbers without rewriting policy")
    func hydrationKeepsRenderingArithmeticSafe() throws {
        let fixture = try Fixture()
        try fixture.write(["storage": [
            "eventsMaxSizeMB": Int.min, "evidenceMaxSizeMB": Int.max,
            "alertsMaxSizeMB": Int.min, "campaignsMaxSizeMB": Int.max,
            "eventsHotTierMinutes": Int.max, "alertsRetentionDays": Int.min,
        ]])
        let before = try Data(contentsOf: fixture.url)
        try SettingsStorageEdits.hydrate(preferences: fixture.preferences, at: fixture.url)
        #expect(fixture.preferences.integer(forKey: "storage.eventsMaxSizeMB") == 162)
        #expect(fixture.preferences.integer(forKey: "storage.evidenceMaxSizeMB") == 50)
        #expect(fixture.preferences.integer(forKey: "storage.alertsMaxSizeMB") == 50)
        #expect(fixture.preferences.integer(forKey: "storage.campaignsMaxSizeMB") == 200)
        #expect(fixture.preferences.integer(forKey: "storage.eventsHotTierMinutes") == 1440)
        #expect(fixture.preferences.integer(forKey: "storage.alertsRetentionDays") == 30)
        #expect(try Data(contentsOf: fixture.url) == before)
        #expect(fixture.reloads == 0)
    }

    @Test("an envelope increase does not reduce an existing larger evidence intent")
    func envelopeIncreasePreservesOversizedEvidenceIntent() throws {
        let fixture = try Fixture()
        try fixture.write(["storage": ["eventsMaxSizeMB": 420, "evidenceMaxSizeMB": 500]])
        try fixture.save(.eventsMaxSizeMB, 520)
        #expect(try fixture.storage()["evidenceMaxSizeMB"] as? Int == 500)
        // The control reflects its feasible range, not a new evidence override.
        #expect(fixture.preferences.integer(forKey: "storage.evidenceMaxSizeMB") == 408)
    }

    @Test("legacy display-hours conversion preserves bounds without integer overflow")
    func legacyDisplayHoursAreBounded() {
        let cases: [(hours: Int, minutes: Int)] = [
            (.min, 15), (-1, 15), (0, 15), (1, 60), (2, 120),
            (23, 1380), (24, 1440), (25, 1440), (.max, 1440),
        ]
        for item in cases {
            #expect(SettingsStorageEdits.displayMinutes(fromLegacyHours: item.hours) == item.minutes)
        }
    }

    @Test("legacy hours hydrate safely without generating a minutes override")
    func legacyHoursAreDisplayOnly() throws {
        let fixture = try Fixture()
        for (hours, minutes) in [(Int.min, 15), (2, 120), (Int.max, 1440)] {
            try fixture.write(["storage": ["events_hot_tier_hours": hours]])
            let before = try Data(contentsOf: fixture.url)
            try SettingsStorageEdits.hydrate(preferences: fixture.preferences, at: fixture.url)
            #expect(fixture.preferences.integer(forKey: "storage.eventsHotTierMinutes") == minutes)
            #expect(try Data(contentsOf: fixture.url) == before)
        }
        #expect(fixture.reloads == 0)
    }

    @Test("saved and reload-queued are distinct outcomes, neither claims application")
    func unavailableEngineStillLeavesDurableIntent() throws {
        let fixture = try Fixture()
        #expect(try fixture.save(.eventsMaxSizeMB, 2000, queued: false) == .savedAwaitingReload)
        #expect(try fixture.storage()["eventsMaxSizeMB"] as? Int == 2000)
        #expect(fixture.preferences.integer(forKey: "storage.eventsMaxSizeMB") == 2000)
        #expect(fixture.reloads == 1)
    }

    @Test("malformed storage fails closed without changing bytes, preferences or reload count")
    func malformedOverridesAreNotReplaced() throws {
        let fixture = try Fixture()
        fixture.preferences.set(420, forKey: "storage.eventsMaxSizeMB")
        for payload in ["{", "[]", "{\"storage\":[]}", "{\"storage\":null}",
                        "{\"storage\":{\"eventsMaxSizeMB\":true}}",
                        "{\"storage\":{\"eventsMaxSizeMB\":420.5}}"] {
            let before = Data(payload.utf8)
            try before.write(to: fixture.url)
            #expect(throws: (any Error).self) {
                try fixture.save(.eventsMaxSizeMB, 2000)
            }
            #expect(try Data(contentsOf: fixture.url) == before)
            #expect(fixture.preferences.integer(forKey: "storage.eventsMaxSizeMB") == 420)
            #expect(fixture.reloads == 0)
        }
    }

    @Test("a non-file override is a read failure, not an empty configuration")
    func nonFileOverridesAreNotReplaced() throws {
        let fixture = try Fixture()
        try FileManager.default.createDirectory(at: fixture.url, withIntermediateDirectories: false)
        fixture.preferences.set(420, forKey: "storage.eventsMaxSizeMB")
        #expect(throws: (any Error).self) { try fixture.save(.eventsMaxSizeMB, 2000) }
        var isDirectory: ObjCBool = false
        #expect(FileManager.default.fileExists(atPath: fixture.url.path, isDirectory: &isDirectory))
        #expect(isDirectory.boolValue)
        #expect(fixture.preferences.integer(forKey: "storage.eventsMaxSizeMB") == 420)
        #expect(fixture.reloads == 0)
    }

    @Test("post-read persistence failure leaves preferences and reload state untouched")
    func persistenceFailureDoesNotAdvanceUI() throws {
        enum TestFailure: Error { case refused }
        let fixture = try Fixture()
        try fixture.write(["storage": ["eventsMaxSizeMB": 420]])
        let before = try Data(contentsOf: fixture.url)
        fixture.preferences.set(420, forKey: "storage.eventsMaxSizeMB")
        var attemptedWrites = 0
        #expect(throws: TestFailure.self) {
            try SettingsStorageEdits.save(
                field: .eventsMaxSizeMB, value: 2000, displayedEnvelopeMiB: 420,
                preferences: fixture.preferences, at: fixture.url,
                persist: { _, _ in attemptedWrites += 1; throw TestFailure.refused },
                queueReload: { fixture.reloads += 1; return true }
            )
        }
        #expect(attemptedWrites == 1)
        #expect(try Data(contentsOf: fixture.url) == before)
        #expect(fixture.preferences.integer(forKey: "storage.eventsMaxSizeMB") == 420)
        #expect(fixture.reloads == 0)
    }

    @Test("the Settings view wires explicit setters and has no storage notification writer")
    func viewUsesExplicitEditBindings() throws {
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent()
        let view = try String(contentsOf: root.appendingPathComponent("Sources/MacCrabApp/Views/SettingsView.swift"))
        for field in SettingsStorageField.allCases {
            #expect(view.contains("storageBinding(.\(field.rawValue), $\(field.rawValue))"))
            #expect(!view.contains(".onChange(of: \(field.rawValue))"))
        }
        #expect(!view.contains("syncStorageOverrides()"))
        #expect(view.contains("migrateLegacyStorageKeys()\n                        hydrateStorageOverrides()"))
        #expect(view.contains("eventsHotTierMinutes = SettingsStorageEdits.displayMinutes(fromLegacyHours: legacyHours)"))
        #expect(!view.contains("legacyHours * 60"))
        #expect(view.contains("storageSession.binding("))
        #expect(view.contains("try storageSession.appear("))
    }

    @Test("production appearance and binding lifecycle writes only for an explicit edit")
    func productionBindingLifecycle() throws {
        let fixture = try Fixture()
        try fixture.write(["storage": ["eventsMaxSizeMB": 2000, "futureKnob": 7]])
        let before = try Data(contentsOf: fixture.url)
        var writes = 0
        var saves: [SettingsStorageEdits.SaveResult] = []
        var failures = 0
        func session() -> SettingsStorageSession {
            SettingsStorageSession(
                preferences: fixture.preferences, url: fixture.url,
                persist: { data, url in writes += 1; try data.write(to: url, options: .atomic) },
                queueReload: { fixture.reloads += 1; return true }
            )
        }
        let first = session()
        try first.appear(inheritedEnvelopeMiB: 476)
        let display = Binding<Int>(
            get: { fixture.preferences.integer(forKey: "storage.eventsMaxSizeMB") },
            set: { fixture.preferences.set($0, forKey: "storage.eventsMaxSizeMB") }
        )
        let binding = first.binding(.eventsMaxSizeMB, display: display,
            displayedEnvelopeMiB: { display.wrappedValue }, onSave: { result in
                switch result {
                case .success(let value): saves.append(value)
                case .failure: failures += 1
                }
            })
        #expect(binding.wrappedValue == 2000)
        // Simulate local display notifications, then reopening the same policy.
        fixture.preferences.set(420, forKey: "storage.eventsMaxSizeMB")
        try session().appear(inheritedEnvelopeMiB: 476)
        #expect(binding.wrappedValue == 2000)
        #expect(try Data(contentsOf: fixture.url) == before)
        #expect(writes == 0)
        #expect(fixture.reloads == 0)
        #expect(saves.isEmpty)
        binding.wrappedValue = 1900
        #expect(writes == 1)
        #expect(binding.wrappedValue == 1900)
        #expect(fixture.reloads == 1)
        #expect(saves == [.reloadQueued])
        #expect(failures == 0)
        #expect(try fixture.storage()["eventsMaxSizeMB"] as? Int == 1900)
        #expect(try fixture.storage()["futureKnob"] as? Int == 7)
        let edited = try Data(contentsOf: fixture.url)
        try session().appear(inheritedEnvelopeMiB: 476)
        #expect(try Data(contentsOf: fixture.url) == edited)
        #expect(writes == 1)
        #expect(fixture.reloads == 1)
    }

    @Test("production binding reports persistence failure without reload or display advancement")
    func productionBindingFailure() throws {
        enum Refused: Error { case write }
        let fixture = try Fixture()
        try fixture.write(["storage": ["eventsMaxSizeMB": 2000]])
        let before = try Data(contentsOf: fixture.url)
        var failures = 0
        var displaySets = 0
        let session = SettingsStorageSession(
            preferences: fixture.preferences, url: fixture.url,
            persist: { _, _ in throw Refused.write },
            queueReload: { fixture.reloads += 1; return true }
        )
        try session.appear()
        let binding = session.binding(.eventsMaxSizeMB,
            display: Binding(get: { fixture.preferences.integer(forKey: "storage.eventsMaxSizeMB") }, set: {
                displaySets += 1
                fixture.preferences.set($0, forKey: "storage.eventsMaxSizeMB")
            }),
            displayedEnvelopeMiB: { 2000 }, onSave: { result in
                if case .failure = result { failures += 1 }
            })
        binding.wrappedValue = 1900
        #expect(failures == 1)
        #expect(displaySets == 0)
        #expect(fixture.reloads == 0)
        #expect(binding.wrappedValue == 2000)
        #expect(try Data(contentsOf: fixture.url) == before)
    }
}
