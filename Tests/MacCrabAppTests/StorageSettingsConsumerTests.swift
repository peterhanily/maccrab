import Darwin
import Foundation
import MacCrabCore
import SwiftUI
import Testing
@testable import MacCrabAgentKit
@testable import MacCrabApp

/// Exercises the real Settings writer and daemon consumer without enumerating
/// accounts, consulting admin membership, signalling an engine, or touching
/// installed preferences/configuration. This is not installed reload evidence.
@Suite("Settings saved storage → daemon override consumer")
struct StorageSettingsConsumerTests {
    private final class Fixture {
        let directory: URL
        let system: URL
        let home: RealUserHome
        let url: URL
        let suite = "maccrab-storage-consumer-\(UUID())"
        let preferences: UserDefaults
        var reloads = 0

        init() throws {
            directory = FileManager.default.temporaryDirectory.resolvingSymlinksInPath()
                .appendingPathComponent("maccrab-storage-consumer-\(UUID())")
            system = directory.appendingPathComponent("system")
            home = RealUserHome(path: directory.appendingPathComponent("fixture-home").path,
                                userID: getuid(), userName: "fixture")
            url = URL(fileURLWithPath: home.appending("Library/Application Support/MacCrab/user_overrides.json"))
            preferences = try #require(UserDefaults(suiteName: suite))
            try FileManager.default.createDirectory(at: system, withIntermediateDirectories: true)
            try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        }

        deinit {
            preferences.removePersistentDomain(forName: suite)
            try? FileManager.default.removeItem(at: directory)
        }

        func write(_ object: [String: Any], at destination: URL? = nil) throws {
            try JSONSerialization.data(withJSONObject: object).write(to: destination ?? url, options: .atomic)
        }

        func systemConfig(_ object: [String: Any]) throws {
            try write(object, at: system.appendingPathComponent("daemon_config.json"))
        }

        func load(homes: [RealUserHome]? = nil, isAdmin: @escaping (UInt32) -> Bool = { _ in true }) -> DaemonConfig {
            let selectedHomes = homes ?? [home]
            return DaemonConfig.load(from: system.path, overrideEnvironment: .init(
                homes: { selectedHomes }, isAdmin: isAdmin
            ))
        }

        func edit(_ field: SettingsStorageField, _ value: Int, envelope: Int = 700) throws {
            let session = SettingsStorageSession(preferences: preferences, url: url,
                queueReload: { self.reloads += 1; return true })
            var outcome: Result<SettingsStorageEdits.SaveResult, Error>?
            let binding = session.binding(field, display: Binding(get: { 0 }, set: { _ in }),
                displayedEnvelopeMiB: { envelope }, onSave: { outcome = $0 })
            binding.wrappedValue = value
            let result = try #require(outcome)
            #expect(try result.get() == .reloadQueued)
        }
    }

    private var oldGeneratedStorage: [String: Any] {
        ["eventsHotTierMinutes": 30, "eventsMaxSizeMB": 420,
         "alertsRetentionDays": 365, "alertsMaxSizeMB": 100,
         "evidenceMaxSizeMB": 100, "campaignsRetentionDays": 365,
         "campaignsMaxSizeMB": 50]
    }

    @Test("all seven explicit Settings bindings persist bytes consumed by the engine")
    func sevenSavedEditsReachRealConsumer() throws {
        let fixture = try Fixture()
        try fixture.systemConfig(["behaviorAlertThreshold": 15,
                                  "storage": ["aggregateDays": 61, "processEventsFloorMinutes": 80]])
        let edits: [(SettingsStorageField, Int)] = [
            (.eventsHotTierMinutes, 45), (.eventsMaxSizeMB, 700),
            (.alertsRetentionDays, 90), (.alertsMaxSizeMB, 180),
            (.evidenceMaxSizeMB, 120), (.campaignsRetentionDays, 120), (.campaignsMaxSizeMB, 75),
        ]
        for (field, value) in edits { try fixture.edit(field, value) }
        let config = fixture.load()
        #expect(config.storage.eventsHotTierMinutes == 45)
        #expect(config.storage.eventsMaxSizeMB == 700)
        #expect(config.storage.alertsRetentionDays == 90)
        #expect(config.storage.alertsMaxSizeMB == 180)
        #expect(config.storage.evidenceMaxSizeMB == 120)
        #expect(config.storage.campaignsRetentionDays == 120)
        #expect(config.storage.campaignsMaxSizeMB == 75)
        #expect(config.storage.aggregateDays == 61)
        #expect(config.storage.processEventsFloorMinutes == 80)
        #expect(config.behaviorAlertThreshold == 15)
        #expect(fixture.reloads == 7)
        #expect(config.storage.clampedToSafeFloors() == config.storage)
    }

    @Test("an omitted override stays inherited after a real single-field save")
    func omittedKeysRemainInherited() throws {
        let fixture = try Fixture()
        try fixture.systemConfig(["storage": ["eventsMaxSizeMB": 2000, "evidenceMaxSizeMB": 300,
                                               "campaignsRetentionDays": 450]])
        try fixture.edit(.alertsRetentionDays, 90, envelope: 2000)
        let saved = try #require(SettingsStorageEdits.read(at: fixture.url)["storage"] as? [String: Any])
        #expect(Set(saved.keys) == ["alertsRetentionDays", "settingsDefaultsGeneration"])
        let config = fixture.load()
        #expect(config.storage.eventsMaxSizeMB == 2000)
        #expect(config.storage.evidenceMaxSizeMB == 300)
        #expect(config.storage.campaignsRetentionDays == 450)
        #expect(config.storage.alertsRetentionDays == 90)
    }

    @Test("generated legacy values inherit but a saved intentional prior cap wins")
    func generatedVersusIntentional() throws {
        let fixture = try Fixture()
        try fixture.systemConfig(["storage": ["eventsMaxSizeMB": 2000]])
        try fixture.write(["storage": oldGeneratedStorage])
        #expect(fixture.load().storage.eventsMaxSizeMB == 2000)
        try fixture.edit(.alertsRetentionDays, 395, envelope: 2000)
        #expect(fixture.load().storage.eventsMaxSizeMB == 2000)
        #expect(fixture.load().storage.alertsRetentionDays == 395)
        try fixture.edit(.eventsMaxSizeMB, 420, envelope: 2000)
        #expect(fixture.load().storage.eventsMaxSizeMB == 420)
        var explicit = oldGeneratedStorage
        explicit["settingsDefaultsGeneration"] = 1
        try fixture.write(["storage": explicit])
        #expect(fixture.load().storage.eventsMaxSizeMB == 420)
    }

    @Test("new nested keys beat legacy top-level keys, which beat nested aliases")
    func legacyPrecedenceUsesRealConsumer() throws {
        let fixture = try Fixture()
        try fixture.write(["maxDatabaseSizeMB": 800, "retentionDays": 180,
            "storage": ["events_max_size_mb": 900, "alertsRetentionDays": 90,
                        "campaigns_retention_days": 270]])
        let config = fixture.load()
        #expect(config.storage.eventsMaxSizeMB == 800)
        #expect(config.storage.alertsRetentionDays == 90)
        #expect(config.storage.campaignsRetentionDays == 180)
        try fixture.write(["maxDatabaseSizeMB": 800, "storage": ["eventsMaxSizeMB": 1000]])
        #expect(fixture.load().storage.eventsMaxSizeMB == 1000)
    }

    @Test("descriptor ownership and administrator membership both gate overrides")
    func ownerAndAdminAreRequired() throws {
        let fixture = try Fixture()
        try fixture.edit(.eventsMaxSizeMB, 700)
        let wrongOwner = RealUserHome(path: fixture.home.path, userID: getuid() == 0 ? 501 : 0,
                                     userName: "wrong-owner")
        var adminChecks = 0
        let rejectedOwner = fixture.load(homes: [wrongOwner], isAdmin: { _ in adminChecks += 1; return true })
        #expect(rejectedOwner.storage.eventsMaxSizeMB == DaemonConfig().storage.eventsMaxSizeMB)
        #expect(adminChecks == 0)
        let rejectedAdmin = fixture.load(isAdmin: { uid in
            #expect(uid == fixture.home.userID)
            adminChecks += 1
            return false
        })
        #expect(rejectedAdmin.storage.eventsMaxSizeMB == DaemonConfig().storage.eventsMaxSizeMB)
        #expect(adminChecks == 1)
        #expect(fixture.load().storage.eventsMaxSizeMB == 700)
    }

    @Test("newest authorized file wins independently of enumeration order")
    func freshnessSelection() throws {
        let older = try Fixture()
        let newer = try Fixture()
        try older.edit(.eventsMaxSizeMB, 700)
        try newer.edit(.eventsMaxSizeMB, 900)
        try FileManager.default.setAttributes([.modificationDate: Date(timeIntervalSince1970: 1_000)],
                                              ofItemAtPath: older.url.path)
        try FileManager.default.setAttributes([.modificationDate: Date(timeIntervalSince1970: 2_000)],
                                              ofItemAtPath: newer.url.path)
        for homes in [[older.home, newer.home], [newer.home, older.home]] {
            #expect(older.load(homes: homes).storage.eventsMaxSizeMB == 900)
        }
        let unauthorizedNewer = RealUserHome(path: newer.home.path,
            userID: getuid() == 0 ? 501 : 0, userName: "wrong-owner")
        #expect(older.load(homes: [unauthorizedNewer, older.home]).storage.eventsMaxSizeMB == 700)
        // A malformed newest policy does not silently resurrect an older one.
        try Data("not JSON".utf8).write(to: newer.url)
        #expect(older.load(homes: [newer.home, older.home]).storage.eventsMaxSizeMB
                == DaemonConfig().storage.eventsMaxSizeMB)
    }

    @Test("malformed or unsafe override carriers cannot change storage")
    func malformedAndUnsafeInputs() throws {
        let fixture = try Fixture()
        let initial = DaemonConfig().storage
        for raw in ["{", "[]", "null", "{\"storage\":\"wrong type\"}",
                    "{\"storage\":{\"eventsMaxSizeMB\":\"700\"}}"] {
            try Data(raw.utf8).write(to: fixture.url)
            #expect(fixture.load().storage == initial)
        }
        try Data(repeating: 32, count: DaemonConfig.maximumConfigurationBytes + 1).write(to: fixture.url)
        #expect(fixture.load().storage == initial)
        try FileManager.default.removeItem(at: fixture.url)
        let target = fixture.directory.appendingPathComponent("link-target.json")
        try fixture.write(["storage": ["eventsMaxSizeMB": 700]], at: target)
        try FileManager.default.createSymbolicLink(at: fixture.url, withDestinationURL: target)
        #expect(fixture.load().storage == initial)
    }

    @Test("override allowlist cannot change security knobs and preserves runtime safe floors")
    func forbiddenFieldsAndSafeFloors() throws {
        let fixture = try Fixture()
        try fixture.systemConfig(["statisticalZThreshold": 4, "subscribeFileOpenEvents": true,
                                  "outputs": [["type": "file", "path": "fixture-output"]]])
        try fixture.write(["statisticalZThreshold": 0, "subscribeFileOpenEvents": false,
            "outputs": [], "ruleProfile": "all",
            "storage": ["eventsHotTierMinutes": -1, "eventsMaxSizeMB": -1,
                        "evidenceMaxSizeMB": -1, "alertsRetentionDays": -1,
                        "alertsMaxSizeMB": -1, "campaignsRetentionDays": -1,
                        "campaignsMaxSizeMB": -1]])
        let config = fixture.load()
        #expect(config.statisticalZThreshold == 4)
        #expect(config.subscribeFileOpenEvents)
        #expect(config.ruleProfile == DaemonConfig().ruleProfile)
        #expect(config.outputs.count == 1)
        #expect(config.outputs.first?.type == "file")
        #expect(config.outputs.first?.path == "fixture-output")
        // Boot and SIGHUP both use this production clamp after reading config.
        // The consumer retains raw intent; it must not bypass these floors.
        let effective = config.storage.clampedToSafeFloors()
        #expect(effective.eventsHotTierMinutes >= 15)
        #expect(effective.effectiveEventsFamilyMaxSizeMB >= DaemonConfig.StorageConfig.minimumEventsSizeMiB)
        #expect(effective.evidenceMaxSizeMB >= 50)
        #expect(effective.alertsRetentionDays >= 1)
        #expect(effective.alertsMaxSizeMB >= 50)
        #expect(effective.campaignsRetentionDays >= 1)
        #expect(effective.campaignsMaxSizeMB >= 50)
    }
}
