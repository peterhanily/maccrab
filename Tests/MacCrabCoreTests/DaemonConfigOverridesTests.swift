// DaemonConfigOverridesTests.swift
//
// v1.6.14: regression tests for the user_overrides.json overlay path
// that wires the dashboard's storage sliders to the sysext.
// v1.8.0: rewritten for the per-tier `storage` block. Legacy
// retentionDays / maxDatabaseSizeMB inputs still work — they get
// folded onto the new fields by `migrateLegacyStorageKeys`.

import Testing
import Foundation
@testable import MacCrabAgentKit

@Suite("DaemonConfig: user_overrides.json overlay (v1.6.14 / v1.8.0)")
struct DaemonConfigOverridesTests {

    private func oldGeneratedSettingsStorage() -> [String: Any] {
        [
            "eventsHotTierMinutes": 30,
            "eventsMaxSizeMB": 420,
            "alertsRetentionDays": 365,
            "alertsMaxSizeMB": 100,
            "evidenceMaxSizeMB": 100,
            "campaignsRetentionDays": 365,
            "campaignsMaxSizeMB": 50,
        ]
    }

    /// When no `daemon_config.json` exists, `load` returns pure defaults
    /// — this is the pre-v1.6.14 behavior and must not regress.
    @Test("load returns defaults when no config file present")
    func loadDefaults() {
        let tmp = NSTemporaryDirectory() + "MacCrabCfgTest-\(UUID().uuidString)"
        try? FileManager.default.createDirectory(atPath: tmp, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: tmp) }

        let cfg = DaemonConfig.load(from: tmp, applyOverrides: false)
        #expect(cfg.storage.eventsMaxSizeMB == 440)   // v1.21.6-rc.12: measured 15-minute floor
        #expect(cfg.storage.eventsHotTierMinutes == 30)
        #expect(cfg.storage.alertsRetentionDays == 365)
        #expect(cfg.storage.campaignsRetentionDays == 365)
        #expect(cfg.storage.aggregateDays == 90)
    }

    @Test("the prior 420 MiB value remains authoritative when explicitly configured")
    func explicitPriorDefaultIsPreserved() throws {
        let tmp = NSTemporaryDirectory()
            + "MacCrabCfgTest-\(UUID().uuidString)"
        try FileManager.default.createDirectory(
            atPath: tmp,
            withIntermediateDirectories: true
        )
        defer { try? FileManager.default.removeItem(atPath: tmp) }

        let json = #"{"storage":{"events_max_size_mb":420}}"#
        try json.write(
            toFile: tmp + "/daemon_config.json",
            atomically: true,
            encoding: .utf8
        )

        let cfg = DaemonConfig.load(from: tmp, applyOverrides: false)
        #expect(cfg.storage.eventsMaxSizeMB == 420)
    }

    @Test("old complete Settings-generated storage tuple inherits the new default")
    func oldGeneratedSettingsTupleRebaselinesWithoutOpeningUI() throws {
        // Parse the production JSON shape rather than constructing only Swift
        // integers, so Foundation's NSNumber bridging is covered too.
        let data = """
        {
          "storage": {
            "eventsHotTierMinutes": 30,
            "eventsMaxSizeMB": 420,
            "alertsRetentionDays": 365,
            "alertsMaxSizeMB": 100,
            "evidenceMaxSizeMB": 100,
            "campaignsRetentionDays": 365,
            "campaignsMaxSizeMB": 50
          }
        }
        """.data(using: .utf8)!
        let object = try #require(
            JSONSerialization.jsonObject(with: data) as? [String: Any]
        )
        var overrideObject = object
        #expect(DaemonConfig.rebaselineGeneratedSettingsOverrides(
            &overrideObject,
            inheritedEventsMaxSizeMB: 440
        ))
        let storage = try #require(
            overrideObject["storage"] as? [String: Any]
        )
        #expect(storage["eventsMaxSizeMB"] as? Int == 440)
        // The ownership split and retention controls are not reclassified.
        #expect(storage["evidenceMaxSizeMB"] as? Int == 100)
        #expect(storage["alertsRetentionDays"] as? Int == 365)
    }

    @Test("partial manual 420 override is preserved")
    func partialPriorCapIsNotGeneratedTuple() {
        var storage: [String: Any] = ["eventsMaxSizeMB": 420]
        #expect(!DaemonConfig.rebaselineGeneratedSettingsStorage(
            &storage,
            inheritedEventsMaxSizeMB: 440
        ))
        #expect(storage["eventsMaxSizeMB"] as? Int == 420)
    }

    @Test("complete but tuned Settings tuple preserves 420")
    func tunedSettingsTupleIsNotReclassified() {
        var storage = oldGeneratedSettingsStorage()
        storage["eventsHotTierMinutes"] = 60
        #expect(!DaemonConfig.rebaselineGeneratedSettingsStorage(
            &storage,
            inheritedEventsMaxSizeMB: 440
        ))
        #expect(storage["eventsMaxSizeMB"] as? Int == 420)
    }

    @Test("current Settings generation marker preserves intentional 420")
    func currentGenerationPreservesPriorCap() {
        var storage = oldGeneratedSettingsStorage()
        storage["settingsDefaultsGeneration"] = 1
        #expect(!DaemonConfig.rebaselineGeneratedSettingsStorage(
            &storage,
            inheritedEventsMaxSizeMB: 440
        ))
        #expect(storage["eventsMaxSizeMB"] as? Int == 420)
    }

    @Test("legacy top-level cap provenance blocks generated-tuple migration")
    func legacyCapProvenancePreservesPriorCap() throws {
        for legacyKey in ["maxDatabaseSizeMB", "max_database_size_mb"] {
            var object: [String: Any] = [
                "storage": oldGeneratedSettingsStorage(),
                legacyKey: 420,
            ]
            #expect(!DaemonConfig.rebaselineGeneratedSettingsOverrides(
                &object,
                inheritedEventsMaxSizeMB: 440
            ))
            let storage = try #require(
                object["storage"] as? [String: Any]
            )
            #expect(storage["eventsMaxSizeMB"] as? Int == 420)
        }
    }

    @Test("generated UI default does not shadow explicit daemon config")
    func generatedDefaultInheritsExplicitSystemConfiguration() {
        var storage = oldGeneratedSettingsStorage()
        #expect(DaemonConfig.rebaselineGeneratedSettingsStorage(
            &storage,
            inheritedEventsMaxSizeMB: 512
        ))
        #expect(storage["eventsMaxSizeMB"] as? Int == 512)
    }

    /// v1.6.14 + v1.8.0: snake_case `max_database_size_mb` and
    /// `retention_days` are LEGACY keys. They must still load — folded
    /// onto storage.eventsMaxSizeMB / storage.alertsRetentionDays /
    /// storage.campaignsRetentionDays.
    @Test("legacy snake_case keys fold onto storage block")
    func legacySnakeCaseKeys() throws {
        let tmp = NSTemporaryDirectory() + "MacCrabCfgTest-\(UUID().uuidString)"
        try FileManager.default.createDirectory(atPath: tmp, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: tmp) }

        let json = """
        {
          "max_database_size_mb": 250,
          "retention_days": 7,
          "behavior_alert_threshold": 15.0
        }
        """
        try json.write(
            toFile: tmp + "/daemon_config.json",
            atomically: true,
            encoding: .utf8
        )

        let cfg = DaemonConfig.load(from: tmp, applyOverrides: false)
        #expect(cfg.storage.eventsMaxSizeMB == 250)
        #expect(cfg.storage.alertsRetentionDays == 7)
        #expect(cfg.storage.campaignsRetentionDays == 7)
        #expect(cfg.behaviorAlertThreshold == 15.0)
    }

    /// camelCase legacy keys: same migration semantics.
    @Test("legacy camelCase keys fold onto storage block")
    func legacyCamelCaseKeys() throws {
        let tmp = NSTemporaryDirectory() + "MacCrabCfgTest-\(UUID().uuidString)"
        try FileManager.default.createDirectory(atPath: tmp, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: tmp) }

        let json = """
        {
          "maxDatabaseSizeMB": 300,
          "retentionDays": 14
        }
        """
        try json.write(
            toFile: tmp + "/daemon_config.json",
            atomically: true,
            encoding: .utf8
        )

        let cfg = DaemonConfig.load(from: tmp, applyOverrides: false)
        #expect(cfg.storage.eventsMaxSizeMB == 300)
        #expect(cfg.storage.alertsRetentionDays == 14)
        #expect(cfg.storage.campaignsRetentionDays == 14)
    }

    /// New v1.8.0 shape: `storage` block with full per-tier control.
    @Test("v1.8.0 storage block shape decodes")
    func newStorageBlockShape() throws {
        let tmp = NSTemporaryDirectory() + "MacCrabCfgTest-\(UUID().uuidString)"
        try FileManager.default.createDirectory(atPath: tmp, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: tmp) }

        let json = """
        {
          "storage": {
            "eventsHotTierMinutes": 360,
            "eventsMaxSizeMB": 500,
            "aggregateDays": 60,
            "alertsRetentionDays": 180,
            "alertsMaxSizeMB": 250,
            "campaignsRetentionDays": 180,
            "campaignsMaxSizeMB": 75
          }
        }
        """
        try json.write(toFile: tmp + "/daemon_config.json", atomically: true, encoding: .utf8)

        let cfg = DaemonConfig.load(from: tmp, applyOverrides: false)
        #expect(cfg.storage.eventsHotTierMinutes == 360)
        #expect(cfg.storage.eventsMaxSizeMB == 500)
        #expect(cfg.storage.aggregateDays == 60)
        #expect(cfg.storage.alertsRetentionDays == 180)
        #expect(cfg.storage.alertsMaxSizeMB == 250)
        #expect(cfg.storage.campaignsRetentionDays == 180)
        #expect(cfg.storage.campaignsMaxSizeMB == 75)
    }

    /// New v1.8.0 shape: snake_case nested keys also rewrite.
    @Test("v1.8.0 storage block snake_case keys rewrite")
    func newStorageBlockSnakeCase() throws {
        let tmp = NSTemporaryDirectory() + "MacCrabCfgTest-\(UUID().uuidString)"
        try FileManager.default.createDirectory(atPath: tmp, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: tmp) }

        let json = """
        {
          "storage": {
            "events_hot_tier_minutes": 90,
            "alerts_retention_days": 90
          }
        }
        """
        try json.write(toFile: tmp + "/daemon_config.json", atomically: true, encoding: .utf8)

        let cfg = DaemonConfig.load(from: tmp, applyOverrides: false)
        #expect(cfg.storage.eventsHotTierMinutes == 90)
        #expect(cfg.storage.alertsRetentionDays == 90)
    }

    /// v1.18.0: tracegraph + traces caps (previously hardcoded in
    /// DaemonTimers, absent from config) decode in both camelCase and
    /// snake_case shapes, and default sensibly when omitted.
    @Test("v1.18.0 tracegraph/traces storage keys decode (camelCase)")
    func tracegraphTracesKeysCamel() throws {
        let tmp = NSTemporaryDirectory() + "MacCrabCfgTest-\(UUID().uuidString)"
        try FileManager.default.createDirectory(atPath: tmp, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: tmp) }

        let json = """
        {
          "storage": {
            "tracegraphRetentionDays": 30,
            "tracegraphMaxSizeMB": 500,
            "tracesRetentionDays": 14,
            "tracesMaxSizeMB": 64,
            "reportsRetentionDays": 45,
            "autoGeneratedRulesMax": 50
          }
        }
        """
        try json.write(toFile: tmp + "/daemon_config.json", atomically: true, encoding: .utf8)

        let cfg = DaemonConfig.load(from: tmp, applyOverrides: false)
        #expect(cfg.storage.tracegraphRetentionDays == 30)
        #expect(cfg.storage.tracegraphMaxSizeMB == 500)
        #expect(cfg.storage.tracesRetentionDays == 14)
        #expect(cfg.storage.tracesMaxSizeMB == 64)
        #expect(cfg.storage.reportsRetentionDays == 45)
        #expect(cfg.storage.autoGeneratedRulesMax == 50)
        // Untouched tiers stay at their defaults.
        #expect(cfg.storage.eventsMaxSizeMB == 440)   // v1.21.6-rc.12 default
    }

    @Test("v1.18.0 tracegraph/traces storage keys decode (snake_case)")
    func tracegraphTracesKeysSnake() throws {
        let tmp = NSTemporaryDirectory() + "MacCrabCfgTest-\(UUID().uuidString)"
        try FileManager.default.createDirectory(atPath: tmp, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: tmp) }

        let json = """
        {
          "storage": {
            "tracegraph_retention_days": 45,
            "tracegraph_max_size_mb": 300,
            "traces_retention_days": 7,
            "traces_max_size_mb": 80
          }
        }
        """
        try json.write(toFile: tmp + "/daemon_config.json", atomically: true, encoding: .utf8)

        let cfg = DaemonConfig.load(from: tmp, applyOverrides: false)
        #expect(cfg.storage.tracegraphRetentionDays == 45)
        #expect(cfg.storage.tracegraphMaxSizeMB == 300)
        #expect(cfg.storage.tracesRetentionDays == 7)
        #expect(cfg.storage.tracesMaxSizeMB == 80)
    }

    @Test("v1.18.0 tracegraph/traces caps default when omitted")
    func tracegraphTracesDefaults() {
        let tmp = NSTemporaryDirectory() + "MacCrabCfgTest-\(UUID().uuidString)"
        try? FileManager.default.createDirectory(atPath: tmp, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: tmp) }
        let cfg = DaemonConfig.load(from: tmp, applyOverrides: false)
        #expect(cfg.storage.tracegraphRetentionDays == 90)
        #expect(cfg.storage.tracegraphMaxSizeMB == 250)
        #expect(cfg.storage.tracesRetentionDays == 90)
        #expect(cfg.storage.tracesMaxSizeMB == 100)
    }

    /// v1.8.0-rc4 → rc5: legacy `eventsHotTierHours` (or its snake_case)
    /// folds onto `eventsHotTierMinutes` × 60.
    @Test("legacy eventsHotTierHours folds onto eventsHotTierMinutes")
    func legacyHotTierHoursFolds() throws {
        let tmp = NSTemporaryDirectory() + "MacCrabCfgTest-\(UUID().uuidString)"
        try FileManager.default.createDirectory(atPath: tmp, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: tmp) }

        let json = """
        { "storage": { "eventsHotTierHours": 2 } }
        """
        try json.write(toFile: tmp + "/daemon_config.json", atomically: true, encoding: .utf8)

        let cfg = DaemonConfig.load(from: tmp, applyOverrides: false)
        #expect(cfg.storage.eventsHotTierMinutes == 120)  // 2h × 60
    }

    /// New keys in `storage` win over legacy top-level keys when both
    /// are present — operators upgrading their config file shouldn't
    /// surprise themselves.
    @Test("new storage keys take precedence over legacy")
    func newKeysWinOverLegacy() throws {
        let tmp = NSTemporaryDirectory() + "MacCrabCfgTest-\(UUID().uuidString)"
        try FileManager.default.createDirectory(atPath: tmp, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: tmp) }

        let json = """
        {
          "retentionDays": 30,
          "maxDatabaseSizeMB": 1024,
          "storage": {
            "alertsRetentionDays": 365,
            "eventsMaxSizeMB": 200
          }
        }
        """
        try json.write(toFile: tmp + "/daemon_config.json", atomically: true, encoding: .utf8)

        let cfg = DaemonConfig.load(from: tmp, applyOverrides: false)
        // New keys present — legacy is ignored for those slots.
        #expect(cfg.storage.alertsRetentionDays == 365)
        #expect(cfg.storage.eventsMaxSizeMB == 200)
        // Legacy retentionDays still folds onto campaignsRetentionDays
        // (no new key set for that slot).
        #expect(cfg.storage.campaignsRetentionDays == 30)
    }

    /// A partial config that only sets one storage key should leave
    /// every other field at its default. Before v1.6.14 the decoder
    /// failed on any unknown key shape and returned all defaults,
    /// which hid the fact that the file was partially broken.
    @Test("partial config leaves untouched fields at defaults")
    func partialConfig() throws {
        let tmp = NSTemporaryDirectory() + "MacCrabCfgTest-\(UUID().uuidString)"
        try FileManager.default.createDirectory(atPath: tmp, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: tmp) }

        let json = """
        { "max_database_size_mb": 200 }
        """
        try json.write(toFile: tmp + "/daemon_config.json", atomically: true, encoding: .utf8)

        let cfg = DaemonConfig.load(from: tmp, applyOverrides: false)
        #expect(cfg.storage.eventsMaxSizeMB == 200)
        #expect(cfg.storage.alertsRetentionDays == 365)  // default
        #expect(cfg.behaviorAlertThreshold == 10.0)  // default
    }
}

// v1.21.5: the rule_profile → enabled-statuses mapping is shared by the boot
// path (DaemonSetup) and the SIGHUP reload (SignalHandlers), and gates all
// three rule families. Pin the mapping — including the corr-detection #273
// typo fallback ("stabel" must warn + degrade to the safe stable set, never
// silently widen to "all").
@Suite("DaemonConfig.enabledRuleStatuses (F-04 profile mapping, v1.21.5)")
struct DaemonConfigEnabledRuleStatusesTests {

    @Test("\"all\" maps to nil (every non-deprecated rule)")
    func allMapsToNil() {
        #expect(DaemonConfig.enabledRuleStatuses(forProfile: "all") == nil)
    }

    @Test("\"ALL\" is case-insensitive")
    func allUppercase() {
        #expect(DaemonConfig.enabledRuleStatuses(forProfile: "ALL") == nil)
    }

    @Test("\"stable\" maps to the stable-only set")
    func stable() {
        #expect(DaemonConfig.enabledRuleStatuses(forProfile: "stable") == ["stable"])
    }

    @Test("\"Stable\" is case-insensitive")
    func stableMixedCase() {
        #expect(DaemonConfig.enabledRuleStatuses(forProfile: "Stable") == ["stable"])
    }

    @Test("typo \"stabel\" falls back to the safe stable set")
    func typoFallsBackToStable() {
        #expect(DaemonConfig.enabledRuleStatuses(forProfile: "stabel") == ["stable"])
    }

    @Test("empty string falls back to the safe stable set")
    func emptyFallsBackToStable() {
        #expect(DaemonConfig.enabledRuleStatuses(forProfile: "") == ["stable"])
    }
}
