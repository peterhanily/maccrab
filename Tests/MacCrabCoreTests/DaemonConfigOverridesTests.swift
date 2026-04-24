// DaemonConfigOverridesTests.swift
//
// v1.6.14: regression tests for the user_overrides.json overlay path
// that wires the dashboard's storage sliders to the sysext.
//
// These tests exercise `DaemonConfig.load(from:)` only, not the full
// applyUserOverrides path (which reads from `/Users/*` and requires
// ownership matching the home directory — not reproducible in CI
// without root). That path is exercised by the integration test
// suite.

import Testing
import Foundation
@testable import MacCrabAgentKit

@Suite("DaemonConfig: user_overrides.json overlay (v1.6.14)")
struct DaemonConfigOverridesTests {

    /// When no `daemon_config.json` exists, `load` returns pure defaults
    /// — this is the pre-v1.6.14 behavior and must not regress.
    @Test("load returns defaults when no config file present")
    func loadDefaults() {
        let tmp = NSTemporaryDirectory() + "MacCrabCfgTest-\(UUID().uuidString)"
        try? FileManager.default.createDirectory(atPath: tmp, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: tmp) }

        let cfg = DaemonConfig.load(from: tmp)
        #expect(cfg.maxDatabaseSizeMB == 500)
        #expect(cfg.retentionDays == 30)
    }

    /// CLAUDE.md documents the `daemon_config.json` keys as snake_case.
    /// This test locks in the v1.6.14 fix: pre-v1.6.14, the decoder
    /// used `.convertFromSnakeCase` which turned `max_database_size_mb`
    /// into `maxDatabaseSizeMb` (lowercase `b`) — no match for the
    /// Swift property `maxDatabaseSizeMB`. The decode failed, and
    /// because `load()` used `try?`, the ENTIRE config was silently
    /// discarded. Any operator following the docs got full defaults.
    @Test("snake_case keys in daemon_config.json are honored (v1.6.14 regression)")
    func snakeCaseKeys() throws {
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

        let cfg = DaemonConfig.load(from: tmp)
        #expect(cfg.maxDatabaseSizeMB == 250)
        #expect(cfg.retentionDays == 7)
        #expect(cfg.behaviorAlertThreshold == 15.0)
    }

    /// camelCase keys must also work — the dashboard's
    /// `user_overrides.json` writer uses camelCase, and operators
    /// hand-editing might do either.
    @Test("camelCase keys are honored")
    func camelCaseKeys() throws {
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

        let cfg = DaemonConfig.load(from: tmp)
        #expect(cfg.maxDatabaseSizeMB == 300)
        #expect(cfg.retentionDays == 14)
    }

    /// A partial config that only sets the storage keys should leave
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
        try json.write(
            toFile: tmp + "/daemon_config.json",
            atomically: true,
            encoding: .utf8
        )

        let cfg = DaemonConfig.load(from: tmp)
        #expect(cfg.maxDatabaseSizeMB == 200)
        #expect(cfg.retentionDays == 30)  // default
        #expect(cfg.behaviorAlertThreshold == 10.0)  // default
    }
}
