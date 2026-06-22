// RevocationReverifyServiceTests — the timer-driven reconcile wired to the
// installed-plugin store: an install-once box self-heals (a stale third-party
// plugin is quarantined) and a fresh re-verify clears the escalation.

import Testing
import Foundation
@testable import MacCrabForensics

@Suite("RevocationReverifyService (reconcile + apply)")
struct RevocationReverifyServiceTests {

    static func installThirdParty(id: String) async throws -> PluginInstaller {
        let bin = NSTemporaryDirectory() + "revsvc-bin-\(UUID().uuidString)"
        try Data("#!/bin/sh\nexit 0\n".utf8).write(to: URL(fileURLWithPath: bin))
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: bin)
        defer { try? FileManager.default.removeItem(atPath: bin) }
        let m = TierBManifest(id: id, displayName: "P", version: "1.0", schemaVersion: 1, description: "d")
        let (src, _) = try TierBRegistryTests.signedBundle(manifest: m, binaryPath: bin)
        defer { try? FileManager.default.removeItem(at: src) }
        let installer = TierBRegistryTests.freshInstaller()
        _ = try await installer.install(sourceDir: src, trustOnInstall: true)
        return installer
    }

    static func freshStore() -> RaveTrustStateStore {
        RaveTrustStateStore(path: NSTemporaryDirectory() + "revsvc-ts-\(UUID().uuidString).json")
    }
    static func emptyReceipts() -> URL {
        URL(fileURLWithPath: NSTemporaryDirectory() + "revsvc-receipts-\(UUID().uuidString)")
    }

    @Test("offline + STALE feed: a third-party plugin is quarantined as stale (self-heal)")
    func staleQuarantines() async throws {
        let installer = try await Self.installThirdParty(id: "com.x.rev1")
        defer { try? FileManager.default.removeItem(atPath: installer.pluginsRootPath) }
        let store = Self.freshStore()
        defer { try? FileManager.default.removeItem(atPath: store.filePath) }

        // Seed a genuinely STALE clock: a signed list WAS verified once, 8 days ago
        // (past the 7-day ceiling). `.never` no longer escalates (audit #6) — only
        // real staleness does — so the self-heal is driven from a lapsed feed.
        let now = Date(timeIntervalSince1970: 1_750_000_000)
        try store.recordRevocations(serial: 1, verifiedAt: now.addingTimeInterval(-8 * 24 * 3600))

        let records = try await RevocationReverifyService.reconcile(
            verifiedList: nil, installer: installer, trustStateStore: store,
            receiptsDir: Self.emptyReceipts(), now: now)
        #expect(records.contains { $0.pluginID == "com.x.rev1" && $0.code == "REVOCATION_STALE" })
        let q = await installer.currentQuarantine()
        #expect(q["com.x.rev1"] != nil)   // actually applied
    }

    @Test("offline + never-fetched: an operator sideload RUNS, not quarantined (audit #6)")
    func neverFetchedRunsSideload() async throws {
        let installer = try await Self.installThirdParty(id: "com.x.rev3")
        defer { try? FileManager.default.removeItem(atPath: installer.pluginsRootPath) }
        let store = Self.freshStore()   // never recorded → freshness .never
        defer { try? FileManager.default.removeItem(atPath: store.filePath) }

        let records = try await RevocationReverifyService.reconcile(
            verifiedList: nil, installer: installer, trustStateStore: store, receiptsDir: Self.emptyReceipts())
        #expect(records.isEmpty)
        let q = await installer.currentQuarantine()
        #expect(q["com.x.rev3"] == nil)   // the operator's TOFU sideload is runnable offline
    }

    @Test("fresh verified list: a non-revoked third-party plugin is NOT quarantined")
    func freshClears() async throws {
        let installer = try await Self.installThirdParty(id: "com.x.rev2")
        defer { try? FileManager.default.removeItem(atPath: installer.pluginsRootPath) }
        let store = Self.freshStore()
        defer { try? FileManager.default.removeItem(atPath: store.filePath) }

        let freshList = RaveRevocationList(formatVersion: "1", serial: 1, updatedAt: nil, revocations: [])
        let records = try await RevocationReverifyService.reconcile(
            verifiedList: freshList, installer: installer, trustStateStore: store, receiptsDir: Self.emptyReceipts())
        #expect(records.isEmpty)
        let q = await installer.currentQuarantine()
        #expect(q["com.x.rev2"] == nil)
    }
}
