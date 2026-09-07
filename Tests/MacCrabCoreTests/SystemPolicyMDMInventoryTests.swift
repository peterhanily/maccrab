import Foundation
import Testing
@testable import MacCrabCore

@Suite("MDM inventory failure preserves observed state")
struct SystemPolicyMDMInventoryTests {
    private func directory() throws -> URL {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("maccrab-mdm-inventory-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        return directory
    }

    private func collectedEvents(
        from monitor: SystemPolicyMonitor
    ) async -> [SystemPolicyMonitor.SystemPolicyEvent] {
        await monitor.stop()
        var events: [SystemPolicyMonitor.SystemPolicyEvent] = []
        for await event in monitor.events { events.append(event) }
        return events
    }

    @Test("success, unavailable enumeration, recovery and real removal do not fabricate drift")
    func failedEnumerationPreservesBaselineAndContentDedup() async throws {
        let directory = try directory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let profile = directory.appendingPathComponent("ordinary.mobileconfig")
        try "com.apple.TCC".write(to: profile, atomically: true, encoding: .utf8)
        let monitor = SystemPolicyMonitor(homesProvider: { [] })

        // Only this directory reconciliation is called; the monitor never
        // starts, refreshes MDM, runs a command, or inspects the host inventory.
        await monitor.inspectMDMProfiles(at: directory.path)
        await monitor.inspectMDMProfiles(at: directory.path) { _ in
            throw CocoaError(.fileReadNoPermission)
        }
        await monitor.inspectMDMProfiles(at: directory.path)
        try FileManager.default.removeItem(at: profile)
        await monitor.inspectMDMProfiles(at: directory.path)
        try "com.apple.TCC".write(to: profile, atomically: true, encoding: .utf8)
        await monitor.inspectMDMProfiles(at: directory.path)

        let events = await collectedEvents(from: monitor)
        #expect(events.map { $0.type } == [
            .rogueMDMProfile,
            .mdmProfileRemoved,
            .mdmProfileInstalled,
            .rogueMDMProfile,
        ])
        #expect(events.allSatisfy { $0.path == profile.path })
    }

    @Test("a missing inventory directory preserves state until a successful empty listing")
    func missingDirectoryIsUnknownAndEmptyDirectoryIsAuthoritative() async throws {
        let directory = try directory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let profile = directory.appendingPathComponent("ordinary.plist")
        try "ordinary fixture".write(to: profile, atomically: true, encoding: .utf8)
        let monitor = SystemPolicyMonitor(homesProvider: { [] })
        await monitor.inspectMDMProfiles(at: directory.path)
        try FileManager.default.removeItem(at: directory)
        await monitor.inspectMDMProfiles(at: directory.path)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        await monitor.inspectMDMProfiles(at: directory.path)

        let events = await collectedEvents(from: monitor)
        #expect(events.map { $0.type } == [.mdmProfileRemoved])
        #expect(events.first?.path == profile.path)
    }

    @Test("an initial enumeration failure cannot establish an empty baseline")
    func firstSuccessfulReadEstablishesBaseline() async throws {
        let directory = try directory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let profile = directory.appendingPathComponent("ordinary.mobileconfig")
        try "com.apple.TCC".write(to: profile, atomically: true, encoding: .utf8)
        let monitor = SystemPolicyMonitor(homesProvider: { [] })
        await monitor.inspectMDMProfiles(at: directory.path) { _ in
            throw CocoaError(.fileReadUnknown)
        }
        await monitor.inspectMDMProfiles(at: directory.path)
        let events = await collectedEvents(from: monitor)
        #expect(events.map { $0.type } == [.rogueMDMProfile])
    }
}
