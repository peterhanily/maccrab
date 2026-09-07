import Testing
@testable import MacCrabApp

@Suite("Settings storage-default migration")
struct StorageSettingsDefaultMigrationTests {
    @Test("complete prior generated tuple upgrades once")
    func generatedTupleUpgradesOnce() {
        let first = SettingsStorageDefaultMigration.upgradedEventsMaxSizeMB(
            snapshot: .generatedBeforeEnvelopeRebaseline,
            eventsKeyWasPersisted: true,
            legacyCapWasPresent: false,
            completedGeneration: 0
        )
        #expect(first == 440)

        let repeated = SettingsStorageDefaultMigration.upgradedEventsMaxSizeMB(
            snapshot: .generatedBeforeEnvelopeRebaseline,
            eventsKeyWasPersisted: true,
            legacyCapWasPresent: false,
            completedGeneration:
                SettingsStorageDefaultMigration.currentGeneration
        )
        #expect(repeated == nil)
    }

    @Test("missing key is already on the new default and is not rewritten")
    func absentEventsKeyIsNotClassifiedAsOldGeneratedState() {
        let result = SettingsStorageDefaultMigration.upgradedEventsMaxSizeMB(
            snapshot: .generatedBeforeEnvelopeRebaseline,
            eventsKeyWasPersisted: false,
            legacyCapWasPresent: false,
            completedGeneration: 0
        )
        #expect(result == nil)
    }

    @Test("distinguishable operator 420 override remains authoritative")
    func tunedTuplePreservesPriorCap() {
        let tuned = SettingsStorageDefaultsSnapshot(
            eventsHotTierMinutes: 60,
            eventsMaxSizeMB: 420,
            alertsRetentionDays: 365,
            alertsMaxSizeMB: 100,
            evidenceMaxSizeMB: 100,
            campaignsRetentionDays: 365,
            campaignsMaxSizeMB: 50
        )
        let result = SettingsStorageDefaultMigration.upgradedEventsMaxSizeMB(
            snapshot: tuned,
            eventsKeyWasPersisted: true,
            legacyCapWasPresent: false,
            completedGeneration: 0
        )
        #expect(result == nil)
    }

    @Test("saved 440 cap is not reclassified when the factory fallback changes")
    func saved440CapIsPreserved() {
        let saved = SettingsStorageDefaultsSnapshot(
            eventsHotTierMinutes: 30,
            eventsMaxSizeMB: 440,
            alertsRetentionDays: 365,
            alertsMaxSizeMB: 100,
            evidenceMaxSizeMB: 100,
            campaignsRetentionDays: 365,
            campaignsMaxSizeMB: 50
        )
        let result = SettingsStorageDefaultMigration.upgradedEventsMaxSizeMB(
            snapshot: saved,
            eventsKeyWasPersisted: true,
            legacyCapWasPresent: false,
            completedGeneration: 0
        )
        #expect(result == nil)
    }

    @Test("legacy explicit cap is never reclassified as a generated default")
    func legacyExplicitCapWins() {
        let result = SettingsStorageDefaultMigration.upgradedEventsMaxSizeMB(
            snapshot: .generatedBeforeEnvelopeRebaseline,
            eventsKeyWasPersisted: true,
            legacyCapWasPresent: true,
            completedGeneration: 0
        )
        #expect(result == nil)
    }
}
