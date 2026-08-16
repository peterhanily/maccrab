import Foundation
import Testing

@Suite("Forensics storage and crypto surface inventory")
struct StorageAndCryptoSurfaceInventoryTests {
    private var repositoryRoot: URL {
        URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent() // MacCrabForensicsTests
            .deletingLastPathComponent() // Tests
            .deletingLastPathComponent() // repository
    }

    private func swiftFiles(under relativeRoot: String) throws -> [String: String] {
        let root = repositoryRoot.appendingPathComponent(relativeRoot, isDirectory: true)
        guard let enumerator = FileManager.default.enumerator(
            at: root,
            includingPropertiesForKeys: [.isRegularFileKey],
            options: [.skipsHiddenFiles]
        ) else { return [:] }
        var result: [String: String] = [:]
        for case let url as URL in enumerator where url.pathExtension == "swift" {
            let values = try url.resourceValues(forKeys: [.isRegularFileKey])
            guard values.isRegularFile == true else { continue }
            let relative = String(url.path.dropFirst(root.path.count + 1))
            result[relative] = try String(contentsOf: url, encoding: .utf8)
        }
        return result
    }

    @Test("Every Forensics SQLite opener is explicitly inventoried and shared")
    func sqliteOpenersCannotDriftSilently() throws {
        let files = try swiftFiles(under: "Sources/MacCrabForensics")
        let found = Set(files.compactMap { path, text in
            text.contains("SQLiteOpenPathPolicy.open(")
                ? path : nil
        })
        let expected: Set<String> = [
            "Plugins/Analyzers/PostureAnalyzer.swift",
            "Plugins/Collectors/ChromiumLite/ChromiumLitePlugin.swift",
            "Plugins/Collectors/FaceTime/FaceTimePlugin.swift",
            "Plugins/Collectors/KnowledgeC/KnowledgeCPlugin.swift",
            "Plugins/Collectors/MailLite/MailLitePlugin.swift",
            "Plugins/Collectors/Quarantine/QuarantinePlugin.swift",
            "Plugins/Collectors/SafariLite/SafariLitePlugin.swift",
            "Plugins/Collectors/TCCLite/TCCLitePlugin.swift",
            "Plugins/Collectors/iMessageBodies/iMessageBodiesPlugin.swift",
            "Plugins/Collectors/iMessageMetadata/iMessageMetadataPlugin.swift",
            "Snapshots/LiveDBSnapshot.swift",
            "Storage/ArtifactStore.swift",
        ]
        #expect(found == expected,
                "a direct SQLite opener was added/removed; review flags, trust, retention, and disk bounds before updating this inventory")

        for path in found {
            let text = try #require(files[path])
            #expect(text.contains("import MacCrabCore"),
                    "\(path) cannot use the shared alias/NOFOLLOW boundary")
            #expect(!text.contains("sqlite3_open_v2("),
                    "\(path) bypasses SQLiteOpenPathPolicy")
        }

        let writable = Set([
            "Snapshots/LiveDBSnapshot.swift", // bounded temp destination only
            "Storage/ArtifactStore.swift",    // single per-case writer
        ])
        for path in found.subtracting(writable) {
            let text = try #require(files[path])
            #expect(text.contains("SQLITE_OPEN_READONLY"), "\(path) must open snapshots read-only")
            #expect(!text.contains("SQLITE_OPEN_READWRITE"), "\(path) unexpectedly gained a write-capable SQLite open")
            #expect(!text.contains("SQLITE_OPEN_CREATE"), "\(path) must never create a source/snapshot database")
        }
    }

    @Test("Every production forensic DEK caller uses the canonical vault policy")
    func keychainDEKCallersCannotDriftSilently() throws {
        let files = try swiftFiles(under: "Sources")
        let found = Set(files.compactMap { path, text in
            text.contains("KeychainDEKVault(") ? path : nil
        })
        let expected: Set<String> = [
            "MacCrabApp/MacCrabApp.swift",
            "MacCrabApp/V2/Forensics/KitRunner.swift",
            "MacCrabApp/V2/Forensics/SampleOutputLoader.swift",
            "MacCrabApp/V2/Workspaces/V2ForensicsFindingsView.swift",
            "MacCrabApp/V2/Workspaces/V2ForensicsPastScansView.swift",
            "MacCrabApp/V2/Workspaces/V2ForensicsScanDetailView.swift",
            "MacCrabApp/V2/Workspaces/V2ForensicsScansView.swift",
            "MacCrabApp/V2/Workspaces/V2OverviewWorkspace.swift",
            "MacCrabApp/Views/SettingsView.swift",
            "maccrab-mcp/main.swift",
            "maccrabctl/CaseCommands.swift",
        ]
        #expect(found == expected,
                "a DEK-vault caller changed; verify service, auth policy, entitlements, and interactive-UI behavior before updating this inventory")
        for path in found {
            let text = try #require(files[path])
            let constructors = text.components(separatedBy: "KeychainDEKVault(").count - 1
            let canonical = text.components(separatedBy: "KeychainDEKVault()").count - 1
            #expect(constructors == canonical,
                    "\(path) overrides the canonical DEK service/auth policy; this requires an explicit migration")
        }
    }

    @Test("DatabaseEncryption constructors stay on audited daemon and dashboard surfaces")
    func databaseEncryptionCallersCannotDriftSilently() throws {
        let files = try swiftFiles(under: "Sources")
        let found = Set(files.compactMap { path, text in
            text.contains("DatabaseEncryption(") ? path : nil
        })
        #expect(found == [
            "MacCrabAgentKit/DaemonSetup.swift",
            "MacCrabApp/AppState.swift",
            "MacCrabApp/V2/Data/V2LiveDataProvider.swift",
            "MacCrabCore/Storage/TraceDashboardKeyExchange.swift",
        ],
                "a DatabaseEncryption constructor was added; verify persistent-key policy and cross-process key identity")
    }

    @Test("Dashboard trace-key handoff never reaches into Keychain")
    func dashboardTraceKeyHandoffIsSessionOnly() throws {
        let source = try String(
            contentsOfFile: "Sources/MacCrabCore/Storage/TraceDashboardKeyExchange.swift",
            encoding: .utf8
        )
        #expect(!source.contains("SecItem"))
        #expect(!source.contains("kSec"))
        #expect(!source.contains("import Security"))
        #expect(source.contains("dashboardSessionPrivateKey"))
    }

    @Test("Every SQLite backup copy has a page cap and free-space admission")
    func sqliteBackupCopiesCannotDriftToUnbounded() throws {
        let files = try swiftFiles(under: "Sources")
        let found = Set(files.compactMap { path, text in
            text.contains("sqlite3_backup_init(") ? path : nil
        })
        #expect(found == [
            "MacCrabCore/Enrichment/DeliveryProvenanceWeld.swift",
            "MacCrabForensics/Snapshots/LiveDBSnapshot.swift",
        ], "a SQLite backup surface changed; audit source trust, cap, disk reserve, temp cleanup, and finish status")
        for path in found {
            let text = try #require(files[path])
            #expect(text.contains("PRAGMA max_page_count"), "\(path) lacks a hard SQLite page ceiling")
            #expect(text.contains("f_bavail"), "\(path) does not measure immediately writable free blocks")
            #expect(text.contains("sqlite3_backup_finish(backup)"), "\(path) must check backup finalization")
        }
    }

    @Test("Writable forensic SQLite surfaces are explicitly bounded and recover safely")
    func writableSQLiteBoundsCannotDriftSilently() throws {
        let files = try swiftFiles(under: "Sources")
        let artifact = try #require(
            files["MacCrabForensics/Storage/ArtifactStore.swift"]
        )
        for required in [
            "SQLitePersistentStoreAdmission(",
            "latchOperationalPressure: existingDatabase",
            "installPageLimit(on: h)",
            "try admitStorageWrite(",
            "estimatedTransactionBytes:",
            "SchemaMigrator.pendingStorageWork(",
            "admitSchemaRebuild(",
            "latchSQLitePressure(",
            "initializationPending",
            "performOperationalInitialization(",
        ] {
            #expect(artifact.contains(required),
                    "ArtifactStore lost required disk-pressure control: \(required)")
        }
        #expect(artifact.components(separatedBy: "try admitStorageWrite(").count - 1 == 6,
                "every ArtifactStore mutation API must pass the common writer gate")

        let snapshot = try #require(
            files["MacCrabForensics/Snapshots/LiveDBSnapshot.swift"]
        )
        for required in [
            "maxSQLiteBytes: Int64 = 1_024 * 1_048_576",
            "info.f_bavail",
            "PRAGMA max_page_count",
            "sqlite3_backup_step(backup, 256)",
            "sqlite3_backup_finish(backup)",
            "O_RDONLY | O_NOFOLLOW | O_CLOEXEC",
            "nextTotal <= maxBytes",
        ] {
            #expect(snapshot.contains(required),
                    "LiveDBSnapshot lost required copy bound: \(required)")
        }
    }
}
