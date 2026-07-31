// CaseManager lifecycle tests — create, open, list, delete.
// Uses InMemoryDEKVault so no Keychain auth UI fires during CI.

import Foundation
import Testing
@testable import MacCrabForensics

@Suite("CaseManager lifecycle")
struct CaseManagerLifecycleTests {

    private func tempRoot() -> URL {
        URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("maccrab-case-manager-\(UUID().uuidString)")
    }

    @Test("createCase produces a directory + manifest + cases row")
    func createCaseBasic() async throws {
        let root = tempRoot()
        let mgr = CaseManager(casesRoot: root, dekVault: InMemoryDEKVault())
        let handle = try await mgr.createCase(name: "first audit")
        defer { try? FileManager.default.removeItem(at: root) }

        // Directory structure exists.
        #expect(FileManager.default.fileExists(atPath: handle.layout.caseDirectory.path))
        #expect(FileManager.default.fileExists(atPath: handle.layout.sqliteFile.path))
        #expect(FileManager.default.fileExists(atPath: handle.layout.manifestFile.path))
        #expect(FileManager.default.fileExists(atPath: handle.layout.vaultRoot.path))
        #expect(FileManager.default.fileExists(atPath: handle.layout.snapshotsRoot.path))

        // Cases row is in the store.
        let fetched = try await handle.store.fetchCase(id: handle.caseID)
        #expect(fetched?.name == "first audit")
        #expect(fetched?.encryptionState == .encryptedKeychain)
    }

    @Test("createCase(encrypted: false) produces a plaintext case with no vault entry")
    func createCasePlaintext() async throws {
        let root = tempRoot()
        let vault = InMemoryDEKVault()
        let mgr = CaseManager(casesRoot: root, dekVault: vault)
        let handle = try await mgr.createCase(name: "plain", encrypted: false)
        defer { try? FileManager.default.removeItem(at: root) }

        #expect(handle.encryptionState == .plaintext)
        #expect(handle.vault == nil)

        // No DEK stored.
        await #expect(throws: DEKVaultError.self) {
            _ = try await vault.retrieve(for: handle.caseID)
        }
    }

    @Test("listCases returns manifests for every case directory")
    func listCases() async throws {
        let root = tempRoot()
        let mgr = CaseManager(casesRoot: root, dekVault: InMemoryDEKVault())
        defer { try? FileManager.default.removeItem(at: root) }

        let h1 = try await mgr.createCase(name: "alpha")
        let h2 = try await mgr.createCase(name: "beta")
        let h3 = try await mgr.createCase(name: "gamma", encrypted: false)
        _ = h1; _ = h2; _ = h3

        let manifests = try await mgr.listCases()
        #expect(manifests.count == 3)
        let names = Set(manifests.map { $0.name })
        #expect(names == ["alpha", "beta", "gamma"])
    }

    @Test("listCases sorts newest-first")
    func listCasesSortNewestFirst() async throws {
        let root = tempRoot()
        let mgr = CaseManager(casesRoot: root, dekVault: InMemoryDEKVault())
        defer { try? FileManager.default.removeItem(at: root) }

        let h1 = try await mgr.createCase(name: "old")
        // Tiny sleep so timestamps differ.
        try await Task.sleep(nanoseconds: 50_000_000)
        let h2 = try await mgr.createCase(name: "new")
        _ = h1; _ = h2

        let manifests = try await mgr.listCases()
        #expect(manifests.first?.name == "new")
        #expect(manifests.last?.name == "old")
    }

    @Test("listCases on an empty root is an empty array")
    func listCasesEmpty() async throws {
        let root = tempRoot()
        let mgr = CaseManager(casesRoot: root, dekVault: InMemoryDEKVault())
        let manifests = try await mgr.listCases()
        #expect(manifests.isEmpty)
    }

    @Test("openCase round-trips: create, reopen, fetch")
    func openCaseRoundTrip() async throws {
        let root = tempRoot()
        let vault = InMemoryDEKVault()
        let mgr = CaseManager(casesRoot: root, dekVault: vault)
        defer { try? FileManager.default.removeItem(at: root) }

        let firstHandle = try await mgr.createCase(name: "reopen-me")
        let caseID = firstHandle.caseID

        // Drop the first handle so the SQLite handle closes.
        // (Actor deinit closes; we just need to release the
        // reference.)

        let secondHandle = try await mgr.openCase(id: caseID)
        let fetched = try await secondHandle.store.fetchCase(id: caseID)
        #expect(fetched?.name == "reopen-me")
    }

    @Test("openCase fails when no DEK is on file for an encrypted case")
    func openCaseFailsWithoutDEK() async throws {
        let root = tempRoot()
        let vault = InMemoryDEKVault()
        let mgr = CaseManager(casesRoot: root, dekVault: vault)
        defer { try? FileManager.default.removeItem(at: root) }

        let handle = try await mgr.createCase(name: "lost-key")
        let caseID = handle.caseID

        // Simulate a lost DEK.
        try await vault.delete(for: caseID)

        await #expect(throws: DEKVaultError.self) {
            _ = try await mgr.openCase(id: caseID)
        }
    }

    @Test("openCase fails when case directory doesn't exist")
    func openCaseFailsWhenAbsent() async throws {
        let root = tempRoot()
        let mgr = CaseManager(casesRoot: root, dekVault: InMemoryDEKVault())
        await #expect(throws: CaseManagerError.self) {
            _ = try await mgr.openCase(id: "no-such-case")
        }
    }

    @Test("deleteCase removes directory + DEK")
    func deleteCase() async throws {
        let root = tempRoot()
        let vault = InMemoryDEKVault()
        let mgr = CaseManager(casesRoot: root, dekVault: vault)
        defer { try? FileManager.default.removeItem(at: root) }

        let handle = try await mgr.createCase(name: "doomed")
        let caseID = handle.caseID
        let dir = handle.layout.caseDirectory.path

        try await mgr.deleteCase(id: caseID, shred: false)

        #expect(!FileManager.default.fileExists(atPath: dir))
        await #expect(throws: DEKVaultError.self) {
            _ = try await vault.retrieve(for: caseID)
        }
    }

    @Test("deleteCase with shred=true overwrites case.sqlite before unlinking")
    func deleteCaseShred() async throws {
        let root = tempRoot()
        let mgr = CaseManager(casesRoot: root, dekVault: InMemoryDEKVault())
        defer { try? FileManager.default.removeItem(at: root) }

        let handle = try await mgr.createCase(name: "to be shredded")
        let caseID = handle.caseID

        try await mgr.deleteCase(id: caseID, shred: true)
        #expect(!FileManager.default.fileExists(atPath: handle.layout.caseDirectory.path))
    }
}

@Suite("CaseManifest")
struct CaseManifestTests {

    @Test("Manifest encodes + decodes losslessly")
    func roundTrip() throws {
        let original = CaseManifest(
            id: "abc-def",
            name: "manifest test",
            createdAt: Date(timeIntervalSince1970: 1_700_000_000),
            encryptionState: .encryptedKeychain
        )
        let data = try JSONEncoder().encode(original)
        let decoded = try JSONDecoder().decode(CaseManifest.self, from: data)
        #expect(decoded.id == "abc-def")
        #expect(decoded.name == "manifest test")
        #expect(decoded.encryptionState == .encryptedKeychain)
        #expect(decoded.createdAtMillis == 1_700_000_000_000)
    }
}

@Suite("KeychainDEKVault SecItem provisioning (source guard)")
struct KeychainDEKVaultProvisioningTests {

    /// Every keychain test in the tree is either opt-in (SecretsStoreTests) or
    /// runs against InMemoryDEKVault, so NOTHING covered which SecItem
    /// ATTRIBUTES the vault sets — the exact gap that shipped the
    /// kSecUseDataProtectionKeychain bug (store landed items in the
    /// data-protection keychain via kSecAttrAccessControl while retrieve/delete
    /// queried the legacy file-based one, making every encrypted case
    /// unopenable). A source assertion covers it with no keychain, no prompt
    /// and no flake, and fails the moment a fifth SecItem dictionary is added
    /// without the opt-in.
    @Test("every SecItem dictionary opts into the data-protection keychain")
    func dataProtectionOnEverySecItemDict() throws {
        let source = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()   // Tests/MacCrabForensicsTests
            .deletingLastPathComponent()   // Tests
            .deletingLastPathComponent()   // package root
            .appendingPathComponent("Sources/MacCrabForensics/Cases/KeychainDEKVault.swift")
        let text = try String(contentsOf: source, encoding: .utf8)
        // One `kSecClass: kSecClassGenericPassword` per SecItem dictionary.
        let dicts = text.components(separatedBy: "kSecClass: kSecClassGenericPassword").count - 1
        let optIns = text.components(separatedBy: "kSecUseDataProtectionKeychain").count - 1
        #expect(dicts >= 4, "expected the 4 SecItem dictionaries (delete/add/retrieve/delete); found \(dicts)")
        #expect(optIns >= dicts,
                "\(dicts) SecItem dictionaries but only \(optIns) kSecUseDataProtectionKeychain occurrences — a query that omits it hits the LEGACY file-based keychain and silently finds nothing")
        #expect(text.contains("kSecAttrSynchronizable: kCFBooleanFalse as Any"),
                "the DEK add-query must pin kSecAttrSynchronizable=false so the key never escapes to iCloud Keychain")
    }
}
