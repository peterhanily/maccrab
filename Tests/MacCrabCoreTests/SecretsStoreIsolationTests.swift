import Foundation
import LocalAuthentication
import Security
import Testing
@testable import MacCrabCore

// Every operation is an in-memory replacement. These tests never call Security
// APIs, enumerate Keychain items, request credentials, or require the opt-in.
@Suite("SecretsStore isolated query and migration contracts")
struct SecretsStoreIsolationTests {
    private let key = SecretKey.urlScanKey

    @Test("Production defaults remain unchanged without accessing Keychain")
    func defaults() {
        let store = SecretsStore()
        #expect(store.serviceNamespace == "com.maccrab.secrets")
        #expect(store.accessGroup == "79S425CW99.com.maccrab.shared")
    }

    @Test("Custom service confines reads, writes, listing and deletion")
    func serviceIsolation() throws {
        let mock = MemoryKeychain()
        let first = SecretsStore(accessGroup: nil, service: "fixture.first", keychain: mock.operations)
        let second = SecretsStore(accessGroup: nil, service: "fixture.second", keychain: mock.operations)
        let production = SecretsStore(accessGroup: nil, service: SecretsStore.service, keychain: mock.operations)
        try production.set(key, value: "synthetic-production-sentinel")
        try second.set(key, value: "synthetic-second")
        #expect(try first.get(key) == nil)
        try first.set(key, value: "synthetic-first")
        #expect(try first.get(key) == "synthetic-first")
        #expect(first.exists(key))
        #expect(first.storedKeys() == [key])
        try first.set(key, value: "synthetic-overwrite")
        #expect(try first.get(key) == "synthetic-overwrite")
        first.deleteAll()
        #expect(first.storedKeys().isEmpty)
        #expect(try second.get(key) == "synthetic-second")
        #expect(try production.get(key) == "synthetic-production-sentinel")
    }

    @Test("Legacy copy retains both original and destination and uses the custom service")
    func migrationPreservesBothItems() throws {
        let mock = MemoryKeychain()
        let legacy = SecretsStore(accessGroup: nil, service: "fixture.migration", keychain: mock.operations)
        let destination = SecretsStore(accessGroup: "fixture.shared", service: "fixture.migration", keychain: mock.operations)
        try legacy.set(key, value: "synthetic-legacy")
        #expect(try destination.get(key) == "synthetic-legacy")
        #expect(mock.snapshot().items.count == 2)
        #expect(mock.snapshot().deleteCalls == 0)
        #expect(Set(mock.snapshot().services) == ["fixture.migration"])
        #expect(try destination.get(key) == "synthetic-legacy")
        #expect(mock.snapshot().items.count == 2)
    }

    @Test("Failed destination write preserves the original without deletion")
    func failedMigrationPreservesOriginal() throws {
        let mock = MemoryKeychain(failingWriteGroup: "fixture.shared")
        let legacy = SecretsStore(accessGroup: nil, service: "fixture.failure", keychain: mock.operations)
        let destination = SecretsStore(accessGroup: "fixture.shared", service: "fixture.failure", keychain: mock.operations)
        try legacy.set(key, value: "synthetic-survivor")
        #expect(throws: SecretsStoreError.self) { try destination.get(key) }
        #expect(mock.snapshot().items.count == 1)
        #expect(mock.snapshot().deleteCalls == 0)
        #expect(try legacy.get(key) == "synthetic-survivor")
    }

    @Test("Backend aliasing of grouped and ungrouped queries never deletes the rewritten item")
    func aliasedMigrationPreservesItem() throws {
        let mock = MemoryKeychain(ignoreGroups: true, missOnceForGroup: "fixture.shared")
        let legacy = SecretsStore(accessGroup: nil, service: "fixture.alias", keychain: mock.operations)
        let destination = SecretsStore(accessGroup: "fixture.shared", service: "fixture.alias", keychain: mock.operations)
        try legacy.set(key, value: "synthetic-aliased")
        #expect(try destination.get(key) == "synthetic-aliased")
        #expect(mock.snapshot().items.count == 1)
        #expect(mock.snapshot().deleteCalls == 0)
        #expect(try destination.get(key) == "synthetic-aliased")
        try destination.delete(key)
        #expect(try destination.get(key) == nil)
        #expect(mock.snapshot().items.isEmpty)
    }

    @Test("Explicit deletion paths remove fallback copies and keep unrelated keys")
    func explicitDeletionCannotResurrectLegacy() throws {
        for operation in ["delete", "empty", "noninteractive-empty", "all"] {
            let mock = MemoryKeychain()
            let legacy = SecretsStore(accessGroup: nil, service: "fixture.delete", keychain: mock.operations)
            let destination = SecretsStore(accessGroup: "fixture.shared", service: "fixture.delete", keychain: mock.operations)
            let unrelated = SecretsStore(accessGroup: nil, service: "fixture.unrelated", keychain: mock.operations)
            try legacy.set(key, value: "synthetic-old")
            try legacy.set(.openaiAPIKey, value: "synthetic-other-account")
            try unrelated.set(key, value: "synthetic-other-service")
            #expect(try destination.get(key) == "synthetic-old")
            #expect(mock.snapshot().items.count == 4)
            switch operation {
            case "delete": try destination.delete(key)
            case "empty": try destination.set(key, value: "")
            case "noninteractive-empty": try destination.setNonInteractive(key, value: "")
            default: destination.deleteAll()
            }
            #expect(try destination.get(key) == nil)
            #expect(try legacy.get(key) == nil)
            #expect(try unrelated.get(key) == "synthetic-other-service")
            #expect(try legacy.get(.openaiAPIKey) == (operation == "all" ? nil : "synthetic-other-account"))
            let deletions = mock.snapshot().deletions
            #expect(!deletions.isEmpty)
            #expect(deletions.allSatisfy { $0.service == "fixture.delete" && $0.group == nil && $0.matchesAll })
            if operation != "all" { #expect(deletions.allSatisfy { $0.account == key.rawValue }) }
            #expect(deletions.allSatisfy { $0.noninteractive == (operation == "noninteractive-empty") })
        }
    }

    @Test("A failed copy can still be explicitly deleted without fallback resurrection")
    func deletionAfterFailedCopy() throws {
        let mock = MemoryKeychain(failingWriteGroup: "fixture.shared")
        let legacy = SecretsStore(accessGroup: nil, service: "fixture.copy-failed", keychain: mock.operations)
        let destination = SecretsStore(accessGroup: "fixture.shared", service: "fixture.copy-failed", keychain: mock.operations)
        try legacy.set(key, value: "synthetic-old")
        #expect(throws: SecretsStoreError.self) { try destination.get(key) }
        #expect(mock.snapshot().items.count == 1)
        try destination.delete(key)
        #expect(try destination.get(key) == nil)
        #expect(mock.snapshot().items.isEmpty)
    }

    @Test("Denied explicit deletion reports failure and preserves compatible entries")
    func deletionFailureIsNotSuccess() throws {
        let mock = MemoryKeychain(failingDelete: true)
        let legacy = SecretsStore(accessGroup: nil, service: "fixture.delete-failed", keychain: mock.operations)
        let destination = SecretsStore(accessGroup: "fixture.shared", service: "fixture.delete-failed", keychain: mock.operations)
        try legacy.set(key, value: "synthetic-old")
        #expect(try destination.get(key) == "synthetic-old")
        #expect(throws: SecretsStoreError.self) { try destination.delete(key) }
        #expect(mock.snapshot().items.count == 2)
        #expect(try destination.get(key) == "synthetic-old")
    }
}

private final class MemoryKeychain: @unchecked Sendable {
    struct Item {
        let service: String
        let account: String
        let group: String
        var data: Data
    }

    struct Deletion {
        let service: String?
        let account: String?
        let group: String?
        let matchesAll: Bool
        let noninteractive: Bool
    }

    private let lock = NSLock()
    private var items: [Item] = []
    private var services: [String] = []
    private var deleteCalls = 0
    private var deletions: [Deletion] = []
    private let ignoreGroups: Bool
    private let failingWriteGroup: String?
    private let failingDelete: Bool
    private var missOnceForGroup: String?

    init(ignoreGroups: Bool = false, failingWriteGroup: String? = nil, missOnceForGroup: String? = nil, failingDelete: Bool = false) {
        self.ignoreGroups = ignoreGroups
        self.failingWriteGroup = failingWriteGroup
        self.missOnceForGroup = missOnceForGroup
        self.failingDelete = failingDelete
    }

    var operations: SecretsStoreKeychainOperations {
        SecretsStoreKeychainOperations(
            copyMatching: { [self] in copyMatching($0, $1) },
            update: { [self] in update($0, $1) },
            add: { [self] in add($0) },
            delete: { [self] in delete($0) }
        )
    }

    func snapshot() -> (items: [Item], services: [String], deleteCalls: Int, deletions: [Deletion]) {
        lock.lock()
        defer { lock.unlock() }
        return (items, services, deleteCalls, deletions)
    }

    private func matches(_ item: Item, _ query: [String: Any]) -> Bool {
        guard query[kSecClass as String] as? String == kSecClassGenericPassword as String,
              query[kSecAttrService as String] as? String == item.service,
              query[kSecAttrAccount as String] as? String == item.account else { return false }
        guard !ignoreGroups, let group = query[kSecAttrAccessGroup as String] as? String else { return true }
        return group == item.group
    }

    private func record(_ query: [String: Any]) {
        services.append(query[kSecAttrService as String] as? String ?? "MISSING_SERVICE")
    }

    private func copyMatching(_ query: [String: Any], _ result: UnsafeMutablePointer<CFTypeRef?>?) -> OSStatus {
        lock.lock()
        defer { lock.unlock() }
        record(query)
        if let group = missOnceForGroup, query[kSecAttrAccessGroup as String] as? String == group {
            missOnceForGroup = nil
            return errSecItemNotFound
        }
        guard let item = items.first(where: { matches($0, query) }) else { return errSecItemNotFound }
        if query[kSecReturnData as String] as? Bool == true { result?.pointee = item.data as NSData }
        return errSecSuccess
    }

    private func update(_ query: [String: Any], _ attributes: [String: Any]) -> OSStatus {
        lock.lock()
        defer { lock.unlock() }
        record(query)
        if let group = failingWriteGroup, query[kSecAttrAccessGroup as String] as? String == group {
            return errSecAuthFailed
        }
        let indices = items.indices.filter { matches(items[$0], query) }
        guard !indices.isEmpty else { return errSecItemNotFound }
        guard let data = attributes[kSecValueData as String] as? Data else { return errSecParam }
        for index in indices { items[index].data = data }
        return errSecSuccess
    }

    private func add(_ query: [String: Any]) -> OSStatus {
        lock.lock()
        defer { lock.unlock() }
        record(query)
        guard let service = query[kSecAttrService as String] as? String,
              let account = query[kSecAttrAccount as String] as? String,
              let data = query[kSecValueData as String] as? Data else { return errSecParam }
        items.append(Item(service: service, account: account,
                          group: query[kSecAttrAccessGroup as String] as? String ?? "fixture.default", data: data))
        return errSecSuccess
    }

    private func delete(_ query: [String: Any]) -> OSStatus {
        lock.lock()
        defer { lock.unlock() }
        record(query)
        deleteCalls += 1
        let matchesAll = query[kSecMatchLimit as String] as? String == kSecMatchLimitAll as String
        deletions.append(Deletion(service: query[kSecAttrService as String] as? String,
                                  account: query[kSecAttrAccount as String] as? String,
                                  group: query[kSecAttrAccessGroup as String] as? String,
                                  matchesAll: matchesAll,
                                  noninteractive: (query[kSecUseAuthenticationContext as String] as? LAContext)?.interactionNotAllowed == true))
        if failingDelete { return errSecAuthFailed }
        let before = items.count
        if matchesAll {
            items.removeAll { matches($0, query) }
        } else if let index = items.firstIndex(where: { matches($0, query) }) {
            // Model macOS's file-based default-one behavior so missing the
            // explicit all limit cannot accidentally pass these regressions.
            items.remove(at: index)
        }
        return items.count == before ? errSecItemNotFound : errSecSuccess
    }
}
