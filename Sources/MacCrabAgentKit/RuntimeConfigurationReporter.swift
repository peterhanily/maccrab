import Foundation
import MacCrabCore

/// Owns applied configuration and bounded durable request outcomes. All writes
/// are serialized here; clients cannot turn an inbox file into an applied claim.
actor RuntimeConfigurationReporter {
    private var directory: String?
    private var configuration: EffectiveRuntimeConfiguration?
    private var reloadRequests: Set<UUID> = []
    private static let maximumReceipts = 4096
    private static let retentionSeconds: TimeInterval = 30 * 86400

    func configure(directory: String, snapshot: EffectiveRuntimeConfiguration) throws {
        self.directory = directory
        configuration = snapshot
        let statusDirectory = directory + "/request_status"
        try FileManager.default.createDirectory(atPath: statusDirectory, withIntermediateDirectories: true,
                                                attributes: [.posixPermissions: 0o750])
        if geteuid() == 0 {
            try FileManager.default.setAttributes([.groupOwnerAccountID: 80], ofItemAtPath: statusDirectory)
        }
        try persistConfiguration()
        for var receipt in try receipts() where receipt.state == .accepted {
            if receipt.operation == "reload-rules" || receipt.operation == "remove-suppression" {
                receipt.state = .rejected
                receipt.reason = "Engine restarted before completion could be confirmed; inspect saved state before submitting a new request"
                receipt.updatedAt = Date()
                try persist(receipt)
            }
        }
        try reconcileConfigRequests()
        try pruneReceipts()
    }

    func snapshot() -> EffectiveRuntimeConfiguration? { configuration }

    func record(_ receipt: RuntimeRequestReceipt, supersedingPendingForKey: Bool = false) throws {
        guard configuration != nil else { throw RuntimeConfigContractError("Runtime configuration status is not initialized") }
        try persist(receipt)
        if receipt.operation == "reload-rules", receipt.state == .accepted {
            reloadRequests.insert(receipt.requestID)
        }
        if supersedingPendingForKey, receipt.operation == "set-daemon-config", receipt.state == .accepted, let key = receipt.key {
            for var earlier in try receipts() where earlier.requestID != receipt.requestID
                && earlier.operation == receipt.operation && earlier.key == key && earlier.state == .accepted {
                earlier.state = .superseded
                earlier.reason = "A later accepted request replaced the pending value"
                earlier.updatedAt = Date()
                try persist(earlier)
            }
        }
        try pruneReceipts()
    }

    func apply(_ values: [String: EffectiveRuntimeConfiguration.Entry]) throws {
        guard var snapshot = configuration else { throw RuntimeConfigContractError("Runtime configuration status is not initialized") }
        var changed = false
        for (key, value) in values where snapshot.values[key] != value {
            snapshot.values[key] = value
            changed = true
        }
        if changed { snapshot.generation &+= 1 }
        snapshot.writtenAt = Date()
        configuration = snapshot
        try persistConfiguration()
        try reconcileConfigRequests()
    }

    func takeReloadRequests() -> [UUID] {
        let result = Array(reloadRequests)
        reloadRequests.removeAll()
        return result
    }

    func hasQueuedReloads() -> Bool { !reloadRequests.isEmpty }

    func finishReload(_ identifiers: [UUID], succeeded: Bool, reason: String) throws {
        guard var snapshot = configuration else { return }
        if succeeded {
            snapshot.generation &+= 1
            snapshot.writtenAt = Date()
            configuration = snapshot
            try persistConfiguration()
        }
        let selected = Set(identifiers)
        for var receipt in try receipts() where selected.contains(receipt.requestID) {
            receipt.state = succeeded ? .applied : .rejected
            receipt.reason = reason
            receipt.updatedAt = Date()
            receipt.engineIdentity = snapshot.engineIdentity
            receipt.appliedGeneration = succeeded ? snapshot.generation : nil
            try persist(receipt)
        }
    }

    private func reconcileConfigRequests() throws {
        guard let snapshot = configuration else { return }
        for var receipt in try receipts() where receipt.operation == "set-daemon-config" && receipt.state == .accepted {
            guard let key = receipt.key, let expected = receipt.acceptedValue,
                  let entry = snapshot.values[key], entry.value == expected,
                  entry.configuredValue == expected else { continue }
            receipt.state = .applied
            receipt.reason = "The running engine reports the accepted effective value"
            receipt.engineIdentity = snapshot.engineIdentity
            receipt.appliedGeneration = snapshot.generation
            receipt.updatedAt = Date()
            try persist(receipt)
        }
    }

    private func persistConfiguration() throws {
        guard let directory, let configuration else { return }
        try write(configuration, at: directory + "/effective_config.json")
    }

    private func persist(_ receipt: RuntimeRequestReceipt) throws {
        guard let directory else { throw RuntimeConfigContractError("Request status directory is unavailable") }
        try write(receipt, at: directory + "/request_status/" + receipt.requestID.uuidString + ".json")
    }

    private func write<T: Encodable>(_ value: T, at path: String) throws {
        let data = try JSONEncoder().encode(value)
        try SecureFileIO.atomicReplace(at: path, data: data, mode: 0o640)
        if geteuid() == 0 {
            try FileManager.default.setAttributes([.groupOwnerAccountID: 80], ofItemAtPath: path)
        }
    }

    private func receipts() throws -> [RuntimeRequestReceipt] {
        guard let directory else { return [] }
        let root = URL(fileURLWithPath: directory + "/request_status")
        let files = try FileManager.default.contentsOfDirectory(at: root, includingPropertiesForKeys: nil)
            .filter { $0.pathExtension == "json" && UUID(uuidString: $0.deletingPathExtension().lastPathComponent) != nil }
        return try files.map { file in
            guard let data = try RuntimeConfigurationFiles.readControlData(at: file.path, maximumBytes: 64 * 1024) else {
                throw RuntimeConfigContractError("Request receipt disappeared during enumeration")
            }
            return try JSONDecoder().decode(RuntimeRequestReceipt.self, from: data)
        }
    }

    private func pruneReceipts() throws {
        guard let directory else { return }
        let ordered = try receipts().sorted { $0.updatedAt > $1.updatedAt }
        let cutoff = Date().addingTimeInterval(-Self.retentionSeconds)
        for (index, receipt) in ordered.enumerated() where index >= Self.maximumReceipts || receipt.updatedAt < cutoff {
            try FileManager.default.removeItem(atPath: directory + "/request_status/" + receipt.requestID.uuidString + ".json")
        }
    }
}
