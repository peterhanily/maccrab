import Foundation

public enum RuntimeConfigurationFiles {
    public static func readControlData(at path: String, maximumBytes: Int = 1024 * 1024) throws -> Data? {
        switch BoundedRegularFileReader.readOutcome(at: path, maximumBytes: maximumBytes) {
        case .success(let snapshot): return snapshot.data
        case .rejected(.notFound): return nil
        case .rejected(let reason):
            throw RuntimeConfigContractError("Control file could not be read: \(URL(fileURLWithPath: path).lastPathComponent) (\(reason))")
        }
    }

    public static func readConfigured(at path: String) throws -> [String: Any]? {
        guard let data = try readControlData(at: path) else { return nil }
        guard let object = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw RuntimeConfigContractError("Configuration must contain a JSON object")
        }
        return object
    }

    public static func readEffective(directory: String) throws -> EffectiveRuntimeConfiguration {
        guard let data = try readControlData(at: directory + "/effective_config.json", maximumBytes: 256 * 1024) else {
            throw RuntimeConfigContractError("Effective runtime configuration is unavailable")
        }
        return try JSONDecoder().decode(EffectiveRuntimeConfiguration.self, from: data)
    }

    public static func readReceipt(directory: String, requestID: UUID) throws -> RuntimeRequestReceipt? {
        let path = directory + "/request_status/" + requestID.uuidString + ".json"
        guard let data = try readControlData(at: path, maximumBytes: 64 * 1024) else { return nil }
        return try JSONDecoder().decode(RuntimeRequestReceipt.self, from: data)
    }

    /// Submission establishes only that a request was placed in the inbox.
    /// The daemon writes its separately owned durable outcome after validation.
    public static func submit(
        operation: String, payload: [String: Any], directory: String, requestID: UUID = UUID()
    ) throws -> UUID {
        guard ["set-daemon-config", "reload-rules", "remove-suppression"].contains(operation) else {
            throw RuntimeConfigContractError("Unsupported runtime request operation")
        }
        let inbox = directory + "/inbox"
        try FileManager.default.createDirectory(atPath: inbox, withIntermediateDirectories: true)
        let data = try JSONSerialization.data(withJSONObject: payload, options: [.sortedKeys])
        let path = inbox + "/" + operation + "-" + requestID.uuidString + ".json"
        try SecureFileIO.atomicReplace(at: path, data: data, mode: 0o600)
        return requestID
    }

    public static func requestID(filename: String, operation: String) -> UUID? {
        let prefix = operation + "-"
        guard filename.hasPrefix(prefix), filename.hasSuffix(".json") else { return nil }
        return UUID(uuidString: String(filename.dropFirst(prefix.count).dropLast(5)))
    }
}
