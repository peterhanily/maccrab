import Foundation

func cliFailure(_ message: String, code: Int32 = 1) -> Never {
    FileHandle.standardError.write(Data((message + "\n").utf8))
    exit(code)
}

/// Shared by the actual stdout path and its serialization contract tests.
func encodeCLIJSON<T: Encodable>(_ value: T) throws -> Data {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
    encoder.keyEncodingStrategy = .convertToSnakeCase
    encoder.dateEncodingStrategy = .iso8601
    return try encoder.encode(value)
}

func printCLIJSON<T: Encodable>(_ value: T) throws {
    let data = try encodeCLIJSON(value)
    print(String(decoding: data, as: UTF8.self))
}

func printCLIJSONObject(_ value: [String: Any]) throws {
    let data = try JSONSerialization.data(withJSONObject: value, options: [.prettyPrinted, .sortedKeys])
    print(String(decoding: data, as: UTF8.self))
}
