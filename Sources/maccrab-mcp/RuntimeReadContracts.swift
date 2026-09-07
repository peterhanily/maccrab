import Foundation
import MacCrabCore

func mcpReadDocument<T: Encodable>(_ value: T) throws -> [String: Any] {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys]
    encoder.keyEncodingStrategy = .convertToSnakeCase
    encoder.dateEncodingStrategy = .iso8601
    let data = try encoder.encode(value)
    return ["content": [["type": "text", "text": String(decoding: data, as: UTF8.self)]]]
}

func mcpRuntimeStatus(directory: String, now: Date = Date()) async -> Any {
    do { return try mcpReadDocument(await RuntimeStatusDocument.read(directory: directory, now: now)) }
    catch { return toolError("Status read failed: \(error.localizedDescription)") }
}

func mcpRuleInventory(directory: String, arguments: [String: Any], now: Date = Date()) -> Any {
    do {
        let document = try RuleInventoryDocument.read(directory: directory, now: now)
        let encoder = JSONEncoder()
        encoder.keyEncodingStrategy = .convertToSnakeCase
        encoder.dateEncodingStrategy = .iso8601
        let encoded = try encoder.encode(document)
        var payload = try JSONSerialization.jsonObject(with: encoded) as? [String: Any] ?? [:]
        let level = (arguments["level"] as? String)?.lowercased()
        let search = (arguments["search"] as? String)?.lowercased()
        let tactic = (arguments["tactic"] as? String)?.lowercased()
        let limit = min(max(arguments["limit"] as? Int ?? 100, 1), 500)
        let offset = max(arguments["offset"] as? Int ?? 0, 0)
        let rows = (payload["rules"] as? [[String: Any]] ?? []).filter { row in
            if let level, (row["level"] as? String)?.lowercased() != level { return false }
            if let tactic, !(row["tags"] as? [String] ?? []).contains(where: { $0.lowercased().contains(tactic) }) { return false }
            if let search, !(row["title"] as? String ?? "").lowercased().contains(search),
               !(row["id"] as? String ?? "").lowercased().contains(search) { return false }
            return true
        }
        payload["total"] = document.rules.count
        payload["matching"] = rows.count
        payload["offset"] = offset
        payload["rules"] = Array(rows.dropFirst(offset).prefix(limit))
        payload["next_offset"] = offset < rows.count && rows.count - offset > limit
            ? ((offset + limit) as Any) : NSNull()
        let data = try JSONSerialization.data(withJSONObject: payload, options: [.sortedKeys])
        return ["content": [["type": "text", "text": String(decoding: data, as: UTF8.self)]]]
    } catch { return toolError("Rule inventory read failed: \(error.localizedDescription)") }
}
