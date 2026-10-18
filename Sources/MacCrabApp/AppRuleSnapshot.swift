import Foundation
import MacCrabCore

/// Value-only inputs captured on MainActor before directory I/O and decoding.
struct AppRuleSnapshotRequest: Sendable {
    let directory: String
    let cachedDirectory: String?
    let cachedModificationDate: Date?
    let hasCachedRows: Bool

    init(directory: String, cachedDirectory: String? = nil,
         cachedModificationDate: Date? = nil, hasCachedRows: Bool = false) {
        self.directory = directory
        self.cachedDirectory = cachedDirectory
        self.cachedModificationDate = cachedModificationDate
        self.hasCachedRows = hasCachedRows
    }
}

enum AppRuleSnapshot: Equatable, Sendable {
    case unchanged
    case loaded(rows: [RuleViewModel], modificationDate: Date?)
    case missing
}

/// Preserves AppState's display-only parser and directory-mtime shortcut.
/// This is not RuleEngine loading: no rule evaluation, trust-policy changes,
/// alternate source fallback, sorting, deduplication or profile filtering.
enum AppRuleSnapshotReader {
    static func read(_ request: AppRuleSnapshotRequest) throws -> AppRuleSnapshot {
        try Task.checkCancellation()
        let fileManager = FileManager.default
        guard let files = try? fileManager.contentsOfDirectory(atPath: request.directory),
              files.contains(where: { $0.hasSuffix(".json") }) else {
            try Task.checkCancellation()
            return .missing
        }
        try Task.checkCancellation()
        let mtime = (try? fileManager.attributesOfItem(atPath: request.directory))?[.modificationDate] as? Date
        if request.directory == request.cachedDirectory, let mtime,
           mtime == request.cachedModificationDate, request.hasCachedRows {
            try Task.checkCancellation()
            return .unchanged
        }
        let rows = try decode(directory: request.directory, files: files)
        try Task.checkCancellation()
        return .loaded(rows: rows, modificationDate: mtime)
    }

    static func decode(directory: String, files: [String]) throws -> [RuleViewModel] {
        let decoder = JSONDecoder()
        var rows: [RuleViewModel] = []
        for file in files {
            try Task.checkCancellation()
            guard file.hasSuffix(".json") else { continue }
            let data = try? Data(contentsOf: URL(fileURLWithPath: directory + "/" + file))
            try Task.checkCancellation()
            guard let data, let rule = try? decoder.decode(CompiledRule.self, from: data) else { continue }
            rows.append(RuleViewModel(id: rule.id, title: rule.title, level: rule.level.rawValue,
                                      tags: rule.tags, description: rule.description, enabled: rule.enabled))
        }
        try Task.checkCancellation()
        return rows
    }
}
