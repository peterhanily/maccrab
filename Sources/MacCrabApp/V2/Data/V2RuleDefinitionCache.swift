import Foundation
import Darwin
import MacCrabCore

/// Definition-only rows. Runtime counters/coverage must never enter this cache.
struct V2RuleDefinitions: Sendable {
    let singleEvent: [V2MockRule]
    let other: [V2MockRule]

    func overlay(_ context: RuleTelemetryContext) -> [V2MockRule] {
        singleEvent.map { row in
            let stats = context.statsByID[row.id]
            return V2MockRule(
                id: row.id, title: row.title, category: row.category, severity: row.severity,
                mitre: row.mitre, isEnabled: row.isEnabled && !context.autoDisabledRuleIDs.contains(row.id),
                lastFired: stats?.lastFiredAt, firesLastWeek: Int(stats?.fireCount ?? 0),
                isCustom: row.isCustom, description: row.description, status: row.status,
                severityOverrideRaw: row.severityOverrideRaw,
                telemetryCoverage: V2RuleCoverage(rawValue: context.coverage(
                    ruleID: row.id, status: row.status ?? "", enabled: row.isEnabled).rawValue) ?? .unknown,
                telemetryWrittenAt: context.snapshotWrittenAt)
        } + other
    }
}

/// Metadata of every file the existing rule loaders consume, including nested
/// composite directories and in-place edits to existing overrides. Telemetry is
/// deliberately excluded. This is an invalidation hint, not an integrity proof;
/// the normal RuleFileLoadingPolicy remains the content reader on every miss.
struct V2RuleDefinitionStamp: Equatable, Sendable {
    struct Entry: Equatable, Sendable {
        let path: String
        let device: Int32
        let inode: UInt64
        let mode: UInt16
        let size: Int64
        let modifiedSeconds: Int
        let modifiedNanos: Int
        let changedSeconds: Int
        let changedNanos: Int
    }
    let entries: [Entry]

    static func read(directory: String) throws -> Self {
        func entry(_ path: String, missingAllowed: Bool, followLink: Bool = false) throws -> Entry? {
            var metadata = stat()
            let result = followLink ? stat(path, &metadata) : lstat(path, &metadata)
            guard result == 0 else {
                if missingAllowed && errno == ENOENT { return nil }
                throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno))
            }
            return Entry(path: path + (followLink ? "#target" : ""), device: metadata.st_dev, inode: metadata.st_ino,
                         mode: metadata.st_mode, size: metadata.st_size,
                         modifiedSeconds: metadata.st_mtimespec.tv_sec,
                         modifiedNanos: metadata.st_mtimespec.tv_nsec,
                         changedSeconds: metadata.st_ctimespec.tv_sec,
                         changedNanos: metadata.st_ctimespec.tv_nsec)
        }
        var entries: [Entry] = []
        for relative in ["compiled_rules", "compiled_rules/sequences", "compiled_rules/graph", "user_rules"] {
            let path = directory + "/" + relative
            guard let root = try entry(path, missingAllowed: true) else { continue }
            entries.append(root)
            let urls: [URL]
            do {
                urls = try FileManager.default.contentsOfDirectory(
                    at: URL(fileURLWithPath: path), includingPropertiesForKeys: nil,
                    options: [.skipsHiddenFiles])
            } catch {
                // The existing composite/user loaders tolerate unavailable
                // optional trees. The compiled base remains required.
                if relative == "compiled_rules" { throw error }
                continue
            }
            for url in urls where url.pathExtension == "json" {
                // Only RuleEngine excludes the base/override integrity
                // manifest. Composite readers consume every JSON filename.
                if (relative == "compiled_rules" || relative == "user_rules"),
                   url.lastPathComponent == "manifest.json" { continue }
                if let metadata = try entry(url.path, missingAllowed: false) {
                    entries.append(metadata)
                    // Composite loaders historically permit links. Track both
                    // link and target metadata without changing that contract.
                    if metadata.mode & UInt16(S_IFMT) == UInt16(S_IFLNK),
                       let target = try entry(url.path, missingAllowed: true, followLink: true) { entries.append(target) }
                }
            }
        }
        if let settings = try entry(directory + "/" + BuiltinRuleSettings.fileName, missingAllowed: true) {
            entries.append(settings)
            if settings.mode & UInt16(S_IFMT) == UInt16(S_IFLNK),
               let target = try entry(settings.path, missingAllowed: true, followLink: true) { entries.append(target) }
        }
        return .init(entries: entries.sorted { $0.path < $1.path })
    }
}

/// One completed definition snapshot and at most one in-flight load. Different
/// profile requests join the old work before starting a new load; cancellation
/// of one consumer never cancels work shared with another consumer.
actor V2RuleDefinitionCache {
    struct Request: Equatable, Sendable {
        let directory: String
        let profile: String
    }
    private struct Cached: Sendable {
        let request: Request
        let stamp: V2RuleDefinitionStamp
        let definitions: V2RuleDefinitions
    }
    private struct Flight {
        let id: UUID
        let request: Request
        let task: Task<Cached, Error>
    }
    enum ReadError: Error { case definitionsChangedDuringRead }
    private var cached: Cached?
    private var flight: Flight?
    private let stamp: @Sendable (String) throws -> V2RuleDefinitionStamp
    private let load: @Sendable (String, String) async throws -> V2RuleDefinitions
    private let onJoin: (@Sendable () async -> Void)?

    init(stamp: @escaping @Sendable (String) throws -> V2RuleDefinitionStamp = {
             try V2RuleDefinitionStamp.read(directory: $0)
         },
         load: @escaping @Sendable (String, String) async throws -> V2RuleDefinitions = { directory, profile in
             try await V2LiveDataProvider.loadRuleDefinitions(directory: directory, profile: profile)
         },
         onJoin: (@Sendable () async -> Void)? = nil) {
        self.stamp = stamp
        self.load = load
        self.onJoin = onJoin
    }

    func definitions(directory: String, profile: String) async throws -> V2RuleDefinitions {
        try Task.checkCancellation()
        let request = Request(directory: directory, profile: profile)
        while let current = flight {
            if let onJoin { await onJoin() }
            let result = await current.task.result
            finish(current, result: result)
            try Task.checkCancellation()
            if current.request == request { return try result.get().definitions }
        }
        let previous = cached
        let stamp = self.stamp
        let load = self.load
        let task = Task.detached(priority: .userInitiated) {
            let before = try stamp(directory)
            if let previous, previous.request == request, previous.stamp == before { return previous }
            let definitions = try await load(directory, profile)
            guard try stamp(directory) == before else { throw ReadError.definitionsChangedDuringRead }
            return Cached(request: request, stamp: before, definitions: definitions)
        }
        let current = Flight(id: UUID(), request: request, task: task)
        flight = current
        let result = await task.result
        finish(current, result: result)
        try Task.checkCancellation()
        return try result.get().definitions
    }

    private func finish(_ current: Flight, result: Result<Cached, Error>) {
        guard flight?.id == current.id else { return }
        flight = nil
        if case .success(let value) = result { cached = value }
        // Never substitute the previous cache after a failed load.
    }
}
