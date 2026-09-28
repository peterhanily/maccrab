import Foundation
import Darwin

/// The host owns selection and persistence; the collector only reads this file.
/// Keep this v1 shape compatible with the independently packaged collector.
enum SecretTrailScope {
    static let pluginID = "com.maccrab.forensics.secret-trail"
    enum Profile: String, CaseIterable {
        case secretTrail = "secret-trail", repoTripwire = "repo-tripwire", scriptTrace = "script-trace", trustDelta = "trust-delta", firstHour = "first-hour"

        // Rave expansion candidates
        case remoteHands = "remote-hands", skillCheck = "skill-check", localhostLens = "localhost-lens", dependencyAutopsy = "dependency-autopsy", decoy = "decoy", exitCheck = "exit-check", sideDoor = "side-door", identityAftershock = "identity-aftershock", buildWitness = "build-witness", lastGood = "last-good"
        init?(pluginID: String) {
            guard let match = Self.allCases.first(where: { $0.pluginID == pluginID }) else { return nil }; self = match
        }
        var pluginID: String { "com.maccrab.forensics." + rawValue }
        var folder: String { switch self { case .secretTrail: return "SecretTrail"; case .repoTripwire: return "RepoTripwire"; case .scriptTrace: return "ScriptTrace"; case .trustDelta: return "TrustDelta"; case .firstHour: return "FirstHour"; default: return "Rave/" + rawValue } }
        var title: String { switch self { case .secretTrail: return "Secret Trail"; case .repoTripwire: return "Repo Tripwire"; case .scriptTrace: return "Script Trace"; case .trustDelta: return "Trust Delta"; case .firstHour: return "First Hour"; default: return rawValue.split(separator: "-").map { $0.capitalized }.joined(separator: " ") } }
        var kinds: [Kind] { switch self { case .secretTrail: return [.project, .aiSession, .shellHistory, .log]; case .repoTripwire: return [.project]; case .scriptTrace: return [.script]; case .trustDelta: return [.previousApp, .currentApp]; case .firstHour: return [.evidence, .baseline, .current, .savedReview]; case .remoteHands: return [.configuration, .directory]; case .skillCheck: return [.instruction, .directory]; case .localhostLens: return [.listeners, .configuration, .liveListeners]; case .dependencyAutopsy: return [.project, .executionEvents]; case .decoy: return [.registry, .events]; case .exitCheck: return [.archive, .directory]; case .sideDoor: return [.binary, .loadEvents]; case .identityAftershock: return [.incident, .audit, .currentState]; case .buildWitness: return [.checkpoint, .writeEvents]; case .lastGood: return [.earlierSnapshot, .laterSnapshot] } }
        var allowsFiles: Bool { self != .repoTripwire && self != .trustDelta }
        var allowsDirectories: Bool { self != .scriptTrace && self != .firstHour }
        var selectionHelp: String {
            switch self {
            case .secretTrail: return "Choose what this scan may read. Folders include their contents; everything else stays outside the selection."
            case .repoTripwire: return "Choose project folders. Inspect supported execution declarations and referenced shell files before trusting a project."
            case .scriptTrace: return "Choose shell script files. Inspect supported commands and literal encoded layers without running them."
            case .trustDelta: return "Choose exactly one previous and one current .app bundle with the same bundle identifier. Signing metadata is inspected without running the apps."
            case .firstHour: return "Investigate: choose evidence reports. Verify: choose one earlier and one current report. Recheck: choose one saved review. Supports selected Rave reports and single-plugin MacCrab JSON exports."
            case .remoteHands: return "Choose supported remote-tool configurations or directories. Effective permissions, running state and remote sessions are not assessed."
            case .skillCheck: return "Choose instruction files or skill directories. Review supported lexical instructions without executing them."
            case .localhostLens: return "Choose lsof listener output, supported configuration, or an explicit live-listener consent file. Network reachability is not established by a bind address."
            case .dependencyAutopsy: return "Choose an npm project with a lockfile, plus optional supported supplied execution records. Lock declarations and observed execution remain separate."
            case .decoy: return "Choose a managed decoy registry and supported exported file-open events. This scan reviews evidence; creation and cleanup use explicit CLI commands."
            case .exitCheck: return "Choose a ZIP or directory to review before sharing. Nested and binary content can remain uninspected. Sharing-copy creation uses the explicit CLI command."
            case .sideDoor: return "Choose Mach-O binaries for declared libraries and search paths, or supported supplied library-load events. Declarations do not prove loading."
            case .identityAftershock: return "Choose an incident record and supported Microsoft directory-audit export, with optional current grants. Historical events do not establish current authorization."
            case .buildWitness: return "Choose captured checkpoints from the same build run. Capture uses the explicit CLI command; fingerprints alone cannot identify a modifying process."
            case .lastGood: return "Choose two extracted snapshot directories containing rave-snapshot.json. Compare identical declared artifact scopes; dates are supplied snapshot metadata."
            }
        }
    }
    static let components = ["Library", "Application Support", "MacCrab", "SecretTrail"]
    enum Kind: String, Codable, CaseIterable, Identifiable {
        case script, project, aiSession = "ai-session", shellHistory = "shell-history", log
        case previousApp = "previous-app", currentApp = "current-app", evidence, baseline, current, savedReview = "saved-review"
        case configuration = "configuration", directory = "directory", sessions = "sessions", listeners = "listeners", liveListeners = "live-listeners", instruction = "instruction", archive = "archive", binary = "binary", loadEvents = "load-events", registry = "registry", events = "events", incident = "incident", audit = "audit", currentState = "current-state", checkpoint = "checkpoint", writeEvents = "write-events", earlierSnapshot = "earlier-snapshot", laterSnapshot = "later-snapshot", executionEvents = "execution-events"
        var id: String { rawValue }
        var title: String {
            switch self { case .script: return "Shell script"; case .project: return "Project / config"; case .aiSession: return "Saved AI conversation"
            case .shellHistory: return "Shell history"; case .log: return "Log"
            case .previousApp: return "Previous app"; case .currentApp: return "Current app"
            case .evidence: return "Investigation evidence"; case .baseline: return "Earlier report (Verify)"
            case .current: return "Current report (Verify)"; case .savedReview: return "Saved review (Recheck)"
            default: return rawValue.replacingOccurrences(of: "-", with: " ").capitalized }
        }
    }
    struct Source: Codable, Equatable, Identifiable {
        var path: String
        var kind: Kind
        var id: String { path }
    }
    struct Document: Codable { let schemaVersion: Int; let sources: [Source] }
    enum Failure: Error, LocalizedError {
        case selection, unavailable, invalid, write
        var errorDescription: String? {
            switch self {
            case .selection: return "Choose a regular file or folder inside your home, without symbolic links."
            case .unavailable: return "The saved selection could not be read. Check access to the MacCrab settings folder."
            case .invalid: return "The saved selection is invalid. Choose up to 32 distinct files or folders."
            case .write: return "The selection could not be saved. No source files were changed."
            }
        }
    }
    static func valid(_ path: String) -> Bool {
        !path.isEmpty && path.utf8.count <= 1024 && !path.hasPrefix("/")
        && !path.unicodeScalars.contains { CharacterSet.controlCharacters.contains($0) }
        && path.split(separator: "/", omittingEmptySubsequences: false).allSatisfy { !$0.isEmpty && $0 != "." && $0 != ".." && $0 != "~" }
    }
    static func relativeSelection(_ url: URL, home: URL, profile: Profile = .secretTrail) throws -> String {
        guard url.isFileURL, url.path.hasPrefix(home.path + "/") else { throw Failure.selection }
        let relative = String(url.path.dropFirst(home.path.count + 1))
        guard valid(relative), profile != .trustDelta || url.pathExtension == "app" else { throw Failure.selection }
        let parent = try directory(url.deletingLastPathComponent(), create: false)
        defer { close(parent) }
        var st = stat()
        guard fstatat(parent, url.lastPathComponent, &st, AT_SYMLINK_NOFOLLOW) == 0,
              (profile.allowsFiles && st.st_mode & S_IFMT == S_IFREG) || (profile.allowsDirectories && st.st_mode & S_IFMT == S_IFDIR) else { throw Failure.selection }
        return relative
    }
    static func load(home: URL = FileManager.default.homeDirectoryForCurrentUser, profile: Profile = .secretTrail) throws -> [Source] {
        let dir: Int32
        do { dir = try directory(configURL(home, profile: profile), create: false) }
        catch { if errno == ENOENT { return [] }; throw Failure.unavailable }
        defer { close(dir) }
        let fd = openat(dir, "scope.json", O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        guard fd >= 0 else { if errno == ENOENT { return [] }; throw Failure.unavailable }
        defer { close(fd) }
        var st = stat()
        guard fstat(fd, &st) == 0, st.st_mode & S_IFMT == S_IFREG, st.st_size <= 65_536 else { throw Failure.invalid }
        var data = Data(), buffer = [UInt8](repeating: 0, count: 4096)
        while data.count <= 65_536 {
            let count = Darwin.read(fd, &buffer, min(buffer.count, 65_537 - data.count))
            if count < 0 { if errno == EINTR { continue }; throw Failure.unavailable }
            if count == 0 { break }
            data.append(contentsOf: buffer.prefix(count))
        }
        return try decode(data, profile: profile)
    }
    static func decode(_ data: Data, profile: Profile = .secretTrail) throws -> [Source] {
        guard data.count <= 65_536,
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              Set(json.keys) == ["schemaVersion", "sources"],
              let rows = json["sources"] as? [[String: Any]],
              rows.allSatisfy({ Set($0.keys) == ["path", "kind"] }),
              let document = try? JSONDecoder().decode(Document.self, from: data),
              document.schemaVersion == 1 else { throw Failure.invalid }
        try validate(document.sources, profile: profile)
        return document.sources
    }
    static func validate(_ sources: [Source], profile: Profile = .secretTrail, complete: Bool = true) throws {
        guard (1...32).contains(sources.count), sources.allSatisfy({ valid($0.path) && profile.kinds.contains($0.kind) }),
              Set(sources.map { $0.path.precomposedStringWithCanonicalMapping.lowercased() }).count == sources.count else { throw Failure.invalid }
        if profile == .trustDelta || profile == .firstHour {
            guard sources.count <= 8 else { throw Failure.invalid }
            guard complete else { return }
            let kinds = sources.map(\.kind)
            if profile == .trustDelta {
                guard kinds.count == 2, Set(kinds) == [.previousApp, .currentApp] else { throw Failure.invalid }
            } else {
                guard kinds.allSatisfy({ $0 == .evidence }) || kinds == [.savedReview] ||
                    (kinds.count == 2 && Set(kinds) == [.baseline, .current]) else { throw Failure.invalid }
            }
        }
    }
    static func save(_ sources: [Source], home: URL = FileManager.default.homeDirectoryForCurrentUser, profile: Profile = .secretTrail) throws {
        try validate(sources, profile: profile)
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys, .prettyPrinted, .withoutEscapingSlashes]
        let bytes = try encoder.encode(Document(schemaVersion: 1, sources: sources))
        guard bytes.count <= 65_536 else { throw Failure.invalid }
        let dir = try directory(configURL(home, profile: profile), create: true)
        defer { close(dir) }
        // Atomic replacement never follows an existing destination link.
        var st = stat()
        if fstatat(dir, "scope.json", &st, AT_SYMLINK_NOFOLLOW) == 0 {
            guard st.st_mode & S_IFMT == S_IFREG else { throw Failure.write }
        } else if errno != ENOENT { throw Failure.write }
        let temporary = ".scope-" + UUID().uuidString
        let fd = openat(dir, temporary, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard fd >= 0 else { throw Failure.write }
        defer { close(fd); unlinkat(dir, temporary, 0) }
        try bytes.withUnsafeBytes { raw in
            var written = 0
            while written < raw.count {
                let count = Darwin.write(fd, raw.baseAddress!.advanced(by: written), raw.count - written)
                if count < 0 && errno == EINTR { continue }
                guard count > 0 else { throw Failure.write }; written += count
            }
        }
        guard fsync(fd) == 0, renameat(dir, temporary, dir, "scope.json") == 0 else { throw Failure.write }
    }
    private static func configURL(_ home: URL, profile: Profile) -> URL {
        (Array(components.dropLast()) + [profile.folder]).reduce(home) { $0.appendingPathComponent($1, isDirectory: true) }
    }
    private static func directory(_ url: URL, create: Bool) throws -> Int32 {
        var path = url.path
        if path == "/tmp" || path.hasPrefix("/tmp/") || path == "/var" || path.hasPrefix("/var/") { path = "/private" + path }
        guard path.hasPrefix("/"), !path.contains("\u{0}") else { throw Failure.selection }
        let parts = path.split(separator: "/").map(String.init)
        guard !parts.contains("."), !parts.contains("..") else { throw Failure.selection }
        var parent = open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard parent >= 0 else { throw Failure.unavailable }
        for part in parts {
            if create && mkdirat(parent, part, 0o700) != 0 && errno != EEXIST {
                let code = errno; close(parent); errno = code; throw Failure.write
            }
            let child = openat(parent, part, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            let code = errno; close(parent)
            guard child >= 0 else { errno = code; throw Failure.unavailable }
            parent = child
        }
        return parent
    }
}
