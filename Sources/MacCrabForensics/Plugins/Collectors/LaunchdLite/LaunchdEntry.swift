// LaunchdEntry — value type carrying parsed fields from a single
// launchd plist (or StartupItem). Domain plus label plus program
// resolution plus codesign cross-reference is what the operator
// sees per plan §4.2.

import Foundation

public struct LaunchdEntry: Sendable {

    /// Where this plist lives. Drives risk classification + the
    /// dashboard's grouping.
    public enum Domain: String, Codable, Sendable {
        case systemWideAgent = "system-wide-agent"     // /Library/LaunchAgents
        case systemWideDaemon = "system-wide-daemon"   // /Library/LaunchDaemons (root)
        case userAgent = "user-agent"                  // ~/Library/LaunchAgents
        case systemProtected = "system-protected"      // /System/Library/Launch* (SIP)
        case legacyStartup = "legacy-startup"          // {~,/}Library/StartupItems
        case bam = "bam"                                // BAM login-item (BackgroundItems-v9.btm)
    }

    public let domain: Domain
    public let plistPath: String
    public let label: String
    public let programPath: String?
    public let arguments: [String]
    public let runAtLoad: Bool
    public let keepAlive: Bool
    public let startIntervalSeconds: Int?
    public let watchPaths: [String]
    public let processType: String?

    /// plist mtime in unix epoch milliseconds. Used as observed_at.
    public let plistMtimeMillis: Int64

    /// True iff this entry's process runs as root. Derived from
    /// the domain plus the `UserName` key in the plist when
    /// present.
    public let runsAsRoot: Bool

    /// Username the entry runs as (root, _spotlight, the operator,
    /// etc.). Defaults to the operator account for user-domain
    /// plists, root for system-daemon, the UserName key value
    /// otherwise.
    public let effectiveUser: String

    /// For user-domain plists, which user account owns the agent.
    /// nil for system-wide or BAM entries.
    public let sourceUser: String?

    /// True iff the resolved program_path exists + is readable to
    /// the daemon at parse time.
    public let programExists: Bool

    /// When programExists=false, names the reason:
    ///   "deleted"     no file at the path
    ///   "inaccessible" file present but unreadable
    ///   "unresolved"  the plist's Program / ProgramArguments[0]
    ///                 contained a relative path or unresolved
    ///                 ${VAR} substitution
    public let programMissingReason: String?

    public init(
        domain: Domain,
        plistPath: String,
        label: String,
        programPath: String?,
        arguments: [String] = [],
        runAtLoad: Bool = false,
        keepAlive: Bool = false,
        startIntervalSeconds: Int? = nil,
        watchPaths: [String] = [],
        processType: String? = nil,
        plistMtimeMillis: Int64,
        runsAsRoot: Bool,
        effectiveUser: String,
        sourceUser: String? = nil,
        programExists: Bool,
        programMissingReason: String? = nil
    ) {
        self.domain = domain
        self.plistPath = plistPath
        self.label = label
        self.programPath = programPath
        self.arguments = arguments
        self.runAtLoad = runAtLoad
        self.keepAlive = keepAlive
        self.startIntervalSeconds = startIntervalSeconds
        self.watchPaths = watchPaths
        self.processType = processType
        self.plistMtimeMillis = plistMtimeMillis
        self.runsAsRoot = runsAsRoot
        self.effectiveUser = effectiveUser
        self.sourceUser = sourceUser
        self.programExists = programExists
        self.programMissingReason = programMissingReason
    }
}

/// One-shot parser for a launchd plist file. Pure: takes raw plist
/// data + the path/domain context, returns a LaunchdEntry. Tested
/// directly against fixture plist files; the production walker
/// (LaunchdLitePlugin) builds the file list + calls this for each.
public enum LaunchdPlistParser {

    public enum ParseError: Error, CustomStringConvertible {
        case readFailed(path: String, message: String)
        case decodeFailed(path: String, message: String)
        case missingLabel(path: String)

        public var description: String {
            switch self {
            case .readFailed(let p, let m): return "launchd parse: read failed at \(p): \(m)"
            case .decodeFailed(let p, let m): return "launchd parse: decode failed at \(p): \(m)"
            case .missingLabel(let p): return "launchd parse: plist at \(p) has no Label key (malformed)"
            }
        }
    }

    public static func parse(
        path: String,
        domain: LaunchdEntry.Domain,
        sourceUser: String? = nil
    ) throws -> LaunchdEntry {
        let url = URL(fileURLWithPath: path)
        let data: Data
        do {
            data = try Data(contentsOf: url)
        } catch {
            throw ParseError.readFailed(path: path, message: error.localizedDescription)
        }

        let plist: Any
        do {
            plist = try PropertyListSerialization.propertyList(
                from: data, options: [], format: nil
            )
        } catch {
            throw ParseError.decodeFailed(path: path, message: error.localizedDescription)
        }

        guard let dict = plist as? [String: Any] else {
            throw ParseError.decodeFailed(path: path, message: "top-level plist is not a dictionary")
        }

        guard let label = dict["Label"] as? String else {
            throw ParseError.missingLabel(path: path)
        }

        // Program path can come from `Program` (single) or
        // `ProgramArguments[0]` (more common).
        let programString = dict["Program"] as? String
        let programArguments = (dict["ProgramArguments"] as? [String]) ?? []
        let programPath: String? = programString ?? programArguments.first

        let runAtLoad = (dict["RunAtLoad"] as? Bool) ?? false

        // KeepAlive can be a Bool OR a dictionary of conditions. We
        // treat any KeepAlive dict as "true" for the purposes of
        // the artifact's keepAlive bool — the operator inspects
        // arguments_json for the detail when curious.
        let keepAlive: Bool = {
            if let b = dict["KeepAlive"] as? Bool { return b }
            if dict["KeepAlive"] is [String: Any] { return true }
            return false
        }()

        let startIntervalSeconds = dict["StartInterval"] as? Int
        let watchPaths = (dict["WatchPaths"] as? [String]) ?? []
        let processType = dict["ProcessType"] as? String
        let userNameKey = dict["UserName"] as? String

        // Plist file mtime — the observed_at for the artifact.
        let mtimeMillis: Int64 = {
            guard let attrs = try? FileManager.default.attributesOfItem(atPath: path),
                  let date = attrs[.modificationDate] as? Date else {
                return Int64(Date().timeIntervalSince1970 * 1000)
            }
            return Int64(date.timeIntervalSince1970 * 1000)
        }()

        // Determine effective user + runs-as-root. launchd's
        // documented behavior: the UserName key (when present)
        // overrides the domain default. We follow that — a
        // LaunchDaemon with UserName=_spotlight runs as
        // _spotlight, not as root.
        let effectiveUser: String
        if let u = userNameKey {
            effectiveUser = u
        } else if domain == .systemWideDaemon {
            effectiveUser = "root"
        } else if domain == .userAgent {
            effectiveUser = sourceUser ?? NSUserName()
        } else if domain == .systemWideAgent {
            // Loaded into each user's session at login. From the
            // daemon's perspective, "current operator" is the
            // closest we can attribute. The dashboard's
            // per-user filter handles disambiguation.
            effectiveUser = NSUserName()
        } else if domain == .systemProtected {
            effectiveUser = "root"
        } else {
            effectiveUser = NSUserName()
        }
        let runsAsRoot = (effectiveUser == "root")

        // Resolve program existence.
        var programExists = false
        var missingReason: String? = nil
        if let p = programPath {
            if p.contains("${") {
                missingReason = "unresolved"
            } else if !p.hasPrefix("/") {
                missingReason = "unresolved"
            } else if !FileManager.default.fileExists(atPath: p) {
                missingReason = "deleted"
            } else if !FileManager.default.isReadableFile(atPath: p) {
                missingReason = "inaccessible"
                programExists = true  // present but not readable
            } else {
                programExists = true
            }
        }

        return LaunchdEntry(
            domain: domain,
            plistPath: path,
            label: label,
            programPath: programPath,
            arguments: programArguments,
            runAtLoad: runAtLoad,
            keepAlive: keepAlive,
            startIntervalSeconds: startIntervalSeconds,
            watchPaths: watchPaths,
            processType: processType,
            plistMtimeMillis: mtimeMillis,
            runsAsRoot: runsAsRoot,
            effectiveUser: effectiveUser,
            sourceUser: sourceUser,
            programExists: programExists,
            programMissingReason: missingReason
        )
    }
}
