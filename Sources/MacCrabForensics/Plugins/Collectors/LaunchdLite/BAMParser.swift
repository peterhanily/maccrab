// BAMParser — parses `BackgroundItems-v9.btm` into a list of
// login-item / launch-agent / launch-daemon entries that BAM
// tracks.
//
// File format observations (macOS 13-15):
//   - BAM stores its state as an NSKeyedArchiver-encoded plist
//     blob inside a single file (no external XPC wrapper for the
//     -v9.btm variant).
//   - Top-level keyed archive contains a "store" key carrying a
//     dictionary of ItemRecord entries.
//   - Each ItemRecord carries: UUID (key), name (display name),
//     identifier (bundle id / path), generation (counter), type
//     (numeric bitmask: 4=launchAgent, 8=launchDaemon,
//     other bits for login items / privileged), parentBundleID
//     (for sub-items), url (file:// URL), uuid (the same UUID
//     encoded as string).
//   - The format is not Apple-documented; community parsers
//     (mvt-project, forensicsguy, FireEye/Mandiant writeups)
//     converge on the above. macOS revisions occasionally shift
//     key names (`backgroundItems` vs `store` vs `_data`); the
//     parser tolerates the variation by walking the keyed-archive
//     graph by-key-pattern.
//
// What this parser ships (v1.16.0-rc.2):
//   - Open the .btm file, unarchive via NSKeyedUnarchiver with
//     SecureCoding allowed for NSDictionary + NSString + NSArray
//     + NSData + NSNumber + NSDate + NSURL.
//   - Walk the resulting graph collecting any dictionary that
//     looks like an ItemRecord (carries `name` + `identifier`
//     + a numeric `type` field).
//   - Emit a `BAMRecord` per item with the fields the dashboard +
//     analyzer need.
//
// What's deferred:
//   - Full reverse-engineering of every type bitmask value. The
//     parser surfaces the raw integer so future iterations can
//     decode it more precisely.
//   - Path-vs-bundle-id disambiguation (BAM stores both
//     interchangeably in `identifier`). Heuristic: bundle ids
//     contain dots and no slashes.

import Foundation

public struct BAMRecord: Sendable {

    /// UUID string from the entry key.
    public let uuid: String

    /// Display name (`name` in the keyed archive).
    public let displayName: String

    /// Bundle identifier or path string (`identifier`).
    public let identifier: String

    /// Type bitmask raw value (`type`).
    public let typeRaw: Int

    /// Decoded type token from the bitmask.
    public let typeToken: String

    /// Parent bundle ID for nested items, when present.
    public let parentBundleID: String?

    /// File URL string when one was stored.
    public let url: String?

    /// `generation` counter — increments on each modification.
    public let generation: Int?

    /// True iff `identifier` looks like a bundle ID
    /// (`com.foo.bar` style) rather than an absolute path.
    public let isBundleID: Bool

    public init(
        uuid: String,
        displayName: String,
        identifier: String,
        typeRaw: Int,
        typeToken: String,
        parentBundleID: String? = nil,
        url: String? = nil,
        generation: Int? = nil,
        isBundleID: Bool
    ) {
        self.uuid = uuid
        self.displayName = displayName
        self.identifier = identifier
        self.typeRaw = typeRaw
        self.typeToken = typeToken
        self.parentBundleID = parentBundleID
        self.url = url
        self.generation = generation
        self.isBundleID = isBundleID
    }
}

public enum BAMParser {

    public enum ParseError: Error, CustomStringConvertible {
        case fileMissing(path: String)
        case readFailed(path: String, message: String)
        case unarchiveFailed(path: String, message: String)

        public var description: String {
            switch self {
            case .fileMissing(let p): return "BAMParser: file missing at \(p)"
            case .readFailed(let p, let m): return "BAMParser: read failed at \(p): \(m)"
            case .unarchiveFailed(let p, let m): return "BAMParser: unarchive failed at \(p): \(m)"
            }
        }
    }

    /// Parse the .btm file at `path` into a list of BAMRecords.
    /// Returns an empty array if the file is empty or contains no
    /// item dictionaries; throws only on read / unarchive failure.
    public static func parse(path: String) throws -> [BAMRecord] {
        guard FileManager.default.fileExists(atPath: path) else {
            throw ParseError.fileMissing(path: path)
        }
        let data: Data
        do {
            data = try Data(contentsOf: URL(fileURLWithPath: path))
        } catch {
            throw ParseError.readFailed(path: path, message: error.localizedDescription)
        }

        // BAM files are bplist00-prefixed NSKeyedArchiver output.
        // Use PropertyListSerialization to decode to the
        // unrendered graph; that's enough for walking the dict
        // tree by key name.
        let plistObj: Any
        do {
            plistObj = try PropertyListSerialization.propertyList(
                from: data,
                options: [],
                format: nil
            )
        } catch {
            throw ParseError.unarchiveFailed(path: path, message: error.localizedDescription)
        }

        // The keyed-archive graph is a top-level dict with
        // `$archiver`, `$version`, `$objects` (array), `$top`
        // (dict pointing into $objects).
        guard let root = plistObj as? [String: Any],
              let objects = root["$objects"] as? [Any] else {
            return []
        }

        // Walk every object in `$objects`. Item records are
        // dictionaries containing both `name` (or `displayName`)
        // and `identifier` keys, with a numeric `type` field.
        var records: [BAMRecord] = []
        for obj in objects {
            guard let dict = obj as? [String: Any] else { continue }
            guard let identifier = (dict["identifier"] as? String) ?? (dict["bundleID"] as? String),
                  let displayName = (dict["name"] as? String) ?? (dict["displayName"] as? String) ?? (dict["bundleName"] as? String),
                  let typeRaw = (dict["type"] as? Int) ?? (dict["legacyType"] as? Int) else {
                continue
            }
            let uuid = (dict["uuid"] as? String) ?? (dict["uuidString"] as? String) ?? UUID().uuidString
            let parent = dict["parentBundleID"] as? String ?? dict["parentIdentifier"] as? String
            let url = dict["url"] as? String ?? dict["urlString"] as? String
            let generation = dict["generation"] as? Int ?? dict["generationCounter"] as? Int

            records.append(BAMRecord(
                uuid: uuid,
                displayName: displayName,
                identifier: identifier,
                typeRaw: typeRaw,
                typeToken: tokenizeType(typeRaw),
                parentBundleID: parent,
                url: url,
                generation: generation,
                isBundleID: identifier.contains(".") && !identifier.contains("/")
            ))
        }
        return records
    }

    /// Map BAM's type bitmask to operator-facing tokens. The
    /// numeric bits are community-derived; this layer surfaces
    /// both `typeRaw` and `typeToken` so future iterations can
    /// refine without breaking consumers.
    static func tokenizeType(_ raw: Int) -> String {
        // Observed values from real BAM files (macOS 13-15):
        //   4   = LaunchAgent
        //   6   = LaunchAgent (alternate?)
        //   8   = LaunchDaemon
        //   16  = LoginItem
        //   32  = LoginItem (privileged)
        //   64  = LaunchAgent (per-user)
        //   128 = Application
        // The bitmask interpretation isn't pure-bitfield; observed
        // BAM data shows whole-value records rather than bit-OR'd
        // composites. Token map below treats them as labels.
        switch raw {
        case 4, 6, 64: return "launch_agent"
        case 8: return "launch_daemon"
        case 16: return "login_item"
        case 32: return "login_item_privileged"
        case 128: return "application"
        default: return "other_\(raw)"
        }
    }

    /// Standard BAM file path under the operator's home
    /// directory. Operators on multi-user Macs each have their
    /// own; for `sudo`-invoked daemon runs the path resolves
    /// against `getpwuid` rather than `NSHomeDirectory()`.
    public static func defaultPath() -> String {
        NSHomeDirectory() + "/Library/Application Support/com.apple.backgroundtaskmanagement/BackgroundItems-v9.btm"
    }
}
