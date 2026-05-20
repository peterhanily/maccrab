// FSEventsPlugin — com.maccrab.forensics.fsevents.
//
// Plan §13.6. macOS records file-system events in /.fseventsd/
// (gzip-compressed binary log files). v1.16.0-rc.7 ships a
// DISCOVERY plugin only — it enumerates the .fseventsd files +
// their UUIDs + sizes + mtimes, leaving the binary record-stream
// parsing for a follow-up.
//
// The discovery layer is still useful: operators can see when
// FSEvents was last truncated, how much history is on disk, and
// (via mtime) whether the daemon has been writing recently — all
// signals for "was something tampering with this volume?"
// Full binary record parsing is documented to be undocumented
// by Apple; community parsers (mvt-project, mac4n6) get the
// structure right but landing a clean Swift port is a multi-
// hundred-LOC follow-up.

import Foundation
import CryptoKit

public struct FSEventsPlugin: Collector {

    public static let manifest = PluginManifest(
        id: "com.maccrab.forensics.fsevents",
        version: "1.0.0",
        displayName: "FSEvents",
        description: "Discovery plugin: enumerates /.fseventsd/ log files (gzipped binary records) with UUID + size + mtime. Full record-stream parsing deferred to a follow-up sub-slice.",
        type: .collector,
        runtime: .tierA,
        tccRequirements: [.fullDiskAccess],
        inputs: [],
        outputs: [
            OutputSpec(contentType: "fsevents.log_file", privacyClass: .metadata),
        ],
        mcpTools: [
            MCPToolDescriptor(
                name: "fsevents_recent_log_files",
                description: "Enumerate /.fseventsd/ log files (UUID + size + mtime). Records inside are not yet parsed.",
                exposesPrivacyClass: .metadata
            ),
        ],
        schemaVersion: 1,
        stability: .preview
    )

    public init() async throws {}

    public func collect(
        case caseContext: CaseContext,
        window: TimeWindow?,
        output: any CollectorOutput
    ) async throws -> CollectionResult {

        var notes: [String] = []
        var committed = 0
        var rejected = 0
        let now = Date()

        // /.fseventsd at the root volume + per-volume FSEvents
        // directories. Read the root for now; cross-volume
        // discovery lands later (requires statfs walking).
        let roots = ["/.fseventsd"]

        for root in roots {
            guard FileManager.default.fileExists(atPath: root) else {
                notes.append("\(root) not present")
                continue
            }
            guard let entries = try? FileManager.default.contentsOfDirectory(
                at: URL(fileURLWithPath: root),
                includingPropertiesForKeys: [.fileSizeKey, .contentModificationDateKey],
                options: [.skipsHiddenFiles]
            ) else {
                notes.append("\(root) not readable (FDA?)")
                continue
            }
            for url in entries {
                let attrs = try? FileManager.default.attributesOfItem(atPath: url.path)
                let size = (attrs?[.size] as? NSNumber)?.int64Value ?? 0
                let mtime = (attrs?[.modificationDate] as? Date) ?? now
                let filename = url.lastPathComponent

                // FSEvents log files are gzipped — name is a hex
                // UUID. Skip non-log entries like fseventsd-uuid.
                let isLog = filename.allSatisfy { c in
                    c.isHexDigit
                }
                if !isLog && !filename.hasSuffix(".gz") { continue }

                let data: [String: JSONValue] = [
                    "filename": .string(filename),
                    "path": .string(url.path),
                    "size_bytes": .integer(size),
                    "mtime_iso": .string(ISO8601DateFormatter().string(from: mtime)),
                ]
                let seed = "fsevents.log_file:\(url.path):\(size)"
                let sha = SHA256.hash(data: Data(seed.utf8)).map { String(format: "%02x", $0) }.joined()
                let record = ArtifactRecord(
                    caseID: caseContext.caseID,
                    pluginID: Self.manifest.id,
                    pluginVersion: Self.manifest.version,
                    schemaVersion: Self.manifest.schemaVersion,
                    contentType: "fsevents.log_file",
                    sourcePath: url.path,
                    sha256: sha,
                    observedAt: mtime,
                    capturedAt: now,
                    summary: "FSEvents log: \(filename) (\(size) bytes)",
                    sizeBytes: size,
                    confidence: .observed,
                    privacyClass: .metadata,
                    actor: "root",
                    data: data
                )
                do {
                    try await output.commit(record)
                    committed += 1
                } catch { rejected += 1 }
            }
        }

        notes.append("FSEvents: \(committed) log files discovered. Binary record-stream parsing deferred.")
        return CollectionResult(
            artifactsCommitted: committed,
            artifactsRejected: rejected,
            notes: notes,
            status: committed > 0 ? .ok : .partial
        )
    }
}
