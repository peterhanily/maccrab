// LaunchdLitePlugin — com.maccrab.forensics.launchd-lite.
//
// Walks the standard launchd plist directories + StartupItems,
// parses each plist via LaunchdPlistParser, enriches each
// program_path with codesign posture via CodesignResolveEnricher,
// emits one `launchd.entry` artifact per plist.
//
// Plan reference: §4.2.
//
// BAM (BackgroundItems-v9.btm) is the format-specific binary
// parser; deferred to follow-up. The v1.13a-4 RC ships plist
// coverage + codesign cross-reference, which catches the dominant
// macOS persistence pattern. BAM-driven login items emit a
// coverage advisory note.

import Foundation
import CryptoKit

public struct LaunchdLitePlugin: Collector {

    public static let manifest = PluginManifest(
        id: "com.maccrab.forensics.launchd-lite",
        version: "1.0.0",
        displayName: "launchd-lite",
        description: "Inventory every launchd plist on disk (LaunchAgents + LaunchDaemons + StartupItems). Each program_path is codesign-enriched so team_id + signing_status land on the artifact alongside the persistence-point metadata. BAM (BackgroundItems-v9.btm) parse is deferred to a follow-up sub-slice.",
        type: .collector,
        runtime: .tierA,
        tccRequirements: [.fullDiskAccess],
        inputs: [
            InputSpec(
                name: "includeSystemBaseline",
                description: "Include /System/Library/LaunchAgents + /System/Library/LaunchDaemons (the Apple-supplied baseline). Default false — these are SIP-protected, almost always Apple-signed, and the volume is high. Enable for diff-against-baseline runs.",
                type: .bool,
                default: .bool(false),
                required: false
            ),
        ],
        outputs: [
            OutputSpec(contentType: "launchd.entry", privacyClass: .metadata),
            OutputSpec(contentType: "launchd.bam_entry", privacyClass: .metadata),
        ],
        mcpTools: [
            MCPToolDescriptor(
                name: "launchd_unsigned_or_unknown_team",
                description: "List launchd entries pointing to unsigned binaries or unfamiliar-team binaries.",
                exposesPrivacyClass: .metadata
            ),
            MCPToolDescriptor(
                name: "launchd_recently_modified",
                description: "List launchd entries whose plist mtime is within a recent window (default 7 days).",
                exposesPrivacyClass: .metadata
            ),
            MCPToolDescriptor(
                name: "launchd_runs_as_root",
                description: "List launchd entries that run with root privilege.",
                exposesPrivacyClass: .metadata
            ),
            MCPToolDescriptor(
                name: "launchd_by_path",
                description: "Show every launchd entry whose program_path matches a specific binary path.",
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

        let enricher = try await CodesignResolveEnricher()
        var notes: [String] = []
        var committed = 0
        var rejected = 0
        var status: CollectionResult.ExitStatus = .ok
        let now = Date()

        // Source set. (systemBaseline opt-in is wired through the
        // manifest's inputs but PluginRunner hasn't surfaced
        // per-invocation inputs to plugins yet — that lands later.
        // For v1.13a-4 we default to skipping the baseline.)
        struct Source {
            let path: String
            let domain: LaunchdEntry.Domain
            let sourceUser: String?
        }
        let sources: [Source] = [
            Source(path: "/Library/LaunchAgents", domain: .systemWideAgent, sourceUser: nil),
            Source(path: "/Library/LaunchDaemons", domain: .systemWideDaemon, sourceUser: nil),
            Source(path: NSHomeDirectory() + "/Library/LaunchAgents",
                   domain: .userAgent,
                   sourceUser: NSUserName()),
            Source(path: NSHomeDirectory() + "/Library/StartupItems",
                   domain: .legacyStartup,
                   sourceUser: NSUserName()),
            Source(path: "/Library/StartupItems", domain: .legacyStartup, sourceUser: nil),
        ]

        for src in sources {
            guard FileManager.default.fileExists(atPath: src.path) else { continue }
            let urls: [URL]
            do {
                urls = try FileManager.default.contentsOfDirectory(
                    at: URL(fileURLWithPath: src.path),
                    includingPropertiesForKeys: [.isRegularFileKey],
                    options: [.skipsHiddenFiles]
                )
            } catch {
                notes.append("Couldn't list \(src.path): \(error.localizedDescription)")
                status = .partial
                continue
            }

            for url in urls where url.pathExtension == "plist" {
                let entry: LaunchdEntry
                do {
                    entry = try LaunchdPlistParser.parse(
                        path: url.path,
                        domain: src.domain,
                        sourceUser: src.sourceUser
                    )
                } catch {
                    notes.append("plist parse failed at \(url.path): \(error)")
                    rejected += 1
                    continue
                }

                // Codesign cross-reference on the program path (when
                // present + exists). Returns metadata-class fields.
                var codesignFields: [String: EnrichmentValue] = [:]
                if let p = entry.programPath, entry.programExists {
                    let enrichment = try? await enricher.enrich(
                        .path(URL(fileURLWithPath: p)),
                        stage: .onDemand
                    )
                    codesignFields = enrichment?.fields ?? [:]
                }

                // Build the artifact payload.
                var data: [String: JSONValue] = [
                    "domain": .string(entry.domain.rawValue),
                    "plist_path": .string(entry.plistPath),
                    "label": .string(entry.label),
                    "runs_as_root": .bool(entry.runsAsRoot),
                    "effective_user": .string(entry.effectiveUser),
                    "run_at_load": .bool(entry.runAtLoad),
                    "keep_alive": .bool(entry.keepAlive),
                    "program_exists": .bool(entry.programExists),
                    "arguments_count": .integer(Int64(entry.arguments.count)),
                ]
                if let p = entry.programPath {
                    data["program_path"] = .string(p)
                }
                if !entry.arguments.isEmpty {
                    data["arguments_json"] = .array(entry.arguments.map { .string($0) })
                }
                if let interval = entry.startIntervalSeconds {
                    data["start_interval_seconds"] = .integer(Int64(interval))
                }
                if !entry.watchPaths.isEmpty {
                    data["watch_paths_json"] = .array(entry.watchPaths.map { .string($0) })
                }
                if let proc = entry.processType {
                    data["process_type"] = .string(proc)
                }
                if let reason = entry.programMissingReason {
                    data["program_missing_reason"] = .string(reason)
                }
                if let sourceUser = entry.sourceUser {
                    data["source_user"] = .string(sourceUser)
                }
                data["plist_mtime_ms"] = .integer(entry.plistMtimeMillis)

                // Merge codesign fields onto the artifact data so
                // dashboards / Sigma rules see codesign.team_id
                // alongside the launchd metadata in one record.
                // EnrichmentValue and JSONValue have overlapping
                // shape; convert via the helper below.
                for (key, value) in codesignFields {
                    data[key] = Self.jsonValue(from: value)
                }

                // sha256 over (domain, plist_path, label) — stable
                // per persistence point.
                let dedupSeed = "\(entry.domain.rawValue):\(entry.plistPath):\(entry.label)"
                let sha = SHA256.hash(data: Data(dedupSeed.utf8))
                    .map { String(format: "%02x", $0) }.joined()

                let observed = Date(timeIntervalSince1970: Double(entry.plistMtimeMillis) / 1000)
                let summary = "\(entry.domain.rawValue) \(entry.label) → \(entry.programPath ?? "(none)")"

                let record = ArtifactRecord(
                    caseID: caseContext.caseID,
                    pluginID: Self.manifest.id,
                    pluginVersion: Self.manifest.version,
                    schemaVersion: Self.manifest.schemaVersion,
                    contentType: "launchd.entry",
                    sourcePath: entry.plistPath,
                    sourceMtime: entry.plistMtimeMillis,
                    sha256: sha,
                    observedAt: observed,
                    capturedAt: now,
                    summary: summary,
                    sizeBytes: 0,
                    confidence: .observed,
                    privacyClass: .metadata,
                    actor: entry.sourceUser,
                    data: data
                )

                do {
                    try await output.commit(record)
                    committed += 1
                } catch {
                    rejected += 1
                }
            }
        }

        // v1.16.0-rc.2: BAM (BackgroundItems-v9.btm) parse landed.
        let bamPath = BAMParser.defaultPath()
        if FileManager.default.fileExists(atPath: bamPath) {
            do {
                let bamRecords = try BAMParser.parse(path: bamPath)
                for bam in bamRecords {
                    let dedupSeed = "bam:\(bam.uuid):\(bam.identifier)"
                    let sha = SHA256.hash(data: Data(dedupSeed.utf8))
                        .map { String(format: "%02x", $0) }.joined()
                    var bamData: [String: JSONValue] = [
                        "uuid": .string(bam.uuid),
                        "display_name": .string(bam.displayName),
                        "identifier": .string(bam.identifier),
                        "is_bundle_id": .bool(bam.isBundleID),
                        "type_raw": .integer(Int64(bam.typeRaw)),
                        "type_token": .string(bam.typeToken),
                    ]
                    if let p = bam.parentBundleID { bamData["parent_bundle_id"] = .string(p) }
                    if let u = bam.url { bamData["url"] = .string(u) }
                    if let g = bam.generation { bamData["generation"] = .integer(Int64(g)) }
                    let bamRecord = ArtifactRecord(
                        caseID: caseContext.caseID,
                        pluginID: Self.manifest.id,
                        pluginVersion: Self.manifest.version,
                        schemaVersion: Self.manifest.schemaVersion,
                        contentType: "launchd.bam_entry",
                        sourcePath: bamPath,
                        sha256: sha,
                        observedAt: now,
                        capturedAt: now,
                        summary: "BAM \(bam.typeToken): \(bam.displayName) (\(bam.identifier))",
                        sizeBytes: 0,
                        confidence: .observed,
                        privacyClass: .metadata,
                        actor: NSUserName(),
                        data: bamData
                    )
                    do {
                        try await output.commit(bamRecord)
                        committed += 1
                    } catch {
                        rejected += 1
                    }
                }
                notes.append("BAM parse: \(bamRecords.count) entries emitted")
            } catch {
                notes.append("BAM parse failed: \(error)")
                status = .partial
            }
        } else {
            notes.append("BAM file not present at \(bamPath) — skipped")
        }

        _ = enricher
        return CollectionResult(
            artifactsCommitted: committed,
            artifactsRejected: rejected,
            notes: notes,
            status: status
        )
    }

    /// Translate an EnrichmentValue (codesign-resolve output shape)
    /// into a JSONValue (artifact_data payload shape). The two
    /// enums overlap in scalar cases; we widen array-of-string
    /// into an array of JSONValue strings. Other enrichers may
    /// produce values we don't yet handle (.double); fall back to
    /// string-coerced.
    private static func jsonValue(from value: EnrichmentValue) -> JSONValue {
        switch value {
        case .bool(let b): return .bool(b)
        case .integer(let i): return .integer(Int64(i))
        case .double(let d): return .double(d)
        case .string(let s): return .string(s)
        case .stringArray(let a): return .array(a.map { .string($0) })
        case .nil: return .null
        }
    }
}
