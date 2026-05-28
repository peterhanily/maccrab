// TCCLitePlugin — com.maccrab.forensics.tcc-lite.
//
// First-party Collector. Snapshots user + system TCC.db via the
// LiveDBSnapshot utility, parses the `access` table from each
// snapshot, emits one `tcc.grant` artifact per row + one
// `tcc.summary_by_service` artifact per service.
//
// Plan reference: §4.1.
//
// Codesign cross-reference for risk scoring (clientSignedByApple
// / clientHasKnownTeam) is wired in v1.13a-4 once launchd-lite
// also needs the same integration point. v1.13a-3 RC ships the
// collector with default-false for those signals — scoring still
// surfaces the high-value services correctly; missing the
// signed-by-Apple mitigation just slightly inflates a few rows.

import Foundation
import CSQLCipher
import CryptoKit

public struct TCCLitePlugin: Collector {

    public static let manifest = PluginManifest(
        id: "com.maccrab.forensics.tcc-lite",
        version: "1.0.0",
        displayName: "TCC-lite",
        description: "Inventory TCC.db grants across user and system scopes. Emits one tcc.grant artifact per row, plus tcc.summary_by_service aggregates. Snapshot-before-parse via SQLite backup API; uses deterministic per-grant risk scoring per plan §4.1.",
        type: .collector,
        runtime: .tierA,
        tccRequirements: [.fullDiskAccess],
        inputs: [
            InputSpec(
                name: "includeDeniedGrants",
                description: "Include access rows with auth_value=denied. Default true — denied grants are useful signal for detecting attempted bypass.",
                type: .bool,
                default: .bool(true),
                required: false
            ),
        ],
        outputs: [
            OutputSpec(
                contentType: "tcc.grant",
                privacyClass: .metadata,
                viewerHint: ViewerHint(
                    viewer: .table,
                    fieldRoles: [
                        "service": .title,
                        "client": .path,
                        "auth_value": .status,
                        "last_modified": .timestamp,
                    ],
                    columns: ["service", "client", "auth_value", "last_modified"]
                )
            ),
            OutputSpec(
                contentType: "tcc.summary_by_service",
                privacyClass: .metadata,
                viewerHint: ViewerHint(
                    viewer: .table,
                    fieldRoles: [
                        "service": .title,
                        "granted_count": .count,
                        "denied_count": .count,
                    ]
                )
            ),
        ],
        mcpTools: [
            MCPToolDescriptor(
                name: "tcc_grants_for_service",
                description: "List clients granted access to a specific TCC service (e.g. fda, accessibility, automation).",
                exposesPrivacyClass: .metadata
            ),
            MCPToolDescriptor(
                name: "tcc_grants_for_client",
                description: "List services granted to a specific client bundle id or binary path.",
                exposesPrivacyClass: .metadata
            ),
            MCPToolDescriptor(
                name: "tcc_automation_chain",
                description: "For a target bundle id (Safari, Mail, Messages, Terminal, etc.), show every client that can drive it via Automation grants.",
                exposesPrivacyClass: .metadata
            ),
            MCPToolDescriptor(
                name: "tcc_high_risk_clients",
                description: "List clients ranked by tcc.grant.risk_score, descending.",
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

        // Source paths. Plan §4.1 lists three; v1.13a-3 covers two
        // (user + system access tables). REG.db gets a coverage
        // advisory note rather than parsing.
        let userTCCPath = NSHomeDirectory() + "/Library/Application Support/com.apple.TCC/TCC.db"
        let systemTCCPath = "/Library/Application Support/com.apple.TCC/TCC.db"

        let layout = CaseDirectoryLayout(
            casesRoot: caseContext.directory.deletingLastPathComponent(),
            caseID: caseContext.caseID
        )

        var notes: [String] = []
        var committed = 0
        var rejected = 0
        var status: CollectionResult.ExitStatus = .ok
        let now = Date()

        // v1.16.0-rc.17: honor includeDeniedGrants input.
        let includeDenied: Bool = {
            if case .bool(let b) = caseContext.inputs.values["includeDeniedGrants"] { return b }
            return true   // manifest default
        }()

        // Aggregate buckets for summary_by_service.
        var perService: [TCCServiceCanonical: (count: Int, allowed: Int, denied: Int, riskMax: Int)] = [:]

        for (path, scope) in [(userTCCPath, "user"), (systemTCCPath, "system")] {
            guard FileManager.default.isReadableFile(atPath: path) else {
                notes.append("\(scope) TCC.db not readable at \(path) — skipped (FDA may be missing)")
                status = .partial
                continue
            }

            // Snapshot before parse — TCC.db is actively written by
            // tccd; the SQLite backup API drains the WAL into the
            // destination so the parser sees a frozen image.
            let snap: LiveDBSnapshotResult
            do {
                snap = try LiveDBSnapshot.snapshot(sourcePath: path, layout: layout)
            } catch {
                notes.append("\(scope) TCC.db snapshot failed: \(error.localizedDescription)")
                status = .partial
                continue
            }

            // Parse the snapshot read-only.
            var db: OpaquePointer?
            let openRC = sqlite3_open_v2(
                snap.path.path, &db,
                SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX,
                nil
            )
            guard openRC == SQLITE_OK, let h = db else {
                notes.append("\(scope) snapshot open failed: \(openRC)")
                status = .partial
                if let h = db { sqlite3_close(h) }
                continue
            }
            defer { sqlite3_close(h) }

            // Different macOS versions have shifted column layouts.
            // Use a tolerant SELECT: pull only columns guaranteed
            // present since macOS 11+. Future migrations can extend.
            let sql = """
            SELECT service, client, client_type, auth_value, auth_reason,
                   indirect_object_identifier, last_modified, csreq
            FROM access
            """
            var stmt: OpaquePointer?
            let prepRC = sqlite3_prepare_v2(h, sql, -1, &stmt, nil)
            if prepRC != SQLITE_OK {
                let msg = String(cString: sqlite3_errmsg(h))
                notes.append("\(scope) prepare failed: \(msg)")
                status = .partial
                sqlite3_finalize(stmt)
                continue
            }
            defer { sqlite3_finalize(stmt) }

            while sqlite3_step(stmt) == SQLITE_ROW {
                guard let serviceCStr = sqlite3_column_text(stmt, 0) else { continue }
                guard let clientCStr = sqlite3_column_text(stmt, 1) else { continue }
                let rawService = String(cString: serviceCStr)
                let client = String(cString: clientCStr)
                let clientType = Int(sqlite3_column_int(stmt, 2))
                let authValueRaw = Int(sqlite3_column_int(stmt, 3))
                let authReasonRaw = Int(sqlite3_column_int(stmt, 4))
                let indirectTarget: String? = {
                    guard sqlite3_column_type(stmt, 5) != SQLITE_NULL else { return nil }
                    return sqlite3_column_text(stmt, 5).map { String(cString: $0) }
                }()
                let lastModifiedRaw = sqlite3_column_int64(stmt, 6)

                let csreqHash: String? = {
                    guard sqlite3_column_type(stmt, 7) != SQLITE_NULL else { return nil }
                    let bytes = sqlite3_column_blob(stmt, 7)
                    let n = sqlite3_column_bytes(stmt, 7)
                    guard let b = bytes, n > 0 else { return nil }
                    let data = Data(bytes: b, count: Int(n))
                    let digest = SHA256.hash(data: data)
                    return digest.map { String(format: "%02x", $0) }.joined()
                }()

                let canonical = TCCServiceNormalization.canonical(for: rawService)
                let authValue = TCCAuthValue.decode(authValueRaw)
                let authReason = TCCAuthReason.decode(authReasonRaw)

                // Skip denied rows when the operator opted out
                // via --includeDeniedGrants=false.
                if !includeDenied, authValue == .denied { continue }

                // macOS stores last_modified as NSDate epoch (seconds
                // since 2001-01-01 00:00:00 UTC), not Unix epoch.
                // Convert.
                let nsDateRef: TimeInterval = 978_307_200
                let lastModified = lastModifiedRaw == 0
                    ? nil
                    : Date(timeIntervalSince1970: nsDateRef + TimeInterval(lastModifiedRaw))

                // Risk scoring (uses defaults for codesign signals
                // until v1.13a-4 cross-reference lands).
                let risk = TCCRiskScoring.score(TCCRiskInput(
                    service: canonical,
                    serviceRaw: rawService,
                    indirectTarget: indirectTarget,
                    authValue: authValue,
                    authReason: authReason,
                    clientSignedByApple: false,
                    clientHasKnownTeam: false,
                    lastModified: lastModified
                ))

                // Build sha256 over the canonical key (path + raw service + client + client_type + scope).
                let dedupSeed = "\(scope):\(rawService):\(client):\(clientType)"
                let sha = SHA256.hash(data: Data(dedupSeed.utf8))
                    .map { String(format: "%02x", $0) }.joined()

                var data: [String: JSONValue] = [
                    "service": .string(canonical.rawValue),
                    "service_raw": .string(rawService),
                    "client": .string(client),
                    "client_type": .integer(Int64(clientType)),
                    "is_bundle_id": .bool(clientType == 0),
                    "auth_value": .string(authValue.token),
                    "auth_reason": .string(authReason.token),
                    "scope": .string(scope),
                    "is_user_scope": .bool(scope == "user"),
                    "risk_score": .integer(Int64(risk.score)),
                    "risk_reason": .array(risk.reasons.map { .string($0.rawValue) }),
                ]
                if let target = indirectTarget {
                    data["indirect_target"] = .string(target)
                }
                if let csHash = csreqHash {
                    data["csreq_hash"] = .string(csHash)
                }
                if let lm = lastModified {
                    data["granted_at_iso"] = .string(ISO8601DateFormatter().string(from: lm))
                }

                let observed = lastModified ?? now
                let summary = "\(canonical.rawValue) \(authValue.token) for \(client) (risk \(risk.score))"

                let record = ArtifactRecord(
                    caseID: caseContext.caseID,
                    pluginID: Self.manifest.id,
                    pluginVersion: Self.manifest.version,
                    schemaVersion: Self.manifest.schemaVersion,
                    contentType: "tcc.grant",
                    sourcePath: snap.path.path,
                    sha256: sha,
                    observedAt: observed,
                    capturedAt: now,
                    summary: summary,
                    sizeBytes: 0,
                    confidence: .observed,
                    privacyClass: .metadata,
                    actor: scope == "user" ? NSUserName() : "system",
                    data: data
                )

                do {
                    try await output.commit(record)
                    committed += 1
                } catch {
                    rejected += 1
                }

                // Update per-service summary bucket.
                var bucket = perService[canonical] ?? (0, 0, 0, 0)
                bucket.count += 1
                if authValue == .allowed || authValue == .limited { bucket.allowed += 1 }
                if authValue == .denied { bucket.denied += 1 }
                if risk.score > bucket.riskMax { bucket.riskMax = risk.score }
                perService[canonical] = bucket
            }
        }

        // Emit per-service summary artifacts.
        for (service, bucket) in perService {
            let summarySeed = "summary:\(service.rawValue):\(bucket.count):\(bucket.allowed):\(bucket.denied)"
            let sha = SHA256.hash(data: Data(summarySeed.utf8))
                .map { String(format: "%02x", $0) }.joined()
            let summaryRecord = ArtifactRecord(
                caseID: caseContext.caseID,
                pluginID: Self.manifest.id,
                pluginVersion: Self.manifest.version,
                schemaVersion: Self.manifest.schemaVersion,
                contentType: "tcc.summary_by_service",
                sha256: sha,
                observedAt: now,
                capturedAt: now,
                summary: "\(service.rawValue): \(bucket.count) grants (\(bucket.allowed) allowed, \(bucket.denied) denied, max risk \(bucket.riskMax))",
                sizeBytes: 0,
                confidence: .derived,
                privacyClass: .metadata,
                data: [
                    "service": .string(service.rawValue),
                    "count": .integer(Int64(bucket.count)),
                    "allowed": .integer(Int64(bucket.allowed)),
                    "denied": .integer(Int64(bucket.denied)),
                    "risk_max": .integer(Int64(bucket.riskMax)),
                ]
            )
            do {
                try await output.commit(summaryRecord)
                committed += 1
            } catch {
                rejected += 1
            }
        }

        notes.append("REG.db not parsed in v1.13a-3 (coverage advisory; planned for v1.13a follow-up)")

        return CollectionResult(
            artifactsCommitted: committed,
            artifactsRejected: rejected,
            notes: notes,
            status: status
        )
    }
}
