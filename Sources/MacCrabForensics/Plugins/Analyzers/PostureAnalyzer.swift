// PostureAnalyzer — com.maccrab.forensics.posture-analyzer.
//
// The composition-proof for the platform. Reads existing tcc.grant
// + launchd.entry artifacts from a case, cross-references them by
// client bundle id / path, and emits structured posture.* findings.
//
// Plan reference: §7 v1.15 release card.
//
// What this Analyzer demonstrates:
//   - Three plugin types compose end-to-end. TCC-lite (Collector,
//     v1.13a-3) + launchd-lite (Collector, v1.13a-4) +
//     codesign-resolve (Enricher, v1.13a-2) feed the substrate
//     artifacts. PostureAnalyzer (this file, v1.15) consumes them.
//   - The four-protocol scheme works for real findings, not just
//     plumbing.

import Foundation
import CryptoKit
import CSQLCipher

public struct PostureAnalyzer: Analyzer {

    /// Shared viewer hint for every posture.* finding artifact — they
    /// share one shape (severity + explanation; the finding title is the
    /// record-level summary). Rendered as a severity-tinted table so the
    /// operator can scan findings.
    static let findingHint = ViewerHint(
        viewer: .table,
        fieldRoles: [
            "severity": .severity,
            "explanation": .body,
        ]
    )

    public static let manifest = PluginManifest(
        id: "com.maccrab.forensics.posture-analyzer",
        version: "1.0.0",
        displayName: "Posture Analyzer",
        description: "Reads tcc.grant + launchd.entry artifacts and emits posture.* findings (unsigned_persistence / unfamiliar_team_persistence / automation_to_sensitive_target / high_privilege_unsigned_combo / permissioned_persistence). Composition-proof demonstrating all four plugin types working end-to-end.",
        type: .analyzer,
        runtime: .tierA,
        tccRequirements: [],
        inputs: [],
        outputs: [
            OutputSpec(contentType: "posture.unsigned_persistence", privacyClass: .metadata, viewerHint: Self.findingHint),
            OutputSpec(contentType: "posture.unfamiliar_team_persistence", privacyClass: .metadata, viewerHint: Self.findingHint),
            OutputSpec(contentType: "posture.automation_to_sensitive_target", privacyClass: .metadata, viewerHint: Self.findingHint),
            OutputSpec(contentType: "posture.high_privilege_unsigned_combo", privacyClass: .metadata, viewerHint: Self.findingHint),
            OutputSpec(contentType: "posture.permissioned_persistence", privacyClass: .metadata, viewerHint: Self.findingHint),
            OutputSpec(contentType: "posture.analysis_unavailable_encrypted", privacyClass: .metadata, viewerHint: Self.findingHint),
        ],
        mcpTools: [],
        schemaVersion: 1,
        stability: .preview
    )

    public init() async throws {}

    public func analyze(
        case caseContext: CaseContext,
        scope: AnalyzerScope
    ) async throws -> [Finding] {
        // The Analyzer doesn't get a CollectorOutput; it returns
        // [Finding] which the PluginRunner is responsible for
        // committing back as artifacts. (Runner wiring lands in
        // v1.15-1.2.)
        //
        // We open a side connection to the case.sqlite directly
        // here — Analyzer would prefer to consume via the
        // ArtifactStore's query API, but the protocol doesn't
        // currently thread the store through. v1.15 RC ships this
        // direct-read pattern; a future iteration can plumb the
        // store handle through the protocol.

        let casesRoot = caseContext.directory.deletingLastPathComponent()
        let layout = CaseDirectoryLayout(casesRoot: casesRoot, caseID: caseContext.caseID)
        let sqlitePath = layout.sqliteFile.path

        guard FileManager.default.fileExists(atPath: sqlitePath) else {
            return []
        }

        // For v1.15 RC we read via a fresh connection. Encrypted
        // cases need the DEK applied. PluginRunner will pass the
        // already-open store handle in a future revision; for now
        // we work with the case's plaintext store only.
        if caseContext.encryptionState == .encryptedKeychain ||
           caseContext.encryptionState == .encryptedPassword {
            // The analyzer opens a fresh read-only SQLite connection
            // (below) and does not yet have the case DEK, so it can't
            // read an encrypted store. Rather than returning [] —
            // which is indistinguishable from "analyzed, found
            // nothing" and silently hides the gap — emit ONE honest
            // informational finding so the operator (and the
            // posture_findings MCP tool) sees that analysis was
            // skipped, not clean. The real fix is to thread the
            // already-open (decrypted) ArtifactStore handle through
            // the Analyzer protocol; until then this surfaces the
            // limitation instead of masking it.
            return [Finding(
                findingType: "posture.analysis_unavailable_encrypted",
                severity: .informational,
                title: "Posture analysis unavailable — encrypted case",
                explanation: "This case is encrypted, and the posture analyzer cannot yet read an encrypted store (it opens a direct read-only connection without the case key). Any tcc.grant / launchd.entry artifacts were collected but NOT cross-referenced, so the absence of posture findings here does not mean the case is clean. Re-run posture analysis on a plaintext case, or this gap closes once the analyzer is handed the already-open decrypted store handle.",
                backedBy: [],
                confidence: .observed
            )]
        }

        // Read tcc.grant + launchd.entry rows.
        let tccGrants = try readArtifacts(sqlitePath: sqlitePath, contentType: "tcc.grant", caseID: caseContext.caseID)
        let launchdEntries = try readArtifacts(sqlitePath: sqlitePath, contentType: "launchd.entry", caseID: caseContext.caseID)

        var findings: [Finding] = []

        findings.append(contentsOf: detectUnsignedPersistence(launchd: launchdEntries))
        findings.append(contentsOf: detectUnfamiliarTeamPersistence(launchd: launchdEntries))
        findings.append(contentsOf: detectAutomationToSensitive(tcc: tccGrants))
        findings.append(contentsOf: detectHighPrivilegeUnsignedCombo(launchd: launchdEntries, tcc: tccGrants))
        findings.append(contentsOf: detectPermissionedPersistence(launchd: launchdEntries, tcc: tccGrants))

        return findings
    }

    // MARK: - Finding detectors

    private struct ArtifactRow {
        let id: Int64
        let contentType: String
        let summary: String?
        let data: [String: Any]
    }

    private func readArtifacts(sqlitePath: String, contentType: String, caseID: String) throws -> [ArtifactRow] {
        var db: OpaquePointer?
        let rc = sqlite3_open_v2(sqlitePath, &db, SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX, nil)
        guard rc == SQLITE_OK, let h = db else {
            if let h = db { sqlite3_close(h) }
            return []
        }
        defer { sqlite3_close(h) }

        let sql = """
            SELECT a.id, a.content_type, a.summary, d.json
            FROM artifacts a JOIN artifact_data d ON d.artifact_id = a.id
            WHERE a.case_id = ? AND a.content_type = ?
            """
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(h, sql, -1, &stmt, nil) == SQLITE_OK else {
            return []
        }
        defer { sqlite3_finalize(stmt) }
        sqlite3_bind_text(stmt, 1, caseID, -1, unsafeBitCast(OpaquePointer(bitPattern: -1)!, to: sqlite3_destructor_type.self))
        sqlite3_bind_text(stmt, 2, contentType, -1, unsafeBitCast(OpaquePointer(bitPattern: -1)!, to: sqlite3_destructor_type.self))

        var out: [ArtifactRow] = []
        while sqlite3_step(stmt) == SQLITE_ROW {
            let id = sqlite3_column_int64(stmt, 0)
            let ct = String(cString: sqlite3_column_text(stmt, 1))
            let summary: String? = sqlite3_column_type(stmt, 2) == SQLITE_NULL
                ? nil
                : String(cString: sqlite3_column_text(stmt, 2))
            let json = String(cString: sqlite3_column_text(stmt, 3))
            let data: [String: Any]
            if let jdata = json.data(using: .utf8),
               let obj = try? JSONSerialization.jsonObject(with: jdata) as? [String: Any] {
                data = obj
            } else {
                data = [:]
            }
            out.append(ArtifactRow(id: id, contentType: ct, summary: summary, data: data))
        }
        return out
    }

    // MARK: - Detector implementations

    private func detectUnsignedPersistence(launchd: [ArtifactRow]) -> [Finding] {
        launchd.compactMap { row -> Finding? in
            let signingStatus = row.data["codesign.signing_status"] as? String
            // No codesign field at all (missing program) OR explicit
            // "unsigned"  → high-trust signal.
            if signingStatus == nil || signingStatus == "unsigned" {
                // Skip rows where the binary doesn't exist on disk —
                // those are already surfaced via program_missing_reason.
                if let exists = row.data["program_exists"] as? Bool, !exists {
                    return nil
                }
                let label = row.data["label"] as? String ?? "(no label)"
                let programPath = row.data["program_path"] as? String ?? "(no program)"
                let domain = row.data["domain"] as? String ?? "(unknown)"
                return Finding(
                    findingType: "posture.unsigned_persistence",
                    severity: row.data["runs_as_root"] as? Bool == true ? .high : .medium,
                    title: "Unsigned persistence: \(label)",
                    explanation: "The launchd plist '\(label)' in \(domain) launches \(programPath), which is unsigned or has no detectable codesign posture. Unsigned binaries persisting on a Mac are a high-trust signal for post-compromise persistence — the same surface AI-agent-deposited binaries use.",
                    backedBy: [FindingEvidence(contentType: "launchd.entry", artifactID: row.id)],
                    confidence: .observed
                )
            }
            return nil
        }
    }

    private func detectUnfamiliarTeamPersistence(launchd: [ArtifactRow]) -> [Finding] {
        // Build team_id → entry count map.
        var teamCounts: [String: Int] = [:]
        for row in launchd {
            if let teamID = row.data["codesign.team_id"] as? String, !teamID.isEmpty {
                teamCounts[teamID, default: 0] += 1
            }
        }
        return launchd.compactMap { row -> Finding? in
            guard let teamID = row.data["codesign.team_id"] as? String, !teamID.isEmpty else { return nil }
            guard let count = teamCounts[teamID], count == 1 else { return nil }
            let label = row.data["label"] as? String ?? "(no label)"
            return Finding(
                findingType: "posture.unfamiliar_team_persistence",
                severity: .medium,
                title: "Unfamiliar-team persistence: \(label) (team \(teamID))",
                explanation: "The launchd plist '\(label)' is signed by team \(teamID), and this team appears only once across all observed launchd entries. Unfamiliar third-party teams persisting on a Mac warrant inspection — a legitimate vendor would typically ship multiple launchd entries.",
                backedBy: [FindingEvidence(contentType: "launchd.entry", artifactID: row.id)],
                confidence: .observed
            )
        }
    }

    private func detectAutomationToSensitive(tcc: [ArtifactRow]) -> [Finding] {
        tcc.compactMap { row -> Finding? in
            guard let service = row.data["service"] as? String,
                  service == "automation" || service == "apple_events" else { return nil }
            guard let target = row.data["indirect_target"] as? String,
                  TCCRiskScoring.highValueAutomationTargets.contains(target) else { return nil }
            // Skip Apple-signed clients — they're the dominant
            // false-positive class.
            if let apple = row.data["codesign.signing_status"] as? String, apple == "apple" {
                return nil
            }
            let client = row.data["client"] as? String ?? "(unknown)"
            return Finding(
                findingType: "posture.automation_to_sensitive_target",
                severity: .high,
                title: "Automation grant: \(client) → \(target)",
                explanation: "The client \(client) holds an Automation (AppleEvents) grant to drive \(target) — a sensitive target (browser / mail / messages / terminal / System Events). Non-Apple clients with broad Automation grants are the canonical surface an AI-agent compromise would exploit to reach personal data or escalate.",
                backedBy: [FindingEvidence(contentType: "tcc.grant", artifactID: row.id)],
                confidence: .observed
            )
        }
    }

    private func detectHighPrivilegeUnsignedCombo(launchd: [ArtifactRow], tcc: [ArtifactRow]) -> [Finding] {
        // The plan §7 v1.15 card is explicit: BOTH clauses required
        // (unsigned launchd entry AND that same client has FDA /
        // Accessibility / Screen Recording / Automation). The
        // OR-variant fires constantly on developer Macs.
        let highValueServices: Set<String> = ["fda", "accessibility", "screen_recording", "automation", "apple_events"]
        var findings: [Finding] = []
        for entry in launchd {
            let signingStatus = entry.data["codesign.signing_status"] as? String
            let isUnsigned = (signingStatus == nil || signingStatus == "unsigned" || signingStatus == "adhoc")
            guard isUnsigned else { continue }
            guard let programPath = entry.data["program_path"] as? String,
                  !programPath.isEmpty else { continue }

            // Find TCC grants whose client matches this program path
            // or its bundle id. We don't have bundle id on launchd
            // entries; match by path-suffix or exact-match for
            // bundle-id-vs-path comparisons.
            let matchingGrants = tcc.filter { grant in
                guard let client = grant.data["client"] as? String,
                      let service = grant.data["service"] as? String,
                      highValueServices.contains(service) else { return false }
                // client is either a bundle id or a path.
                return programPath.hasSuffix(client) || programPath == client
            }
            guard !matchingGrants.isEmpty else { continue }

            let label = entry.data["label"] as? String ?? "(no label)"
            let services = matchingGrants.compactMap { $0.data["service"] as? String }.joined(separator: ", ")
            findings.append(Finding(
                findingType: "posture.high_privilege_unsigned_combo",
                severity: .critical,
                title: "Unsigned binary in launchd + high-privilege TCC: \(label)",
                explanation: "The unsigned binary '\(programPath)' persists via launchd ('\(label)') AND holds high-privilege TCC grants (\(services)). Persistence + broad reach + no codesign anchor is the precise combination the plan §7 v1.15 card flags as the highest-trust signal short of explicit malware match.",
                backedBy: [FindingEvidence(contentType: "launchd.entry", artifactID: entry.id)] +
                    matchingGrants.map { FindingEvidence(contentType: "tcc.grant", artifactID: $0.id) },
                confidence: .observed
            ))
        }
        return findings
    }

    private func detectPermissionedPersistence(launchd: [ArtifactRow], tcc: [ArtifactRow]) -> [Finding] {
        // Different from unsigned_combo: this fires on LEGITIMATELY-
        // SIGNED apps that combine persistence with broad reach.
        // The combination is the signal even when codesign is clean
        // — operator wants to know "what signed apps can persist
        // AND reach my data."
        let highValueServices: Set<String> = ["fda", "accessibility", "screen_recording", "automation", "apple_events"]
        var findings: [Finding] = []
        for entry in launchd {
            let signingStatus = entry.data["codesign.signing_status"] as? String
            // ONLY fire on signed entries. Unsigned -> the
            // unsigned_combo finding covered it.
            guard let status = signingStatus, status == "apple" || status == "developer_id" else { continue }
            guard let programPath = entry.data["program_path"] as? String,
                  !programPath.isEmpty else { continue }

            let matchingGrants = tcc.filter { grant in
                guard let client = grant.data["client"] as? String,
                      let service = grant.data["service"] as? String,
                      highValueServices.contains(service) else { return false }
                return programPath.hasSuffix(client) || programPath == client
            }
            guard !matchingGrants.isEmpty else { continue }

            // Suppress Apple-signed entries from this finding type —
            // Apple itself persists + holds TCC grants, that's
            // expected. Developer-ID-signed third-party apps are
            // the signal.
            guard status == "developer_id" else { continue }

            let label = entry.data["label"] as? String ?? "(no label)"
            let services = matchingGrants.compactMap { $0.data["service"] as? String }.joined(separator: ", ")
            findings.append(Finding(
                findingType: "posture.permissioned_persistence",
                severity: .medium,
                title: "Developer-ID app with persistence + broad TCC: \(label)",
                explanation: "The Developer-ID-signed app at '\(programPath)' persists via launchd ('\(label)') AND holds high-privilege TCC grants (\(services)). The combination — not the signing status — is the signal. Inspect whether the app's persistence is intentional and whether its TCC reach matches the apparent purpose.",
                backedBy: [FindingEvidence(contentType: "launchd.entry", artifactID: entry.id)] +
                    matchingGrants.map { FindingEvidence(contentType: "tcc.grant", artifactID: $0.id) },
                confidence: .derived
            ))
        }
        return findings
    }
}
