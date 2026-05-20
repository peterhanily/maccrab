// AppleScriptRuntimePlugin — com.maccrab.forensics.applescript-runtime.
//
// Plan §13.5 — explicit v1.16 candidate. Catches the 2025-2026
// fileless macOS infostealer class that runs entirely inside
// trusted Apple-signed binaries (osascript / osacompile / JXA),
// where the payload arrives via argv passed to the trusted binary
// rather than as a file on disk. The v1.13 substrate (TCC +
// launchd) misses this entirely because the attack lives in argv,
// not in TCC or launchd.
//
// Source: queries MacCrabCore's EventStore (populated by the
// Track 1 ESCollector via NOTIFY_EXEC) for exec events whose
// process.executable matches an AppleScript-runtime path. For
// each match emits an applescript.invocation artifact with full
// argv + parent process attribution + a heuristic base64-decoded
// payload (where the argv looks base64-shaped).
//
// **Inline §10.7 justification for content-class default**:
//   1. The argv IS the malware.
//   2. The capture window is at-exec only — not files at rest.
//   3. The privacy class is still labelled content; dashboard
//      shows the warning chip + MCP exposure gated by
//      case.ai_content_allowed (§10.8).

import Foundation
import CryptoKit
import MacCrabCore

public struct AppleScriptRuntimePlugin: Collector {

    public static let manifest = PluginManifest(
        id: "com.maccrab.forensics.applescript-runtime",
        version: "1.0.0",
        displayName: "AppleScript Runtime Monitor",
        description: "Inventories osascript / osacompile / JXA invocations from MacCrabCore.EventStore. Catches argv-resident AppleScript / JavaScript payloads that the v1.13 TCC + launchd substrate misses (the 2025-2026 fileless infostealer class). Privacy class content — the argv is the payload; MCP exposure gated by case.ai_content_allowed per plan §10.8.",
        type: .collector,
        runtime: .tierA,
        tccRequirements: [],   // Reads EventStore, which the daemon already populated.
        inputs: [],
        outputs: [
            OutputSpec(contentType: "applescript.invocation", privacyClass: .content, optInRequired: false),
        ],
        mcpTools: [
            MCPToolDescriptor(
                name: "applescript_invocations_recent",
                description: "Recent osascript / osacompile / JXA invocations. Returns argv + parent + decoded payload heuristic.",
                exposesPrivacyClass: .content
            ),
            MCPToolDescriptor(
                name: "applescript_with_base64_payload",
                description: "Recent AppleScript / JXA invocations whose argv contains a heuristically-decoded base64 payload.",
                exposesPrivacyClass: .content
            ),
        ],
        schemaVersion: 1,
        stability: .preview
    )

    /// Known AppleScript / JavaScriptCore runtime binaries. The
    /// match is by exact path (osascript) or by suffix
    /// (jsc lives under a versioned framework path that changes
    /// between OS releases).
    public static let runtimePaths: Set<String> = [
        "/usr/bin/osascript",
        "/usr/bin/osacompile",
        "/usr/bin/osalang",
    ]
    public static let runtimePathSuffixes: [String] = [
        "/JavaScriptCore.framework/Resources/jsc",
        "/JavaScriptCore.framework/Versions/A/Resources/jsc",
    ]

    public init() async throws {}

    public func collect(
        case caseContext: CaseContext,
        window: TimeWindow?,
        output: any CollectorOutput
    ) async throws -> CollectionResult {

        let since = window?.start ?? Date().addingTimeInterval(-86_400)  // default 24h

        // EventStore is in MacCrabCore. We open it directly from
        // the daemon's standard support directory. If MacCrab's
        // daemon isn't running, the file may not exist — surface
        // as partial result with a clear note.
        let eventStorePath = Self.eventStorePath()
        guard FileManager.default.fileExists(atPath: eventStorePath) else {
            return CollectionResult(
                artifactsCommitted: 0,
                artifactsRejected: 0,
                notes: [
                    "MacCrab events.db not found at \(eventStorePath). The AppleScript runtime monitor reads exec events that the Track 1 ES collector populates; ensure the daemon is running.",
                ],
                status: .partial
            )
        }

        let store = try await EventStore(path: eventStorePath)
        let events: [Event]
        do {
            events = try await store.events(since: since, limit: 50_000)
        } catch {
            return CollectionResult(
                artifactsCommitted: 0,
                artifactsRejected: 0,
                notes: ["EventStore query failed: \(error.localizedDescription)"],
                status: .error
            )
        }

        var committed = 0
        var rejected = 0
        let now = Date()

        for event in events {
            guard Self.isRuntimeBinary(event.process.executable) else { continue }

            let argv = event.process.args
            let decodedPayload = Self.heuristicBase64Decode(argv: argv)
            let parentInfo = event.process.ancestors.first

            var data: [String: JSONValue] = [
                "runtime": .string(event.process.executable),
                "pid": .integer(Int64(event.process.pid)),
                "ppid": .integer(Int64(event.process.ppid)),
                "command_line": .string(event.process.commandLine),
                "arguments_json": .array(argv.map { .string($0) }),
                "user_name": .string(event.process.userName),
                "exec_observed_at_iso": .string(ISO8601DateFormatter().string(from: event.timestamp)),
            ]
            if let p = parentInfo {
                data["parent_pid"] = .integer(Int64(p.pid))
                data["parent_executable"] = .string(p.executable)
            }
            if let decoded = decodedPayload {
                data["decoded_payload_b64_input"] = .string(decoded.b64Input)
                data["decoded_payload_text"] = .string(decoded.text)
                data["decoded_payload_size_bytes"] = .integer(Int64(decoded.text.utf8.count))
            }

            let seed = "\(event.process.executable):\(event.process.pid):\(event.timestamp.timeIntervalSince1970)"
            let sha = SHA256.hash(data: Data(seed.utf8))
                .map { String(format: "%02x", $0) }.joined()

            let summary: String = {
                if argv.count > 1 {
                    let argsPreview = argv.dropFirst().prefix(2).joined(separator: " ")
                    let suffix = argv.count > 3 ? "…" : ""
                    return "\(event.process.executable.components(separatedBy: "/").last ?? "osascript") \(argsPreview)\(suffix)"
                } else {
                    return event.process.executable.components(separatedBy: "/").last ?? "osascript"
                }
            }()

            let record = ArtifactRecord(
                caseID: caseContext.caseID,
                pluginID: Self.manifest.id,
                pluginVersion: Self.manifest.version,
                schemaVersion: Self.manifest.schemaVersion,
                contentType: "applescript.invocation",
                sourcePath: eventStorePath,
                sha256: sha,
                observedAt: event.timestamp,
                capturedAt: now,
                summary: summary,
                sizeBytes: Int64(event.process.commandLine.utf8.count),
                confidence: .observed,
                privacyClass: .content,
                actor: event.process.userName.isEmpty ? nil : event.process.userName,
                data: data
            )

            do {
                try await output.commit(record)
                committed += 1
            } catch ArtifactStoreError.plaintextCaseRejectsNonMetadata {
                rejected += 1
            } catch {
                rejected += 1
            }
        }

        var notes: [String] = []
        notes.append("Scanned \(events.count) exec events; \(committed) matched AppleScript-runtime binaries.")
        if rejected > 0 {
            notes.append("\(rejected) AppleScript invocations rejected at INSERT — plaintext case can't hold content-class artifacts (Pass 2026-D). Create an encrypted case to capture these.")
        }
        return CollectionResult(
            artifactsCommitted: committed,
            artifactsRejected: rejected,
            notes: notes,
            status: rejected > 0 ? .partial : .ok
        )
    }

    // MARK: - Helpers

    static func isRuntimeBinary(_ executable: String) -> Bool {
        if Self.runtimePaths.contains(executable) { return true }
        for suffix in Self.runtimePathSuffixes {
            if executable.hasSuffix(suffix) { return true }
        }
        return false
    }

    /// Walk the argv looking for arguments that look base64 (long
    /// strings of [A-Za-z0-9+/=] with realistic decodability) and
    /// attempt a decode. Returns the first successfully-decoded
    /// argument's content. Heuristic, intentionally — operators
    /// inspect the result manually.
    static func heuristicBase64Decode(argv: [String]) -> (b64Input: String, text: String)? {
        let allowed = CharacterSet(charactersIn: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
        for arg in argv {
            guard arg.count >= 40 else { continue }
            guard arg.unicodeScalars.allSatisfy({ allowed.contains($0) }) else { continue }
            guard let data = Data(base64Encoded: arg) else { continue }
            // Must look like printable text to be worth surfacing.
            // Pure binary doesn't help; let the operator see a
            // hex dump elsewhere.
            guard let text = String(data: data, encoding: .utf8) else { continue }
            let printableRatio = text.unicodeScalars.reduce(0.0) { acc, sc in
                acc + (sc.isASCII && (sc.value >= 32 && sc.value < 127 || sc.value == 0x0a || sc.value == 0x09) ? 1.0 : 0.0)
            } / Double(text.unicodeScalars.count)
            guard printableRatio >= 0.85 else { continue }
            return (b64Input: arg, text: text)
        }
        return nil
    }

    /// The EventStore lives in MacCrab's standard support
    /// directory. Path resolution mirrors what `maccrabd` /
    /// `maccrabctl` already do.
    static func eventStorePath() -> String {
        // Production: /Library/Application Support/MacCrab/ (root
        // sysext writes here). Dev fallback: ~/Library/...
        let systemPath = "/Library/Application Support/MacCrab/events.db"
        if FileManager.default.fileExists(atPath: systemPath) {
            return systemPath
        }
        return NSHomeDirectory() + "/Library/Application Support/MacCrab/events.db"
    }
}
