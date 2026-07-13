// InjectionEvidenceWeld.swift
// MacCrabCore
//
// Phase-5 P2 — injection-evidence enrichment on agent alerts.
//
// When a shipped, high-confidence AGENT-ATTRIBUTED credential-read / read->egress
// rule fires (the TRACEPARENT-bound `agent_traceparent_credential_access` /
// `agent_filesystem_violation_high_conf`), this weld retro-scans the FileContent
// of files the SAME `ai_tool_session_id` READ in the prior N seconds against the
// EXISTING injection-marker set that ships in two rules:
//   - skill_md_poisoning_install.yml     (SKILL.md instruction-poisoning markers)
//   - claude_code_project_config_rce.yml (hook config + dangerous-command markers)
// If any file matches, the poisoned file is attached to the triggering alert as
// context and the alert's severity is bumped one level. Session-scoped, temporally
// bounded, and additive — it never emits a new alert of its own and never
// auto-executes a response action.
//
// Why a retro-scan and not capture-at-read: even after the collector emits the
// agent's read (ESCollector.isAgentContentReadPath), persisting the file's
// content on the read event would be stripped by EventStore.truncatePayload for
// near-max files. So the read event records only the PATH, and this weld
// re-reads the current file content on demand at trigger time via the existing
// FileContentEnricher (O_NOFOLLOW, 64 KB / 8 MB caps), sidestepping storage
// truncation entirely.
//
// HONESTY — detection fidelity: this is PLAINTEXT substring marker-matching only,
// exactly mirroring the two shipped rules. Obfuscation-resistant taint (invisible-
// unicode / bidi / zero-width / base64 / homoglyph-hidden injection) requires an
// obfuscation-aware scanner — `scan_text` / Forensicate.ai ("pip install
// forensicate-ai") — which is NOT installed in the daemon. (The
// `FileContent_Obfuscated` enrichment key IntentEvidenceClassifier reads is set
// by nothing today.) Until that scanner is present, this weld catches the
// plaintext campaign class and nothing more; a determined attacker who hides the
// markers evades it. This limit is stated in the report as well as here.

import Foundation

// MARK: - Marker scanner (pure)

/// The injection-marker scanner. Holds the two shipped marker sets as Swift
/// constants copied verbatim from the YAML rules and matches them with
/// case-sensitive, plaintext substring compares (`range(of:)`) — the same
/// semantics the rule engine applies to `FileContent|contains`.
public enum InjectionMarkerScanner {

    /// skill_md_poisoning_install.yml -> selection_payload_markers. The rule
    /// fires on ANY single one of these appearing in a SKILL.md body, so any
    /// single hit here is contributory.
    public static let skillPoisonMarkers: [String] = [
        "<INSTRUCTIONS>",
        "<eval>",
        "<run>",
        "<fetch>",
        "![](data:text/html;base64,",
        "__import__(\"os\")",
    ]

    /// claude_code_project_config_rce.yml -> selection_hook_payload. The rule
    /// ANDs this selection with selection_dangerous_command, so a hook-payload
    /// marker only counts when a dangerous-command marker is ALSO present.
    public static let hookPayloadMarkers: [String] = [
        "\"PreToolUse\"",
        "\"PostToolUse\"",
        "\"command\":",
        "\"shell\":",
    ]

    /// claude_code_project_config_rce.yml -> selection_dangerous_command.
    public static let dangerousCommandMarkers: [String] = [
        "curl ",
        "wget ",
        "bash -c",
        "sh -c",
        "eval ",
        "/tmp/",
        "$(curl",
        "&& curl",
        "| bash",
        "| sh",
    ]

    /// Returns the markers that constitute a hit, honoring each rule's own
    /// condition (skill markers OR'd; config-RCE hook+command AND'd). Empty when
    /// the content is clean. Case-sensitive plaintext substring match.
    public static func scan(_ text: String) -> [String] {
        guard !text.isEmpty else { return [] }
        var hits: [String] = []

        // Skill-poisoning: any single payload marker is a hit.
        for m in skillPoisonMarkers where text.range(of: m) != nil {
            hits.append(m)
        }

        // Config-RCE: only contributory when BOTH a hook-payload marker AND a
        // dangerous-command marker are present (the rule's AND), so an ordinary
        // config that merely mentions "command" isn't flagged.
        let hookHits = hookPayloadMarkers.filter { text.range(of: $0) != nil }
        let dangerHits = dangerousCommandMarkers.filter { text.range(of: $0) != nil }
        if !hookHits.isEmpty && !dangerHits.isEmpty {
            hits.append(contentsOf: hookHits)
            hits.append(contentsOf: dangerHits)
        }

        return hits
    }
}

// MARK: - Evidence result

/// The evidence one retro-scan produced: the poisoned file the agent read, the
/// markers it carried, and the two timestamps that make the causal story
/// ("read adversarial content at t1, then read credentials at t2"). Never a new
/// alert — this is appended to the triggering alert's description and used to
/// bump its severity.
public struct InjectionEvidence: Sendable, Equatable {
    /// The agent-content file that carried injection markers.
    public let poisonedFilePath: String
    /// The distinct markers matched, in a stable order.
    public let markers: [String]
    /// When the agent read the poisoned file (t1).
    public let readAt: Date
    /// When the credential-access rule fired (t2).
    public let triggerAt: Date

    public init(poisonedFilePath: String, markers: [String], readAt: Date, triggerAt: Date) {
        self.poisonedFilePath = poisonedFilePath
        self.markers = markers
        self.readAt = readAt
        self.triggerAt = triggerAt
    }

    /// Human-readable narrative, appended to the alert description in the same
    /// "<base> — <clause>" style AlertSink / the delivery-provenance weld use.
    /// The trailing "(plaintext-marker match)" is deliberate honesty: it tells a
    /// triager the match fidelity (see the file header on obfuscation).
    public func appended(to base: String?) -> String {
        let iso = ISO8601DateFormatter()
        let markerList = markers.prefix(8).joined(separator: ", ")
        let clause = "Prompt-injection evidence: agent session read adversarial content in "
            + "\(poisonedFilePath) (markers: \(markerList)) at \(iso.string(from: readAt)), "
            + "then read credential material at \(iso.string(from: triggerAt)) "
            + "— possible prompt-injection-driven credential access (plaintext-marker match)"
        if let base, !base.isEmpty { return "\(base) — \(clause)" }
        return clause
    }

    /// One-level severity bump, saturating at critical. High (the trigger rules'
    /// level) -> critical.
    public func bumpedSeverity(from s: Severity) -> Severity {
        switch s {
        case .informational: return .low
        case .low: return .medium
        case .medium: return .high
        case .high, .critical: return .critical
        }
    }
}

// MARK: - Source (injectable)

/// A read of an agent-content file in the retro-scan window: its path and when
/// the agent read it.
public struct AgentContentRead: Sendable, Equatable {
    public let path: String
    public let readAt: Date
    public init(path: String, readAt: Date) {
        self.path = path
        self.readAt = readAt
    }
}

/// Injectable so the weld's gate/marker logic is unit-testable without a live
/// EventStore or on-disk files. Production is `EventStoreInjectionSource`.
public protocol InjectionEvidenceSource: Sendable {
    /// Agent-content READ events (ESCollector.isAgentContentReadPath) for
    /// `sessionId` within [since, until], chronological.
    func agentContentReads(sessionId: String, since: Date, until: Date) async -> [AgentContentRead]
    /// Re-read the current content of `path` (O_NOFOLLOW, byte/size capped), or
    /// nil on any error / non-text / oversized file.
    func readContent(path: String) async -> String?
}

// MARK: - The weld

/// Runs the injection-evidence retro-scan on firing agent-attributed cred/exfil
/// alerts. Pure value type — it holds no mutable state; the session scoping and
/// temporal bound come from the alert/event and the injected source.
public struct InjectionEvidenceWeld: Sendable {

    /// The exact rule IDs the weld retro-scans on — the shipped TRACEPARENT-bound
    /// agent triggers. Closed set: attaching to anything else would break the
    /// "enrichment on an already-precise, session-attributed trigger" contract.
    ///  - agent_traceparent_credential_access  (agent read credential material)
    ///  - agent_filesystem_violation_high_conf  (agent wrote to a privileged path;
    ///    the read->egress companion the credential-access rule references)
    public static let triggerRuleIds: Set<String> = [
        "d1a2b3c4-2052-4000-a000-000000002052", // Agent Read Credential Material (Traceparent-Bound)
        "d1a2b3c4-2050-4000-a000-000000002050", // Agent Wrote To Privileged Path (High Confidence)
    ]

    private let source: any InjectionEvidenceSource
    /// Retro-scan window: how far before the trigger to look for the poisoned
    /// read. Default 300 s — comfortably inside the 30-min hot tier, so hot-tier
    /// pruning is not a blocker.
    public let windowSeconds: Double
    /// Defensive cap on files re-read per trigger (the session+window scope makes
    /// the real count tiny, but this bounds pathological sessions).
    private let maxCandidateReads: Int

    public init(source: any InjectionEvidenceSource,
                windowSeconds: Double = 300,
                maxCandidateReads: Int = 64) {
        self.source = source
        self.windowSeconds = windowSeconds
        self.maxCandidateReads = maxCandidateReads
    }

    /// True iff `ruleId` is one the weld retro-scans on. Cheap sync gate so the
    /// hot path short-circuits before the async hop for the overwhelming
    /// non-trigger majority.
    public func isTrigger(ruleId: String) -> Bool {
        Self.triggerRuleIds.contains(ruleId)
    }

    /// Phase-6 6B (leg 2): per-event companion to `evidence(...)`. Returns true
    /// when `path` is an AGENT-CONTENT read (skills / hooks / config / workflows —
    /// the same `ESCollector.isAgentContentReadPath` allowlist the weld's own
    /// source uses, disjoint from credential paths) whose CURRENT content carries
    /// the shipped plaintext injection markers. Reuses the SAME
    /// `InjectionEvidenceSource.readContent` (FileContentEnricher: O_NOFOLLOW,
    /// 64 KB / 8 MB caps) and `InjectionMarkerScanner` as `evidence()` — no second
    /// scanner and no new marker set. The caller (EventLoop) stamps
    /// `enrichments["untrusted_content"]="true"` on a hit so the causal
    /// substrate's `FileNode` records the load-bearing leg-2 signal for the
    /// lethal-trifecta graph rule. Plaintext-marker fidelity only (see the file
    /// header on obfuscation); it never emits an alert of its own.
    public func readsInjectedContent(path: String) async -> Bool {
        guard ESCollector.isAgentContentReadPath(path) else { return false }
        guard let content = await source.readContent(path: path) else { return false }
        return !InjectionMarkerScanner.scan(content).isEmpty
    }

    /// Retro-scan the session's agent-content reads for injection markers.
    /// Returns nil (no change) when: the rule isn't a trigger, the event carries
    /// no `ai_tool_session_id`, the session read no marker-bearing agent-content
    /// files in the window, or the source yields nothing. Never emits an alert.
    ///
    /// On a hit, returns the MOST RECENT marker-bearing read before the trigger —
    /// the read closest in time to the credential access, i.e. the most likely
    /// injection source.
    public func evidence(alert: Alert, event: Event) async -> InjectionEvidence? {
        guard Self.triggerRuleIds.contains(alert.ruleId) else { return nil }
        guard let sid = event.enrichments["ai_tool_session_id"], !sid.isEmpty else { return nil }

        let triggerAt = event.timestamp
        let since = triggerAt.addingTimeInterval(-windowSeconds)
        let reads = await source.agentContentReads(sessionId: sid, since: since, until: triggerAt)
        guard !reads.isEmpty else { return nil }

        // Most-recent read first (closest to the credential access). Cap the
        // number of files we re-read from disk.
        let ordered = reads.sorted { $0.readAt > $1.readAt }.prefix(maxCandidateReads)
        for read in ordered {
            guard let content = await source.readContent(path: read.path) else { continue }
            let markers = InjectionMarkerScanner.scan(content)
            if !markers.isEmpty {
                // De-dup markers, preserve first-seen order.
                var seen = Set<String>()
                let distinct = markers.filter { seen.insert($0).inserted }
                return InjectionEvidence(
                    poisonedFilePath: read.path,
                    markers: distinct,
                    readAt: read.readAt,
                    triggerAt: triggerAt
                )
            }
        }
        return nil
    }
}

// MARK: - Production source

/// Production `InjectionEvidenceSource`: reads the session's agent-content OPEN
/// events from the EventStore session index (idx_events_ai_session) and re-reads
/// file content on demand via the shared `FileContentEnricher` (O_NOFOLLOW,
/// 64 KB / 8 MB caps). Credential paths are never re-read — the read filter is the
/// AGENT-CONTENT allowlist (skills / hooks / config / workflows), which is
/// disjoint from the credential allowlist, so the scanner only ever touches
/// skill/config content, never the credential file the trigger fired on.
public struct EventStoreInjectionSource: InjectionEvidenceSource {

    private let eventStore: EventStore
    private let fileContent: FileContentEnricher

    public init(eventStore: EventStore, fileContent: FileContentEnricher) {
        self.eventStore = eventStore
        self.fileContent = fileContent
    }

    public func agentContentReads(sessionId: String, since: Date, until: Date) async -> [AgentContentRead] {
        guard let events = try? await eventStore.eventsForAgentSession(sessionId, since: since, until: until) else {
            return []
        }
        return events.compactMap { ev -> AgentContentRead? in
            guard ev.eventCategory == .file,
                  ev.eventAction == "open",
                  let path = ev.file?.path,
                  ESCollector.isAgentContentReadPath(path) else { return nil }
            return AgentContentRead(path: path, readAt: ev.timestamp)
        }
    }

    public func readContent(path: String) async -> String? {
        await fileContent.scan(path: path)
    }
}
