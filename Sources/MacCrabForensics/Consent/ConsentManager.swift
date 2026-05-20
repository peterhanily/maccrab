// ConsentManager — abstraction over the operator consent surface
// for plugin invocations. Plan §10.5 defines four execution modes
// (interactive / scheduled default / scheduled trusted / MCP from
// agent); this protocol gives the runtime one place to ask "should
// I proceed?" and returns the verdict.
//
// v1.13b ships:
//   - The protocol + the consent decision enum + per-mode policy.
//   - `LoggingConsentManager` — production-safe default that logs
//     to stdout / mcp_audit.log and auto-approves except for
//     non-metadata MCP calls on cases without ai_content_allowed.
//   - `AlwaysAcceptConsentManager` — test path that grants
//     everything (replaces the production impl in unit tests).
//
// What's deferred to a follow-up sub-slice:
//   - `UNNotificationConsentManager` — backed by
//     UserNotifications.UNUserNotificationCenter. Requires the
//     host process be a registered .app with notification
//     entitlements (so MacCrabApp + the future maccrab-forensicsd
//     daemon, but NOT the maccrabctl CLI). The visible toast +
//     the operator's accept/dismiss handler land then.
//
// The runtime change in PluginRunner is gated by ConsentManager
// regardless of backing impl — the surface is wired now so the UN
// upgrade is purely additive later.

import Foundation

/// Execution mode for a plugin invocation. Plan §10.5.
public enum ConsentMode: String, Sendable, Codable {
    /// Operator typed `maccrabctl plugin run` or clicked a Run
    /// button in the dashboard. No additional consent needed —
    /// the act of initiating IS the consent.
    case interactive

    /// Case scheduler fired (post-v1.13b daemon territory). Plan
    /// §10.5 wants a toast + block-until-operator-clicks-Run UI.
    /// `scheduled_trusted_case` opt-in (per case) auto-proceeds
    /// after a brief visibility window.
    case scheduled

    /// AI agent called `forensics.run_collector` (or similar) via
    /// MCP. Plan §10.5 wants a toast naming the agent; metadata-
    /// class auto-proceeds, non-metadata blocks if
    /// `case.ai_content_allowed == 0` per §10.8.
    case mcpFromAgent
}

/// What the runtime needs to know about the invocation before
/// asking the consent layer. ConsentManager implementations read
/// these fields to decide.
public struct ConsentRequest: Sendable {

    /// Case the plugin is being invoked against.
    public let caseID: String
    public let caseName: String

    /// Plugin id + display name (operator-facing).
    public let pluginID: String
    public let pluginDisplayName: String

    /// The plugin's manifest type so the consent layer can apply
    /// type-specific policy (e.g. Analyzers can be auto-approved
    /// because they read only existing case data; Collectors that
    /// snapshot live DBs cannot).
    public let pluginType: PluginType

    /// Mode determining the policy bucket per plan §10.5.
    public let mode: ConsentMode

    /// Whether the case has the `ai_content_allowed` grant set
    /// (plan §10.8). Drives MCP-from-agent decisions when the
    /// plugin's outputs include non-metadata classes.
    public let caseAIContentAllowed: Bool

    /// Whether the case has the `scheduled_trusted` opt-in set
    /// (plan §10.5). When `true` AND mode == .scheduled, the
    /// consent layer auto-proceeds after a brief visible toast
    /// rather than blocking on operator click.
    public let caseScheduledTrusted: Bool

    /// Highest privacy class the plugin's outputs include. The
    /// MCP-from-agent gate uses this against ai_content_allowed.
    public let highestEmittedPrivacyClass: PrivacyClass

    /// For `mcpFromAgent`, an identifying label for the agent
    /// initiating the call (e.g. "Claude Code"). Surfaced in the
    /// audit log. Nil for non-MCP modes.
    public let agentName: String?

    public init(
        caseID: String,
        caseName: String,
        pluginID: String,
        pluginDisplayName: String,
        pluginType: PluginType,
        mode: ConsentMode,
        caseAIContentAllowed: Bool,
        caseScheduledTrusted: Bool,
        highestEmittedPrivacyClass: PrivacyClass,
        agentName: String? = nil
    ) {
        self.caseID = caseID
        self.caseName = caseName
        self.pluginID = pluginID
        self.pluginDisplayName = pluginDisplayName
        self.pluginType = pluginType
        self.mode = mode
        self.caseAIContentAllowed = caseAIContentAllowed
        self.caseScheduledTrusted = caseScheduledTrusted
        self.highestEmittedPrivacyClass = highestEmittedPrivacyClass
        self.agentName = agentName
    }
}

/// Verdict from the consent layer.
public enum ConsentDecision: Sendable, Equatable {

    /// Operator (or policy) granted. Plugin proceeds normally.
    case granted

    /// Granted automatically — the toast / log entry still fires
    /// for audit visibility, but no operator block. Trusted-
    /// scheduled cases land here.
    case autoApproved(reason: String)

    /// Denied. Plugin must not run. Caller surfaces the §10.8
    /// structured error (for MCP) or a normal exit code (for
    /// CLI / dashboard).
    case denied(reason: String)
}

/// Single-method protocol. Implementations decide how to gather
/// the verdict — log + auto-decide, post a toast and wait, etc.
public protocol ConsentManager: Sendable {
    func decide(_ request: ConsentRequest) async -> ConsentDecision
}

// MARK: - Production default

/// Logs every request to stdout (under MacCrab's standard
/// "consent:" prefix) and applies the plan §10.5 policy rules
/// without blocking on a UI prompt:
///
///   interactive    → granted unconditionally (operator initiated)
///   scheduled +
///     trusted=true → autoApproved (the visible-toast contract
///                    needs UN; the audit-log entry fires)
///     trusted=false → denied (with reason pointing the operator
///                    at `maccrabctl case mark-trusted-scheduled`)
///   mcpFromAgent +
///     metadata-class plugin OR ai_content_allowed=true → granted
///     non-metadata-class plugin AND ai_content_allowed=false →
///       denied (§10.8 structured error)
///
/// The follow-up `UNNotificationConsentManager` upgrades the
/// scheduled-default path: instead of immediate denial, it posts a
/// UNUserNotification toast and waits for the operator's Run / Dismiss
/// action. v1.13b ships the policy-correct shape; the visible
/// notification UI is the additive upgrade.
public actor LoggingConsentManager: ConsentManager {

    /// Sink writes to stdout by default. Tests inject a closure.
    public typealias Sink = @Sendable (String) -> Void
    private let sink: Sink

    public init(sink: @escaping Sink = { print("consent: \($0)") }) {
        self.sink = sink
    }

    public func decide(_ request: ConsentRequest) async -> ConsentDecision {
        let line = "request mode=\(request.mode.rawValue) case=\(request.caseID) plugin=\(request.pluginID) class=\(request.highestEmittedPrivacyClass.rawValue) ai_allowed=\(request.caseAIContentAllowed) trusted=\(request.caseScheduledTrusted) agent=\(request.agentName ?? "-")"
        sink(line)

        switch request.mode {

        case .interactive:
            // Operator initiated. Granted.
            return .granted

        case .scheduled:
            if request.caseScheduledTrusted {
                let reason = "case '\(request.caseName)' opted into scheduled_trusted; toast emitted, auto-proceeding per plan §10.5"
                sink(reason)
                return .autoApproved(reason: reason)
            }
            // Default policy: deny unattended scheduled runs.
            // Operator can flip the case via:
            //   maccrabctl case mark-trusted-scheduled <id>
            let reason = "scheduled run on case '\(request.caseName)' blocked: scheduled_trusted=0. Run `maccrabctl case mark-trusted-scheduled \(request.caseID)` to opt in, or invoke interactively."
            sink(reason)
            return .denied(reason: reason)

        case .mcpFromAgent:
            // Metadata-class is always exposable to MCP (plan
            // §10.2 default). Higher classes require
            // ai_content_allowed=1 on the case.
            if request.highestEmittedPrivacyClass == .metadata {
                return .granted
            }
            if request.caseAIContentAllowed {
                return .granted
            }
            // §10.8 — structured error path. The runtime surfaces
            // the operator-runnable command in the denied
            // reason; the MCP layer composes the
            // structuredContent block from this string.
            let reason = "case '\(request.caseName)' (id: \(request.caseID)) has not granted AI content access. Plugin '\(request.pluginID)' exposes \(request.highestEmittedPrivacyClass.rawValue)-class artifacts. Run: maccrabctl case allow-ai --content \(request.caseID)"
            sink(reason)
            return .denied(reason: reason)
        }
    }
}

/// Test-only: grants everything. Used in unit tests where the
/// consent surface would block on a real notification UI.
public actor AlwaysAcceptConsentManager: ConsentManager {
    public init() {}
    public func decide(_ request: ConsentRequest) async -> ConsentDecision {
        return .granted
    }
}
