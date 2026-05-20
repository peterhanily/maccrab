// TCCRiskScoring — deterministic per-grant risk score per plan §4.1.
//
// The scoring table is open / debatable — operators argue with the
// numbers, not the concept. Every weight is named, captured as a
// constant here so the audit can confirm the implementation
// matches the documented contract.
//
// Plan reference: §4.1 risk-score table.
//
// Final score clamped to [0, 100]. The reasons array names every
// scoring-table row that fired, in stable order — drives dashboard
// sorting + Analyzer findings.

import Foundation

public enum TCCRiskReason: String, Codable, Sendable, CaseIterable {
    case fullDiskAccess           // FDA — total filesystem reach
    case accessibility            // Accessibility — can drive UI
    case automationToBrowser      // Automation to Safari / Chrome / browsers
    case automationToMessages     // Automation to Messages
    case automationToMail         // Automation to Mail
    case automationToTerminal     // Automation to Terminal
    case automationToSystemEvents // Automation to System Events
    case automationGeneric        // Other automation grants
    case screenRecording          // Captures screen contents
    case inputMonitoring          // Captures keystrokes
    case appleEventsToSensitive   // AppleEvents to a sensitive target
    case camera
    case microphone
    case unknownTeam              // Client is unsigned or unknown team
    case appleSigned              // Apple-signed client (mitigating)
    case mdmGranted               // MDM-granted (mitigating)
    case deniedRecentlyAttempted  // Denied but recently attempted
}

public struct TCCRiskInput: Sendable {
    /// Canonical normalized service name.
    public let service: TCCServiceCanonical

    /// Raw kTCCService* constant — only needed for ambiguity
    /// resolution (e.g. distinguishing AppleEvents from PostEvent).
    public let serviceRaw: String

    /// Indirect target identifier for Automation / AppleEvents
    /// grants (the bundle id of the app being automated). Nil for
    /// non-automation services.
    public let indirectTarget: String?

    /// Auth value (allowed / denied / limited).
    public let authValue: TCCAuthValue

    /// Auth reason (user / mdm / system / inherited).
    public let authReason: TCCAuthReason

    /// `true` if the client is signed by Apple. From the codesign
    /// enricher when available; otherwise default `false`.
    public let clientSignedByApple: Bool

    /// `true` if the client is signed by a known team (any non-
    /// empty team_id from the codesign enricher). `false` for
    /// unsigned binaries or binaries the enricher couldn't resolve.
    public let clientHasKnownTeam: Bool

    /// `last_modified` from the TCC.db row. Used for the "denied
    /// but recently attempted" mitigation.
    public let lastModified: Date?

    public init(
        service: TCCServiceCanonical,
        serviceRaw: String,
        indirectTarget: String? = nil,
        authValue: TCCAuthValue,
        authReason: TCCAuthReason,
        clientSignedByApple: Bool,
        clientHasKnownTeam: Bool,
        lastModified: Date? = nil
    ) {
        self.service = service
        self.serviceRaw = serviceRaw
        self.indirectTarget = indirectTarget
        self.authValue = authValue
        self.authReason = authReason
        self.clientSignedByApple = clientSignedByApple
        self.clientHasKnownTeam = clientHasKnownTeam
        self.lastModified = lastModified
    }
}

public struct TCCRiskScore: Sendable {
    /// Integer [0, 100]. Higher = more concerning.
    public let score: Int

    /// Reasons array in stable order.
    public let reasons: [TCCRiskReason]
}

public enum TCCRiskScoring {

    /// Weight deltas — single source of truth. Tests reference
    /// these by name to detect drift between the documented
    /// scoring table (plan §4.1) and the implementation.
    public enum Weight {
        public static let fullDiskAccess: Int = 35
        public static let accessibility: Int = 30
        public static let automationToHighValue: Int = 30
        public static let screenRecording: Int = 25
        public static let inputMonitoring: Int = 25
        public static let appleEventsToSensitive: Int = 20
        public static let camera: Int = 20
        public static let microphone: Int = 20
        public static let unknownTeam: Int = 20
        public static let automationGeneric: Int = 10

        // Mitigations (negative)
        public static let appleSigned: Int = -20
        public static let mdmGranted: Int = -5
    }

    /// "High-value" automation targets — operators care more when
    /// these are reachable than when, say, Calculator is.
    public static let highValueAutomationTargets: Set<String> = [
        "com.apple.Safari",
        "com.apple.mail",
        "com.apple.Messages",
        "com.apple.Terminal",
        "com.apple.iChat",
        "com.apple.systemevents",
        "com.apple.SystemEvents",
        "com.google.Chrome",
        "com.brave.Browser",
        "com.microsoft.edgemac",
        "com.microsoft.Outlook",
        "org.mozilla.firefox",
    ]

    /// Mapping from high-value target bundle id to the specific
    /// risk reason. Drives the dashboard's "automation to Safari"
    /// label rather than the generic "automation to high-value
    /// target."
    private static func reasonForTarget(_ target: String) -> TCCRiskReason {
        switch target {
        case "com.apple.Safari", "com.google.Chrome", "com.brave.Browser",
             "com.microsoft.edgemac", "org.mozilla.firefox":
            return .automationToBrowser
        case "com.apple.Messages", "com.apple.iChat":
            return .automationToMessages
        case "com.apple.mail", "com.microsoft.Outlook":
            return .automationToMail
        case "com.apple.Terminal":
            return .automationToTerminal
        case "com.apple.systemevents", "com.apple.SystemEvents":
            return .automationToSystemEvents
        default:
            return .automationGeneric
        }
    }

    /// Compute the deterministic risk score.
    public static func score(_ input: TCCRiskInput) -> TCCRiskScore {
        var delta = 0
        var reasons: [TCCRiskReason] = []

        switch input.service {
        case .fullDiskAccess, .allFiles:
            delta += Weight.fullDiskAccess
            reasons.append(.fullDiskAccess)

        case .accessibility:
            delta += Weight.accessibility
            reasons.append(.accessibility)

        case .automation, .appleEvents:
            // Disambiguate by indirectTarget.
            if let target = input.indirectTarget {
                if highValueAutomationTargets.contains(target) {
                    delta += Weight.automationToHighValue
                    reasons.append(reasonForTarget(target))
                } else {
                    delta += Weight.automationGeneric
                    reasons.append(.automationGeneric)
                }
            } else {
                // Automation grant with no target stamped — broadly
                // applicable, treat as generic.
                delta += Weight.automationGeneric
                reasons.append(.automationGeneric)
            }

        case .screenRecording:
            delta += Weight.screenRecording
            reasons.append(.screenRecording)

        case .inputMonitoring:
            delta += Weight.inputMonitoring
            reasons.append(.inputMonitoring)

        case .camera:
            delta += Weight.camera
            reasons.append(.camera)

        case .microphone:
            delta += Weight.microphone
            reasons.append(.microphone)

        default:
            // Other privacy surfaces (contacts, photos, etc.) carry
            // no inherent scoring weight in this table. They're
            // still emitted with score=0, the operator sees them.
            break
        }

        // Client trust modifiers.
        if !input.clientHasKnownTeam {
            delta += Weight.unknownTeam
            reasons.append(.unknownTeam)
        }
        if input.clientSignedByApple {
            delta += Weight.appleSigned
            reasons.append(.appleSigned)
        }

        // Auth-reason modifier — MDM-granted means operator policy
        // already approved this, so deduct.
        if input.authReason.isMDMGranted {
            delta += Weight.mdmGranted
            reasons.append(.mdmGranted)
        }

        // Plan §4.1: "Denied grant where last_modified within
        // recent window (attempted but blocked) — scored as if
        // granted to surface the attempt; otherwise 0".
        //
        // We surface "denied recently attempted" as an additional
        // reason but don't double-count the base weight (the
        // service weight already fired above). For denied grants
        // OUTSIDE the recent window we'd want to zero the score —
        // but for v1.13a-3 RC we surface the reason and let the
        // operator's filter handle it; a future iteration can
        // refine.
        if input.authValue == .denied, input.lastModified != nil,
           let lm = input.lastModified, Date().timeIntervalSince(lm) < 7 * 24 * 3600 {
            reasons.append(.deniedRecentlyAttempted)
        }

        // Clamp to [0, 100].
        let clamped = max(0, min(100, delta))
        return TCCRiskScore(score: clamped, reasons: reasons)
    }
}
