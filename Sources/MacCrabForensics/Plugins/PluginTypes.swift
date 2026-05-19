// Plugin enums + small value types shared across the four plugin
// kinds (Collector / Enricher / Fingerprinter / Analyzer).
//
// Plan reference: §3.3 — ForensicPlugin protocol.

import Foundation

/// What kind of plugin this is. The manifest declares one; each kind
/// has its own protocol with a different `func` shape (collect /
/// enrich / fingerprint / analyze).
public enum PluginType: String, Codable, CaseIterable, Sendable {
    case collector
    case enricher
    case fingerprinter
    case analyzer
}

/// Trust tier. v1.13a accepts `.tierA` only — first-party Swift
/// code linked in-process. `.tierB` is reserved for the future
/// sandboxed-subprocess runtime (plan §3.9, §12); the loader
/// rejects it for now.
public enum PluginRuntime: String, Codable, Sendable {
    /// First-party Swift code, compiled into `MacCrabForensics` and
    /// linked into the calling binary.
    case tierA

    /// Subprocess-sandboxed plugin. Reserved field; not yet loadable.
    case tierB
}

/// Maturity label. Drives dashboard visibility and the documentation
/// generator. `.preview` plugins are visible but warn the operator
/// that the schema and behavior may change without notice.
public enum Stability: String, Codable, Sendable {
    case preview
    case beta
    case ga
}

/// Privacy classification of a plugin's output OR an MCP tool's
/// returned data. Drives:
///   - default MCP exposure (only `metadata` is allowed without
///     `case.ai_content_allowed = 1`),
///   - dashboard warning-chip rendering,
///   - audit Pass 2026-D plaintext-rejects-non-metadata invariant
///     at INSERT time.
///
/// Plan §10.2 defines the classes; this enum is the source of truth
/// for them in code.
public enum PrivacyClass: String, Codable, CaseIterable, Sendable {
    /// Configuration metadata — TCC grants, launchd entries, codesign
    /// team IDs, MCFP fingerprints, risk scores. Default-allowed in
    /// dashboard + MCP.
    case metadata

    /// Body / payload data — email body, message text, attachment
    /// payloads, cookie values. Blocked from MCP by default; dashboard
    /// shows content-class warning chip.
    case content

    /// Personal-communication metadata + content — iMessage body,
    /// FaceTime call peer, email From/To for personal accounts.
    /// Blocked from MCP; personal-comms warning chip on dashboard.
    case personalComms

    /// Credential-adjacent metadata — Keychain ACL row, Safari Form
    /// Values metadata. Blocked from MCP; warning chip on dashboard.
    case credentialAdjacent

    /// Decrypted secret material — keychain plaintext, decrypted
    /// attachment. Blocked from MCP regardless of operator grant;
    /// dashboard requires explicit reveal.
    case secret
}

/// Confidence level on a single emitted field or artifact. Plan
/// §6.3 / §5.2 distinguish:
///   - `.observed`   — direct read from the source-of-truth
///   - `.derived`    — computed from observed data via a deterministic
///                     transformation
///   - `.heuristic`  — best-effort interpretation; may be wrong
///                     (e.g. MCFP dyld component captured via
///                      cooperative DYLD_INSERT_LIBRARIES)
public enum Confidence: String, Codable, Sendable {
    case observed
    case derived
    case heuristic
}

/// When in the event pipeline an Enricher fires. A single Enricher
/// may declare multiple stages via `Enricher.stages`.
///
/// Plan §5.1.
public enum EnrichmentStage: String, Codable, CaseIterable, Sendable {
    /// After capture, before Sigma / sequence rules run. Adds fields
    /// rules can match on. The codesign-resolve enricher (v1.13a-2)
    /// runs here.
    case preDetection

    /// After an alert is committed by `AlertSink`. Adds expensive
    /// context that doesn't influence detection but enriches display
    /// and downstream consumers.
    case postEmission

    /// User-initiated (clicking "Enrich" in the dashboard) or
    /// AI-agent-initiated (MCP tool call). Pulls heavy / external
    /// context.
    case onDemand
}

/// TCC services that a plugin may declare in its manifest. The set
/// drives:
///   - the macOS privacy prompts (the loading binary's Info.plist
///     must contain matching `NSAppleEventsUsageDescription` /
///     `NSSystemAdministrationUsageDescription` / etc. strings —
///     enforced by audit Pass 2026-A),
///   - the first-run setup walk for `maccrab-forensicsd` (v1.13b).
///
/// String values match the macOS `kTCCService*` canonical short
/// names so the dashboard can normalize raw constants to the same
/// vocabulary.
public enum TCCService: String, Codable, CaseIterable, Sendable {
    case fullDiskAccess          // kTCCServiceSystemPolicyAllFiles
    case accessibility           // kTCCServiceAccessibility
    case automation              // kTCCServiceAppleEvents
    case screenRecording         // kTCCServiceScreenCapture
    case inputMonitoring         // kTCCServiceListenEvent
    case microphone              // kTCCServiceMicrophone
    case camera                  // kTCCServiceCamera
    case contacts                // kTCCServiceAddressBook
    case photos                  // kTCCServicePhotos
    case calendars               // kTCCServiceCalendar
    case reminders               // kTCCServiceReminders
    case desktopFolder           // kTCCServiceSystemPolicyDesktopFolder
    case documentsFolder         // kTCCServiceSystemPolicyDocumentsFolder
    case downloadsFolder         // kTCCServiceSystemPolicyDownloadsFolder
}
