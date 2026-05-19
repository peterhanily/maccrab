// Output declaration — the content-type a plugin promises to emit
// plus the privacy class that governs MCP exposure and dashboard
// display.
//
// Plan reference: §3.3 (manifest), §10.2 (privacy classes), §3.8
// audit Pass 2026-A (every output declares privacyClass; contentType
// namespace prefix matches plugin id).

import Foundation

/// A content type / privacy-class pair the plugin promises to emit.
/// One plugin may declare multiple OutputSpecs (e.g. TCC-lite emits
/// `tcc.grant`, `tcc.summary_by_service`, `tcc.grant_added`, ...).
public struct OutputSpec: Codable, Sendable, Hashable {

    /// Stable namespaced content identifier. Convention: leading
    /// segment matches the plugin's id prefix so consumers can route
    /// without ambiguity. Pass 2026-A enforces.
    ///
    /// Examples: `tcc.grant`, `launchd.entry`, `posture.finding`.
    public let contentType: String

    /// Privacy class of every artifact emitted under this content
    /// type. Pass 2026-D enforces that runtime-emitted artifacts
    /// carry the declared class, and that plaintext cases reject
    /// non-metadata classes at INSERT time.
    public let privacyClass: PrivacyClass

    /// `true` means the plugin will NOT emit artifacts under this
    /// content type unless the operator passes an opt-in flag
    /// (or, for case-scoped opt-ins, unless `case.ai_content_allowed
    /// = 1` is set for the running case). Used for surfaces that
    /// upgrade the privacy class above the plugin's default.
    public let optInRequired: Bool

    public init(
        contentType: String,
        privacyClass: PrivacyClass,
        optInRequired: Bool = false
    ) {
        self.contentType = contentType
        self.privacyClass = privacyClass
        self.optInRequired = optInRequired
    }
}

/// Descriptor for one MCP tool the plugin exposes. Auto-registered
/// with `maccrab-mcp` at plugin registration time.
///
/// `exposesPrivacyClass` is the per-tool ceiling — if a single
/// plugin emits both `metadata` and `content` artifacts (the
/// AppleScript runtime monitor §13.5 will, when it lands), each
/// MCP tool declares the highest class it can return. The
/// gate-at-call-time logic (plan §10.8) reads this to decide
/// whether to block or allow.
public struct MCPToolDescriptor: Codable, Sendable, Hashable {
    public let name: String
    public let description: String
    public let exposesPrivacyClass: PrivacyClass

    public init(
        name: String,
        description: String,
        exposesPrivacyClass: PrivacyClass
    ) {
        self.name = name
        self.description = description
        self.exposesPrivacyClass = exposesPrivacyClass
    }
}
