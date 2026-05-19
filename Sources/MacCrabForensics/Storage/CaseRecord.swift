// Case row — what `cases` holds per plan §3.4.
//
// Constructed via CaseManager (Cases/CaseManager.swift, landing in
// v1.13a-1.5). ArtifactStore reads + writes these rows; consumers
// query via CaseManager.

import Foundation

public struct CaseRecord: Sendable {

    /// UUID-style id. Primary key in `cases`.
    public let id: String

    /// Operator-supplied case name.
    public let name: String

    /// When the case was created.
    public let createdAt: Date

    /// Optional declared time window. Plugins consult this when
    /// the operator didn't supply a per-invocation window.
    public let timeWindowStart: Date?
    public let timeWindowEnd: Date?

    /// Free-form notes the operator may attach via
    /// `maccrabctl case set-notes <id> <text>` (CLI surface
    /// landing in v1.13a-1.6).
    public let notes: String?

    /// Encryption posture — immutable at case creation per plan
    /// §3.4. Drives Pass 2026-D INSERT-time rejection of
    /// non-metadata artifacts when state == .plaintext.
    public let encryptionState: CaseEncryptionState

    /// Per-case AI grant. Default false; flipped by
    /// `maccrabctl case allow-ai --content <id>` per plan §10.
    public let aiContentAllowed: Bool

    /// Per-case opt-in for unattended scheduled runs (plan §10.5).
    /// Default false — scheduled runs prompt for consent at run
    /// time unless this is on.
    public let scheduledTrusted: Bool

    public init(
        id: String,
        name: String,
        createdAt: Date,
        timeWindowStart: Date? = nil,
        timeWindowEnd: Date? = nil,
        notes: String? = nil,
        encryptionState: CaseEncryptionState,
        aiContentAllowed: Bool = false,
        scheduledTrusted: Bool = false
    ) {
        self.id = id
        self.name = name
        self.createdAt = createdAt
        self.timeWindowStart = timeWindowStart
        self.timeWindowEnd = timeWindowEnd
        self.notes = notes
        self.encryptionState = encryptionState
        self.aiContentAllowed = aiContentAllowed
        self.scheduledTrusted = scheduledTrusted
    }
}
