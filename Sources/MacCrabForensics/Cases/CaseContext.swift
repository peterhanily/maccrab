// CaseContext — the runtime handle passed into every plugin
// invocation. Carries the case identity, the in-memory DEK (so
// the plugin can use the SQLCipher key without re-prompting), and
// the unlock state. The CaseManager (Cases/CaseManager.swift,
// landing in v1.13a-1.5) constructs it after unlock and discards
// it on relock.
//
// Plan reference: §3.4 (case schema), §10.4 (encryption + DEK
// caching).

import Foundation

/// Per-invocation context. Construct via `CaseManager.context(for:)`
/// — never directly. The DEK lives in memory only for the lifetime
/// of an unlocked daemon session (plan §10.4 default 30-minute
/// idle relock).
public struct CaseContext: Sendable {

    /// UUID-like case identifier (the `cases.id` primary key). Used
    /// for path derivation and as the foreign key on every committed
    /// artifact.
    public let caseID: String

    /// Operator-supplied case name. Surfaced in `mcp_audit.log`
    /// entries and in dashboard headers.
    public let caseName: String

    /// Whether AI agents may invoke MCP tools that expose
    /// non-metadata artifacts in this case. Plan §10.8 — the per-
    /// case grant the operator flips via
    /// `maccrabctl case allow-ai --content <id>`. Default `false`.
    public let aiContentAllowed: Bool

    /// Whether scheduled-run consent is bypassed for this case
    /// (plan §10.5 — the `scheduled_trusted` flag). Plugins read
    /// this for log annotation only; the consent UX itself is
    /// owned by the runtime / dashboard.
    public let scheduledTrusted: Bool

    /// Absolute path to the case's directory under
    /// `~/Library/Application Support/MacCrab/Cases/<case-id>/`.
    /// Plugins may read from `<case>/snapshots/` and write nothing
    /// directly — all artifacts go through `ArtifactStore`.
    public let directory: URL

    /// Encryption state of the case. Plugins read this to decide
    /// whether the privacy-class invariant (Pass 2026-D) applies
    /// inline; the ArtifactStore itself rejects bad-class INSERTs
    /// regardless, so plugins don't need to gate.
    public let encryptionState: CaseEncryptionState

    public init(
        caseID: String,
        caseName: String,
        aiContentAllowed: Bool,
        scheduledTrusted: Bool,
        directory: URL,
        encryptionState: CaseEncryptionState
    ) {
        self.caseID = caseID
        self.caseName = caseName
        self.aiContentAllowed = aiContentAllowed
        self.scheduledTrusted = scheduledTrusted
        self.directory = directory
        self.encryptionState = encryptionState
    }
}

/// `cases.encryption_state` — immutable at case creation per
/// plan §3.4. The platform never upgrades plaintext → encrypted
/// or downgrades encrypted → plaintext on an existing case.
public enum CaseEncryptionState: String, Codable, Sendable {
    /// Default. DEK wrapped via the macOS login keychain, AES-256-GCM
    /// on the SQLCipher case.sqlite, AES-GCM per blob in vault/.
    /// Touch ID convenience layer arrives in v1.13b.
    case encryptedKeychain = "encrypted_keychain"

    /// Reserved for explicit operator-set password not bound to the
    /// login keychain. Not exposed in v1.13a; field-name reserved.
    case encryptedPassword = "encrypted_password"

    /// Opt-in only via `--no-encrypt`. Pass 2026-D rejects
    /// non-metadata artifact INSERTs at the store layer.
    case plaintext = "plaintext"
}
