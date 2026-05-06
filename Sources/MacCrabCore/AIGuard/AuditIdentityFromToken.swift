// AuditIdentityFromToken.swift
// MacCrabCore
//
// Bridge between Apple's `audit_token_t` and our pure-Swift `AuditIdentity`.
// Kept in its own file so `ProcessIdentity.swift` stays free of macOS-only
// imports — useful for tests and for any future port to a non-Apple platform.
//
// `audit_token_to_pidversion` is the load-bearing field for anti-pid-recycle.
// macOS increments pidversion on every successful exec; a recycled pid that
// gets reused by an unrelated process carries a different pidversion than the
// original binding, and our equality check will reject the stale lookup.

import Foundation
import EndpointSecurity

extension AuditIdentity {
    /// Build an `AuditIdentity` from an Endpoint Security `audit_token_t`.
    ///
    /// Uses the `audit_token_to_*` accessors from `<bsm/libbsm.h>`, which
    /// the EndpointSecurity overlay re-exports. Every field is a normalised
    /// integer — we never store the raw `audit_token_t` struct because it
    /// is platform-private and not Codable/Sendable-friendly.
    public init(from token: audit_token_t) {
        self.init(
            auid: audit_token_to_auid(token),
            euid: audit_token_to_euid(token),
            egid: audit_token_to_egid(token),
            ruid: audit_token_to_ruid(token),
            rgid: audit_token_to_rgid(token),
            pid: audit_token_to_pid(token),
            pidversion: UInt32(bitPattern: audit_token_to_pidversion(token)),
            asid: audit_token_to_asid(token)
        )
    }
}

extension ProcessIdentity {
    /// Convenience builder used by ESCollector at NOTIFY_EXEC time.
    /// Pulls the audit token, executable path, and start time straight from
    /// the ES payload so the caller doesn't have to thread them separately.
    public init(from esProcess: UnsafePointer<es_process_t>, executablePath: String) {
        let token = esProcess.pointee.audit_token
        let auditIdentity = AuditIdentity(from: token)
        let pathHash = ProcessIdentity.fnv1a64(executablePath)
        let pid = auditIdentity.pid
        // start_time is `timespec`; collapse to seconds-since-1970 for
        // display purposes only (display-only field, not part of identity).
        let startSec = UInt64(esProcess.pointee.start_time.tv_sec)
        self.init(
            auditIdentity: auditIdentity,
            pathHash: pathHash,
            pid: pid,
            startTime: startSec
        )
    }
}
