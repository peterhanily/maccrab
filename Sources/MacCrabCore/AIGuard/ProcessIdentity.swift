// ProcessIdentity.swift
// MacCrabCore
//
// v1.9 Agent Traces — pid-recycle-resistant process identity for the
// TraceRegistry (PR-2). Plain `pid_t` is unsafe as a registry key because the
// kernel recycles pids on reasonable timescales (seconds on a busy build host)
// and a bound trace_id from a dead process must NEVER attribute to a fresh
// unrelated process that happens to inherit the same pid.
//
// `audit_token_t` carries `pidversion`, the kernel's anti-recycle counter:
// every fresh exec increments it and a recycled pid carries a different
// pidversion than the original. We normalise the audit_token into our own
// `AuditIdentity` (not stored raw — `audit_token_t` is platform-specific and
// awkward as Hashable/Sendable) and let `AuditIdentity` alone determine
// equality. `pathHash` is defence-in-depth against any audit_token edge case
// (e.g. reused pidversion across boots, which we should never see but should
// not silently mis-attribute to either).
//
// PR-1 ships this type and its tests; PR-2 wires it into TraceRegistry.

import Foundation

/// Normalised projection of `audit_token_t` for use as a Hashable/Sendable
/// identity key. Built via the `audit_token_to_*` accessors in
/// `<bsm/libbsm.h>`; we do not store the raw 8-uint32_t struct.
///
/// `pidversion` is the load-bearing field for anti-recycle: the kernel
/// increments it on every exec, so a fresh process that recycles a freed pid
/// carries a different pidversion than the original.
public struct AuditIdentity: Hashable, Sendable, Codable {
    public let auid: UInt32
    public let euid: UInt32
    public let egid: UInt32
    public let ruid: UInt32
    public let rgid: UInt32
    public let pid: Int32
    /// Kernel anti-pid-recycle counter. Non-zero on every modern macOS process.
    public let pidversion: UInt32
    public let asid: Int32

    public init(
        auid: UInt32,
        euid: UInt32,
        egid: UInt32,
        ruid: UInt32,
        rgid: UInt32,
        pid: Int32,
        pidversion: UInt32,
        asid: Int32
    ) {
        self.auid = auid
        self.euid = euid
        self.egid = egid
        self.ruid = ruid
        self.rgid = rgid
        self.pid = pid
        self.pidversion = pidversion
        self.asid = asid
    }
}

/// Identity for entries in the TraceRegistry pid → trace_id map.
///
/// IMPORTANT: identity is determined by `auditIdentity` alone (whose
/// `pidversion` is the kernel's anti-recycle counter); `pathHash` is
/// defence-in-depth. `pid` and `startTime` are display-only — useful for
/// logging and debugging, but MUST NOT be relied on for hash/equality. A
/// future contributor "optimising" by hashing pid alone would reintroduce the
/// pid-recycle attribution bug Plan v3 review #5 specifically called out.
public struct ProcessIdentity: Hashable, Sendable, Codable {
    /// Identity field. Equal iff every audit_token field matches.
    public let auditIdentity: AuditIdentity
    /// Defence-in-depth identity field — FNV-1a of the resolved executable
    /// path. Cheap to compute, not security-critical, but catches the rare
    /// case where audit_token alone is ambiguous.
    public let pathHash: UInt64
    /// Display-only. Read for log lines and UI; ignored by ==/hash.
    public let pid: pid_t
    /// Display-only. Process start time (seconds since 1970). Ignored by ==/hash.
    public let startTime: UInt64

    public init(
        auditIdentity: AuditIdentity,
        pathHash: UInt64,
        pid: pid_t,
        startTime: UInt64
    ) {
        self.auditIdentity = auditIdentity
        self.pathHash = pathHash
        self.pid = pid
        self.startTime = startTime
    }

    // Custom Hashable: identity = auditIdentity + pathHash. pid and startTime
    // are intentionally excluded so a copy of the struct with only display
    // fields differing still compares equal.
    public static func == (lhs: ProcessIdentity, rhs: ProcessIdentity) -> Bool {
        lhs.auditIdentity == rhs.auditIdentity && lhs.pathHash == rhs.pathHash
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(auditIdentity)
        hasher.combine(pathHash)
    }
}

// MARK: - FNV-1a path hash

extension ProcessIdentity {
    /// FNV-1a 64-bit hash of a path string. Stable across runs, not
    /// cryptographic — defence-in-depth against audit_token edge cases only.
    public static func fnv1a64(_ path: String) -> UInt64 {
        var hash: UInt64 = 0xcbf29ce484222325
        let prime: UInt64 = 0x100000001b3
        for byte in path.utf8 {
            hash ^= UInt64(byte)
            hash &*= prime
        }
        return hash
    }
}
