// ProcessKey.swift
// MacCrabCore
//
// v1.10 TraceGraph (PR-6a) — derives a stable string identifier for a
// `ProcessIdentity` so it can be used as a primary key in `tracegraph.db`
// and as the canonical reference in cross-store joins.
//
// Per §10.1 of the v1.10.0 TraceGraph spec, `processKey` is computed as
// SHA-256 over the existing v1.9 anti-PID-recycle identity inputs in a
// fixed canonical order:
//
//     auid || euid || pid || pidversion || asid || pathHash
//
// Critically, this DOES NOT fold `startTime` into the key. v1.9's
// `ProcessIdentity` already excludes `startTime` from hash/equality (see
// `ProcessIdentity.swift` line 65 onward) precisely because timestamp
// resolution differences across collectors otherwise make the same
// logical process unequal across observations. Adding it back here would
// reintroduce that bug — a regression Plan v3 review #5 specifically
// called out for the v1.9 work.

import Foundation
import CryptoKit

extension ProcessIdentity {

    /// Stable lowercase-hex SHA-256 over the load-bearing identity inputs.
    /// 64 characters; deterministic across daemon runs.
    public var processKey: String {
        // Fixed canonical byte layout. Little-endian on macOS for all
        // UInt32; we don't normalise endianness explicitly because every
        // byte producer here runs on the same host and the digest is
        // never compared across architectures (a bundle exported on
        // arm64 and validated on x86_64 carries the *string*, not the
        // raw bytes — and the canonical reduction in §19.2 hashes the
        // emitted string, not the underlying integers).
        var buffer = Data()
        buffer.reserveCapacity(4 + 4 + 4 + 4 + 4 + 8)
        var auid = auditIdentity.auid
        var euid = auditIdentity.euid
        var pidU = UInt32(bitPattern: auditIdentity.pid)
        var pidversion = auditIdentity.pidversion
        var asid = UInt32(bitPattern: auditIdentity.asid)
        var pathHashLE = pathHash
        withUnsafeBytes(of: &auid) { buffer.append(contentsOf: $0) }
        withUnsafeBytes(of: &euid) { buffer.append(contentsOf: $0) }
        withUnsafeBytes(of: &pidU) { buffer.append(contentsOf: $0) }
        withUnsafeBytes(of: &pidversion) { buffer.append(contentsOf: $0) }
        withUnsafeBytes(of: &asid) { buffer.append(contentsOf: $0) }
        withUnsafeBytes(of: &pathHashLE) { buffer.append(contentsOf: $0) }
        let digest = SHA256.hash(data: buffer)
        return digest.map { String(format: "%02x", $0) }.joined()
    }
}
