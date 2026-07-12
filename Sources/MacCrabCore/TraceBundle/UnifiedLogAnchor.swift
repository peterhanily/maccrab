// UnifiedLogAnchor.swift
// MacCrabCore
//
// v1.10 TraceGraph (PR-10c) — emits and queries the daemon-signed
// chain head in the macOS unified log per §19.1 of the spec.
//
// Subsystem name: `com.maccrab.tracegraph.chain` (§19.1).
//
// The unified log is the second of three anchoring layers (along
// with the daemon signature on the bundle and the optional fleet
// anchor). The unified log isn't authentication — any process can
// log to any subsystem name — but it provides an OS-managed
// independent witness of when the daemon emitted a signed chain
// head, which raises the cost of silent retroactive tampering.
//
// Two implementations:
//
//   SystemUnifiedLogAnchor — emits via os.log Logger, reads via
//   OSLogStore. Production path. Read-back may degrade gracefully
//   on hosts where OSLogStore access is restricted (sandboxed
//   binaries, missing entitlements).
//
//   InMemoryUnifiedLogAnchor — in-memory record list. Used by tests
//   and as a fallback when OSLogStore is unavailable.

import Foundation
import os.log   // Logger (emit path)
import OSLog    // OSLogStore / OSLogEntryLog (read-back path)

/// One emitted chain-head record.
public struct UnifiedLogChainHeadRecord: Sendable, Codable, Equatable {
    public let merkleRoot: String
    public let signatureBase64: String
    public let signingKeyMode: String
    public let signingKeyFingerprint: String
    public let traceId: String
    public let emittedAt: Date

    public init(
        merkleRoot: String,
        signatureBase64: String,
        signingKeyMode: String,
        signingKeyFingerprint: String,
        traceId: String,
        emittedAt: Date
    ) {
        self.merkleRoot = merkleRoot
        self.signatureBase64 = signatureBase64
        self.signingKeyMode = signingKeyMode
        self.signingKeyFingerprint = signingKeyFingerprint
        self.traceId = traceId
        self.emittedAt = emittedAt
    }
}

public enum UnifiedLogAnchorError: Error, Equatable {
    case emissionFailed(String)
    case readUnavailable(String)
}

/// Protocol for emit + lookup of chain heads in the unified log.
public protocol UnifiedLogAnchor: Sendable {
    func emit(_ record: UnifiedLogChainHeadRecord) async throws
    func findChainHead(merkleRoot: String, within window: TimeWindow) async throws -> UnifiedLogChainHeadRecord?
}

// MARK: - InMemoryUnifiedLogAnchor

public actor InMemoryUnifiedLogAnchor: UnifiedLogAnchor {

    // Test-only stub. Production implementer is a unified-log-backed
    // actor that uses macOS's log rotation as the bound; tests
    // instantiate this actor per-test and discard.
    private var records: [UnifiedLogChainHeadRecord] = [] // bounded: test stub (per-test lifetime, prod uses macOS unified log)

    public init(seed: [UnifiedLogChainHeadRecord] = []) {
        self.records = seed
    }

    public func emit(_ record: UnifiedLogChainHeadRecord) {
        records.append(record)
    }

    public func findChainHead(merkleRoot: String, within window: TimeWindow) -> UnifiedLogChainHeadRecord? {
        records.first { record in
            record.merkleRoot == merkleRoot
                && record.emittedAt >= window.start
                && record.emittedAt <= window.end
        }
    }

    public func allEmitted() -> [UnifiedLogChainHeadRecord] {
        records
    }
}

// MARK: - SystemUnifiedLogAnchor

public actor SystemUnifiedLogAnchor: UnifiedLogAnchor {

    public static let subsystem = "com.maccrab.tracegraph.chain"

    private let logger: Logger
    private let category: String
    private let inMemoryFallback: InMemoryUnifiedLogAnchor

    public init(category: String = "anchor") {
        self.category = category
        self.logger = Logger(subsystem: SystemUnifiedLogAnchor.subsystem, category: category)
        self.inMemoryFallback = InMemoryUnifiedLogAnchor()
    }

    public func emit(_ record: UnifiedLogChainHeadRecord) async throws {
        // Encode as compact JSON for log readability + later re-parsing.
        let encoder = canonicalJSONEncoder()
        guard let data = try? encoder.encode(record),
              let json = String(data: data, encoding: .utf8) else {
            throw UnifiedLogAnchorError.emissionFailed("encode failed")
        }
        // Log at .info level under the dedicated subsystem so OSLogStore
        // queries with subsystem == "com.maccrab.tracegraph.chain" find it.
        logger.info("\(json, privacy: .public)")
        // Mirror into the in-memory fallback so that read-back works
        // even on hosts where OSLogStore access is restricted.
        await inMemoryFallback.emit(record)
    }

    public func findChainHead(merkleRoot: String, within window: TimeWindow) async throws -> UnifiedLogChainHeadRecord? {
        // Try the in-memory mirror first — fast path for chains
        // emitted during this daemon run (or this process, in tests).
        if let record = await inMemoryFallback.findChainHead(merkleRoot: merkleRoot, within: window) {
            return record
        }
        // Cross-process / cross-run read-back from the macOS unified log.
        return readChainHeadFromUnifiedLog(merkleRoot: merkleRoot, within: window)
    }

    /// Query `OSLogStore` for a previously-emitted chain-head record.
    ///
    /// UNVERIFIED RUNTIME PATH — NEEDS ON-DEVICE VERIFICATION.
    /// The realistic production shape is: the **root System Extension** emits
    /// the chain head (`emit`, logged under `\(Self.subsystem)`), and a
    /// separate **uid-501 verifier process** (maccrabctl / the app) reads it
    /// back here on a later invocation. That cross-uid, cross-run read cannot
    /// be exercised by a unit test or reasoned to "proven" from source:
    ///   - `OSLogStore.local()` reads the whole-system store, which is
    ///     entitlement/privilege gated — a sandboxed or unentitled reader gets
    ///     a throw, and we DEGRADE GRACEFULLY (return nil → the verifier emits
    ///     the §19.4 "degraded, re-run without --check-unified-log" warning,
    ///     never a crash and never a false "verified").
    ///   - Log retention/rotation bounds how far back a head is visible.
    ///   - The composed message must round-trip exactly through the log.
    /// Everything here is best-effort and failure-tolerant on purpose; the
    /// authoritative anchors remain the per-export daemon signature and the
    /// in-memory fast path for same-run checks.
    private func readChainHeadFromUnifiedLog(
        merkleRoot: String,
        within window: TimeWindow
    ) -> UnifiedLogChainHeadRecord? {
        // `OSLogStore.local()` is the whole-system store (needs privilege /
        // the logging entitlement). Any failure — including the common
        // unentitled case — degrades to nil rather than throwing.
        guard let store = try? OSLogStore.local() else { return nil }
        let position = store.position(date: window.start)
        let predicate = NSPredicate(format: "subsystem == %@", Self.subsystem)
        guard let entries = try? store.getEntries(at: position, matching: predicate) else {
            return nil
        }
        let decoder = canonicalJSONDecoder()
        for entry in entries {
            guard let logEntry = entry as? OSLogEntryLog else { continue }
            // We logged the record as compact JSON at .public privacy, so the
            // composed message IS the JSON payload — parse it straight back.
            guard let data = logEntry.composedMessage.data(using: .utf8),
                  let record = try? decoder.decode(UnifiedLogChainHeadRecord.self, from: data)
            else { continue }
            if record.merkleRoot == merkleRoot,
               record.emittedAt >= window.start,
               record.emittedAt <= window.end {
                return record
            }
        }
        return nil
    }
}
