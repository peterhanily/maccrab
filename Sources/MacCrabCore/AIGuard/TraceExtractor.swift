// TraceExtractor.swift
// MacCrabCore
//
// v1.9 Agent Traces — extracts W3C trace context from a process's execve env
// block and parses it under strict v00 rules.
//
// Hard invariants (Plan v3):
//   * Bounded scan: at most 256 vars OR 16 KB cumulative, whichever first.
//   * Only TRACEPARENT and TRACESTATE are inspected; nothing else is even
//     copied. The env block is never persisted, logged, or sent to LLMs.
//   * TRACESTATE is presence-only in v1.9 (its value is opaque vendor context
//     and not stored). Privacy doc: "MacCrab scans for TRACEPARENT;
//     TRACESTATE is not persisted in v1.9."
//   * The parsed `TraceContext` is a pure 32-hex trace_id + 16-hex span_id +
//     1-byte flags + tracestatePresent bool — no semantic content. Even an
//     unintended log of the parsed value exposes only "a trace existed."
//
// W3C parser is strict-on-v00, drop-on-anything-else:
//   * Length must equal exactly 55 bytes (`00-<32hex>-<16hex>-<2hex>`).
//   * Lowercase hex only. Uppercase or mixed case is rejected (no tolerant
//     mode in v1.9; documented as a strict-by-design choice).
//   * version `ff` is rejected (W3C reserves it as forever-invalid).
//   * version `01` and any other non-`00` is rejected — we will revisit when
//     W3C ratifies v01. The TraceExtractorTests.swift breadcrumb comment
//     marks the v01 test for removal at that time.
//   * trace_id and parent_span_id are both rejected if all-zero.
//   * The flags byte is read; the sampled bit is `flags & 0x01`, never an
//     integer compare. Higher bits are preserved for completeness but not
//     interpreted in v1.9.

import Foundation

/// Strict-parsed W3C TRACEPARENT plus a presence flag for TRACESTATE.
///
/// All 32-hex / 16-hex / 2-hex strings are lowercase. Trust callers to log
/// the whole struct safely — there is no field whose value carries env-block
/// content.
public struct TraceContext: Sendable, Hashable, Codable {
    public let traceId: String         // 32 lowercase hex chars
    public let parentSpanId: String    // 16 lowercase hex chars
    public let flagsByte: UInt8        // raw flags byte (0x00..0xff)
    public let tracestatePresent: Bool

    public init(
        traceId: String,
        parentSpanId: String,
        flagsByte: UInt8,
        tracestatePresent: Bool
    ) {
        self.traceId = traceId
        self.parentSpanId = parentSpanId
        self.flagsByte = flagsByte
        self.tracestatePresent = tracestatePresent
    }

    /// Per W3C Trace Context, the sampled flag is bit 0 of the flags byte.
    /// Read as a bit-mask, never an integer compare — higher bits are
    /// reserved for future flags and must not change `sampled`'s value.
    public var sampled: Bool { (flagsByte & 0x01) != 0 }
}

/// Stateless parser + bounded env scanner for the agent trace correlation
/// engine. PR-1 ships extraction + parsing only. PR-2 wires the result into
/// TraceRegistry; PR-3 adds the OTLP receiver.
public enum TraceExtractor {

    // MARK: - Public bounds (also referenced by tests)

    /// Maximum number of env vars scanned before we give up looking for
    /// TRACEPARENT. Long envs (Xcode toolchains, dense Node spawns) routinely
    /// have 50–80 vars; 256 leaves comfortable headroom without being open-ended.
    public static let maxEnvVarsScanned: Int = 256

    /// Maximum cumulative bytes of env data scanned. Protects the worst case
    /// (huge serialised JSON in a single var) from blocking the exec hot path.
    public static let maxEnvBytesScanned: Int = 16_384

    /// Exact length of a v00 TRACEPARENT header per W3C Trace Context Level 1.
    public static let v00HeaderLength: Int = 55

    // MARK: - W3C parser

    /// Parse a TRACEPARENT header value under strict v00 rules.
    ///
    /// Returns nil for any non-conforming input. Callers treat nil as "no
    /// trace context present" — never as "try a tolerant fallback."
    ///
    /// - Parameter raw: raw value of the env var (no `TRACEPARENT=` prefix)
    /// - Parameter tracestatePresent: whether TRACESTATE was also seen in env
    public static func parseTraceparent(
        _ raw: String,
        tracestatePresent: Bool
    ) -> TraceContext? {
        // Length: exactly 55 chars for v00. Reject anything longer to avoid
        // future-version leniency surprises (Plan v3 review #1).
        guard raw.count == v00HeaderLength else { return nil }

        // Field positions for v00 are positional, not delimited-tolerant:
        //   00-<32hex>-<16hex>-<2hex>
        //    0  3       36      53
        let bytes = Array(raw.utf8)
        guard bytes.count == v00HeaderLength else { return nil }

        // Hyphens at positions 2, 35, 52
        guard bytes[2] == 0x2D, bytes[35] == 0x2D, bytes[52] == 0x2D else { return nil }

        // Lowercase-hex only. ASCII fast path.
        @inline(__always) func isLowerHex(_ b: UInt8) -> Bool {
            return (b >= 0x30 && b <= 0x39) || (b >= 0x61 && b <= 0x66) // 0-9 a-f
        }

        // Version: positions 0..2.
        let v0 = bytes[0], v1 = bytes[1]
        guard isLowerHex(v0), isLowerHex(v1) else { return nil }
        // version `ff` is reserved-invalid per W3C Trace Context.
        if v0 == 0x66 && v1 == 0x66 { return nil }
        // Strict-on-v00: any other version is rejected for v1.9.
        // Tests assert v01 is rejected with a breadcrumb to remove that test
        // when W3C ratifies v01.
        if !(v0 == 0x30 && v1 == 0x30) { return nil }

        // trace_id: positions 3..35 (32 hex chars)
        var traceIdAllZero = true
        for i in 3..<35 {
            let b = bytes[i]
            if !isLowerHex(b) { return nil }
            if b != 0x30 { traceIdAllZero = false }
        }
        if traceIdAllZero { return nil }

        // parent_span_id: positions 36..52 (16 hex chars)
        var spanIdAllZero = true
        for i in 36..<52 {
            let b = bytes[i]
            if !isLowerHex(b) { return nil }
            if b != 0x30 { spanIdAllZero = false }
        }
        if spanIdAllZero { return nil }

        // flags: positions 53..55 (2 hex chars). Build the raw byte; do NOT
        // interpret beyond bit 0 (`sampled`) in v1.9.
        let f0 = bytes[53], f1 = bytes[54]
        guard isLowerHex(f0), isLowerHex(f1) else { return nil }
        let flagsByte = (hexNibble(f0) &<< 4) | hexNibble(f1)

        // Slice substrings safely — the bytes already validated as ASCII hex
        // are guaranteed valid UTF-8.
        let traceId = String(raw[raw.index(raw.startIndex, offsetBy: 3)..<raw.index(raw.startIndex, offsetBy: 35)])
        let spanId = String(raw[raw.index(raw.startIndex, offsetBy: 36)..<raw.index(raw.startIndex, offsetBy: 52)])

        return TraceContext(
            traceId: traceId,
            parentSpanId: spanId,
            flagsByte: flagsByte,
            tracestatePresent: tracestatePresent
        )
    }

    @inline(__always)
    private static func hexNibble(_ b: UInt8) -> UInt8 {
        if b <= 0x39 { return b - 0x30 }       // '0'..'9'
        return b - 0x61 + 10                    // 'a'..'f'
    }

    // MARK: - Bounded env scanner

    /// Scan a sequence of env strings for TRACEPARENT and TRACESTATE without
    /// copying anything else.
    ///
    /// The caller passes a closure that yields env entries one at a time —
    /// this avoids materialising the whole env block as a Swift array (the
    /// ES NOTIFY_EXEC env iterator is index-based and zero-copy). The scan
    /// stops at the first of:
    ///   * `maxEnvVarsScanned` entries seen
    ///   * `maxEnvBytesScanned` cumulative bytes seen
    ///   * both TRACEPARENT and TRACESTATE found
    ///
    /// - Parameters:
    ///   - count: total number of env entries available
    ///   - read: closure that returns the i-th entry as a `String`. Should
    ///     return nil for malformed entries (e.g. invalid UTF-8); the scan
    ///     skips those without aborting.
    /// - Returns: parsed `TraceContext`, or nil if no valid TRACEPARENT was
    ///   present within the scan bounds.
    public static func scanEnv(
        count: Int,
        read: (Int) -> String?
    ) -> TraceContext? {
        var bytesScanned = 0
        var traceparentRaw: String?
        var tracestatePresent = false

        let cap = min(count, maxEnvVarsScanned)
        for i in 0..<cap {
            guard let entry = read(i) else { continue }
            bytesScanned += entry.utf8.count
            if bytesScanned > maxEnvBytesScanned { break }

            // Match prefixes byte-wise. We deliberately do NOT lower-case the
            // env var name — env var names are conventionally uppercase, and
            // a lowercase `traceparent=` should not be accepted as a trace
            // context propagator.
            if entry.hasPrefix("TRACEPARENT=") {
                traceparentRaw = String(entry.dropFirst("TRACEPARENT=".count))
            } else if entry.hasPrefix("TRACESTATE=") {
                tracestatePresent = true
                // VALUE NOT STORED. v1.9 only records that TRACESTATE was
                // present; its content is vendor-opaque routing state and
                // intentionally out of scope.
            }

            if traceparentRaw != nil && tracestatePresent { break }
        }

        guard let raw = traceparentRaw else { return nil }
        return parseTraceparent(raw, tracestatePresent: tracestatePresent)
    }
}

// PR-2: wire ProcessIdentity into TraceRegistry; identity is auditIdentity, not pid.
// PR-3b: log agent_trace.attribution_conflict counter on span/lineage disagreement.
// PR-4: attribution_overrides retention purge must run in same txn as events purge (Pass 12).
// PR-5: rule 4 scope source = tool input args; maccrab.tool.declared_scope is future standard.
