// BroadcastSanitizer.swift
//
// Per-field text sanitization for broadcast title/summary (docs spec §5.1/§5.2).
// Order is fixed: NFC-normalize FIRST, then strip dangerous codepoints, then
// cap — so a combining sequence cannot reintroduce a stripped codepoint. The
// app renders the result with Text(verbatim:) (no markdown/auto-link), so the
// remaining risks this closes are bidi/zero-width spoofing, control chars,
// mixed-script homoglyphs, and unbounded length / layout DoS.

import Foundation

enum BroadcastSanitizer {

    /// Sanitize + cap a title. Returns nil if the field is unsalvageable
    /// (e.g. confusable mixed-script that we refuse rather than display).
    static func sanitizeTitle(_ raw: String) -> String? {
        sanitize(raw, maxGraphemes: BroadcastLimits.maxTitleGraphemes,
                 maxBytes: BroadcastLimits.maxTitleBytes)
    }

    static func sanitizeSummary(_ raw: String) -> String? {
        sanitize(raw, maxGraphemes: BroadcastLimits.maxSummaryGraphemes,
                 maxBytes: BroadcastLimits.maxSummaryBytes)
    }

    /// Sanitize a short, app-rendered host label (the only payload-derived part
    /// of a link affordance). Hosts are ASCII [a-z0-9.-] by the time they reach
    /// here, but we run the same strip so a future caller can't regress.
    static func sanitizeHostLabel(_ raw: String) -> String {
        stripDangerous(raw.precomposedStringWithCanonicalMapping)
    }

    // MARK: - Core

    private static func sanitize(_ raw: String, maxGraphemes: Int, maxBytes: Int) -> String? {
        // 1. NFC normalize.
        let nfc = raw.precomposedStringWithCanonicalMapping
        // 2. Strip control / bidi-override / zero-width.
        let stripped = stripDangerous(nfc)
        // 3. Refuse confusable mixed-script (Latin mixed with Cyrillic/Greek).
        if hasConfusableMixedScript(stripped) { return nil }
        // 4. Cap by grapheme clusters, then by UTF-8 bytes (defends Zalgo:
        //    few graphemes can still be many bytes).
        let capped = cap(stripped, maxGraphemes: maxGraphemes, maxBytes: maxBytes)
        let trimmed = capped.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? nil : trimmed
    }

    /// Remove Unicode control chars, bidi formatting/overrides, and zero-width
    /// codepoints. Keeps normal whitespace (space, tab→space, newline→space).
    static func stripDangerous(_ s: String) -> String {
        var out = String.UnicodeScalarView()
        for u in s.unicodeScalars {
            let v = u.value
            // Bidi overrides + isolates: 202A–202E, 2066–2069.
            if (0x202A...0x202E).contains(v) || (0x2066...0x2069).contains(v) { continue }
            // Zero-width + BOM: 200B–200F, 2060–2064, FEFF.
            if (0x200B...0x200F).contains(v) || (0x2060...0x2064).contains(v) || v == 0xFEFF { continue }
            // Normalize common whitespace controls to a space; drop other controls.
            if v == 0x09 || v == 0x0A || v == 0x0D { out.append(" "); continue }
            if u.properties.generalCategory == .control || u.properties.generalCategory == .format { continue }
            out.append(u)
        }
        // Collapse any run of spaces (created by the above) to a single space.
        var collapsed = String(String.UnicodeScalarView(out))
        while collapsed.contains("  ") {
            collapsed = collapsed.replacingOccurrences(of: "  ", with: " ")
        }
        return collapsed
    }

    /// True when the string mixes Latin letters with letters from a confusable
    /// non-Latin script (Cyrillic / Greek) — the classic "аpple.com" homoglyph.
    /// Conservative: only flags when BOTH a Latin letter and a confusable-script
    /// letter appear, so ordinary all-Latin or all-CJK text is unaffected.
    static func hasConfusableMixedScript(_ s: String) -> Bool {
        var hasLatin = false
        var hasConfusable = false
        for u in s.unicodeScalars {
            let v = u.value
            // Basic Latin + Latin-1/extended letters.
            if (0x41...0x5A).contains(v) || (0x61...0x7A).contains(v) ||
               (0x00C0...0x024F).contains(v) { hasLatin = true }
            // Cyrillic (0400–04FF) + Greek letters (0370–03FF).
            if (0x0400...0x04FF).contains(v) || (0x0370...0x03FF).contains(v) { hasConfusable = true }
            if hasLatin && hasConfusable { return true }
        }
        return false
    }

    /// Cap to maxGraphemes grapheme clusters, then ensure the UTF-8 byte length
    /// is within maxBytes (dropping whole graphemes from the end until it fits).
    static func cap(_ s: String, maxGraphemes: Int, maxBytes: Int) -> String {
        var result = s
        if result.count > maxGraphemes {
            result = String(result.prefix(maxGraphemes))
        }
        while result.utf8.count > maxBytes && !result.isEmpty {
            result.removeLast()
        }
        return result
    }
}
