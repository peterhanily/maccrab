// RaveNamespaceGuard.swift — client-side defense against a third-party or
// sideloaded plugin impersonating a first-party MacCrab scanner. Reserves the
// `com.maccrab.*` id namespace for first-party plugins and flags display names
// confusably close to a known first-party one (homoglyph / spacing / 1-edit).
// (v1.19.0, C-F)
//
// "first-party" is the catalog's authoritative, operator-signed trust signal
// (trust_tier == "first-party"). A plugin that is NOT first-party but claims the
// reserved namespace, or whose name is confusably close to a first-party name,
// is flagged so the UI/install path can refuse or warn — the curated catalog's
// signature protects catalog installs, this also defends sideload/operator-key
// installs and catches a confusable that slipped review.

import Foundation

public enum RaveNamespaceVerdict: Sendable, Equatable {
    case ok
    /// A non-first-party plugin claims a reserved `com.maccrab.*` id.
    case reservedNamespaceImpersonation(id: String)
    /// A non-first-party display name is confusably close to a first-party one.
    case confusableDisplayName(name: String, matchesFirstParty: String)
}

public enum RaveNamespaceGuard {

    /// Reserved id prefix — only first-party (maccrab-signed) plugins may use it.
    public static let reservedPrefix = "com.maccrab."

    public static func isReservedNamespace(_ id: String) -> Bool {
        id.lowercased().hasPrefix(reservedPrefix)
    }

    /// Fold a display name for confusable comparison: lowercase, map common
    /// homoglyphs to their look-alike letter, and drop non-alphanumerics, so
    /// "MacCrab iMessage", "Mac-Crab  iMessage!", and "MacCr4b iMessage" all
    /// collapse to the same key.
    static func normalize(_ s: String) -> String {
        // Width-fold (fullwidth/halfwidth → ASCII), strip diacritics, and
        // case-fold first, so "ＭａｃＣｒａｂ" and "Mäccrab" collapse toward the
        // ASCII key before homoglyph mapping.
        let width = s.folding(
            options: [.widthInsensitive, .diacriticInsensitive, .caseInsensitive],
            locale: nil
        )
        // Map common look-alikes to their Latin twin: ASCII leetspeak/symbols
        // AND cross-script homoglyphs (Cyrillic + Greek), so a Cyrillic "а" or a
        // Greek "ο" can't impersonate an ASCII first-party name. (C-F Unicode
        // hardening — width-folding alone keeps non-ASCII letters as-is.)
        let homoglyphs: [Character: Character] = [
            // leetspeak / symbols
            "0": "o", "1": "l", "5": "s", "3": "e", "4": "a", "@": "a", "$": "s", "7": "t",
            // Cyrillic look-alikes
            "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y",
            "к": "k", "м": "m", "т": "t", "в": "b", "н": "h", "і": "i", "ѕ": "s",
            "ј": "j", "ԁ": "d", "ɡ": "g", "ո": "n",
            // Greek look-alikes
            "α": "a", "ο": "o", "ε": "e", "ρ": "p", "ν": "v", "τ": "t", "κ": "k",
            "ι": "i", "β": "b", "ϲ": "c", "υ": "u", "χ": "x", "μ": "m",
        ]
        let folded = width.lowercased().map { homoglyphs[$0] ?? $0 }
        return String(String(folded).unicodeScalars.filter { CharacterSet.alphanumerics.contains($0) })
    }

    /// Levenshtein edit distance (inputs are short display-name keys).
    static func editDistance(_ a: String, _ b: String) -> Int {
        let x = Array(a), y = Array(b)
        if x.isEmpty { return y.count }
        if y.isEmpty { return x.count }
        var prev = Array(0...y.count)
        var cur = [Int](repeating: 0, count: y.count + 1)
        for i in 1...x.count {
            cur[0] = i
            for j in 1...y.count {
                let cost = x[i - 1] == y[j - 1] ? 0 : 1
                cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            }
            swap(&prev, &cur)
        }
        return prev[y.count]
    }

    /// Evaluate a catalog/sideload entry. `isFirstParty` is the operator-signed
    /// trust signal; a non-first-party entry claiming the reserved namespace, or
    /// whose normalized display name equals or is within one edit of a
    /// first-party name, is flagged. First-party entries are never flagged.
    public static func evaluate(
        id: String,
        displayName: String,
        isFirstParty: Bool,
        firstPartyDisplayNames: [String]
    ) -> RaveNamespaceVerdict {
        if isFirstParty { return .ok }

        if isReservedNamespace(id) {
            return .reservedNamespaceImpersonation(id: id)
        }

        let key = normalize(displayName)
        guard !key.isEmpty else { return .ok }
        for fp in firstPartyDisplayNames {
            let fpKey = normalize(fp)
            guard !fpKey.isEmpty else { continue }
            if key == fpKey || editDistance(key, fpKey) <= 1 {
                return .confusableDisplayName(name: displayName, matchesFirstParty: fp)
            }
        }
        return .ok
    }
}
