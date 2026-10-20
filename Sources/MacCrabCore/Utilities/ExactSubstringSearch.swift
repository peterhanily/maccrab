// ExactSubstringSearch.swift
// MacCrabCore
//
// Foundation's exact `contains` answer for the engine's per-event hot paths,
// without its per-Character cost on the plain-ASCII strings that dominate them.

import Foundation

/// `haystack.contains(needle)` exactly as Foundation answers it, faster.
///
/// Foundation's `StringProtocol.contains(_:)` compares extended grapheme
/// clusters with canonical equivalence on current macOS and bridged to
/// NSString on earlier releases. Those definitions disagree only around a
/// CR LF pair (one Character, two UTF-16 units) and around non-ASCII
/// clustering, combining marks or equivalent compositions; both report no
/// match for an empty needle. When the needle is non-empty and neither string
/// contains a byte above 0x7F or a carriage return, every Character is exactly
/// one byte and every definition reduces to a contiguous byte match. Only that
/// proven case is answered here; every other input, including bridged strings
/// without contiguous UTF-8, is delegated to Foundation unchanged.
///
/// A live engine profile found Foundation's Character-by-Character search
/// behind roughly a third of engine CPU; this keeps those call sites' verdicts
/// identical while removing that cost for ordinary paths and command lines.
public enum ExactSubstringSearch {
    public static func contains(_ haystack: String, _ needle: String) -> Bool {
        if let answer = plainASCIIContains(haystack, needle) {
            return answer
        }
        return haystack.contains(needle)
    }

    /// Byte-match verdict inside the proven-exact domain; nil outside it.
    static func plainASCIIContains(_ haystack: String, _ needle: String) -> Bool? {
        guard !needle.isEmpty else { return nil }
        let verdict = needle.utf8.withContiguousStorageIfAvailable { needleBytes -> Bool? in
            guard isPlainASCII(needleBytes) else { return nil }
            let inner = haystack.utf8.withContiguousStorageIfAvailable { haystackBytes -> Bool? in
                guard isPlainASCII(haystackBytes) else { return nil }
                guard needleBytes.count <= haystackBytes.count,
                      let haystackBase = haystackBytes.baseAddress,
                      let needleBase = needleBytes.baseAddress else {
                    return false
                }
                return memmem(
                    haystackBase,
                    haystackBytes.count,
                    needleBase,
                    needleBytes.count
                ) != nil
            }
            return inner ?? nil
        }
        return verdict ?? nil
    }

    /// `needles.contains { contains(haystack, $0) }`, with the haystack's
    /// plain-ASCII scan done once rather than once per needle. A rule
    /// predicate with many values used to re-scan the same field each time.
    public static func containsAny(_ haystack: String, _ needles: [String]) -> Bool {
        guard !needles.isEmpty else { return false }
        let plainHaystack = haystack.utf8.withContiguousStorageIfAvailable {
            isPlainASCII($0)
        } ?? false
        for needle in needles {
            if plainHaystack, let verdict = plainNeedleContains(haystack, needle) {
                if verdict { return true }
            } else if haystack.contains(needle) {
                return true
            }
        }
        return false
    }

    /// `plainASCIIContains` for a haystack already proven plain ASCII.
    private static func plainNeedleContains(_ haystack: String, _ needle: String) -> Bool? {
        guard !needle.isEmpty else { return nil }
        let verdict = needle.utf8.withContiguousStorageIfAvailable { needleBytes -> Bool? in
            guard isPlainASCII(needleBytes) else { return nil }
            let inner = haystack.utf8.withContiguousStorageIfAvailable { haystackBytes -> Bool in
                guard needleBytes.count <= haystackBytes.count,
                      let haystackBase = haystackBytes.baseAddress,
                      let needleBase = needleBytes.baseAddress else {
                    return false
                }
                return memmem(
                    haystackBase,
                    haystackBytes.count,
                    needleBase,
                    needleBytes.count
                ) != nil
            }
            return inner
        }
        return verdict ?? nil
    }

    /// No byte above 0x7F and no carriage return: one byte per Character.
    @inline(__always)
    static func isPlainASCII(_ bytes: UnsafeBufferPointer<UInt8>) -> Bool {
        for byte in bytes where byte >= 0x80 || byte == 0x0D {
            return false
        }
        return true
    }
}
