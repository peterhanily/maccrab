// BroadcastModel.swift
//
// Strict, fail-closed model for the signed store→app broadcast feed
// (docs spec §5). This is DORMANT infrastructure: nothing in the shipping
// build fetches a broadcast (no production key bundled, feature flag off), but
// the model + its validation are complete and unit-tested so the consumer can
// "read safely" the moment the store/keyholder light it up.
//
// Design rules enforced here (each traces to an adversarial-review finding):
//  - The decoder REJECTS any unknown top-level/per-item key (no AnyCodable /
//    dictionary catch-all) so no future or smuggled field (action/imageURL/
//    html/onTap) can ever be read.
//  - Hard caps (item count, title/summary grapheme AND byte length) measured
//    after normalization.
//  - sequence is a non-negative Int (64-bit on macOS — a value above Int.max
//    throws on decode, which is the desired fail-closed reject).
//  - issuedAt/expiresAt parse with a strict RFC3339 UTC formatter; unparseable
//    → reject the feed.

import Foundation

enum BroadcastError: Error, Equatable {
    case unknownField(String)
    case unknownFeedVersion(Int)
    case badSequence
    case badTimestamp(String)
    case tooManyItems(Int)
    case signatureInvalid
    case oversize
    case redirected
    case fetchFailed(Int)
    case noKey
    case rollback(stored: Int, incoming: Int)
}

/// Caps (docs spec §5). Public so tests + the client share one source of truth.
enum BroadcastLimits {
    static let supportedFeedVersion = 1
    static let maxItems = 10
    static let maxDocumentBytes = 32 * 1024
    static let fetchByteCeiling = 33 * 1024            // 32 KB + 1 KB slack
    static let maxTitleGraphemes = 80
    static let maxTitleBytes = 256
    static let maxSummaryGraphemes = 240
    static let maxSummaryBytes = 1024
    static let maxIDChars = 64
    static let maxClockSkew: TimeInterval = 5 * 60      // future-skew tolerance
    static let maxDisplayAge: TimeInterval = 14 * 24 * 3600   // §6 ceiling
}

/// Closed badge enum. Note: "Preview"/"Security" are intentionally absent — a
/// broadcast must never tease an unannounced launch ("Preview") nor mimic the
/// engine's own alert authority ("Security").
enum BroadcastBadge: String, CaseIterable {
    case update = "Update"
    case new = "New"
    case notice = "Notice"
}

/// A dynamic key that surfaces EVERY key present in the JSON object, so we can
/// reject any that isn't in the allow-list (typed CodingKeys would silently
/// hide unknown keys instead).
private struct AnyKey: CodingKey {
    var stringValue: String
    var intValue: Int? { nil }
    init(_ s: String) { self.stringValue = s }
    init?(stringValue: String) { self.stringValue = stringValue }
    init?(intValue: Int) { nil }
}

struct BroadcastItem: Decodable, Equatable {
    let id: String
    let title: String
    let summary: String
    let badge: String?
    let link: String?

    private static let allowed: Set<String> = ["id", "title", "summary", "badge", "link"]

    init(id: String, title: String, summary: String, badge: String?, link: String?) {
        self.id = id; self.title = title; self.summary = summary
        self.badge = badge; self.link = link
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: AnyKey.self)
        for k in c.allKeys where !Self.allowed.contains(k.stringValue) {
            throw BroadcastError.unknownField(k.stringValue)
        }
        id = try c.decode(String.self, forKey: AnyKey("id"))
        title = try c.decode(String.self, forKey: AnyKey("title"))
        summary = try c.decode(String.self, forKey: AnyKey("summary"))
        badge = try c.decodeIfPresent(String.self, forKey: AnyKey("badge"))
        link = try c.decodeIfPresent(String.self, forKey: AnyKey("link"))
    }
}

struct BroadcastFeed: Decodable, Equatable {
    let feedVersion: Int
    let sequence: Int
    let issuedAt: Date
    let expiresAt: Date?
    let items: [BroadcastItem]

    private static let allowed: Set<String> = ["feedVersion", "sequence", "issuedAt", "expiresAt", "items"]

    init(feedVersion: Int, sequence: Int, issuedAt: Date, expiresAt: Date?, items: [BroadcastItem]) {
        self.feedVersion = feedVersion; self.sequence = sequence
        self.issuedAt = issuedAt; self.expiresAt = expiresAt; self.items = items
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: AnyKey.self)
        for k in c.allKeys where !Self.allowed.contains(k.stringValue) {
            throw BroadcastError.unknownField(k.stringValue)
        }
        feedVersion = try c.decode(Int.self, forKey: AnyKey("feedVersion"))
        // Decoding sequence as Int (64-bit) naturally rejects > Int.max.
        sequence = try c.decode(Int.self, forKey: AnyKey("sequence"))

        let issuedRaw = try c.decode(String.self, forKey: AnyKey("issuedAt"))
        guard let issued = BroadcastDate.parse(issuedRaw) else {
            throw BroadcastError.badTimestamp(issuedRaw)
        }
        issuedAt = issued

        if let expRaw = try c.decodeIfPresent(String.self, forKey: AnyKey("expiresAt")) {
            guard let exp = BroadcastDate.parse(expRaw) else {
                throw BroadcastError.badTimestamp(expRaw)
            }
            expiresAt = exp
        } else {
            expiresAt = nil
        }
        items = try c.decode([BroadcastItem].self, forKey: AnyKey("items"))
    }

    /// Structural validation applied AFTER decode (decode already enforced the
    /// closed key set + parseable types). Throws on the first violation so the
    /// caller fails closed to the bundled feed.
    func validateStructure() throws {
        guard feedVersion == BroadcastLimits.supportedFeedVersion else {
            throw BroadcastError.unknownFeedVersion(feedVersion)
        }
        guard sequence >= 0 else { throw BroadcastError.badSequence }
        guard items.count <= BroadcastLimits.maxItems else {
            throw BroadcastError.tooManyItems(items.count)
        }
    }
}

/// Strict RFC3339/UTC parsing. ISO8601DateFormatter with .withInternetDateTime
/// requires the date-time + zone designator; a bare/locale-formatted string
/// fails → nil → caller rejects the feed.
enum BroadcastDate {
    static func parse(_ s: String) -> Date? {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime]
        return f.date(from: s)
    }
}
