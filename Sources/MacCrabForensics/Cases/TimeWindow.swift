// Optional time window passed to Collector.collect() and read by
// some Analyzers. Inclusive at both ends. Open-ended bounds (nil
// `start` or `end`) are supported for "everything until now" and
// "everything since some point" semantics.
//
// Plan reference: §3.3 manifest InputType.timeWindow.

import Foundation

public struct TimeWindow: Codable, Sendable, Equatable {
    public let start: Date?
    public let end: Date?

    public init(start: Date? = nil, end: Date? = nil) {
        self.start = start
        self.end = end
    }

    /// `--window 24h`-style relative window: `end = now`,
    /// `start = now - duration`. The plan §3.7 CLI surface uses
    /// this form via `maccrabctl case new --window 24h`.
    public static func relative(_ duration: TimeInterval, now: Date = Date()) -> TimeWindow {
        TimeWindow(start: now.addingTimeInterval(-duration), end: now)
    }

    /// `--since YYYY-MM-DD`-style open-ended window: `start = date`,
    /// `end = nil` so "everything from then on" continues to apply
    /// as new events arrive.
    public static func since(_ date: Date) -> TimeWindow {
        TimeWindow(start: date, end: nil)
    }

    /// Both ends explicit. Plan-tagged "between" semantics.
    public static func between(_ start: Date, _ end: Date) -> TimeWindow {
        TimeWindow(start: start, end: end)
    }

    /// `true` iff the given timestamp falls inclusively within
    /// the window. Open-ended bounds always match on that side.
    public func contains(_ when: Date) -> Bool {
        if let s = start, when < s { return false }
        if let e = end, when > e { return false }
        return true
    }
}
