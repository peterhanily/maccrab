// V2NavigationHistory.swift
// Bounded back/forward navigation stack. Records each `goto`
// destination so the user can undo a cross-workspace pivot.

import Foundation

public struct V2NavigationHistory: Sendable {
    public private(set) var entries: [V2NavigationDestination] = []
    public private(set) var cursor: Int = -1
    public let cap: Int

    public init(cap: Int = 50) { self.cap = cap }

    public var canGoBack: Bool    { cursor > 0 }
    public var canGoForward: Bool { cursor >= 0 && cursor < entries.count - 1 }

    public mutating func push(_ destination: V2NavigationDestination) {
        // If we navigated back, drop forward entries before appending.
        if cursor < entries.count - 1 {
            entries.removeSubrange((cursor + 1)..<entries.count)
        }
        entries.append(destination)
        cursor = entries.count - 1
        // Bound by cap.
        if entries.count > cap {
            let drop = entries.count - cap
            entries.removeFirst(drop)
            cursor -= drop
        }
    }

    public mutating func back() -> V2NavigationDestination? {
        guard canGoBack else { return nil }
        cursor -= 1
        return entries[cursor]
    }

    public mutating func forward() -> V2NavigationDestination? {
        guard canGoForward else { return nil }
        cursor += 1
        return entries[cursor]
    }

    public var current: V2NavigationDestination? {
        guard cursor >= 0, cursor < entries.count else { return nil }
        return entries[cursor]
    }
}
