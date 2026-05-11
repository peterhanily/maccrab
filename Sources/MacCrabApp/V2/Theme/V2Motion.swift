// V2Motion.swift
// Motion + transition tokens. All animations route through these
// so respecting `accessibilityReduceMotion` is one switch.

import SwiftUI

public enum V2Motion {
    /// Standard spring for navigation + workspace transitions.
    public static func navigation(reduceMotion: Bool) -> Animation {
        reduceMotion ? .linear(duration: 0.001) : .easeInOut(duration: 0.18)
    }

    /// Snappier overlay reveal (palette, modal sheets).
    public static func overlay(reduceMotion: Bool) -> Animation {
        reduceMotion ? .linear(duration: 0.001) : .easeOut(duration: 0.14)
    }

    /// Toast slide-in / slide-out.
    public static func toast(reduceMotion: Bool) -> Animation {
        reduceMotion ? .linear(duration: 0.001) : .spring(response: 0.32, dampingFraction: 0.78)
    }

    /// Generic fade-only transition. Always safe for reduce-motion.
    public static let fade: AnyTransition = .opacity

    /// Slide-from-bottom for toasts; degrades to fade under reduce motion.
    public static func toastTransition(reduceMotion: Bool) -> AnyTransition {
        reduceMotion
            ? .opacity
            : .move(edge: .bottom).combined(with: .opacity)
    }

    /// Cross-fade for workspace switches — pure opacity, no slide.
    /// The earlier `.move(edge: .leading)` combo was too aggressive
    /// (whole page snapping in from one side felt jarring).
    public static func workspaceTransition(reduceMotion: Bool) -> AnyTransition {
        .opacity
    }
}
