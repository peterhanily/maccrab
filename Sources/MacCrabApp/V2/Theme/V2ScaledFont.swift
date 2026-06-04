// V2ScaledFont.swift
// RC H3 (Dynamic Type): `.font(.system(size:))` is a fixed-point font that does
// NOT respond to Dynamic Type, so low-vision users get no scaling. SwiftUI has
// no `relativeTo:` overload for `.system(size:)`, so this provides a
// size-PRESERVING scalable drop-in: at the default type size the @ScaledMetric
// returns the base size (rendering is identical to the old fixed font), and at
// larger accessibility sizes the font scales relative to `.body`.
//
// Migration: `.font(.system(size: N, weight: W, design: D))`
//         -> `.scaledSystem(N, weight: W, design: D)`.

import SwiftUI

private struct ScaledSystemFont: ViewModifier {
    @ScaledMetric private var size: CGFloat
    private let weight: Font.Weight
    private let design: Font.Design

    init(size: CGFloat, weight: Font.Weight, design: Font.Design) {
        self._size = ScaledMetric(wrappedValue: size, relativeTo: .body)
        self.weight = weight
        self.design = design
    }

    func body(content: Content) -> some View {
        // NOTE: must use the real fixed-size system font here — the metric has
        // already applied Dynamic Type scaling to `size`. Calling .scaledSystem
        // would recurse forever.
        content.font(Font.system(size: size, weight: weight, design: design))
    }
}

extension View {
    /// Scalable, size-preserving replacement for
    /// `.font(.system(size:weight:design:))`. See the file header.
    func scaledSystem(
        _ size: CGFloat,
        weight: Font.Weight = .regular,
        design: Font.Design = .default
    ) -> some View {
        modifier(ScaledSystemFont(size: size, weight: weight, design: design))
    }
}
