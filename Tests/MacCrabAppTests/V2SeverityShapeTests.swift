// V2SeverityShapeTests.swift
// RC H3 (a11y): the severity dot must encode severity by SHAPE, not color
// alone, so color-blind users can distinguish tiers. Pin that the four
// severity tiers map to four DISTINCT SF Symbol shapes.

import Testing
@testable import MacCrabApp

@Suite("V2 severity shape encoding (a11y)")
struct V2SeverityShapeTests {

    @Test("critical/high/medium/low map to four distinct shapes")
    func severityShapesAreDistinct() {
        let symbols = [
            V2ChipKind.critical.shapeSymbol,
            V2ChipKind.high.shapeSymbol,
            V2ChipKind.medium.shapeSymbol,
            V2ChipKind.low.shapeSymbol,
        ]
        #expect(Set(symbols).count == 4, "severity tiers must be shape-distinct, got \(symbols)")
    }

    @Test("every chip kind resolves to a non-empty SF Symbol")
    func allKindsHaveSymbol() {
        let kinds: [V2ChipKind] = [.critical, .high, .medium, .low, .healthy,
                                   .warning, .degraded, .down, .info, .neutral, .ai, .data]
        for k in kinds {
            #expect(!k.shapeSymbol.isEmpty)
            #expect(!k.accessibilityName.isEmpty)
        }
    }
}
