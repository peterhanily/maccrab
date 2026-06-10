# MacCrab Accessibility (WCAG-AA) Checklist

*Created v1.18.1. This is the working checklist for the dashboard's
accessibility program — previously the only documentation was inline
comments scattered through V2Theme and component files. Check items
against a release candidate with VoiceOver + Accessibility Inspector;
model-level invariants are pinned in `Tests/MacCrabAppTests/`
(`V2SeverityShapeTests` pattern).*

## Contrast (WCAG 1.4.3 — AA, measured ratios live in code comments)

- [x] Severity accents adaptive light/dark, 5.0–6.3:1 (`V2Theme.swift:76-82`)
- [x] `tertiaryText` ≥4.5:1 (`V2Theme.swift:105-115`)
- [x] Primary buttons use `brandDim` 5.28:1, not `brand` 3.04:1
      (`V2ActionButton.swift`, `V2Theme.swift:122-125`)
- [ ] Re-verify all measured ratios on macOS 27's refreshed Liquid Glass at
      BOTH ends of the new system transparency slider (Phase 4 of the
      v1.18.1 plan).

## Don't rely on color alone (WCAG 1.4.1)

- [x] Severity dots are shape-encoded — octagon/triangle/diamond/circle
      (`V2StatusChip.swift:91-104`, pinned by `V2SeverityShapeTests`)
- [x] Severity icons that appear without text carry an
      `accessibilityLabel` (v1.18.1 sweep: `V2ForensicsFindingsView`)

## VoiceOver semantics

- [x] Table rows combine into single labelled buttons with `.isSelected`
      (`V2DataTable.swift`)
- [x] Command-palette rows: combined element + `.isSelected`; selection
      moves and result counts are announced via `NSAccessibility.post`
      (v1.18.1 — SwiftUI's Announcement API needs macOS 14; we ship 13)
- [x] Section headers carry `.isHeader` (palette sections, sidebar groups —
      v1.18.1)
- [x] Sidebar items: selected trait + label without literal "⌘N" glyphs
      (shortcut moved to `accessibilityHint`, v1.18.1)
- [x] Sidebar resize handle exposed as an adjustable element (v1.18.1 —
      was drag-only/invisible)
- [x] Charts: summary-only accessibility (one sentence with total / peak)
      instead of per-bar traversal (v1.18.1, all 3 chart views; summary
      builder is static + unit-pinned)
- [x] Decorative icons hidden (`accessibilityHidden(true)`) when adjacent
      text carries the meaning (v1.18.1 sweep: kit cards, Settings legend)

## Keyboard

- [x] Palette: full keyboard nav via hidden-button shortcuts (the
      macOS-13-compatible mechanism; `onKeyPress` needs 14)
- [x] Escape / ⌘K / ⌘⇧P open-close paths
- [ ] Sidebar resize has no pointer-free equivalent beyond the VO
      adjustable action — consider a View menu command if requested.

## Motion (WCAG 2.3.3)

- [x] All animations route through `V2Motion` tokens that degrade under
      Reduce Motion (v1.18.0 ffd4032 + v1.18.1 `paletteScroll`)

## Localization of a11y strings

- [x] NEW a11y strings use `String(localized:)` (v1.18.1 policy)
- [ ] Pre-v1.18.1 hardcoded-English a11y labels (command bar, parts of
      sidebar/alerts) — tracked refactor, fold into the localization
      completion effort.

## Verification routine per release

1. `swift test` — model-level pins (shapes, chart summaries, chip names).
2. VoiceOver pass: palette (selection announced, headers navigable),
   sidebar (groups + selection + resize), one chart per workspace,
   alerts triage flow end-to-end.
3. Accessibility Inspector audit on the dashboard window: no errors.
4. Reduce Motion on: workspace switches, palette, toasts stay functional.
