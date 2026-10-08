// TraceListFormattingTests.swift
// MacCrabCLITests
//
// The `maccrabctl trace list` severity column. Both forms are pinned with an
// explicit `terminal:` flag, so the colored form is checked even when the
// test runner's stdout is not a terminal.

import Testing
import MacCrabCore
@testable import maccrabctl

@Suite("maccrabctl: trace list severity column")
struct TraceListFormattingTests {

    @Test("the whole label is shown, its color is reset on a terminal, and piped output is unchanged")
    func severityCell() {
        let labels: [(Severity, String)] = [
            (.critical, "[CRITICAL]"),
            (.high, "[HIGH]    "),
            (.medium, "[MEDIUM]  "),
            (.low, "[LOW]     "),
            (.informational, "[INFO]    "),
        ]
        #expect(labels.count == Severity.allCases.count)
        for (severity, label) in labels {
            // Piped or redirected: the same ten-column text as before.
            #expect(MacCrabCtl.traceListSeverityCell(severity.rawValue, terminal: false) == label)
            // Terminal: a color code, the whole label, then the reset.
            let cell = MacCrabCtl.traceListSeverityCell(severity.rawValue, terminal: true)
            #expect(cell.hasPrefix("\u{1B}["))
            #expect(cell.hasSuffix(label + "\u{1B}[0m"))
        }
        #expect(MacCrabCtl.traceListSeverityCell("MEDIUM", terminal: true) == "\u{1B}[93m[MEDIUM]  \u{1B}[0m")
        // A value that is not a known severity keeps the plain ten-column pad.
        #expect(MacCrabCtl.traceListSeverityCell("unrated", terminal: true) == "unrated   ")
        #expect(MacCrabCtl.traceListSeverityCell("unclassified", terminal: false) == "unclassifi")
    }
}
