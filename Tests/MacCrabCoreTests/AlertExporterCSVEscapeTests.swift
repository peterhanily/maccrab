// AlertExporterCSVEscapeTests.swift
// MacCrabCoreTests
//
// Same spreadsheet-formula-injection guard as the forensic ArtifactExporter,
// but for the CLI alert exporter (maccrabctl export --format csv). Alert
// fields carry attacker-influenceable process command lines and file paths.

import Testing
import Foundation
@testable import MacCrabCore

@Suite("AlertExporter CSV escaping")
struct AlertExporterCSVEscapeTests {

    @Test("Neutralizes formula-lead characters")
    func neutralizesFormulaLeads() {
        let e = AlertExporter()
        #expect(e.csvEscape("=cmd|'/C calc'!A0").hasPrefix("'="))
        #expect(e.csvEscape("+SUM(1+1)").hasPrefix("'+"))
        #expect(e.csvEscape("-2+3+cmd").hasPrefix("'-"))
        #expect(e.csvEscape("@SUM(A1)").hasPrefix("'@"))
        #expect(e.csvEscape("\t=cmd").hasPrefix("'"))
    }

    @Test("Leaves ordinary values untouched")
    func leavesNormalValuesAlone() {
        let e = AlertExporter()
        #expect(e.csvEscape("normal value") == "normal value")
        #expect(e.csvEscape("a=b") == "a=b")
        #expect(e.csvEscape("") == "")
    }

    @Test("Still applies RFC-4180 quoting and combines with neutralization")
    func rfc4180AndCombined() {
        let e = AlertExporter()
        #expect(e.csvEscape("has,comma") == "\"has,comma\"")
        #expect(e.csvEscape("=evil,with,comma") == "\"'=evil,with,comma\"")
    }
}
