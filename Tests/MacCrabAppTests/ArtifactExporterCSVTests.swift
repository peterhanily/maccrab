// ArtifactExporterCSVTests.swift
// MacCrabAppTests
//
// Guards the evidence-export CSV escaper against spreadsheet formula
// injection. Artifact values (filenames, hosts entries, process args)
// are harvested from a potentially-compromised host; a cell beginning
// with = + - @ becomes a live formula when the analyst opens the
// evidence CSV in Excel/Numbers. csvEscape must neutralize these while
// preserving normal RFC-4180 quoting.

import Testing
import Foundation
@testable import MacCrabApp

@Suite("ArtifactExporter CSV escaping")
struct ArtifactExporterCSVTests {

    @Test("Neutralizes the four formula-lead characters")
    func neutralizesFormulaLeads() {
        // Each dangerous lead gets a single-quote prefix so the sheet reads text.
        #expect(ArtifactExporter.csvEscape("=cmd|'/C calc'!A0").hasPrefix("'="))
        #expect(ArtifactExporter.csvEscape("+SUM(1+1)").hasPrefix("'+"))
        #expect(ArtifactExporter.csvEscape("-2+3+cmd").hasPrefix("'-"))
        #expect(ArtifactExporter.csvEscape("@SUM(A1)").hasPrefix("'@"))
    }

    @Test("Neutralizes leading tab / carriage-return formula smuggling")
    func neutralizesWhitespaceLeads() {
        // Excel strips a leading tab/CR then evaluates the formula char behind it.
        #expect(ArtifactExporter.csvEscape("\t=cmd").hasPrefix("'"))
        #expect(ArtifactExporter.csvEscape("\r=cmd").hasPrefix("'"))
    }

    @Test("Leaves ordinary values untouched")
    func leavesNormalValuesAlone() {
        #expect(ArtifactExporter.csvEscape("normal value") == "normal value")
        #expect(ArtifactExporter.csvEscape("/usr/bin/curl") == "/usr/bin/curl")
        #expect(ArtifactExporter.csvEscape("") == "")
        // A value that merely CONTAINS = is fine — only a leading = is a formula.
        #expect(ArtifactExporter.csvEscape("a=b") == "a=b")
    }

    @Test("Still applies RFC-4180 quoting for comma / quote / newline")
    func rfc4180Quoting() {
        #expect(ArtifactExporter.csvEscape("has,comma") == "\"has,comma\"")
        #expect(ArtifactExporter.csvEscape("she said \"hi\"") == "\"she said \"\"hi\"\"\"")
        #expect(ArtifactExporter.csvEscape("line1\nline2") == "\"line1\nline2\"")
    }

    @Test("Formula lead AND a comma: prefixed then quoted")
    func formulaAndQuoting() {
        // The worst case — both neutralized and quoted.
        let out = ArtifactExporter.csvEscape("=evil,with,comma")
        #expect(out == "\"'=evil,with,comma\"")
        #expect(out.hasPrefix("\"'="))
    }
}
