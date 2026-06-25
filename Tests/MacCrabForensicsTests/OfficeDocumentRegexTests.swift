// OfficeDocumentRegexTests.swift
// MacCrabForensicsTests
//
// Regression guard for the OOXML core-properties metadata extractor. The old
// xmlValue regex required the opening tag to be '>'-terminated right after the
// name, so it never matched the attribute form OOXML ALWAYS writes for
// timestamps: <dcterms:created xsi:type="dcterms:W3CDTF">…</dcterms:created>.
// created_iso/modified_iso were therefore always empty on real .docx/.xlsx/.pptx.

import Testing
@testable import MacCrabForensics

@Suite("OfficeDocument metadata regex")
struct OfficeDocumentRegexTests {
    private let core = """
    <?xml version="1.0" encoding="UTF-8" standalone="yes"?>
    <cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
    <dc:creator>Alice Example</dc:creator>
    <cp:lastModifiedBy>Bob Editor</cp:lastModifiedBy>
    <dcterms:created xsi:type="dcterms:W3CDTF">2026-01-15T10:00:00Z</dcterms:created>
    <dcterms:modified xsi:type="dcterms:W3CDTF">2026-02-20T12:30:00Z</dcterms:modified>
    <dc:title>Quarterly Report</dc:title>
    </cp:coreProperties>
    """

    @Test("extracts attributed dcterms:created / dcterms:modified (xsi:type form)")
    func attributedTimestamps() {
        #expect(OfficeDocumentPlugin.xmlValue(from: core, tagSuffix: "created") == "2026-01-15T10:00:00Z")
        #expect(OfficeDocumentPlugin.xmlValue(from: core, tagSuffix: "modified") == "2026-02-20T12:30:00Z")
    }

    @Test("still extracts attribute-less namespaced tags")
    func plainNamespacedTags() {
        #expect(OfficeDocumentPlugin.xmlValue(from: core, tagSuffix: "creator") == "Alice Example")
        #expect(OfficeDocumentPlugin.xmlValue(from: core, tagSuffix: "lastModifiedBy") == "Bob Editor")
        #expect(OfficeDocumentPlugin.xmlValue(from: core, tagSuffix: "title") == "Quarterly Report")
    }

    @Test("absent tag returns empty, not a false match")
    func absentTag() {
        #expect(OfficeDocumentPlugin.xmlValue(from: core, tagSuffix: "category") == "")
    }
}
