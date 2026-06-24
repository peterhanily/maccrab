// JSONValueFoundationTests.swift
//
// FIQ-1: JSONValue.foundationValue is the privacy-load-bearing primitive
// that surfaces an artifact's entire `data` payload to MCP agents. Pin the
// faithful all-7-case mapping + nesting so a regression can't silently
// drop or mistype fields leaving the server.

import Testing
import Foundation
@testable import MacCrabForensics

@Suite("JSONValue.foundationValue")
struct JSONValueFoundationTests {

    @Test("each scalar case projects to the right Foundation type")
    func scalars() {
        #expect(JSONValue.string("hi").foundationValue as? String == "hi")
        #expect(JSONValue.integer(5).foundationValue as? Int == 5)
        #expect(JSONValue.double(2.5).foundationValue as? Double == 2.5)
        #expect(JSONValue.bool(true).foundationValue as? Bool == true)
        #expect(JSONValue.null.foundationValue is NSNull)
    }

    @Test("arrays and nested objects round-trip recursively")
    func nested() {
        let v = JSONValue.object([
            "severity": .string("critical"),
            "risk_score": .integer(55),
            "risk_reason": .array([.string("fda"), .string("unknown_team")]),
            "backed_by": .array([.object(["content_type": .string("tcc.grant"), "artifact_id": .integer(9)])]),
        ])
        let dict = v.foundationValue as? [String: Any]
        #expect(dict?["severity"] as? String == "critical")
        #expect(dict?["risk_score"] as? Int == 55)
        #expect((dict?["risk_reason"] as? [Any])?.count == 2)
        let backed = (dict?["backed_by"] as? [Any])?.first as? [String: Any]
        #expect(backed?["content_type"] as? String == "tcc.grant")
        #expect(backed?["artifact_id"] as? Int == 9)
    }

    @Test("the projection is JSONSerialization-safe (the contract MCP relies on)")
    func serializable() throws {
        let v = JSONValue.object([
            "a": .array([.integer(1), .null, .bool(false)]),
            "b": .double(1.25),
        ])
        let any = v.foundationValue
        #expect(JSONSerialization.isValidJSONObject(any))
        let data = try JSONSerialization.data(withJSONObject: any)
        #expect(!data.isEmpty)
    }
}
