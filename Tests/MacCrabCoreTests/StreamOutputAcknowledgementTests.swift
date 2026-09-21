// StreamOutputAcknowledgementTests.swift
// v1.22.1: a bulk collector can accept the REQUEST and reject the DOCUMENTS.
//
// Elasticsearch answers a bulk submission with HTTP 200 and an `errors` flag
// plus per-item outcomes. StreamOutput discarded the body and counted any 2xx
// as delivery, so a collector rejecting every document still produced
// stats.sent += 1 and a healthy-looking Output.health(). It also classified the
// whole 4xx range as non-retryable, which made 429 -- the collector explicitly
// asking us to slow down -- a permanent failure that dropped the alert.
//
// External review finding F08, verified against the source before fixing.

import Foundation
import Testing
@testable import MacCrabCore

@Suite("StreamOutput: collector acknowledgement is not the HTTP status")
struct StreamOutputAcknowledgementTests {
    private func body(_ json: String) -> Data { Data(json.utf8) }

    @Test("A wholly successful bulk response reports no item failure")
    func acceptedBulkHasNoFailure() {
        let accepted = body("""
        {"took":7,"errors":false,"items":[
          {"index":{"_index":"maccrab","_id":"1","status":201}},
          {"index":{"_index":"maccrab","_id":"2","status":200}}
        ]}
        """)
        #expect(StreamOutput.bulkItemFailure(in: accepted) == nil)
    }

    @Test("A 200 carrying per-item errors surfaces the first reason")
    func rejectedItemIsDetected() {
        // The shape Elasticsearch actually returns: transport succeeded, the
        // document did not.
        let rejected = body("""
        {"took":3,"errors":true,"items":[
          {"index":{"_index":"maccrab","_id":"1","status":201}},
          {"index":{"_index":"maccrab","_id":"2","status":400,"error":{
             "type":"mapper_parsing_exception",
             "reason":"failed to parse field [severity] of type [long]"}}}
        ]}
        """)
        let reason = StreamOutput.bulkItemFailure(in: rejected)
        #expect(reason != nil, "a rejected document must not count as delivered")
        #expect(reason?.contains("mapper_parsing_exception") == true)
    }

    @Test("A non-2xx item status without an error object still counts as failure")
    func statusOnlyFailureIsDetected() {
        let rejected = body("""
        {"errors":true,"items":[{"create":{"_index":"maccrab","status":429}}]}
        """)
        #expect(StreamOutput.bulkItemFailure(in: rejected) == "status 429")
    }

    // The decoder runs only on a 2xx. A body it cannot understand must not be
    // turned into a delivery failure -- that would invert the defect and start
    // reporting healthy sinks as broken.
    @Test("An unparseable, empty, or oversized body is not reported as failure")
    func malformedBodyIsNotAFailure() {
        #expect(StreamOutput.bulkItemFailure(in: Data()) == nil)
        #expect(StreamOutput.bulkItemFailure(in: body("not json at all")) == nil)
        #expect(StreamOutput.bulkItemFailure(in: body("{}")) == nil)
        #expect(StreamOutput.bulkItemFailure(in: body(#"{"errors":true}"#)) == nil,
                "errors flag with no items array is not an item failure")
        #expect(StreamOutput.bulkItemFailure(in: body(#"{"errors":false,"items":[1,2]}"#)) == nil)
        // Bounded: a collector answering 200 with an enormous body must not let
        // a logging concern allocate without limit.
        let oversized = body("{\"errors\":true,\"items\":[") + Data(repeating: 0x20, count: 1_048_577)
        #expect(StreamOutput.bulkItemFailure(in: oversized) == nil)
    }

    // 429 and 408 are the collector asking for a retry, not refusing content.
    @Test("Throttling and request-timeout statuses stay retryable")
    func throttlingIsRetryable() throws {
        let source = try String(
            contentsOf: URL(fileURLWithPath: #filePath)
                .deletingLastPathComponent().deletingLastPathComponent()
                .deletingLastPathComponent()
                .appendingPathComponent("Sources/MacCrabCore/Output/StreamOutput.swift"),
            encoding: .utf8
        )
        let guardRange = try #require(
            source.range(of: "if (400...499).contains(http.statusCode)"),
            "the non-retryable classification moved"
        )
        let clause = String(source[guardRange.lowerBound...].prefix(160))
        #expect(clause.contains("429"), "429 must not be classified as permanent")
        #expect(clause.contains("408"), "408 must not be classified as permanent")
    }
}
