// OutputBatchRetentionTests.swift
// v1.22.1: the batching sinks (S3, SFTP) dropped a batch whenever its flush
// failed. They now retain it, bounded in bytes and records with oldest-drop
// accounting, and retry on the next flush behind the same exponential
// backoff StreamOutput uses between its in-request retries.

import Foundation
import Testing
@testable import MacCrabCore

@Suite("OutputBatchBuffer: bounded oldest-drop retention")
struct OutputBatchBufferTests {
    private func line(_ s: String) -> Data { Data((s + "\n").utf8) }

    @Test("Append, take and retain preserve record order")
    func retainPutsFailedBatchFirst() {
        var buffer = OutputBatchBuffer(maxRetainedBytes: 1 << 20, maxRetainedRecords: 100)
        #expect(buffer.isEmpty)
        buffer.append(line: line("a"))
        buffer.append(line: line("b"))
        let taken = buffer.take()
        #expect(taken.count == 2)
        #expect(buffer.isEmpty && buffer.count == 0)

        // Records that arrive while the failed batch is in flight...
        buffer.append(line: line("c"))
        // ...end up BEHIND the retained batch on retry.
        #expect(buffer.retain(payload: taken.payload, count: taken.count) == 0)
        #expect(buffer.count == 3)
        #expect(String(decoding: buffer.data, as: UTF8.self) == "a\nb\nc\n")
    }

    @Test("Retaining nothing is a no-op")
    func retainEmptyIsNoop() {
        var buffer = OutputBatchBuffer(maxRetainedBytes: 64, maxRetainedRecords: 2)
        #expect(buffer.retain(payload: Data(), count: 0) == 0)
        #expect(buffer.isEmpty)
    }

    @Test("The record cap evicts the oldest records and reports how many")
    func recordCapEvictsOldest() {
        var buffer = OutputBatchBuffer(maxRetainedBytes: 1 << 20, maxRetainedRecords: 2)
        #expect(buffer.append(line: line("1")) == 0)
        #expect(buffer.append(line: line("2")) == 0)
        #expect(buffer.append(line: line("3")) == 1)
        #expect(buffer.count == 2)
        #expect(String(decoding: buffer.data, as: UTF8.self) == "2\n3\n")

        let taken = buffer.take()
        buffer.append(line: line("4"))
        buffer.append(line: line("5"))
        #expect(buffer.retain(payload: taken.payload, count: taken.count) == 2)
        #expect(buffer.count == 2)
        #expect(String(decoding: buffer.data, as: UTF8.self) == "4\n5\n",
                "the retained (older) batch is what gets evicted")
    }

    @Test("The byte cap evicts whole records until the buffer fits")
    func byteCapEvictsWholeRecords() {
        // Each line is 4 bytes ("abc\n"); cap fits two.
        var buffer = OutputBatchBuffer(maxRetainedBytes: 9, maxRetainedRecords: 100)
        buffer.append(line: line("aaa"))
        buffer.append(line: line("bbb"))
        #expect(buffer.append(line: line("ccc")) == 1)
        #expect(buffer.count == 2)
        #expect(buffer.data.count == 8)
        #expect(String(decoding: buffer.data, as: UTF8.self) == "bbb\nccc\n")
    }

    @Test("A single oversized record cannot wedge the buffer")
    func oversizedSingleRecordIsDropped() {
        var buffer = OutputBatchBuffer(maxRetainedBytes: 4, maxRetainedRecords: 100)
        #expect(buffer.append(line: line("far too long")) == 1)
        #expect(buffer.isEmpty && buffer.count == 0)
        // An unterminated tail (no newline) is likewise dropped whole.
        #expect(buffer.retain(payload: Data("no newline here".utf8), count: 1) == 1)
        #expect(buffer.isEmpty)
    }
}

@Suite("OutputRetryBackoff: StreamOutput's exponential schedule, capped")
struct OutputRetryBackoffTests {
    @Test("Attempts are allowed until a failure, then gated by a doubling delay")
    func doublingDelay() {
        var backoff = OutputRetryBackoff()
        let t0 = Date(timeIntervalSince1970: 1_800_000_000)
        #expect(backoff.mayAttempt(now: t0))

        backoff.recordFailure(now: t0)
        #expect(!backoff.mayAttempt(now: t0))
        #expect(!backoff.mayAttempt(now: t0.addingTimeInterval(0.99)))
        #expect(backoff.mayAttempt(now: t0.addingTimeInterval(1.0)), "first delay is 0.5 * 2^1 = 1 s")

        backoff.recordFailure(now: t0)
        #expect(!backoff.mayAttempt(now: t0.addingTimeInterval(1.99)))
        #expect(backoff.mayAttempt(now: t0.addingTimeInterval(2.0)), "second delay is 2 s")

        backoff.recordFailure(now: t0)
        #expect(backoff.mayAttempt(now: t0.addingTimeInterval(4.0)), "third delay is 4 s")
        #expect(backoff.consecutiveFailures == 3)
    }

    @Test("The delay is capped at five minutes and reset by a success")
    func capAndReset() {
        var backoff = OutputRetryBackoff()
        let t0 = Date(timeIntervalSince1970: 1_800_000_000)
        for _ in 0..<20 { backoff.recordFailure(now: t0) }
        #expect(!backoff.mayAttempt(now: t0.addingTimeInterval(299)))
        #expect(backoff.mayAttempt(now: t0.addingTimeInterval(OutputRetryBackoff.maximumDelaySeconds)),
                "a recovered sink is never ignored for longer than one default flush tick")

        backoff.recordSuccess()
        #expect(backoff.consecutiveFailures == 0)
        #expect(backoff.mayAttempt(now: t0))
    }
}

@Suite("S3Output: a failed PUT is retained and retried behind the backoff")
struct S3OutputRetryTests {
    private func alert(_ id: String) -> Alert {
        Alert(
            id: id,
            timestamp: Date(timeIntervalSince1970: 1_712_500_000),
            ruleId: "rule.test", ruleTitle: "Test",
            severity: .high, eventId: UUID().uuidString,
            description: "test", mitreTactics: "TA0005", mitreTechniques: "T1562"
        )
    }

    // Loopback http:// passes the SSRF policy (MinIO testing path) and port 1
    // is never listening, so the PUT fails with a connection refusal.
    private func unreachableSink(maxRetainedRecords: Int = 10_000) -> S3Output {
        S3Output(
            bucket: "maccrab-test",
            region: "us-east-1",
            accessKey: "AKIATEST",
            secretKey: "not-a-real-secret",
            endpoint: URL(string: "http://127.0.0.1:1")!,
            maxRetainedRecords: maxRetainedRecords
        )
    }

    @Test("The batch survives a failed PUT and is only retried once the backoff has elapsed")
    func failedPutIsRetained() async {
        let out = unreachableSink()
        await out.send(alert: alert("a"), event: nil)
        await out.send(alert: alert("b"), event: nil)

        let t0 = Date(timeIntervalSince1970: 1_800_000_000)
        await out.flushBuffer(now: t0)
        var stats = await out.outputStats()
        #expect(stats.failed == 2)
        #expect(stats.sent == 0)
        #expect(stats.lastError != nil)
        #expect(await out.bufferedRecordCount == 2, "a failed batch is retained, not dropped")

        // Inside the 1 s backoff nothing is attempted, so the failure count
        // does not move even though the bucket is still unreachable.
        await out.flushBuffer(now: t0.addingTimeInterval(0.5))
        stats = await out.outputStats()
        #expect(stats.failed == 2)
        #expect(await out.bufferedRecordCount == 2)

        // Past the backoff the same batch is attempted again.
        await out.flushBuffer(now: t0.addingTimeInterval(2))
        stats = await out.outputStats()
        #expect(stats.failed == 4, "the retained batch was retried")
        #expect(await out.bufferedRecordCount == 2)
        #expect(stats.dropped == 0)
    }

    @Test("Records arriving while the bucket is down evict the oldest, never grow unbounded")
    func retentionIsBounded() async {
        let out = unreachableSink(maxRetainedRecords: 2)
        await out.send(alert: alert("a"), event: nil)
        await out.send(alert: alert("b"), event: nil)
        let t0 = Date(timeIntervalSince1970: 1_800_000_000)
        await out.flushBuffer(now: t0)
        #expect(await out.bufferedRecordCount == 2)

        await out.send(alert: alert("c"), event: nil)
        let stats = await out.outputStats()
        #expect(stats.dropped == 1)
        #expect(await out.bufferedRecordCount == 2)
    }
}
