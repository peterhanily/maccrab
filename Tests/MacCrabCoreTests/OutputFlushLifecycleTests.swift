// OutputFlushLifecycleTests.swift
// v1.22.1: `SFTPOutput.flush()` / `S3Output.flush()` had no caller outside
// their own files, so the batching sinks buffered alerts that never left
// memory. The daemon now arms an output-flush timer (only when an additional
// output is configured) and drains the sinks once more on graceful stop.
//
// Timer arming is verified the way the other DaemonTimers checks are: against
// the source, because DaemonTimers.start() needs a full DaemonState.

import Foundation
import Testing
import MacCrabCore
@testable import MacCrabAgentKit

@Suite("Output flush lifecycle: timer cadence, arming and shutdown drain")
struct OutputFlushLifecycleTests {

    private func source(_ relativePath: String) throws -> String {
        let root = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        return try String(
            contentsOf: root.appendingPathComponent(relativePath),
            encoding: .utf8
        )
    }

    @Test("The flush cadence is the tightest configured interval, clamped, defaulting to five minutes")
    func cadenceDerivation() {
        #expect(DaemonTimers.outputFlushIntervalSeconds(configured: []) == 300)
        #expect(DaemonTimers.outputFlushIntervalSeconds(configured: [600, 120]) == 120)
        #expect(DaemonTimers.outputFlushIntervalSeconds(configured: [5]) == 30,
                "a one-digit interval must not spawn sftp every few seconds")
        #expect(DaemonTimers.outputFlushIntervalSeconds(configured: [99_999]) == 3_600,
                "alerts must not sit in memory for a day")
        #expect(DaemonTimers.outputFlushIntervalSeconds(configured: [-1, 0, .nan, .infinity]) == 300,
                "nonsense values fall back to the default rather than poisoning min()")
    }

    @Test("The output-flush timer is armed only when an additional output exists, and is retained")
    func timerIsArmedAndRetained() throws {
        let timers = try source("Sources/MacCrabAgentKit/DaemonTimers.swift")
        #expect(timers.contains("let outputFlushTimer: DispatchSourceTimer?"),
                "the timer must be a Handles member so it is not ARC-deallocated on return from start()")

        let arming = try #require(timers.range(of: "let outputFlushTimer: DispatchSourceTimer?\n        if state.additionalOutputs.isEmpty {"))
        let retained = try #require(timers.range(
            of: "let retainedTimers: [DispatchSourceTimer?] = [",
            range: arming.upperBound..<timers.endIndex
        ))
        let block = String(timers[arming.lowerBound..<retained.lowerBound])
        #expect(block.contains("outputFlushTimer = nil"),
                "no sink configured means no timer: unchanged behaviour for the default install")
        #expect(block.contains("state.additionalOutputFlushIntervalSeconds"))
        #expect(block.contains("t.schedule(deadline: .now() + interval, repeating: interval)"))
        #expect(block.contains("timerLifecycle.submit(label: \"output-flush\")"),
                "label coalescing prevents a second flush stacking behind a slow sftp")
        #expect(block.contains("await sink.flush()"))
        #expect(block.contains("t.resume()"))

        let retainedList = String(timers[retained.lowerBound..<timers.endIndex])
        #expect(retainedList.contains("            outputFlushTimer,\n        ]"),
                "the timer must be registered with the lifecycle so shutdown cancels it")
        #expect(retainedList.contains("outputFlushTimer: outputFlushTimer"))
    }

    @Test("Graceful shutdown drains the sinks after the output lane is joined and before persistence")
    func shutdownDrainsSinks() throws {
        let lifecycle = try source("Sources/MacCrabAgentKit/DaemonLifecycle.swift")
        let joined = try #require(lifecycle.range(of: "let workResults = await (detection, advisory, outputs)"))
        let ueba = try #require(lifecycle.range(
            of: "if let ueba = state.uebaEngine",
            range: joined.upperBound..<lifecycle.endIndex
        ))
        let drain = String(lifecycle[joined.upperBound..<ueba.lowerBound])
        #expect(drain.contains("if !state.additionalOutputs.isEmpty"),
                "no sink configured means no shutdown work")
        #expect(drain.contains("await sink.flush()"))
        #expect(drain.contains("deadline.remaining(maximum: 0.5)"),
                "the drain consumes a bounded slice of the one monotonic shutdown deadline")
        #expect(drain.contains("withTaskGroup"),
                "one stuck sink must not starve the others of their slice")
        #expect(!drain.contains("DaemonShutdownResult("),
                "an advisory sink flush is not part of the mutation boundary")
    }

    @Test("Setup derives the cadence from the configured specs and hands it to the state")
    func setupWiresCadence() throws {
        let setup = try source("Sources/MacCrabAgentKit/DaemonSetup.swift")
        #expect(setup.contains("DaemonTimers.outputFlushIntervalSeconds("))
        #expect(setup.contains("config.outputs.compactMap { $0.flushIntervalSeconds }"))
        #expect(setup.contains("additionalOutputFlushIntervalSeconds: additionalOutputFlushIntervalSeconds"))
    }
}
