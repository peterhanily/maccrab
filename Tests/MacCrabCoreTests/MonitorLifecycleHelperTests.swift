import Testing

/// Test-only closures and an actor log: no native collectors, listeners,
/// filesystem, preferences, processes, or time-based synchronization.
@Suite("Native lifecycle test-helper truthfulness")
struct MonitorLifecycleHelperTests {
    private enum Failure: Error, Equatable {
        case start
        case body
    }

    private actor Calls {
        private var entries: [String] = []
        func append(_ entry: String) { entries.append(entry) }
        func snapshot() -> [String] { entries }
    }

    @Test("successful body is followed by exactly one joined cleanup")
    func successJoinsOnce() async throws {
        let calls = Calls()
        try await withStartedMonitor(start: {
            await calls.append("start")
        }, stop: {
            await calls.append("stop")
            return true
        }) {
            await calls.append("body")
        }
        #expect(await calls.snapshot() == ["start", "body", "stop"])
    }

    @Test("body failure propagates only after exactly one cleanup")
    func bodyFailureStillJoins() async {
        let calls = Calls()
        await #expect(throws: Failure.body) {
            try await withStartedMonitor(start: {
                await calls.append("start")
            }, stop: {
                await calls.append("stop")
                return true
            }) {
                await calls.append("body")
                throw Failure.body
            }
        }
        #expect(await calls.snapshot() == ["start", "body", "stop"])
    }

    @Test("first-start failure cleans up and cannot enter the success body")
    func startupFailureIsNotSuccess() async {
        let calls = Calls()
        await #expect(throws: Failure.start) {
            try await withStartedMonitor(start: {
                await calls.append("start")
                throw Failure.start
            }, stop: {
                await calls.append("stop")
                return true
            }) {
                await calls.append("must-not-enter")
            }
        }
        #expect(await calls.snapshot() == ["start", "stop"])
    }

    @Test("cancellation thrown by the body still joins before propagating")
    func bodyCancellationStillJoins() async {
        let calls = Calls()
        await #expect(throws: CancellationError.self) {
            try await withStartedMonitor(start: {
                await calls.append("start")
            }, stop: {
                await calls.append("stop")
                return true
            }) {
                await calls.append("body")
                throw CancellationError()
            }
        }
        #expect(await calls.snapshot() == ["start", "body", "stop"])
    }

    @Test("false cleanup is a recorded test failure, never a passing lifecycle")
    func incompleteCleanupRecordsFailure() async throws {
        let calls = Calls()
        // A missing issue fails this test; only the exact cleanup expectation
        // is accepted as known. No real native failure is waived here.
        try await withKnownIssue("synthetic cleanup refusal must be visible") {
            try await withStartedMonitor(start: {
                await calls.append("start")
            }, stop: {
                await calls.append("stop")
                return false
            }) {
                await calls.append("body")
            }
        } matching: { issue in
            guard case .expectationFailed = issue.kind else { return false }
            return issue.comments.contains {
                $0.rawValue == "monitor cleanup did not complete within its deadline"
            }
        }
        #expect(await calls.snapshot() == ["start", "body", "stop"])
    }

    @Test("failed cleanup does not erase the original first-start error")
    func startupAndCleanupFailuresBothRemainVisible() async {
        let calls = Calls()
        await withKnownIssue("synthetic cleanup refusal accompanies startup failure") {
            await #expect(throws: Failure.start) {
                try await withStartedMonitor(start: {
                    await calls.append("start")
                    throw Failure.start
                }, stop: {
                    await calls.append("stop")
                    return false
                }) {
                    await calls.append("must-not-enter")
                }
            }
        } matching: { issue in
            guard case .expectationFailed = issue.kind else { return false }
            return issue.comments.contains {
                $0.rawValue == "monitor cleanup did not complete within its deadline"
            }
        }
        #expect(await calls.snapshot() == ["start", "stop"])
    }
}
