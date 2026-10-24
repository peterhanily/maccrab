import Darwin
import Foundation
import Testing
@testable import MacCrabCore

/// Security.framework opens the files inside a bundle itself, and a FIFO at
/// any of them holds the evaluating thread until a writer appears. No engine
/// caller may wait on that: it gets an answer by its deadline, the run is
/// interrupted, a run that stays blocked is counted, and a site with too many
/// starts no more.
@Suite("Security.framework evaluations wait a bounded time", .serialized)
struct BoundedSecurityEvaluationTests {
    private final class Flag: @unchecked Sendable {
        private let lock = NSLock()
        private var raised = false
        func raise() { lock.lock(); raised = true; lock.unlock() }
        var isRaised: Bool { lock.lock(); defer { lock.unlock() }; return raised }
    }

    private final class Counter: @unchecked Sendable {
        private let lock = NSLock()
        private var count = 0
        func increment() { lock.lock(); count += 1; lock.unlock() }
        var value: Int { lock.lock(); defer { lock.unlock() }; return count }
    }

    private static func plist(executable: String) throws -> Data {
        try PropertyListSerialization.data(fromPropertyList: [
            "CFBundleExecutable": executable,
            "CFBundleIdentifier": "com.example.fifo",
            "CFBundlePackageType": "APPL",
        ], format: .xml, options: 0)
    }

    /// A bundle whose main executable `name` is a FIFO.
    private static func bundleWithFIFOExecutable(in directory: String, name: String) throws -> (bundle: String, fifo: String) {
        let bundle = directory + "/\(name).app"
        try FileManager.default.createDirectory(atPath: bundle + "/Contents/MacOS", withIntermediateDirectories: true)
        try plist(executable: name).write(to: URL(fileURLWithPath: bundle + "/Contents/Info.plist"))
        let fifo = bundle + "/Contents/MacOS/" + name
        try #require(mkfifo(fifo, 0o600) == 0)
        return (bundle, fifo)
    }

    /// A bundle whose main executable `executable` is a real Mach-O, a
    /// regular file that passes any precheck, and whose CodeResources is a FIFO.
    private static func bundleWithFIFOSeal(in directory: String, name: String, executable: String) throws
        -> (bundle: String, executable: String, fifo: String)
    {
        let bundle = directory + "/\(name).app"
        try FileManager.default.createDirectory(atPath: bundle + "/Contents/MacOS", withIntermediateDirectories: true)
        try FileManager.default.createDirectory(atPath: bundle + "/Contents/_CodeSignature", withIntermediateDirectories: true)
        try plist(executable: executable).write(to: URL(fileURLWithPath: bundle + "/Contents/Info.plist"))
        let binary = bundle + "/Contents/MacOS/" + executable
        try FileManager.default.copyItem(atPath: "/bin/ls", toPath: binary)
        let fifo = bundle + "/Contents/_CodeSignature/CodeResources"
        try #require(mkfifo(fifo, 0o600) == 0)
        return (bundle, binary, fifo)
    }

    /// A bundle ad-hoc signed with `codesign --deep`, whose nested
    /// framework's executable is then replaced by a FIFO. Security.framework
    /// validates nested code on its own GCD workers unless told to stay on
    /// the calling thread. Nil when codesign is unavailable.
    private static func bundleWithNestedFIFO(in directory: String, name: String) throws -> (bundle: String, fifo: String)? {
        let codesign = "/usr/bin/codesign"
        guard FileManager.default.isExecutableFile(atPath: codesign) else { return nil }
        let bundle = directory + "/\(name).app"
        let framework = bundle + "/Contents/Frameworks/Nested.framework"
        let fm = FileManager.default
        try fm.createDirectory(atPath: bundle + "/Contents/MacOS", withIntermediateDirectories: true)
        try fm.createDirectory(atPath: framework + "/Versions/A/Resources", withIntermediateDirectories: true)
        try plist(executable: name).write(to: URL(fileURLWithPath: bundle + "/Contents/Info.plist"))
        try fm.copyItem(atPath: "/bin/ls", toPath: bundle + "/Contents/MacOS/" + name)
        try PropertyListSerialization.data(fromPropertyList: [
            "CFBundleExecutable": "Nested",
            "CFBundleIdentifier": "com.example.nested",
            "CFBundlePackageType": "FMWK",
        ], format: .xml, options: 0).write(to: URL(fileURLWithPath: framework + "/Versions/A/Resources/Info.plist"))
        try fm.copyItem(atPath: "/bin/ls", toPath: framework + "/Versions/A/Nested")
        try fm.createSymbolicLink(atPath: framework + "/Versions/Current", withDestinationPath: "A")
        try fm.createSymbolicLink(atPath: framework + "/Nested", withDestinationPath: "Versions/Current/Nested")
        try fm.createSymbolicLink(atPath: framework + "/Resources", withDestinationPath: "Versions/Current/Resources")
        let sign = Process()
        sign.executableURL = URL(fileURLWithPath: codesign)
        sign.arguments = ["--force", "--deep", "-s", "-", bundle]
        sign.standardOutput = FileHandle.nullDevice
        sign.standardError = FileHandle.nullDevice
        try sign.run()
        sign.waitUntilExit()
        guard sign.terminationStatus == 0 else { return nil }
        let fifo = framework + "/Versions/A/Nested"
        try fm.removeItem(atPath: fifo)
        try #require(mkfifo(fifo, 0o600) == 0)
        return (bundle, fifo)
    }

    private static func directory() throws -> String {
        let path = NSTemporaryDirectory() + "bounded-security-\(UUID().uuidString)"
        try FileManager.default.createDirectory(atPath: path, withIntermediateDirectories: true)
        return path
    }

    /// Opens each FIFO's write end until `done`, so an evaluation blocked in
    /// Security.framework's open finishes and no thread outlives the test.
    private static func release(_ fifos: [String], until done: () -> Bool) async -> Bool {
        let deadline = Date().addingTimeInterval(30)
        while !done() && Date() < deadline {
            for fifo in fifos {
                let writer = open(fifo, O_WRONLY | O_NONBLOCK)
                if writer >= 0 { close(writer) }
            }
            try? await Task.sleep(nanoseconds: 20_000_000)
        }
        return done()
    }

    /// Polls `condition` for up to `seconds` without touching any FIFO.
    private static func eventually(within seconds: Double, _ condition: () -> Bool) async -> Bool {
        let deadline = Date().addingTimeInterval(seconds)
        while !condition() && Date() < deadline {
            try? await Task.sleep(nanoseconds: 20_000_000)
        }
        return condition()
    }

    private static func elapsed(since start: Date) -> TimeInterval { Date().timeIntervalSince(start) }

    /// Runs `body` and reports whether it finished within `seconds`. If it is
    /// stuck in Security.framework's open of a FIFO (the defect), the FIFOs
    /// are released so the test fails instead of hanging.
    private static func promptly<T: Sendable>(
        releasing fifos: [String],
        within seconds: Double = 5,
        _ body: @escaping @Sendable () async -> T
    ) async -> (value: T?, prompt: Bool) {
        let finished = Flag()
        let work = Task { () -> T in
            let value = await body()
            finished.raise()
            return value
        }
        let deadline = Date().addingTimeInterval(seconds)
        while !finished.isRaised && Date() < deadline {
            try? await Task.sleep(nanoseconds: 10_000_000)
        }
        let prompt = finished.isRaised
        _ = await release(fifos) { finished.isRaised }
        return (finished.isRaised ? await work.value : nil, prompt)
    }

    private static func started(_ runner: BoundedSecurityEvaluation) -> Int {
        runner.diagnostics()["started_total"] as? Int ?? -1
    }

    @Test("work past its deadline is stuck, not restarted for its key, and capped per site until it returns")
    func runnerBoundsStrandedWork() async throws {
        let runner = BoundedSecurityEvaluation(stuckLimit: 2, interruptsStranded: false)
        let gate = DispatchSemaphore(value: 0)
        let began = DispatchSemaphore(value: 0)
        let started = Counter()
        var released = false
        defer { if !released { gate.signal(); gate.signal() } }
        // Without a deadline the first call would wait for the gate: open it
        // eventually, so that fails the timing checks instead of hanging.
        DispatchQueue.global().asyncAfter(deadline: .now() + 10) { gate.signal(); gate.signal() }

        var start = Date()
        let first = await runner.run(.downloads, key: "a", deadline: 0.2) { _ -> Int in
            started.increment(); began.signal(); gate.wait(); return 1
        }
        #expect(first.value == nil)
        if case .timedOut = first {} else { Issue.record("expected a timeout, got \(first)") }
        #expect(Self.elapsed(since: start) < 5, "the caller waited on the blocked work")
        #expect(runner.stuckCount(.downloads) == 1)
        #expect(began.wait(timeout: .now() + 5) == .success, "the first body never started")

        // The same key is not started again while its work is stuck.
        let again = await runner.run(.downloads, key: "a", deadline: 5) { _ -> Int in started.increment(); return 2 }
        if case .blocked = again {} else { Issue.record("expected the stuck key to be refused, got \(again)") }
        #expect(started.value == 1)
        // Another site is unaffected, and finished work comes back.
        #expect(await runner.run(.libraryInventory, key: "a", deadline: 5) { _ in 3 }.value == 3)

        _ = await runner.run(.downloads, key: "b", deadline: 0.2) { _ -> Int in
            started.increment(); began.signal(); gate.wait(); return 4
        }
        #expect(runner.stuckCount(.downloads) == 2)
        #expect(began.wait(timeout: .now() + 5) == .success, "the second body never started")
        // At the limit nothing starts, and the answer is immediate.
        start = Date()
        let limited = await runner.run(.downloads, key: "c", deadline: 5) { _ -> Int in started.increment(); return 5 }
        if case .refused = limited {} else { Issue.record("expected the site limit to refuse, got \(limited)") }
        #expect(Self.elapsed(since: start) < 1)
        #expect(started.value == 2)

        gate.signal(); gate.signal()
        released = true
        #expect(await Self.eventually(within: 10) { runner.stuckCount(.downloads) == 0 }, "returned work still counts as stuck")
        #expect(await runner.run(.downloads, key: "c", deadline: 5) { _ in 6 }.value == 6)
    }

    @Test("callers for a key whose run is in time share that run")
    func callersJoinTheRunInFlight() async throws {
        let runner = BoundedSecurityEvaluation(stuckLimit: 2)
        let gate = DispatchSemaphore(value: 0)
        let began = DispatchSemaphore(value: 0)
        let calls = Counter()
        defer { gate.signal(); gate.signal() }
        let body: @Sendable (BoundedSecurityEvaluation.Attempt) -> Int = { _ in
            calls.increment(); began.signal(); _ = gate.wait(timeout: .now() + 10); return 7
        }
        let first = Task { await runner.run(.codeSigning, key: "k", deadline: 10, body).value }
        #expect(began.wait(timeout: .now() + 5) == .success)
        let second = Task { await runner.run(.codeSigning, key: "k", deadline: 10, body).value }
        // Open the gate only once the second caller has joined the run.
        #expect(await Self.eventually(within: 5) { runner.waiterCount(.codeSigning, key: "k") == 2 })
        gate.signal()
        #expect(await first.value == 7)
        #expect(await second.value == 7)
        #expect(calls.value == 1, "a second caller started a second run of the same key")
        #expect(Self.started(runner) == 1)
    }

    @Test("a cancelled caller returns at once, and its run goes on")
    func cancelledCallerReturnsAtOnce() async throws {
        let runner = BoundedSecurityEvaluation(stuckLimit: 2)
        let gate = DispatchSemaphore(value: 0)
        let began = DispatchSemaphore(value: 0)
        let finished = Flag()
        defer { gate.signal() }
        let waiter = Task { () -> (String, TimeInterval) in
            let start = Date()
            let outcome = await runner.run(.codeSigning, key: "c", deadline: 10) { _ -> Int in
                began.signal(); _ = gate.wait(timeout: .now() + 10); finished.raise(); return 1
            }
            return ("\(outcome)", Date().timeIntervalSince(start))
        }
        #expect(began.wait(timeout: .now() + 5) == .success)
        waiter.cancel()
        let (outcome, waited) = await waiter.value
        #expect(outcome == "cancelled")
        #expect(waited < 2, "a cancelled caller waited for its run's deadline")
        #expect(!finished.isRaised)
        #expect(runner.stuckCount(.codeSigning) == 0, "a cancelled caller's run is not stuck before its deadline")
        gate.signal()
        #expect(await Self.eventually(within: 5) { finished.isRaised })
    }

    @Test("a run blocked on a FIFO is interrupted after its deadline, wherever the FIFO now is, and its result is not kept")
    func strandedRunIsInterrupted() async throws {
        let dir = try Self.directory()
        defer { try? FileManager.default.removeItem(atPath: dir) }
        let sealed = try Self.bundleWithFIFOSeal(in: dir, name: "Sealed", executable: "Sealed")
        let runner = BoundedSecurityEvaluation(stuckLimit: 2)
        let cache = CodeSigningCache(securityEvaluation: runner, evaluationDeadline: 1, afterEvaluationForTesting: nil)

        // The caller gets its answer at the deadline, while the run is blocked
        // on the FIFO. Moving the FIFO out of the bundle then, before the
        // first interrupt, leaves it where no walk of the bundle could find it
        // and only the test can still open it.
        let moved = dir + "/elsewhere"
        let executable = sealed.executable
        let answer = await Self.promptly(releasing: [sealed.fifo]) { await cache.evaluateExecutable(path: executable) }
        #expect(rename(sealed.fifo, moved) == 0)
        #expect(answer.prompt && answer.value == .some(nil), "a blocked evaluation must not yield a verdict")

        let reclaimed = await Self.eventually(within: 5) { runner.stuckCount(.codeSigning) == 0 }
        if !reclaimed { _ = await Self.release([moved]) { runner.stuckCount(.codeSigning) == 0 } }
        #expect(reclaimed, "the stranded run was not interrupted")
        #expect((runner.diagnostics()["interrupted_total"] as? Int ?? 0) >= 1)
        #expect(cache.lookup(path: executable) == nil, "an interrupted evaluation's failure was cached as a verdict")
    }

    @Test("a file renamed over a stranded one is evaluated afresh")
    func replacedFileIsANewKey() async throws {
        let dir = try Self.directory()
        defer { try? FileManager.default.removeItem(atPath: dir) }
        let sealed = try Self.bundleWithFIFOSeal(in: dir, name: "Swap", executable: "Swap")
        let runner = BoundedSecurityEvaluation(stuckLimit: 4, interruptsStranded: false)
        let cache = CodeSigningCache(securityEvaluation: runner, evaluationDeadline: 0.3, afterEvaluationForTesting: nil)
        let executable = sealed.executable

        let first = await Self.promptly(releasing: [sealed.fifo]) { await cache.evaluateExecutable(path: executable) }
        #expect(first.prompt && first.value == .some(nil))
        #expect(runner.stuckCount(.codeSigning) == 1)
        let unchanged = Self.started(runner)
        let again = await Self.promptly(releasing: [sealed.fifo]) { await cache.evaluateExecutable(path: executable) }
        #expect(again.prompt && again.value == .some(nil))
        #expect(Self.started(runner) == unchanged, "the same file was started again while its run is stuck")

        // A new file at the path is a new key.
        let replacement = dir + "/replacement"
        try FileManager.default.copyItem(atPath: "/bin/ls", toPath: replacement)
        #expect(rename(replacement, executable) == 0)
        let fresh = await Self.promptly(releasing: [sealed.fifo]) { await cache.evaluateExecutable(path: executable) }
        #expect(fresh.prompt && fresh.value == .some(nil))
        #expect(Self.started(runner) == unchanged + 1, "a replaced file was refused as the stranded one")
        #expect(await Self.release([sealed.fifo]) { runner.stuckCount(.codeSigning) == 0 })
    }

    @Test("the code-signing cache answers nil at its deadline, caps blocked work and caches a late verdict")
    func codeSigningCacheIsBounded() async throws {
        let dir = try Self.directory()
        defer { try? FileManager.default.removeItem(atPath: dir) }
        let sealed = try Self.bundleWithFIFOSeal(in: dir, name: "Sealed", executable: "Sealed")
        let fifoExecutable = try Self.bundleWithFIFOExecutable(in: dir, name: "Pipe")
        let runner = BoundedSecurityEvaluation(stuckLimit: 2, interruptsStranded: false)
        let cache = CodeSigningCache(securityEvaluation: runner, evaluationDeadline: 0.5, afterEvaluationForTesting: nil)

        let executable = sealed.executable
        let first = await Self.promptly(releasing: [sealed.fifo]) {
            await cache.evaluateExecutable(path: executable)
        }
        #expect(first.prompt, "the cache waited on Security.framework blocked in a bundle's FIFO")
        #expect(first.value == .some(nil), "a regular executable whose CodeResources is a FIFO must not yield a verdict")
        #expect(cache.lookup(path: sealed.executable) == nil)
        let bundle = fifoExecutable.bundle
        let second = await Self.promptly(releasing: [fifoExecutable.fifo]) {
            await cache.evaluateWithinDeadline(path: bundle)
        }
        #expect(second.prompt)
        #expect(second.value == .some(nil), "TCC must see an unfinished evaluation as unknown, never as unsigned")
        #expect(runner.stuckCount(.codeSigning) == 2)

        let start = Date()
        #expect(await cache.evaluateExecutable(path: "/bin/ls") == nil, "the site was at its limit")
        #expect(Self.elapsed(since: start) < 1)

        let returned = await Self.release([sealed.fifo, fifoExecutable.fifo]) { runner.stuckCount(.codeSigning) == 0 }
        #expect(returned, "released evaluations still count as stuck")
        #expect(await cache.evaluateExecutable(path: "/bin/ls")?.signerType == .apple)
        #expect(cache.lookup(path: sealed.executable) != nil, "the late verdict was not cached")
    }

    @Test("TCC's evaluations have a limit of their own")
    func tccHasItsOwnSite() async throws {
        let dir = try Self.directory()
        defer { try? FileManager.default.removeItem(atPath: dir) }
        let sealed = try Self.bundleWithFIFOSeal(in: dir, name: "Fill", executable: "Fill")
        let runner = BoundedSecurityEvaluation(stuckLimit: 1, interruptsStranded: false)
        let enricher = CodeSigningCache(securityEvaluation: runner, evaluationDeadline: 0.3, afterEvaluationForTesting: nil)
        let tcc = CodeSigningCache(
            securityEvaluation: runner, evaluationDeadline: 0.3, evaluationSite: .tcc, afterEvaluationForTesting: nil)
        let blocked = await Self.promptly(releasing: [sealed.fifo]) { await enricher.evaluateExecutable(path: sealed.executable) }
        #expect(blocked.prompt && blocked.value == .some(nil))
        #expect(runner.stuckCount(.codeSigning) == 1)
        #expect(await enricher.evaluateExecutable(path: "/bin/ls") == nil, "the enricher's site is at its limit")
        #expect(await tcc.evaluateWithinDeadline(path: "/bin/ls")?.signerType == .apple,
                "stranded enricher work left a TCC client unevaluated")
        #expect(await Self.release([sealed.fifo]) { runner.stuckCount(.codeSigning) == 0 })

        let root = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let monitor = try String(contentsOf: root.appendingPathComponent("Sources/MacCrabCore/Collectors/TCCMonitor.swift"), encoding: .utf8)
        #expect(monitor.contains("private let codeSigningCache = CodeSigningCache(evaluationSite: .tcc)"))
    }

    @Test("the Downloads check never waits on a FIFO inside a bundle, and keeps a verdict that comes late")
    func downloadsCheckIsBounded() async throws {
        let dir = try Self.directory()
        defer { try? FileManager.default.removeItem(atPath: dir) }
        let fifoExecutable = try Self.bundleWithFIFOExecutable(in: dir, name: "Pipe")
        let runner = BoundedSecurityEvaluation(stuckLimit: 2, interruptsStranded: false)
        let monitor = SystemPolicyMonitor(homesProvider: { [] }, securityEvaluation: runner, securityDeadline: 0.5)

        let bundle = fifoExecutable.bundle
        let first = await Self.promptly(releasing: [fifoExecutable.fifo]) {
            await monitor.isSignedWithAppleAnchor(path: bundle, expected: .directory)
        }
        #expect(first.prompt, "the scan waited on Security.framework blocked in a bundle's FIFO")
        #expect(first.value == .some(nil))
        #expect(runner.stuckCount(.downloads) == 1)
        // The next scan does not strand a second thread on the same bundle.
        let again = await Self.promptly(releasing: [fifoExecutable.fifo]) {
            await monitor.isSignedWithAppleAnchor(path: bundle, expected: .directory)
        }
        #expect(again.prompt && again.value == .some(nil))
        #expect(runner.stuckCount(.downloads) == 1)
        #expect(Self.started(runner) == 1)

        // The run finishes late, as a slow evaluation does: its verdict serves
        // the next scan, which starts no run of its own.
        #expect(await Self.release([fifoExecutable.fifo]) { runner.stuckCount(.downloads) == 0 })
        #expect(await monitor.isSignedWithAppleAnchor(path: bundle, expected: .directory) == false)
        #expect(Self.started(runner) == 1, "a late verdict was discarded and the bundle evaluated again")
        #expect(await monitor.isSignedWithAppleAnchor(path: "/bin/ls", expected: .regularFile) == true)
    }

    @Test("an interrupted Downloads evaluation leaves no verdict, and the next scan is told it blocked without a new run")
    func interruptedDownloadsVerdictIsNotKept() async throws {
        let dir = try Self.directory()
        defer { try? FileManager.default.removeItem(atPath: dir) }
        let fifoExecutable = try Self.bundleWithFIFOExecutable(in: dir, name: "Cut")
        let runner = BoundedSecurityEvaluation(stuckLimit: 2)
        let monitor = SystemPolicyMonitor(homesProvider: { [] }, securityEvaluation: runner, securityDeadline: 0.5)
        let bundle = fifoExecutable.bundle

        let first = await Self.promptly(releasing: [fifoExecutable.fifo]) {
            await monitor.isSignedWithAppleAnchor(path: bundle, expected: .directory)
        }
        #expect(first.prompt && first.value == .some(nil))
        let reclaimed = await Self.eventually(within: 5) { runner.stuckCount(.downloads) == 0 }
        if !reclaimed { _ = await Self.release([fifoExecutable.fifo]) { runner.stuckCount(.downloads) == 0 } }
        #expect(reclaimed, "the stranded Downloads run was not interrupted")
        // The interrupted run's failure says nothing about the bundle, so no
        // verdict is kept; Security.framework blocked on it, so the next scan
        // is told so at once instead of stranding a thread for the deadline.
        let again = await Self.promptly(releasing: [fifoExecutable.fifo], within: 0.4) {
            await monitor.appleAnchorCheck(path: bundle, expected: .directory)
        }
        #expect(again.prompt && again.value == .some(.blocked), "the next scan waited on, or judged, a bundle Security blocked on")
        #expect(await monitor.isSignedWithAppleAnchor(path: bundle, expected: .directory) == nil)
        #expect(Self.started(runner) == 1, "a bundle Security blocked on was evaluated again")
        // A replaced main executable makes it a new item.
        try FileManager.default.removeItem(atPath: fifoExecutable.fifo)
        try FileManager.default.copyItem(atPath: "/bin/ls", toPath: fifoExecutable.fifo)
        let fresh = await monitor.appleAnchorCheck(path: bundle, expected: .directory)
        #expect(fresh == .notAnchored || fresh == .anchored, "a replaced bundle was not evaluated afresh: \(String(describing: fresh))")
        #expect(Self.started(runner) == 2)
    }

    @Test("the Downloads scan reports an unquarantined bundle Security blocked on, once")
    func downloadsScanAlertsOnABlockedBundle() async throws {
        let home = try Self.directory()
        defer { try? FileManager.default.removeItem(atPath: home) }
        try FileManager.default.createDirectory(atPath: home + "/Downloads", withIntermediateDirectories: true)
        let shield = try Self.bundleWithFIFOExecutable(in: home + "/Downloads", name: "Shield")
        let runner = BoundedSecurityEvaluation(stuckLimit: 2)
        let monitor = SystemPolicyMonitor(homesProvider: { [] }, securityEvaluation: runner, securityDeadline: 0.5)
        let user = RealUserHome(path: home, userID: getuid(), userName: NSUserName())

        // First scan: the evaluation passes its deadline, so nothing is judged.
        let first = await Self.promptly(releasing: [shield.fifo]) { await monitor.scanDownloadsForMissingQuarantine(in: user) }
        #expect(first.prompt)
        let reclaimed = await Self.eventually(within: 5) { runner.stuckCount(.downloads) == 0 }
        if !reclaimed { _ = await Self.release([shield.fifo]) { runner.stuckCount(.downloads) == 0 } }
        #expect(reclaimed)
        // Security blocked on it: the next scans report it once, unverified.
        for _ in 0..<2 {
            let scan = await Self.promptly(releasing: [shield.fifo]) { await monitor.scanDownloadsForMissingQuarantine(in: user) }
            #expect(scan.prompt)
        }
        await monitor.stop()
        var reports: [SystemPolicyMonitor.SystemPolicyEvent] = []
        for await event in monitor.events where event.type == .quarantineStripped { reports.append(event) }
        #expect(reports.count == 1, "a bundle Security blocked on was reported \(reports.count) times")
        #expect(reports.first?.path?.hasSuffix("/Downloads/Shield.app") == true)
        #expect(reports.first?.description.contains("could not be verified") == true)
    }

    @Test("a key whose run was interrupted is answered blocked at once until the key changes")
    func interruptedKeyIsBlockedAtOnce() async throws {
        let dir = try Self.directory()
        defer { try? FileManager.default.removeItem(atPath: dir) }
        let fifo = dir + "/pipe"
        try #require(mkfifo(fifo, 0o600) == 0)
        let runner = BoundedSecurityEvaluation(stuckLimit: 2)
        let interrupted = Flag()
        let first = await Self.promptly(releasing: [fifo]) {
            await runner.run(.libraryInventory, key: "same", deadline: 0.3) { attempt -> Int in
                let fd = open(fifo, O_RDONLY)
                if fd >= 0 { close(fd) }
                if attempt.wasInterrupted() { interrupted.raise() }
                return 1
            }
        }
        #expect(first.prompt)
        if case .timedOut? = first.value {} else { Issue.record("expected a timeout, got \(String(describing: first.value))") }
        let reclaimed = await Self.eventually(within: 5) { runner.stuckCount(.libraryInventory) == 0 }
        if !reclaimed { _ = await Self.release([fifo]) { runner.stuckCount(.libraryInventory) == 0 } }
        #expect(reclaimed && interrupted.isRaised, "the run blocked on the FIFO was not interrupted")

        let start = Date()
        let again = await runner.run(.libraryInventory, key: "same", deadline: 5) { _ in 2 }
        if case .blocked = again {} else { Issue.record("expected the interrupted key to be answered blocked, got \(again)") }
        #expect(Self.elapsed(since: start) < 1)
        #expect(Self.started(runner) == 1)
        #expect(await runner.run(.libraryInventory, key: "changed", deadline: 5) { _ in 3 }.value == 3)
        #expect(await runner.run(.downloads, key: "same", deadline: 5) { _ in 4 }.value == 4, "another site shares the memory")
    }

    @Test("a site runs at most its in-flight limit at once; joiners do not count, and a finished run frees its slot")
    func inFlightRunsAreCapped() async throws {
        let runner = BoundedSecurityEvaluation(stuckLimit: 4, inFlightLimits: [.downloads: 2], interruptsStranded: false)
        let gates = [DispatchSemaphore(value: 0), DispatchSemaphore(value: 0)]
        let began = DispatchSemaphore(value: 0)
        defer { gates.forEach { $0.signal(); $0.signal() } }
        func gated(_ gate: DispatchSemaphore, _ value: Int) -> @Sendable (BoundedSecurityEvaluation.Attempt) -> Int {
            { _ in began.signal(); _ = gate.wait(timeout: .now() + 10); return value }
        }
        let a = Task { await runner.run(.downloads, key: "a", deadline: 10, gated(gates[0], 1)).value }
        let b = Task { await runner.run(.downloads, key: "b", deadline: 10, gated(gates[1], 2)).value }
        #expect(began.wait(timeout: .now() + 5) == .success && began.wait(timeout: .now() + 5) == .success)
        #expect((runner.diagnostics()["in_flight"] as? [String: Int])?["downloads"] == 2)

        let start = Date()
        let refused = await runner.run(.downloads, key: "c", deadline: 10) { _ in 3 }
        if case .refused = refused {} else { Issue.record("expected the in-flight limit to refuse, got \(refused)") }
        #expect(Self.elapsed(since: start) < 1)
        #expect(Self.started(runner) == 2)
        // A caller for a key already in flight joins it.
        let joiner = Task { await runner.run(.downloads, key: "a", deadline: 10) { _ in 9 }.value }
        #expect(await Self.eventually(within: 5) { runner.waiterCount(.downloads, key: "a") == 2 })

        gates[0].signal()
        #expect(await a.value == 1)
        #expect(await joiner.value == 1)
        #expect(await runner.run(.downloads, key: "d", deadline: 10) { _ in 4 }.value == 4, "a finished run kept its slot")
        gates[1].signal()
        #expect(await b.value == 2)
        #expect(Self.started(runner) == 3)
    }

    @Test("a FIFO in nested code is reached by the interrupt, because validation stays on the run's thread")
    func nestedCodeFIFOIsReclaimed() async throws {
        let dir = try Self.directory()
        defer { try? FileManager.default.removeItem(atPath: dir) }
        guard let nested = try Self.bundleWithNestedFIFO(in: dir, name: "Outer") else {
            print("skipping: /usr/bin/codesign is unavailable or could not sign the fixture")
            return
        }
        let runner = BoundedSecurityEvaluation(stuckLimit: 2)
        let cache = CodeSigningCache(securityEvaluation: runner, evaluationDeadline: 1, afterEvaluationForTesting: nil)
        let bundle = nested.bundle
        let answer = await Self.promptly(releasing: [nested.fifo]) { await cache.evaluateWithinDeadline(path: bundle) }
        #expect(answer.prompt && answer.value == .some(nil), "a blocked evaluation must not yield a verdict")
        // No writer opens the FIFO: only the interrupt can end the open.
        let reclaimed = await Self.eventually(within: 5) { runner.stuckCount(.codeSigning) == 0 }
        if !reclaimed { _ = await Self.release([nested.fifo]) { runner.stuckCount(.codeSigning) == 0 } }
        #expect(reclaimed, "nested code was validated on a thread the interrupt cannot reach")
        #expect((runner.diagnostics()["interrupted_total"] as? Int ?? 0) >= 1)
        #expect(cache.lookup(path: bundle) == nil)
    }

    @Test("a run still computing past its deadline is never interrupted")
    func computingRunIsNotInterrupted() async throws {
        let runner = BoundedSecurityEvaluation(stuckLimit: 2)
        let interrupted = Flag()
        let finished = Flag()
        let outcome = await runner.run(.codeSigning, key: "busy", deadline: 0.2) { attempt -> Int in
            // Computes without a system call for about 1.5 s, as a large
            // bundle's hashing does.
            var timebase = mach_timebase_info_data_t()
            mach_timebase_info(&timebase)
            let end = mach_absolute_time() + 1_500_000_000 * UInt64(timebase.denom) / UInt64(timebase.numer)
            var x: UInt64 = 1
            while mach_absolute_time() < end { x = x &* 6364136223846793005 &+ 1442695040888963407 }
            if attempt.wasInterrupted() { interrupted.raise() }
            finished.raise()
            return Int(truncatingIfNeeded: x & 1)
        }
        if case .timedOut = outcome {} else { Issue.record("expected a timeout, got \(outcome)") }
        #expect(await Self.eventually(within: 10) { finished.isRaised })
        #expect(await Self.eventually(within: 5) { runner.stuckCount(.codeSigning) == 0 })
        #expect(!interrupted.isRaised, "a computing run was interrupted")
        #expect((runner.diagnostics()["interrupted_total"] as? Int ?? -1) == 0)
    }

    @Test("a Downloads key changes when a bundle's main files are replaced")
    func downloadsKeyFollowsTheBundle() throws {
        let dir = try Self.directory()
        defer { try? FileManager.default.removeItem(atPath: dir) }
        let pipe = try Self.bundleWithFIFOExecutable(in: dir, name: "Item")
        let before = SystemPolicyMonitor.downloadsKey(path: pipe.bundle)
        #expect(SystemPolicyMonitor.downloadsKey(path: pipe.bundle) == before)
        try FileManager.default.removeItem(atPath: pipe.fifo)
        try FileManager.default.copyItem(atPath: "/bin/ls", toPath: pipe.fifo)
        #expect(SystemPolicyMonitor.downloadsKey(path: pipe.bundle) != before)
    }

    @Test("every engine Security.framework caller goes through the bounded runner")
    func engineCallersAreBounded() throws {
        let root = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        func source(_ relative: String) throws -> String {
            try String(contentsOf: root.appendingPathComponent(relative), encoding: .utf8)
        }
        // TCC's change pass awaits each client's evaluation in turn.
        #expect(try source("Sources/MacCrabCore/Collectors/TCCMonitor.swift")
            .contains("await codeSigningCache.evaluateWithinDeadline(path: clientPath)"))
        #expect(try source("Sources/MacCrabCore/Enrichment/EventEnricher.swift")
            .contains("let verified = await cache.evaluateExecutable(path: path)"))
        let policy = try source("Sources/MacCrabCore/Collectors/SystemPolicyMonitor.swift")
        #expect(policy.contains("let key = Self.downloadsKey(path: path)"))
        #expect(policy.contains("let outcome = await securityEvaluation.run(.downloads, key: key, deadline: securityDeadline) { attempt in"))
        #expect(policy.contains("guard let check = await appleAnchorCheck("))
        #expect(policy.contains("case .blocked: return .blocked"))
        #expect(policy.contains("description: check == .blocked"))
        let library = try source("Sources/MacCrabCore/Detection/LibraryInventory.swift")
        #expect(library.contains(".libraryInventory, key: Self.evaluationKey(path: path), deadline: securityDeadline"))
        // Security.framework is called only from the off-actor verdicts.
        for (text, verdict) in [(policy, "private nonisolated static func appleAnchorVerdict("),
                                (library, "private nonisolated static func trustedSignatureVerdict(")] {
            let start = try #require(text.range(of: verdict))
            let first = try #require(text.range(of: "SecStaticCodeCreateWithPath("))
            #expect(start.upperBound < first.lowerBound, "a Security.framework call outside the bounded verdict")
            #expect(text.components(separatedBy: "SecStaticCodeCreateWithPath(").count == 2)
        }
        // Every bounded validation stays on the run's thread, where the
        // interrupt reaches it.
        #expect(policy.contains("SecCSFlags(rawValue: kSecCSCheckAllArchitectures | kSecCSSingleThreaded)"))
        #expect(library.contains("SecCSFlags(rawValue: kSecCSCheckAllArchitectures | kSecCSSingleThreaded)"))
        let cache = try source("Sources/MacCrabCore/Enrichment/CodeSigningCache.swift")
        #expect(cache.contains("let info = Self.performEvaluation(path: path, singleThreaded: bounded)"))
        #expect(cache.contains("let validation = SecCSFlags(rawValue: singleThreaded ? kSecCSSingleThreaded : 0)"))
        #expect(cache.contains("SecCSFlags(rawValue: kSecCSCheckAllArchitectures).union(validation)"))
        #expect(!cache.contains("SecStaticCodeCheckValidity(staticCode, [], "), "a requirement check validates off the run's thread")
        #expect(cache.components(separatedBy: "SecStaticCodeCheckValidity(staticCode, validation, req)").count == 3)
        // The heartbeat shows blocked runs per site.
        #expect(try source("Sources/MacCrabAgentKit/DaemonTimers.swift")
            .contains("\"security_evaluation\": BoundedSecurityEvaluation.heartbeatDiagnostics(),"))
    }

    @Test("the library check never waits on a FIFO inside a bundle, reports it as blocked, and does not remember it")
    func libraryCheckIsBounded() async throws {
        let dir = try Self.directory()
        defer { try? FileManager.default.removeItem(atPath: dir) }
        let sealed = try Self.bundleWithFIFOSeal(in: dir, name: "Library", executable: "libbundle.dylib")
        let runner = BoundedSecurityEvaluation(stuckLimit: 2, interruptsStranded: false)
        let inventory = LibraryInventory(securityEvaluation: runner, securityDeadline: 0.5)

        let library = sealed.executable
        let first = await Self.promptly(releasing: [sealed.fifo]) {
            await inventory.signatureCheck(path: library)
        }
        #expect(first.prompt, "the scan waited on Security.framework blocked in a bundle's FIFO")
        #expect(first.value == .blocked, "a library Security blocked on must read as unverifiable")
        #expect(runner.stuckCount(.libraryInventory) == 1)

        let returned = await Self.release([sealed.fifo]) { runner.stuckCount(.libraryInventory) == 0 }
        #expect(returned, "a released evaluation still counts as stuck")
        // Without the bundle around it the library is a valid Apple binary: a
        // remembered miss would still answer false.
        try FileManager.default.removeItem(atPath: sealed.bundle + "/Contents/_CodeSignature")
        try FileManager.default.removeItem(atPath: sealed.bundle + "/Contents/Info.plist")
        #expect(await inventory.isTrustedSigned(path: sealed.executable), "the unfinished check was cached")
    }

    @Test("a library refused at the site's limit is skipped, not reported as unsigned or remembered")
    func libraryAtTheLimitIsSkipped() async throws {
        let dir = try Self.directory()
        defer { try? FileManager.default.removeItem(atPath: dir) }
        let sealed = try Self.bundleWithFIFOSeal(in: dir, name: "Hold", executable: "libhold.dylib")
        let runner = BoundedSecurityEvaluation(stuckLimit: 1, interruptsStranded: false)
        let inventory = LibraryInventory(securityEvaluation: runner, securityDeadline: 0.3)
        let library = sealed.executable
        let blocked = await Self.promptly(releasing: [sealed.fifo]) { await inventory.signatureCheck(path: library) }
        #expect(blocked.prompt && blocked.value == .blocked)
        #expect(runner.stuckCount(.libraryInventory) == 1)
        #expect(await inventory.signatureCheck(path: "/bin/ls") == .skipped, "an unevaluated library was judged")
        #expect(await Self.release([sealed.fifo]) { runner.stuckCount(.libraryInventory) == 0 })
        #expect(await inventory.signatureCheck(path: "/bin/ls") == .trusted, "the skip was remembered")

        let root = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let source = try String(contentsOf: root.appendingPathComponent("Sources/MacCrabCore/Detection/LibraryInventory.swift"), encoding: .utf8)
        #expect(source.contains("if check == .untrusted || check == .blocked {"), "only judged libraries may alert")
    }
}
