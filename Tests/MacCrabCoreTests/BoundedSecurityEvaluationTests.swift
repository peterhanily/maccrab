import Darwin
import Foundation
import Testing
@testable import MacCrabCore

/// Security.framework opens the files inside a bundle itself, and a FIFO at
/// any of them holds the evaluating thread until a writer appears. No engine
/// caller may wait on that: it gets nil after its deadline, the stranded work
/// is counted, and a site with too much of it starts no more.
@Suite("Security.framework evaluations wait a bounded time")
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

    @Test("work past its deadline is stuck, not restarted, and capped per site until it returns")
    func runnerBoundsStrandedWork() async throws {
        let runner = BoundedSecurityEvaluation(stuckLimit: 2)
        let gate = DispatchSemaphore(value: 0)
        let started = Counter()
        var released = false
        defer { if !released { gate.signal(); gate.signal() } }
        // Without a deadline the first call would wait for the gate: open it
        // eventually, so that fails the timing checks instead of hanging.
        DispatchQueue.global().asyncAfter(deadline: .now() + 10) { gate.signal(); gate.signal() }

        var start = Date()
        let first = await runner.run(.downloads, key: "a", deadline: 0.2) { () -> Int in
            started.increment(); gate.wait(); return 1
        }
        #expect(first == nil)
        #expect(Self.elapsed(since: start) < 5, "the caller waited on the blocked work")
        #expect(runner.stuckCount(.downloads) == 1)

        // The same key is not started again while its work is stuck.
        #expect(await runner.run(.downloads, key: "a", deadline: 5) { () -> Int in started.increment(); return 2 } == nil)
        #expect(started.value == 1)
        // Another site is unaffected, and finished work comes back.
        #expect(await runner.run(.libraryInventory, key: "a", deadline: 5) { 3 } == 3)

        _ = await runner.run(.downloads, key: "b", deadline: 0.2) { () -> Int in
            started.increment(); gate.wait(); return 4
        }
        #expect(runner.stuckCount(.downloads) == 2)
        // At the limit nothing starts, and the answer is immediate.
        start = Date()
        #expect(await runner.run(.downloads, key: "c", deadline: 5) { () -> Int in started.increment(); return 5 } == nil)
        #expect(Self.elapsed(since: start) < 1)
        #expect(started.value == 2)

        gate.signal(); gate.signal()
        released = true
        let drained = Date().addingTimeInterval(10)
        while runner.stuckCount(.downloads) > 0 && Date() < drained {
            try? await Task.sleep(nanoseconds: 10_000_000)
        }
        #expect(runner.stuckCount(.downloads) == 0, "returned work still counts as stuck")
        #expect(await runner.run(.downloads, key: "c", deadline: 5) { 6 } == 6)
    }

    @Test("the code-signing cache answers nil at its deadline, caps blocked work and caches a late verdict")
    func codeSigningCacheIsBounded() async throws {
        let dir = try Self.directory()
        defer { try? FileManager.default.removeItem(atPath: dir) }
        let sealed = try Self.bundleWithFIFOSeal(in: dir, name: "Sealed", executable: "Sealed")
        let fifoExecutable = try Self.bundleWithFIFOExecutable(in: dir, name: "Pipe")
        let runner = BoundedSecurityEvaluation(stuckLimit: 2)
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

    @Test("the Downloads check never waits on a FIFO inside a bundle")
    func downloadsCheckIsBounded() async throws {
        let dir = try Self.directory()
        defer { try? FileManager.default.removeItem(atPath: dir) }
        let fifoExecutable = try Self.bundleWithFIFOExecutable(in: dir, name: "Pipe")
        let runner = BoundedSecurityEvaluation(stuckLimit: 2)
        let monitor = SystemPolicyMonitor(homesProvider: { [] }, securityEvaluation: runner, securityDeadline: 0.5)

        let bundle = fifoExecutable.bundle
        let first = await Self.promptly(releasing: [fifoExecutable.fifo]) {
            await monitor.isSignedWithAppleAnchor(path: bundle, expected: .directory)
        }
        #expect(first.prompt, "the scan waited on Security.framework blocked in a bundle's FIFO")
        #expect(first.value == .some(nil))
        #expect(runner.stuckCount(.downloads) == 1)
        // The next scan does not strand a second thread on the same bundle.
        let start = Date()
        let again = await Self.promptly(releasing: [fifoExecutable.fifo]) {
            await monitor.isSignedWithAppleAnchor(path: bundle, expected: .directory)
        }
        #expect(again.prompt && again.value == .some(nil))
        #expect(Self.elapsed(since: start) < 1)
        #expect(runner.stuckCount(.downloads) == 1)

        let returned = await Self.release([fifoExecutable.fifo]) { runner.stuckCount(.downloads) == 0 }
        #expect(returned, "a released evaluation still counts as stuck")
        #expect(await monitor.isSignedWithAppleAnchor(path: "/bin/ls", expected: .regularFile) == true)
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
        #expect(policy.contains("await securityEvaluation.run(.downloads, key: path, deadline: securityDeadline) {"))
        #expect(policy.contains("guard let anchored = await isSignedWithAppleAnchor("))
        let library = try source("Sources/MacCrabCore/Detection/LibraryInventory.swift")
        #expect(library.contains("await securityEvaluation.run(.libraryInventory, key: path, deadline: securityDeadline, {"))
        // Security.framework is called only from the off-actor verdicts.
        for (text, verdict) in [(policy, "private nonisolated static func appleAnchorVerdict("),
                                (library, "private nonisolated static func trustedSignatureVerdict(")] {
            let start = try #require(text.range(of: verdict))
            let first = try #require(text.range(of: "SecStaticCodeCreateWithPath("))
            #expect(start.upperBound < first.lowerBound, "a Security.framework call outside the bounded verdict")
            #expect(text.components(separatedBy: "SecStaticCodeCreateWithPath(").count == 2)
        }
    }

    @Test("the library check never waits on a FIFO inside a bundle, and does not remember the miss")
    func libraryCheckIsBounded() async throws {
        let dir = try Self.directory()
        defer { try? FileManager.default.removeItem(atPath: dir) }
        let sealed = try Self.bundleWithFIFOSeal(in: dir, name: "Library", executable: "libbundle.dylib")
        let runner = BoundedSecurityEvaluation(stuckLimit: 2)
        let inventory = LibraryInventory(securityEvaluation: runner, securityDeadline: 0.5)

        let library = sealed.executable
        let first = await Self.promptly(releasing: [sealed.fifo]) {
            await inventory.isTrustedSigned(path: library)
        }
        #expect(first.prompt, "the scan waited on Security.framework blocked in a bundle's FIFO")
        #expect(first.value == false)
        #expect(runner.stuckCount(.libraryInventory) == 1)

        let returned = await Self.release([sealed.fifo]) { runner.stuckCount(.libraryInventory) == 0 }
        #expect(returned, "a released evaluation still counts as stuck")
        // Without the bundle around it the library is a valid Apple binary: a
        // remembered miss would still answer false.
        try FileManager.default.removeItem(atPath: sealed.bundle + "/Contents/_CodeSignature")
        try FileManager.default.removeItem(atPath: sealed.bundle + "/Contents/Info.plist")
        #expect(await inventory.isTrustedSigned(path: sealed.executable), "the unfinished check was cached")
    }
}
