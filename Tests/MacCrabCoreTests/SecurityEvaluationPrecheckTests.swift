import Darwin
import Foundation
import Testing
@testable import MacCrabCore

/// Security.framework opens the paths it evaluates itself: it blocks on a FIFO
/// until a writer appears, and opens without O_NOCTTY. Every engine caller now
/// opens the path safely first and evaluates only the kind it expected.
@Suite("Security.framework only evaluates what a safe open found")
struct SecurityEvaluationPrecheckTests {
    private final class Flag: @unchecked Sendable {
        private let lock = NSLock()
        private var raised = false
        func raise() { lock.lock(); raised = true; lock.unlock() }
        var isRaised: Bool { lock.lock(); defer { lock.unlock() }; return raised }
    }

    private func directory() throws -> String {
        let path = NSTemporaryDirectory() + "security-precheck-\(UUID().uuidString)"
        try FileManager.default.createDirectory(atPath: path, withIntermediateDirectories: true)
        return path
    }

    private func fifo(in directory: String, named name: String) throws -> String {
        let path = directory + "/" + name
        try #require(mkfifo(path, 0o600) == 0)
        return path
    }

    /// Runs `body` and reports whether it finished within `seconds`. If it is
    /// stuck in an open of `fifo` (the defect), a writer releases it so the
    /// test still ends.
    private func promptly<T: Sendable>(
        releasing fifo: String,
        within seconds: Double = 10,
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
        let release = Date().addingTimeInterval(20)
        while !finished.isRaised && Date() < release {
            let writer = open(fifo, O_WRONLY | O_NONBLOCK)
            if writer >= 0 { close(writer) }
            try? await Task.sleep(nanoseconds: 50_000_000)
        }
        return (finished.isRaised ? await work.value : nil, prompt)
    }

    @Test("the precheck admits only the expected kind, and a canonical path never through a symlink")
    func precheckKinds() throws {
        let dir = try directory()
        defer { try? FileManager.default.removeItem(atPath: dir) }
        let file = dir + "/file"
        try Data("x".utf8).write(to: URL(fileURLWithPath: file))
        let pipe = try fifo(in: dir, named: "pipe")
        let link = dir + "/link"
        try #require(symlink(file, link) == 0)
        let device = dir + "/device"
        try #require(symlink("/dev/null", device) == 0)

        #expect(SecurityEvaluationPrecheck.metadata(of: file, expected: .regularFile, canonical: true) != nil,
                "a /var/folders path is normalized to /private/var before the no-follow open")
        #expect(SecurityEvaluationPrecheck.metadata(of: file, expected: .regularFileOrDirectory, canonical: false) != nil)
        #expect(SecurityEvaluationPrecheck.metadata(of: file, expected: .directory, canonical: false) == nil)
        #expect(SecurityEvaluationPrecheck.metadata(of: dir, expected: .directory, canonical: true) != nil)
        #expect(SecurityEvaluationPrecheck.metadata(of: dir, expected: .regularFile, canonical: true) == nil)
        #expect(SecurityEvaluationPrecheck.metadata(of: pipe, expected: .regularFileOrDirectory, canonical: false) == nil)
        #expect(SecurityEvaluationPrecheck.metadata(of: link, expected: .regularFile, canonical: true) == nil)
        #expect(SecurityEvaluationPrecheck.metadata(of: link, expected: .regularFile, canonical: false) != nil)
        #expect(SecurityEvaluationPrecheck.metadata(of: device, expected: .regularFileOrDirectory, canonical: false) == nil)
        #expect(SecurityEvaluationPrecheck.metadata(of: dir + "/missing", expected: .regularFile, canonical: false) == nil)
    }

    @Test("a FIFO is answered at once as unsigned, and nothing is cached")
    func cacheSkipsAFIFO() async throws {
        let dir = try directory()
        defer { try? FileManager.default.removeItem(atPath: dir) }
        let pipe = try fifo(in: dir, named: "Tool.app")
        let cache = CodeSigningCache()
        let result = await promptly(releasing: pipe) { await cache.evaluate(path: pipe) }
        #expect(result.prompt, "Security.framework was handed a FIFO and blocked in its open")
        #expect(result.value?.signerType == .unsigned)
        #expect(cache.lookup(path: pipe) == nil)
    }

    @Test("a symlink to a device is unsigned and uncached; an exec path never follows a symlink")
    func cacheSkipsDevicesAndExecSymlinks() async throws {
        let dir = try directory()
        defer { try? FileManager.default.removeItem(atPath: dir) }
        let device = dir + "/device"
        try #require(symlink("/dev/null", device) == 0)
        let cache = CodeSigningCache()
        #expect(await cache.evaluate(path: device).signerType == .unsigned)
        #expect(cache.lookup(path: device) == nil, "a device's verdict was cached")

        let link = dir + "/ls"
        try #require(symlink("/bin/ls", link) == 0)
        #expect(await CodeSigningCache().evaluateExecutable(path: link) == nil)
        #expect(await CodeSigningCache().evaluateExecutable(path: "/bin/ls")?.signerType == .apple)
        #expect(await CodeSigningCache().evaluate(path: link).signerType == .apple,
                "TCC client paths may still be reached through a symlink")
    }

    @Test("the cache evaluates only the file its first stat saw")
    func cacheBindsThePrecheckToItsIdentity() throws {
        // A swap between the stat and the safe open cannot be staged without
        // a race, so this is pinned in the source.
        let source = try String(
            contentsOf: URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
                .deletingLastPathComponent().appendingPathComponent("Sources/MacCrabCore/Enrichment/CodeSigningCache.swift"),
            encoding: .utf8
        )
        let precheck = try #require(source.range(of: "guard let opened = SecurityEvaluationPrecheck.metadata("))
        let identity = try #require(source.range(of: "), before.map({ $0 == FileIdentity(opened) }) ?? true else { return nil }"))
        let evaluation = try #require(source.range(of: "let verdict = evaluator?(path) ?? Self.performEvaluation(path: path, singleThreaded: bounded)"))
        #expect(precheck.upperBound < identity.lowerBound && identity.upperBound < evaluation.lowerBound)
    }

    @Test("the Downloads check evaluates only the kind the listing saw")
    func downloadsCheckNeedsTheListedKind() async throws {
        let dir = try directory()
        defer { try? FileManager.default.removeItem(atPath: dir) }
        let pipe = try fifo(in: dir, named: "Swapped.app")
        let link = dir + "/ls"
        try #require(symlink("/bin/ls", link) == 0)
        let monitor = SystemPolicyMonitor(homesProvider: { [] })
        let result = await promptly(releasing: pipe) {
            await monitor.isSignedWithAppleAnchor(path: pipe, expected: .directory)
        }
        #expect(result.prompt, "Security.framework was handed a FIFO and blocked in its open")
        #expect(result.value == .some(nil))
        #expect(await monitor.isSignedWithAppleAnchor(path: "/bin/ls", expected: .regularFile) == true)
        #expect(await monitor.isSignedWithAppleAnchor(path: "/bin/ls", expected: .directory) == nil)
        #expect(await monitor.isSignedWithAppleAnchor(path: link, expected: .regularFile) == nil)

        let source = try String(
            contentsOf: URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
                .deletingLastPathComponent().appendingPathComponent("Sources/MacCrabCore/Collectors/SystemPolicyMonitor.swift"),
            encoding: .utf8
        )
        #expect(source.contains("expected: entry.kind == .directory ? .directory : .regularFile\n            ) else { continue }"))
    }

    @Test("a library path swapped onto a FIFO is untrusted at once and not remembered")
    func libraryCheckSkipsAFIFO() async throws {
        let dir = try directory()
        defer { try? FileManager.default.removeItem(atPath: dir) }
        let pipe = try fifo(in: dir, named: "libswap.dylib")
        let inventory = LibraryInventory()
        let result = await promptly(releasing: pipe) { await inventory.isTrustedSigned(path: pipe) }
        #expect(result.prompt, "Security.framework was handed a FIFO and blocked in its open")
        #expect(result.value == false)
        try FileManager.default.removeItem(atPath: pipe)
        try FileManager.default.copyItem(atPath: "/bin/ls", toPath: pipe)
        #expect(await inventory.isTrustedSigned(path: pipe), "the skipped FIFO's verdict was cached")
    }

    @Test("an exec path that is not a regular file is never handed to the cache")
    func enricherDegradesWithoutAnIdentity() async throws {
        let dir = try directory()
        defer { try? FileManager.default.removeItem(atPath: dir) }
        let pipe = try fifo(in: dir, named: "spoof")
        let cache = CodeSigningCache()
        let enricher = EventEnricher(codeSigningCache: cache, heavyEnrichmentPlane: HeavyEnrichmentPlane(
            configuration: .init(operationTimeoutSeconds: 30),
            liveMemoryBudget: .isolatedProductionEquivalentForTesting()
        ))
        let process = MacCrabCore.ProcessInfo(
            pid: 999_101, ppid: 1, rpid: 1, name: "spoof", executable: pipe,
            commandLine: pipe, args: [pipe], workingDirectory: "/tmp",
            userId: UInt32(getuid()), userName: "tester", groupId: 20, startTime: Date(),
            codeSignature: CodeSignatureInfo(signerType: .apple, teamId: "AB12CD34EF",
                                             signingId: "com.apple.spoofed", flags: 0x1),
            isPlatformBinary: false
        )
        let event = Event(eventCategory: .process, eventType: .start, eventAction: "exec", process: process)
        let enriched = await enricher.enrich(event)
        var applied: Event?
        let deadline = Date().addingTimeInterval(30)
        while applied == nil && Date() < deadline {
            if let patch = await enricher.drainDeferredEnrichments(limit: 16).first(where: {
                $0.component == .codeSignature
            }) {
                applied = patch.applying(to: enriched)
            } else {
                try? await Task.sleep(nanoseconds: 5_000_000)
            }
        }
        _ = await enricher.shutdownHeavyEnrichment()
        let patched = try #require(applied)
        #expect(patched.process.codeSignature == nil)
        #expect(await cache.stats().misses == 0, "the cache was asked to evaluate a FIFO")
    }
}
