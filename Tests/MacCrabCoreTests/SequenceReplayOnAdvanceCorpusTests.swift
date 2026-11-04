import Foundation
import Testing
@testable import MacCrabCore

/// The shipped stable sequence rules over synthetic in-memory process, file
/// and network events: no files, processes, collectors or daemon. Event times
/// are fixed offsets from one base date. Processing-time windows come from
/// restoring checkpoint state at a chosen instant, and every engine sweeps
/// periodically only once an hour. Paths and images are fictional fixtures.
@Suite("Sequence replay on advance: shipped stable rules")
struct SequenceReplayOnAdvanceCorpusTests {
    private let base = Date(timeIntervalSince1970: 1_700_000_000)
    private let npmRat = "e1f2a3b4-0020-4000-b000-000000000020"
    private let supplyChain = "e1f2a3b4-0023-4000-b000-000000000023"
    private let worm = "e1f2a3b4-0040-4000-b000-000000000040"
    private let typosquat = "e1f2a3b4-0032-4000-b000-000000000032"
    private let ransomware = "e1f2a3b4-0016-4000-b000-000000000016"
    private static let node = "/opt/homebrew/bin/node"

    // MARK: - Processes and events

    /// One process of a fixture tree. The lineage tracker records it, and its
    /// events carry its parent as their first ancestor, as enrichment would,
    /// so ParentImage resolves.
    private struct Proc {
        let pid: Int32
        let image: String
        let parent: Int32
        let parentImage: String
        var commandLine: String? = nil

        static func root(_ pid: Int32, _ image: String, commandLine: String? = nil) -> Proc {
            Proc(pid: pid, image: image, parent: 1, parentImage: "/sbin/launchd", commandLine: commandLine)
        }

        func child(_ pid: Int32, _ image: String, commandLine: String? = nil) -> Proc {
            Proc(pid: pid, image: image, parent: self.pid, parentImage: self.image, commandLine: commandLine)
        }
    }

    private func processInfo(_ process: Proc) -> MacCrabCore.ProcessInfo {
        MacCrabCore.ProcessInfo(
            pid: process.pid, ppid: process.parent, rpid: process.pid,
            name: (process.image as NSString).lastPathComponent, executable: process.image,
            commandLine: process.commandLine ?? process.image, args: [process.image],
            workingDirectory: "/Users/t/project", userId: 501, userName: "t", groupId: 20, startTime: base,
            ancestors: [ProcessAncestor(pid: process.parent, executable: process.parentImage,
                                        name: (process.parentImage as NSString).lastPathComponent)]
        )
    }

    private func exec(_ process: Proc, at offset: TimeInterval) -> Event {
        Event(timestamp: base.addingTimeInterval(offset), eventCategory: .process, eventType: .start,
              eventAction: "exec", process: processInfo(process))
    }

    private func write(_ process: Proc, _ path: String, action: FileAction = .write,
                       at offset: TimeInterval) -> Event {
        Event(timestamp: base.addingTimeInterval(offset), eventCategory: .file, eventType: .creation,
              eventAction: action.rawValue, process: processInfo(process),
              file: FileInfo(path: path, action: action))
    }

    private func connect(_ process: Proc, to destination: String = "93.184.216.34", hostname: String? = nil,
                         at offset: TimeInterval) -> Event {
        Event(timestamp: base.addingTimeInterval(offset), eventCategory: .network, eventType: .creation,
              eventAction: "connect", process: processInfo(process),
              network: NetworkInfo(sourceIp: "10.0.0.2", sourcePort: 51_000, destinationIp: destination,
                                   destinationPort: 443, destinationHostname: hostname, direction: .outbound,
                                   transport: "tcp"))
    }

    // MARK: - Engine and delivery

    private func stableEngine(_ processes: [Proc]) async throws -> SequenceEngine {
        try ensureRulesCompiled()
        let lineage = ProcessLineage()
        for process in processes {
            await lineage.recordProcess(pid: process.pid, ppid: process.parent, path: process.image,
                                        name: (process.image as NSString).lastPathComponent, startTime: base)
        }
        let engine = SequenceEngine(lineage: lineage, sweepInterval: 3_600)
        _ = try await engine.loadRules(from: compiledRulesDirectory.appendingPathComponent("sequences"),
                                       enabledStatuses: ["stable"])
        return engine
    }

    /// Exact weight and journal accounting, with nothing shed.
    private func assertExact(_ engine: SequenceEngine) async {
        let weight = await engine.checkpointWeightDiagnostics()
        #expect(weight.cachedWeight == weight.recomputedWeight && weight.cachedWeight <= weight.maximumWeight)
        let journal = await engine.pendingStepConservation()
        #expect(journal.conservationMaintained && journal.inFlight == 0)
        #expect(await engine.pendingStepConservationByRule().values.allSatisfy(\.conservationMaintained))
        #expect(await engine.pendingStepsEvictedTotal == 0)
        #expect(await engine.partialPressureDiagnostics().totalShed == 0)
    }

    private struct Delivery {
        let engine: SequenceEngine
        /// Completions of the rule under test returned by each evaluation.
        let counts: [Int]
        /// Every stable rule's completions, each with the event whose
        /// evaluation returned it.
        let completions: [(match: RuleMatch, trigger: Event)]

        var fires: Int { counts.reduce(0, +) }
    }

    /// Evaluates `events` in order, checking exact accounting after each one,
    /// on a fresh stable engine or on `engine` (already restored).
    private func deliver(_ events: [Event], rule ruleID: String, processes: [Proc],
                         into engine: SequenceEngine? = nil) async throws -> Delivery {
        let target: SequenceEngine
        if let engine { target = engine } else { target = try await stableEngine(processes) }
        var counts: [Int] = []
        var completions: [(match: RuleMatch, trigger: Event)] = []
        for event in events {
            let matches = await target.evaluate(event)
            counts.append(matches.filter { $0.ruleId == ruleID }.count)
            completions += matches.map { (match: $0, trigger: event) }
            await assertExact(target)
        }
        _ = try await target.checkpointCapture()
        return Delivery(engine: target, counts: counts, completions: completions)
    }

    private func ledger(offered: UInt64, completed: UInt64 = 0, queued: UInt64) -> SequenceConservationTelemetry {
        SequenceConservationTelemetry(offered: offered, completed: completed, queued: queued, inFlight: 0,
                                      explicitlyShed: 0)
    }

    /// The steps a completion binds, as "step (pid:N", in event-time order and
    /// without the processing-time offsets the description also carries.
    private func boundSteps(_ match: RuleMatch) -> [String] {
        let chain = match.description.components(separatedBy: "[sequence: ").last ?? ""
        return chain.components(separatedBy: " -> ").map { $0.components(separatedBy: ",")[0] }
    }

    private func permutations(_ events: [Event]) -> [[Event]] {
        guard events.count > 1 else { return [events] }
        return events.indices.flatMap { index -> [[Event]] in
            var rest = events
            let head = rest.remove(at: index)
            return permutations(rest).map { [head] + $0 }
        }
    }

    // MARK: - True positives

    /// The axios-style install: npm (as node) runs a lifecycle shell whose
    /// setup script writes the payload under /Library/Caches, and the payload
    /// connects out. A second payload process connects later.
    private struct AxiosChain {
        let processes: [Proc]
        let script: Proc
        let setup: Proc
        let payload: Proc
        let seed: Event
        let drop: Event
        let callback: Event
        let laterCallback: Event
    }

    private func axiosChain() -> AxiosChain {
        let npm = Proc.root(99, Self.node, commandLine: "node /opt/homebrew/bin/npm install")
        let script = npm.child(100, "/bin/sh")
        let setup = script.child(101, Self.node, commandLine: "node setup.js")
        let payload = setup.child(102, "/Library/Caches/com.apple.act.mond")
        let secondPayload = setup.child(103, "/Library/Caches/com.apple.act.mond")
        return AxiosChain(
            processes: [npm, script, setup, payload, secondPayload], script: script, setup: setup,
            payload: payload, seed: exec(script, at: 0),
            drop: write(setup, "/Library/Caches/com.apple.act.mond", at: 1),
            callback: connect(payload, at: 2), laterCallback: connect(secondPayload, at: 3)
        )
    }

    @Test("An axios-style callback evaluated before its drop completes the rule on the drop")
    func callbackBeforeDropCompletesOnDrop() async throws {
        let chain = axiosChain()
        let run = try await deliver([chain.seed, chain.callback, chain.drop], rule: npmRat,
                                    processes: chain.processes)
        #expect(run.counts == [0, 0, 1])
        let completion = try #require(run.completions.first { $0.match.ruleId == npmRat })
        #expect(completion.trigger.id == chain.drop.id)
        #expect(boundSteps(completion.match)
                    == ["postinstall (pid:100", "drop_payload (pid:101", "c2_callback (pid:102"])
        let capture = try await run.engine.checkpointCapture()
        #expect(!capture.partialBuckets.contains { $0.ruleID == npmRat }, "the completed partial left the pool")
        let retained = capture.pendingBuckets.first { $0.ruleID == npmRat }?.steps.map(\.matched.eventID) ?? []
        #expect(Set(retained) == [chain.callback.id, chain.drop.id], "the replay consumed no history")
        #expect(await run.engine.pendingStepConservationByRule()[npmRat] == ledger(offered: 2, queued: 2))
    }

    @Test("Every delivery order of seed, drop and callback completes the rule once, on the last event")
    func everyOrderCompletesOnceOnTheLastEvent() async throws {
        let chain = axiosChain()
        for order in permutations([chain.seed, chain.drop, chain.callback]) {
            let run = try await deliver(order, rule: npmRat, processes: chain.processes)
            #expect(run.counts == [0, 0, 1], "\(order.map(\.eventCategory))")
            #expect(await run.engine.pendingStepConservationByRule()[npmRat] == ledger(offered: 2, queued: 2))
            let capture = try await run.engine.checkpointCapture()
            #expect(!capture.partialBuckets.contains { $0.ruleID == npmRat })
        }
    }

    @Test("A second callback after the completing event fires nothing more", arguments: [false, true])
    func secondCallbackFiresNothingMore(callbackFirst: Bool) async throws {
        let chain = axiosChain()
        let order = callbackFirst
            ? [chain.seed, chain.callback, chain.drop, chain.laterCallback]
            : [chain.seed, chain.drop, chain.callback, chain.laterCallback]
        let run = try await deliver(order, rule: npmRat, processes: chain.processes)
        #expect(run.counts == [0, 0, 1, 0])
        let completion = try #require(run.completions.first { $0.match.ruleId == npmRat })
        #expect(boundSteps(completion.match).last == "c2_callback (pid:102", "the earliest callback is bound")
    }

    /// The other stable three-step chains, each delivered with its last step
    /// before its middle step.
    enum InvertedChain: CaseIterable, Sendable {
        case supplyChainPersistence
        case wormCredentialRead
        case typosquatCallhome
        case ransomwareInhibit
    }

    private func invertedChain(_ shape: InvertedChain) -> (rule: String, processes: [Proc], events: [Event]) {
        switch shape {
        case .supplyChainPersistence:
            let install = Proc.root(100, "/usr/local/bin/node", commandLine: "node /usr/local/bin/npm install evil")
            let script = install.child(101, "/bin/sh")
            return (supplyChain, [install, script], [
                exec(install, at: 0), connect(script, at: 2),
                write(script, "/Users/t/Library/LaunchAgents/com.example.agent.plist", at: 1),
            ])
        case .wormCredentialRead:
            let npm = Proc.root(99, "/usr/local/bin/npm")
            let stage = npm.child(100, "/tmp/stage")
            let helper = stage.child(101, "/tmp/stage-helper")
            return (worm, [npm, stage, helper], [
                exec(stage, at: 0), connect(helper, hostname: "registry.npmjs.org", at: 2),
                write(helper, "/Users/t/.aws/credentials", action: .open, at: 1),
            ])
        case .typosquatCallhome:
            let npm = Proc.root(100, "/usr/local/bin/npm", commandLine: "npm install evil-pkg")
            let payload = npm.child(101, "/tmp/payload")
            return (typosquat, [npm, payload], [
                exec(npm, at: 0), write(payload, "/Users/t/Library/LaunchAgents/typo.plist", at: 2),
                connect(payload, at: 1),
            ])
        case .ransomwareInhibit:
            let curl = Proc.root(99, "/usr/bin/curl")
            let shell = curl.child(100, "/bin/bash")
            let inhibit = shell.child(101, "/usr/bin/tmutil", commandLine: "tmutil disable")
            let wipe = shell.child(102, "/bin/dd", commandLine: "dd if=/dev/zero of=/Users/t/vault")
            return (ransomware, [curl, shell, inhibit, wipe], [
                exec(shell, at: 0), exec(wipe, at: 2), exec(inhibit, at: 1),
            ])
        }
    }

    @Test("The other stable three-step chains complete on their middle step when the last step came first",
          arguments: InvertedChain.allCases)
    func otherChainsCompleteOnTheirMiddleStep(shape: InvertedChain) async throws {
        let chain = invertedChain(shape)
        let run = try await deliver(chain.events, rule: chain.rule, processes: chain.processes)
        #expect(run.counts == [0, 0, 1])
        let capture = try await run.engine.checkpointCapture()
        #expect(!capture.partialBuckets.contains { $0.ruleID == chain.rule })
    }

    // MARK: - Processing-time windows

    /// Restores, as a checkpoint taken at `now`, one npm_postinstall_to_rat
    /// partial holding only `script`'s seed (event time `offset`, evaluated at
    /// `createdAt`) and the given retained callbacks.
    private func restoreSeed(
        _ engine: SequenceEngine, script: Proc, seedAt offset: TimeInterval, createdAt: Date,
        callbacks: [SequenceCheckpointPendingStep], now: Date
    ) async throws {
        let partial = SequenceCheckpointPartial(
            id: UUID(), ruleID: npmRat, createdAt: createdAt,
            matchedSteps: [SequenceCheckpointMatchedStep(
                stepID: "postinstall", eventID: UUID(), timestamp: base.addingTimeInterval(offset),
                processPID: script.pid, processParentPID: script.parent, processParentWasTracked: true,
                processAncestorPIDs: [1, script.parent], filePath: nil, networkDestination: nil
            )],
            correlationKey: String(script.pid)
        )
        let payload = SequenceCheckpointPayload(
            schemaVersion: SequenceCheckpointPayload.currentSchemaVersion, capturedAt: now,
            ruleFingerprint: try SequenceCheckpointCodec.ruleFingerprint(await engine.listRules()),
            sourceGeneration: 1,
            partialBuckets: [SequenceCheckpointPartialBucket(ruleID: npmRat, partials: [partial])],
            pendingBuckets: callbacks.isEmpty ? [] : [SequenceCheckpointPendingBucket(ruleID: npmRat, steps: callbacks)],
            evictionOrder: [partial.id],
            pendingEvictionOrder: callbacks.map {
                SequenceCheckpointPendingIdentity(ruleID: npmRat, stepID: $0.stepID, eventID: $0.matched.eventID)
            }
        )
        let restored = try await engine.restoreCheckpoint(payload, now: now)
        #expect(restored.partialCount == 1 && restored.pendingCount == callbacks.count)
    }

    /// A retained callback by the axios payload at event time `offset`,
    /// admitted at `arrivedAt`, with the ancestry its evaluation recorded.
    private func retainedCallback(_ chain: AxiosChain, at offset: TimeInterval,
                                  arrivedAt: Date) -> SequenceCheckpointPendingStep {
        SequenceCheckpointPendingStep(
            ruleID: npmRat, stepID: "c2_callback",
            matched: SequenceCheckpointMatchedStep(
                stepID: "c2_callback", eventID: UUID(), timestamp: base.addingTimeInterval(offset),
                processPID: chain.payload.pid, processParentPID: chain.setup.pid, processParentWasTracked: true,
                processAncestorPIDs: [1, chain.script.parent, chain.script.pid, chain.setup.pid],
                filePath: nil, networkDestination: "93.184.216.34:443"
            ),
            arrivedAt: arrivedAt
        )
    }

    /// The seed (event time 0) was evaluated at T = 100, the callback (t = 95)
    /// at T = 96, before the seed, and the drop (t = 90) at T = 130, now. At the
    /// drop the partial is 30 s old and the callback 34 s, so both 60 s windows
    /// hold, although the chain spans 95 s of event time. Live Phase 1 does
    /// the same when the callback is delivered right after the drop. Without
    /// the lag the seed would have been evaluated at T = 40, and its partial
    /// would have expired 30 s before the drop.
    @Test("A lagged seed stretches the event-time span replay on advance completes by exactly its lag")
    func laggedSeedStretchesTheCompletedSpan() async throws {
        let chain = axiosChain()
        let drop = write(chain.setup, "/Library/Caches/com.apple.act.mond", at: 90)

        let replayed = try await stableEngine(chain.processes)
        // Taken after the first engine is built, which may wait for the
        // one-time rule compile, so the windows measure only engine work.
        let reference = Date()
        try await restoreSeed(replayed, script: chain.script, seedAt: 0, createdAt: reference.addingTimeInterval(-30),
                              callbacks: [retainedCallback(chain, at: 95, arrivedAt: reference.addingTimeInterval(-34))],
                              now: reference.addingTimeInterval(-30))
        let viaReplay = try await deliver([drop], rule: npmRat, processes: chain.processes, into: replayed)
        #expect(viaReplay.counts == [1])

        let live = try await stableEngine(chain.processes)
        try await restoreSeed(live, script: chain.script, seedAt: 0, createdAt: reference.addingTimeInterval(-30),
                              callbacks: [], now: reference.addingTimeInterval(-30))
        let viaLive = try await deliver([drop, connect(chain.payload, at: 95)], rule: npmRat,
                                        processes: chain.processes, into: live)
        #expect(viaLive.counts == [0, 1])
        let replayedMatch = try #require(viaReplay.completions.first { $0.match.ruleId == npmRat })
        let liveMatch = try #require(viaLive.completions.first { $0.match.ruleId == npmRat })
        #expect(boundSteps(replayedMatch.match) == boundSteps(liveMatch.match))
        #expect(boundSteps(replayedMatch.match)
                    == ["postinstall (pid:100", "drop_payload (pid:101", "c2_callback (pid:102"])

        let unlagged = try await stableEngine(chain.processes)
        try await restoreSeed(unlagged, script: chain.script, seedAt: 0, createdAt: reference.addingTimeInterval(-90),
                              callbacks: [], now: reference.addingTimeInterval(-50))
        let inTime = try await deliver([drop, connect(chain.payload, at: 95)], rule: npmRat,
                                       processes: chain.processes, into: unlagged)
        #expect(inTime.counts == [0, 0], "evaluated at their event times, the seed's partial has expired")
    }

    @Test("A callback past its window at the drop is skipped, not retired, and completes nothing")
    func expiredCallbackIsSkipped() async throws {
        let chain = axiosChain()
        let engine = try await stableEngine(chain.processes)
        // After the build, as above: a slow compile must not expire the
        // partial and skip the case under test.
        let reference = Date()
        let callback = retainedCallback(chain, at: 2, arrivedAt: reference.addingTimeInterval(-70))
        try await restoreSeed(engine, script: chain.script, seedAt: 0, createdAt: reference.addingTimeInterval(-30),
                              callbacks: [callback], now: reference.addingTimeInterval(-30))
        let drop = write(chain.setup, "/Library/Caches/com.apple.act.mond", at: 1)
        let run = try await deliver([drop], rule: npmRat, processes: chain.processes, into: engine)
        #expect(run.counts == [0])
        let capture = try await engine.checkpointCapture()
        let retained = capture.pendingBuckets.first { $0.ruleID == npmRat }?.steps.map(\.matched.eventID) ?? []
        #expect(Set(retained) == [callback.matched.eventID, drop.id], "the sweep, not the replay, retires it")
        #expect(await engine.pendingStepConservationByRule()[npmRat] == ledger(offered: 2, queued: 2))
    }

    // MARK: - Benign shapes

    /// A rule's chain as delivered: the events that open it, a middle-step
    /// candidate and a later-step candidate, over one process tree.
    private struct Chain {
        let rule: String
        let processes: [Proc]
        let opening: [Event]
        let middle: Event
        let later: Event

        var inOrder: [Event] { opening + [middle, later] }
        var inverted: [Event] { opening + [later, middle] }
    }

    /// Benign shapes whose rule must never complete (FP1-FP12). The first
    /// eight are also delivered in every order.
    enum BenignShape: CaseIterable, Sendable {
        /// Playwright's default browser cache under ~/Library/Caches is not a drop prefix.
        case playwrightDefaultCache
        /// The browser writing a trace under /private/tmp is not a listed writer.
        case browserArtifactUnderTmp
        /// The seed's own write and connection: a strict descendant excludes itself.
        case seedWritesAndConnectsItself
        /// The only public connection is the package manager's, the seed's parent.
        case registryTrafficFromNpm
        /// os.tmpdir() under /private/var/folders is not a drop prefix.
        case nodeTemporaryDirectory
        /// The only connection precedes the write in event time.
        case connectionBeforeWrite
        /// Loopback is a private destination.
        case loopbackDestination
        /// RFC 1918 is a private destination.
        case privateDestination
        /// One lifecycle script's child writes, a sibling script's child connects.
        case siblingScripts
        /// A native agent's zsh is no seed.
        case nativeAgentShell
        /// An interactive npm publish reads ~/.npmrc itself, not as a lifecycle descendant.
        case interactivePublish
        /// A node server is not a package install.
        case nonInstallNode
        /// pnpm's own node callhome is filtered, so the middle step never matches.
        case pnpmNodeCallhome

        var everyOrder: Bool {
            switch self {
            case .nativeAgentShell, .interactivePublish, .nonInstallNode, .pnpmNodeCallhome: false
            default: true
            }
        }
    }

    private func benignChain(_ shape: BenignShape) -> Chain {
        let npm = Proc.root(99, Self.node, commandLine: "node /opt/homebrew/bin/npm install")
        let script = npm.child(100, "/bin/sh")
        let builder = script.child(101, Self.node, commandLine: "node build.js")
        let scripted = [npm, script, builder]
        switch shape {
        case .playwrightDefaultCache:
            let installer = npm.child(100, Self.node, commandLine: "node install.js")
            let downloader = installer.child(101, Self.node, commandLine: "node oopDownloadBrowserMain.js")
            return Chain(rule: npmRat, processes: [npm, installer, downloader], opening: [exec(installer, at: 0)],
                         middle: write(downloader, "/Users/t/Library/Caches/ms-playwright/chromium-1155/chrome-mac/Chromium",
                                       at: 1),
                         later: connect(downloader, at: 2))
        case .browserArtifactUnderTmp:
            let worker = npm.child(100, Self.node, commandLine: "node playwright/test/worker.js")
            let browser = worker.child(101, "/private/tmp/ms-playwright/chromium_headless_shell-1155/chrome-mac/headless_shell")
            return Chain(rule: npmRat, processes: [npm, worker, browser], opening: [exec(worker, at: 0)],
                         middle: write(browser, "/private/tmp/playwright-artifacts-x/trace.zip", at: 1),
                         later: connect(browser, at: 2))
        case .seedWritesAndConnectsItself:
            let installer = npm.child(100, Self.node, commandLine: "node install.js")
            return Chain(rule: npmRat, processes: [npm, installer], opening: [exec(installer, at: 0)],
                         middle: write(installer, "/private/tmp/ms-playwright/x", at: 1),
                         later: connect(installer, at: 2))
        case .registryTrafficFromNpm:
            let cli = Proc.root(99, "/usr/local/bin/npm", commandLine: "npm install")
            let lifecycle = cli.child(100, "/bin/sh")
            let writer = lifecycle.child(101, Self.node)
            return Chain(rule: npmRat, processes: [cli, lifecycle, writer], opening: [exec(lifecycle, at: 0)],
                         middle: write(writer, "/private/tmp/x", at: 1),
                         later: connect(cli, to: "104.16.3.35", at: 2))
        case .nodeTemporaryDirectory:
            return Chain(rule: npmRat, processes: scripted, opening: [exec(script, at: 0)],
                         middle: write(builder, "/private/var/folders/00/fixture/T/x", at: 1),
                         later: connect(builder, at: 2))
        case .connectionBeforeWrite:
            return Chain(rule: npmRat, processes: scripted, opening: [exec(script, at: 0)],
                         middle: write(builder, "/private/tmp/x", at: 2), later: connect(builder, at: 1))
        case .loopbackDestination:
            return Chain(rule: npmRat, processes: scripted, opening: [exec(script, at: 0)],
                         middle: write(builder, "/private/tmp/x", at: 1),
                         later: connect(builder, to: "127.0.0.1", at: 2))
        case .privateDestination:
            return Chain(rule: npmRat, processes: scripted, opening: [exec(script, at: 0)],
                         middle: write(builder, "/private/tmp/x", at: 1),
                         later: connect(builder, to: "10.0.0.5", at: 2))
        case .siblingScripts:
            let sibling = npm.child(110, "/bin/sh")
            let caller = sibling.child(111, Self.node)
            return Chain(rule: npmRat, processes: scripted + [sibling, caller],
                         opening: [exec(script, at: 0), exec(sibling, at: 0.5)],
                         middle: write(builder, "/private/tmp/x", at: 1), later: connect(caller, at: 2))
        case .nativeAgentShell:
            let agent = Proc.root(99, "/Users/t/.local/share/claude/versions/2.1.317")
            let shell = agent.child(100, "/bin/zsh")
            let tool = shell.child(101, Self.node)
            return Chain(rule: npmRat, processes: [agent, shell, tool], opening: [exec(shell, at: 0)],
                         middle: write(shell, "/private/tmp/claude-501/x", at: 1), later: connect(tool, at: 2))
        case .interactivePublish:
            let shell = Proc.root(99, "/bin/zsh")
            let cli = shell.child(100, "/usr/local/bin/npm", commandLine: "npm publish")
            let lifecycle = cli.child(101, "/bin/sh")
            return Chain(rule: worm, processes: [shell, cli, lifecycle],
                         opening: [exec(cli, at: 0), exec(lifecycle, at: 0.5)],
                         middle: write(cli, "/Users/t/.npmrc", action: .open, at: 1),
                         later: connect(cli, to: "104.16.3.35", hostname: "registry.npmjs.org", at: 2))
        case .nonInstallNode:
            let server = Proc.root(100, "/usr/local/bin/node", commandLine: "node /Users/t/app/server.js")
            let helper = server.child(101, "/Users/t/app/bin/helper")
            return Chain(rule: supplyChain, processes: [server, helper], opening: [exec(server, at: 0)],
                         middle: write(helper, "/Users/t/Library/LaunchAgents/sc.plist", at: 1),
                         later: connect(helper, at: 2))
        case .pnpmNodeCallhome:
            let pnpm = Proc.root(100, "/usr/local/bin/pnpm", commandLine: "pnpm install")
            let tool = pnpm.child(101, "/usr/local/bin/node")
            return Chain(rule: typosquat, processes: [pnpm, tool], opening: [exec(pnpm, at: 0)],
                         middle: connect(tool, at: 1), later: write(tool, "/Users/t/.zshrc", at: 2))
        }
    }

    @Test("Benign install, test and agent shapes never complete their rule", arguments: BenignShape.allCases)
    func benignShapesNeverComplete(shape: BenignShape) async throws {
        let chain = benignChain(shape)
        let orders = shape.everyOrder ? permutations(chain.inOrder) : [chain.inOrder, chain.inverted]
        for order in orders {
            let run = try await deliver(order, rule: chain.rule, processes: chain.processes)
            #expect(run.fires == 0, "\(shape): \(order.map(\.eventCategory))")
        }
    }

    // MARK: - Known benign classes

    /// Benign shapes that already complete their rule in event order (E1-E6).
    /// Replay on advance makes them complete the same way when the later step
    /// is evaluated first; it adds no new class.
    enum EquivalentShape: CaseIterable, Sendable {
        /// A lifecycle shell's curl downloads into /private/tmp and connects.
        case lifecycleCurlDownload
        /// Playwright with its browsers path under /private/tmp: the
        /// out-of-process downloader writes and connects.
        case playwrightBrowsersUnderTmp
        /// A node-hosted agent's bash runs curl -o into /private/tmp.
        case nodeAgentCurl
        /// npm install's lifecycle shell writes a LaunchAgent and connects.
        case installWritesLaunchAgent
        /// A lifecycle shell's npm reads ~/.npmrc and contacts the registry.
        case npmrcThenRegistry
        /// An e2e project under /private/tmp: the dev server writes and the
        /// browser connects.
        case e2eProjectUnderTmp
    }

    private func equivalentChain(_ shape: EquivalentShape) -> Chain {
        let npm = Proc.root(99, Self.node, commandLine: "node /opt/homebrew/bin/npm install")
        switch shape {
        case .lifecycleCurlDownload:
            let script = npm.child(100, "/bin/sh", commandLine: "sh -c curl -o /private/tmp/pkg.tgz")
            let curl = script.child(101, "/usr/bin/curl", commandLine: "curl -o /private/tmp/pkg.tgz")
            return Chain(rule: npmRat, processes: [npm, script, curl],
                         opening: [exec(script, at: 0), exec(curl, at: 0.5)],
                         middle: write(curl, "/private/tmp/pkg.tgz", at: 1), later: connect(curl, at: 2))
        case .playwrightBrowsersUnderTmp:
            let script = npm.child(100, "/bin/sh", commandLine: "sh -c node install.js")
            let installer = script.child(101, Self.node, commandLine: "node install.js")
            let downloader = installer.child(102, Self.node, commandLine: "node oopDownloadBrowserMain.js")
            return Chain(rule: npmRat, processes: [npm, script, installer, downloader],
                         opening: [exec(script, at: 0), exec(installer, at: 0.2), exec(downloader, at: 0.4)],
                         middle: write(downloader, "/private/tmp/pw-browsers/chromium-1155/chrome-mac/Chromium",
                                       at: 1),
                         later: connect(downloader, at: 2))
        case .nodeAgentCurl:
            let agent = Proc.root(99, Self.node, commandLine: "node /Users/t/.local/lib/agent/cli.js")
            let shell = agent.child(100, "/bin/bash", commandLine: "bash -c curl -o /private/tmp/x")
            let curl = shell.child(101, "/usr/bin/curl", commandLine: "curl -o /private/tmp/x")
            return Chain(rule: npmRat, processes: [agent, shell, curl],
                         opening: [exec(shell, at: 0), exec(curl, at: 0.5)],
                         middle: write(curl, "/private/tmp/x", at: 1), later: connect(curl, at: 2))
        case .installWritesLaunchAgent:
            let install = Proc.root(100, Self.node, commandLine: "node /opt/homebrew/bin/npm install")
            let script = install.child(101, "/bin/sh")
            return Chain(rule: supplyChain, processes: [install, script],
                         opening: [exec(install, at: 0), exec(script, at: 0.5)],
                         middle: write(script, "/Users/t/Library/LaunchAgents/x.plist", at: 1),
                         later: connect(script, at: 2))
        case .npmrcThenRegistry:
            let host = Proc.root(99, Self.node, commandLine: "node /Users/t/.local/lib/agent/cli.js")
            let script = host.child(100, "/bin/sh")
            let cli = script.child(101, "/usr/local/bin/npm", commandLine: "npm publish")
            return Chain(rule: worm, processes: [host, script, cli],
                         opening: [exec(script, at: 0), exec(cli, at: 0.5)],
                         middle: write(cli, "/Users/t/.npmrc", action: .open, at: 1),
                         later: connect(cli, to: "104.16.3.35", hostname: "registry.npmjs.org", at: 2))
        case .e2eProjectUnderTmp:
            let tests = Proc.root(99, Self.node, commandLine: "node /opt/homebrew/bin/npm run test:e2e")
            let script = tests.child(100, "/bin/sh", commandLine: "sh -c playwright test")
            let testHost = script.child(101, Self.node, commandLine: "node playwright test")
            let devServer = testHost.child(102, Self.node, commandLine: "node next dev")
            let browser = testHost.child(103, "/private/tmp/ms-playwright/chromium_headless_shell-1155/chrome-mac/headless_shell")
            return Chain(rule: npmRat, processes: [tests, script, testHost, devServer, browser],
                         opening: [exec(script, at: 0), exec(testHost, at: 0.2), exec(devServer, at: 0.4),
                                   exec(browser, at: 0.6)],
                         middle: write(devServer, "/private/tmp/e2e-project/.next/cache/webpack/client.pack", at: 1),
                         later: connect(browser, at: 2))
        }
    }

    @Test("Known benign classes complete once in event order and once inverted, binding the same processes",
          arguments: EquivalentShape.allCases)
    func knownClassesCompleteAlikeInEitherOrder(shape: EquivalentShape) async throws {
        let chain = equivalentChain(shape)
        let ordered = try await deliver(chain.inOrder, rule: chain.rule, processes: chain.processes)
        let inverted = try await deliver(chain.inverted, rule: chain.rule, processes: chain.processes)
        #expect(ordered.fires == 1 && inverted.fires == 1)
        let orderedCompletion = try #require(ordered.completions.first { $0.match.ruleId == chain.rule })
        let invertedCompletion = try #require(inverted.completions.first { $0.match.ruleId == chain.rule })
        #expect(boundSteps(orderedCompletion.match) == boundSteps(invertedCompletion.match))
        #expect(orderedCompletion.trigger.id == chain.later.id)
        #expect(invertedCompletion.trigger.id == chain.middle.id, "inverted, the alert attaches to the middle event")
    }

    // MARK: - Install burst

    /// The per-rule alert deduplication key: the rule and the executable of
    /// the event whose evaluation returned the completion.
    private struct AlertKey: Hashable, CustomStringConvertible {
        let ruleID: String
        let executable: String
        var description: String { "\(ruleID) \(executable)" }
    }

    /// One npm install: twelve lifecycle scripts at 5 s intervals, each with
    /// one writer under /private/tmp (node, curl or bash, in turn). node and
    /// curl connect themselves; bash's traffic comes from its git child.
    private func installBurst() -> (processes: [Proc], events: [Event]) {
        let shell = Proc.root(900, "/bin/zsh")
        let npm = shell.child(1_000, Self.node, commandLine: "node /opt/homebrew/bin/npm install")
        let writerImages = [Self.node, "/usr/bin/curl", "/bin/bash"]
        var processes = [shell, npm]
        var events = [exec(npm, at: -1)]
        for index in 0..<12 {
            let start = 5 * Double(index)
            let script = npm.child(1_100 + Int32(index), "/bin/sh", commandLine: "sh -c install")
            let writer = script.child(1_200 + Int32(index), writerImages[index % 3])
            processes += [script, writer]
            events += [
                exec(script, at: start), exec(writer, at: start + 0.5),
                write(writer, "/private/tmp/tc-install/pkg-\(index)/part-1", at: start + 1),
                write(writer, "/private/tmp/tc-install/pkg-\(index)/part-2", at: start + 2),
            ]
            var caller = writer
            if index % 3 == 2 {
                caller = writer.child(1_300 + Int32(index), "/usr/bin/git", commandLine: "git fetch")
                processes.append(caller)
                events.append(exec(caller, at: start + 2.5))
            }
            events.append(connect(caller, at: start + 3))
        }
        return (processes, events)
    }

    @Test("An install burst with lagging writes completes as often as in event order, keyed on its writers")
    func installBurstUnderFileLaneLag() async throws {
        let burst = installBurst()
        // The file lane runs 25 s behind the priority lane, so every write is
        // evaluated after its chain's connection.
        func processedAt(_ event: Event) -> Date {
            event.eventCategory == .file ? event.timestamp.addingTimeInterval(25) : event.timestamp
        }
        let inOrder = burst.events.enumerated()
            .sorted { ($0.element.timestamp, $0.offset) < ($1.element.timestamp, $1.offset) }
            .map(\.element)
        let lagged = burst.events.enumerated()
            .sorted { (processedAt($0.element), $0.offset) < (processedAt($1.element), $1.offset) }
            .map(\.element)
        let ordered = try await deliver(inOrder, rule: npmRat, processes: burst.processes)
        let delayed = try await deliver(lagged, rule: npmRat, processes: burst.processes)

        #expect(ordered.fires == 12)
        #expect(delayed.fires == ordered.fires, "the lag changes neither the count nor the bound processes")
        #expect(Set(delayed.completions.map { boundSteps($0.match) })
                    == Set(ordered.completions.map { boundSteps($0.match) }))
        #expect(delayed.completions.allSatisfy { $0.trigger.eventCategory == .file })
        func keys(_ run: Delivery) -> Set<AlertKey> {
            Set(run.completions.map { AlertKey(ruleID: $0.match.ruleId, executable: $0.trigger.process.executable) })
        }
        // One stored alert per key and hour: in event order the connecting
        // process names the alert; lagged, the writer does.
        #expect(keys(ordered) == [AlertKey(ruleID: npmRat, executable: Self.node),
                                  AlertKey(ruleID: npmRat, executable: "/usr/bin/curl"),
                                  AlertKey(ruleID: npmRat, executable: "/usr/bin/git")])
        #expect(keys(delayed) == [AlertKey(ruleID: npmRat, executable: Self.node),
                                  AlertKey(ruleID: npmRat, executable: "/usr/bin/curl"),
                                  AlertKey(ruleID: npmRat, executable: "/bin/bash")])
    }
}
