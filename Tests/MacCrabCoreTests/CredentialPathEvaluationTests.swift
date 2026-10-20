import Foundation
import Testing
@testable import MacCrabCore

/// Inert strings only: no path is opened, no collector or response is started.
@Suite("Credential path evaluation preserves original matching semantics")
struct CredentialPathEvaluationTests {
    /// Deliberately retains the pre-optimization operations, including folding
    /// each pattern inside the loop. This is an oracle, not another fast path.
    private func originalMatch(
        _ input: String,
        custom: [CredentialFence.SensitivePath] = []
    ) -> CredentialFence.CredentialType? {
        let path = input.lowercased()
        let filename = (path as NSString).lastPathComponent
        for fragment in ["/library/application support/maccrab/", "/.maccrab/",
                         "/decoys/", "/t/tcc-home-"] where path.contains(fragment) {
            return nil
        }
        if filename.hasPrefix(".env") {
            for suffix in [".example", ".sample", ".template", ".dist", ".tmpl"]
                where filename.hasSuffix(suffix) { return nil }
        }
        if filename.hasSuffix(".pub") { return nil }
        if path.contains("/system/library/keychains/") { return nil }
        for item in CredentialFence.defaultPaths + custom {
            let pattern = item.pattern.lowercased()
            switch item.kind {
            case .exactFilename:
                if filename == pattern { return item.type }
            case .filenamePrefix:
                if filename.hasPrefix(pattern) { return item.type }
            case .pathFragment:
                if path.contains(pattern) { return item.type }
            }
        }
        return nil
    }

    @Test("Every default pattern and exclusion agrees with the original operations")
    func builtInCorpusAndExclusions() {
        let fence = CredentialFence()
        var inputs = ["", "/", "/fixture/project/ordinary.swift", "/fixture/Cookies.tsx",
                      "/fixture/.env.example", "/fixture/.env.sample", "/fixture/.env.tmpl",
                      "/fixture/.ssh/id_rsa.pub", "/System/Library/Keychains/ordinary",
                      "/Library/Application Support/MacCrab/.env", "/fixture/.maccrab/.env",
                      "/fixture/decoys/.env", "/fixture/T/tcc-home-unit/.env"]
        for item in CredentialFence.defaultPaths {
            switch item.kind {
            case .pathFragment:
                inputs.append("/fixture" + item.pattern + "/ordinary")
            case .exactFilename:
                inputs.append("/fixture/" + item.pattern)
            case .filenamePrefix:
                inputs.append("/fixture/" + item.pattern + "unit")
            }
        }
        for input in inputs {
            for variant in [input, input.uppercased(), input.decomposedStringWithCanonicalMapping] {
                let expected = originalMatch(variant)
                #expect(fence.checkAccess(filePath: variant) == expected)
                #expect(CredentialFence.defaultCredentialType(filePath: variant) == expected)
            }
        }
    }

    @Test("Custom Unicode patterns retain Foundation canonical and case semantics")
    func customUnicodePatterns() {
        let custom: [CredentialFence.SensitivePath] = [
            .init("/Café/", type: .gcpCredential),
            .init("İtem", type: .azureCredential, kind: .exactFilename),
            .init("Σήμα", type: .slackToken, kind: .filenamePrefix),
            .init("/Straße/", type: .githubToken),
            .init("/資料/", type: .dockerAuth),
            .init("/👩🏽‍💻/", type: .kubeConfig),
        ]
        let inputs = ["/fixture/Café/item", "/fixture/Cafe\u{301}/item",
                      "/fixture/CAFÉ/item", "/fixture/İtem", "/fixture/i\u{307}tem",
                      "/fixture/Σήμα-unit", "/fixture/σήμα-unit", "/fixture/STRASSE/item",
                      "/fixture/Straße/item", "/fixture/資料/item", "/fixture/👩🏽‍💻/item",
                      "/fixture/👩‍💻/item", "/fixture/ordinary"]
        let fence = CredentialFence(customPaths: custom)
        for input in inputs {
            #expect(fence.checkAccess(filePath: input) == originalMatch(input, custom: custom))
        }
        #expect(fence.checkAccess(filePath: "/fixture/Cafe\u{301}/item") == .gcpCredential)
        #expect(fence.checkAccess(filePath: "/fixture/資料/item") == .dockerAuth)
    }

    @Test("Default-first and custom-first precedence remain immutable per instance")
    func orderingAndIndependentConfigurations() {
        let first = CredentialFence.SensitivePath("/shared-unit/", type: .gcpCredential)
        let second = CredentialFence.SensitivePath("/shared-unit/", type: .azureCredential)
        var configuration = [first, second,
                             .init("/fixture/", type: .slackToken)]
        let original = CredentialFence(customPaths: configuration)
        configuration[0] = second
        let updated = CredentialFence(customPaths: configuration)
        #expect(original.checkAccess(filePath: "/fixture/shared-unit/item") == .gcpCredential)
        #expect(updated.checkAccess(filePath: "/fixture/shared-unit/item") == .azureCredential)
        #expect(original.checkAccess(filePath: "/fixture/.aws/credentials") == .awsCredential)
        #expect(updated.checkAccess(filePath: "/fixture/.aws/credentials") == .awsCredential)
        #expect(CredentialFence().checkAccess(filePath: "/fixture/shared-unit/item") == nil)
    }

    @Test("Empty patterns and all three custom match kinds keep the exact old behavior")
    func emptyAndMixedKinds() {
        for kind in [CredentialFence.MatchKind.pathFragment, .exactFilename, .filenamePrefix] {
            let custom = [CredentialFence.SensitivePath("", type: .slackToken, kind: kind)]
            let fence = CredentialFence(customPaths: custom)
            for input in ["", "/", "/fixture/ordinary", "/fixture/.env.example", "/fixture/.ssh/id_rsa"] {
                #expect(fence.checkAccess(filePath: input) == originalMatch(input, custom: custom))
            }
        }
    }

    @Test("All relevance and independent-evidence combinations preserve the original Boolean")
    func graphPolicyEquivalence() {
        let paths: [String?] = [nil, "/fixture/ordinary.swift", "/fixture/.aws/credentials",
                               "/fixture/Library/Safari/History.db", "/fixture/.claude/skills/unit.md",
                               "/fixture/資料/ordinary"]
        for path in paths {
            for kind in FileKind.allCases {
                for untrusted in [false, true] {
                    let relevantKind = [FileKind.credentialFile, .launchAgent, .launchDaemon,
                                        .loginItem, .shellProfile].contains(kind)
                    let originalRelevant = untrusted
                        || (path.map { ESCollector.isCredentialReadPath($0) } ?? false)
                        || relevantKind
                    #expect(TraceGraphFileObservationPolicy.isRelevant(
                        path: path, kind: kind, untrustedContent: untrusted) == originalRelevant)
                    guard let path else { continue }
                    for flags in 0..<16 {
                        let agent = flags & 1 != 0
                        let network = flags & 2 != 0
                        let lineage = flags & 4 != 0
                        let anchor = flags & 8 != 0
                        let originalSuppression = !originalRelevant
                            && !agent && !network && !lineage && !anchor
                        #expect(TraceGraphFileObservationPolicy.canSuppressPhysicalWrite(
                            path: path, kind: kind, untrustedContent: untrusted,
                            hasAgent: agent, hasNetwork: network,
                            hasProcessLineage: lineage, processCanAnchor: anchor) == originalSuppression)
                    }
                }
            }
        }
    }
}

@Suite("Graph classification is local to each inert observation")
struct GraphClassificationReuseTests {
    @Test("Kind reuse preserves retained file truth and does not cache across observations")
    func privateStoreIntegration() async throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("graph-classification-unit-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: root) }
        let store = try await SQLiteCausalGraphStore(databasePath: root.appendingPathComponent("owned.sqlite").path)
        do {
            let graph = RollingCausalGraph(store: store, materializer: TraceMaterializer(store: store))
            let now = Date(timeIntervalSince1970: 1_700_000_000)
            let process = RollingCausalGraph.ProcessObservation(
                processKey: "inert-classifier-process", pid: 123,
                executablePath: "/usr/bin/true", isAppleSigned: true,
                isNotarized: true, startTime: now)
            let fixtures: [(String, String, Bool, FileKind?)] = [
                ("ordinary", "/fixture/ordinary.txt", false, nil),
                ("same-path-enriched", "/fixture/ordinary.txt", true, .unknown),
                ("credential", "/fixture/.aws/credentials", false, .credentialFile),
                ("broad-sensitive", "/fixture/Library/Safari/History.db", false, .unknown),
            ]
            for (index, fixture) in fixtures.enumerated() {
                let (key, path, untrusted, expectedKind) = fixture
                _ = try await graph.ingest(.init(
                    eventId: "inert-classifier-\(index)", timestamp: now.addingTimeInterval(Double(index)),
                    category: .file, action: .fileRead, process: process,
                    file: .init(path: path, pathHash: key, untrustedContent: untrusted)))
                try await graph.flushPending()
                let stored = try await store.entity(id: "file:" + key)
                if let expectedKind {
                    let entity = try #require(stored)
                    let decoder = JSONDecoder()
                    decoder.dateDecodingStrategy = .millisecondsSince1970
                    let node = try decoder.decode(FileNode.self, from: Data(entity.attributesJson.utf8))
                    #expect(node.path == path)
                    #expect(node.fileKind == expectedKind)
                    #expect(node.untrustedContent == untrusted)
                } else {
                    #expect(stored == nil)
                }
            }
            let telemetry = await graph.writeTelemetry()
            #expect(telemetry.inputEventsTotal == 4)
            #expect(telemetry.eventsCommittedTotal == 4)
            #expect(telemetry.eventsFailedTotal == 0)
            #expect(telemetry.eventsPending == 0)
            #expect(telemetry.physicalWriteSuppressedEventsTotal == 1)
            await store.close()
        } catch {
            await store.close()
            throw error
        }
    }
}

@Suite("Credential ownership: git and SSH keys")
struct CredentialOwnershipGitTests {
    @Test("git owns public SSH files and .netrc, never a private key")
    func gitDoesNotOwnPrivateKeys() {
        let fence = CredentialFence()
        let home = "/Users/x"
        func flagged(_ path: String, _ binary: String) -> Bool {
            fence.checkAccessDetailed(filePath: home + path, aiToolName: "Claude Code",
                                      accessingBinary: binary) != nil
        }
        #expect(flagged("/.ssh/id_rsa", "git"))
        #expect(flagged("/.ssh/id_ed25519", "git"))
        #expect(!flagged("/.ssh/id_ed25519.pub", "git"))
        #expect(!flagged("/.ssh/allowed_signers", "git"))
        #expect(!flagged("/.netrc", "git"))
        // ssh itself still owns its keys.
        #expect(!flagged("/.ssh/id_rsa", "ssh"))
    }
}
