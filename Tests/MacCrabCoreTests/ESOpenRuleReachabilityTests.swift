// Adversarial regression coverage for the ES OPEN admission boundary.
//
// A rule-engine unit test can happily fire on a synthetic OPEN even when the
// collector drops that path before the event reaches the engine. These tests
// exercise both halves together: callback admission and the real compiled rule
// predicates. They also pin the intentional modified-CLOSE rules separately
// from credential-read rules, because unmodified CLOSE is never emitted.

import EndpointSecurity
import Foundation
import Testing
@testable import MacCrabCore

@Suite("ES OPEN rule reachability")
struct ESOpenRuleReachabilityTests {
    private let compiledDir = compiledRulesDirectory
    private let base = Date(timeIntervalSince1970: 1_700_000_000)
    private let rootPid: Int32 = 700
    private let childPid: Int32 = 701

    private enum CorpusError: Error {
        case malformedJSON(String)
    }

    // MARK: - Event builders

    private func process(
        pid: Int32 = 4242,
        executable: String = "/private/tmp/credential-stealer",
        parentExecutable: String? = nil,
        ancestorExecutable: String? = nil,
        commandLine: String? = nil,
        signer: SignerType? = .unsigned
    ) -> MacCrabCore.ProcessInfo {
        var ancestors: [ProcessAncestor] = []
        if let ancestorExecutable {
            ancestors.append(ProcessAncestor(
                pid: pid - 1,
                executable: ancestorExecutable,
                name: (ancestorExecutable as NSString).lastPathComponent
            ))
        } else if let parentExecutable {
            ancestors.append(ProcessAncestor(
                pid: pid - 1,
                executable: parentExecutable,
                name: (parentExecutable as NSString).lastPathComponent
            ))
        }
        let signature = signer.map {
            CodeSignatureInfo(
                signerType: $0, teamId: nil, signingId: nil, authorities: [],
                flags: 0, isNotarized: false, issuerChain: nil,
                certHashes: nil, isAdhocSigned: nil, entitlements: nil
            )
        }
        return MacCrabCore.ProcessInfo(
            pid: pid,
            ppid: pid == childPid ? rootPid : 1,
            rpid: 1,
            name: (executable as NSString).lastPathComponent,
            executable: executable,
            commandLine: commandLine ?? executable,
            args: [executable],
            workingDirectory: "/private/tmp",
            userId: 501,
            userName: "test",
            groupId: 20,
            startTime: base,
            codeSignature: signature,
            ancestors: ancestors,
            architecture: "arm64",
            isPlatformBinary: signer == .apple
        )
    }

    private func fileEvent(
        _ path: String,
        action: FileAction = .open,
        executable: String = "/private/tmp/credential-stealer",
        parentExecutable: String? = nil,
        ancestorExecutable: String? = nil,
        signer: SignerType? = .unsigned,
        pid: Int32 = 4242,
        at offset: TimeInterval = 0,
        enrichments: [String: String] = [:]
    ) -> Event {
        let eventAction: String
        switch action {
        case .close: eventAction = "close_modified"
        default: eventAction = action.rawValue
        }
        return Event(
            timestamp: base.addingTimeInterval(offset),
            eventCategory: .file,
            eventType: .creation,
            eventAction: eventAction,
            process: process(
                pid: pid,
                executable: executable,
                parentExecutable: parentExecutable,
                ancestorExecutable: ancestorExecutable,
                signer: signer
            ),
            file: FileInfo(path: path, action: action),
            enrichments: enrichments
        )
    }

    private func processEvent(
        executable: String,
        pid: Int32,
        parentExecutable: String? = nil,
        commandLine: String? = nil,
        at offset: TimeInterval
    ) -> Event {
        Event(
            timestamp: base.addingTimeInterval(offset),
            eventCategory: .process,
            eventType: .start,
            eventAction: "exec",
            process: process(
                pid: pid,
                executable: executable,
                parentExecutable: parentExecutable,
                commandLine: commandLine,
                signer: .unsigned
            )
        )
    }

    private func networkEvent(at offset: TimeInterval) -> Event {
        Event(
            timestamp: base.addingTimeInterval(offset),
            eventCategory: .network,
            eventType: .creation,
            eventAction: "connect",
            process: process(pid: childPid, signer: .unsigned),
            network: NetworkInfo(
                sourceIp: "10.0.0.2", sourcePort: 51000,
                destinationIp: "104.16.0.1", destinationPort: 443,
                destinationHostname: "registry.npmjs.org",
                direction: .outbound, transport: "tcp"
            )
        )
    }

    private func stableRuleEngine() async throws -> RuleEngine {
        try ensureRulesCompiled()
        let engine = RuleEngine()
        _ = try await engine.loadRules(from: compiledDir, enabledStatuses: ["stable"])
        return engine
    }

    private func fires(_ ruleID: String, event: Event, engine: RuleEngine) async -> Bool {
        await engine.evaluate(event).contains { $0.ruleId == ruleID }
    }

    // MARK: - Single-event rule reachability

    @Test("newly admitted sensitive OPEN paths reach and fire their stable rules")
    func sensitiveOpenPathsFire() async throws {
        let engine = try await stableRuleEngine()
        let aiAncestor = "/usr/local/bin/claude"
        let cases: [(path: String, ruleID: String, ancestor: String?)] = [
            (
                "/Users/test/Library/Application Support/com.apple.TCC/TCC.db",
                "d1a2b3c4-0033-4000-a000-000000000033",
                nil
            ),
            (
                "/Users/test/Library/Application Support/Google/Chrome/Profile 1/Login Data",
                "d1a2b3c4-0115-4000-a000-000000000115",
                nil
            ),
            (
                "/Users/test/Library/Messages/chat.db",
                "d1a2b3c4-0236-4000-a000-000000000236",
                nil
            ),
            (
                "/Users/test/project/.env.production",
                "d1a2b3c4-2007-4000-a000-000000002007",
                aiAncestor
            ),
            (
                "/Users/test/.ssh/id_ed25519",
                "d1a2b3c4-2006-4000-a000-000000002006",
                aiAncestor
            ),
        ]

        for item in cases {
            #expect(!ESCollector.shouldDropBeforeWorker(
                eventType: ES_EVENT_TYPE_NOTIFY_OPEN.rawValue,
                path: item.path
            ), "callback admission dropped a stable-rule input: \(item.path)")
            let event = fileEvent(item.path, ancestorExecutable: item.ancestor)
            #expect(await fires(item.ruleID, event: event, engine: engine),
                    "admitted OPEN did not fire \(item.ruleID): \(item.path)")
        }
    }

    @Test("traceparent credential read fires on OPEN only")
    func traceparentReadUsesOpen() async throws {
        let ruleID = "d1a2b3c4-2052-4000-a000-000000002052"
        let path = "/Users/test/.aws/credentials"
        let engine = try await stableRuleEngine()
        let attributedOpen = fileEvent(
            path,
            enrichments: ["machine_agent_confidence": "traceparent"]
        )
        #expect(!ESCollector.shouldDropBeforeWorker(
            eventType: ES_EVENT_TYPE_NOTIFY_OPEN.rawValue,
            path: path
        ))
        #expect(await fires(ruleID, event: attributedOpen, engine: engine))

        let unattributedOpen = fileEvent(path)
        #expect(!(await fires(ruleID, event: unattributedOpen, engine: engine)),
                "traceparent rule fired without traceparent attribution")

        // A modified CLOSE is observable, but it is a write signal and must not
        // masquerade as the advertised credential read.
        let attributedWriteClose = fileEvent(
            path,
            action: .close,
            enrichments: ["machine_agent_confidence": "traceparent"]
        )
        #expect(!ESCollector.shouldDropBeforeWorker(
            eventType: ES_EVENT_TYPE_NOTIFY_CLOSE.rawValue,
            path: path,
            closeModified: true
        ))
        #expect(!(await fires(ruleID, event: attributedWriteClose, engine: engine)))
        #expect(ESCollector.shouldDropBeforeWorker(
            eventType: ES_EVENT_TYPE_NOTIFY_CLOSE.rawValue,
            path: path,
            closeModified: false
        ), "unmodified CLOSE must remain outside the worker")
    }

    @Test("every default honeyfile OPEN reaches enrichment and fires the stable HIGH rule")
    func defaultHoneyfilesReachDeceptionEnrichment() async throws {
        let home = FileManager.default.temporaryDirectory
            .appendingPathComponent("maccrab-honey-open-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: home, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: home) }

        let manager = HoneyfileManager(
            homeDir: home.path,
            manifestPath: home.appendingPathComponent("honeyfiles.json").path
        )
        let deployed = try await manager.deploy()
        #expect(deployed.count == 13, "default honeyfile corpus changed; review OPEN admission")

        let enricher = EventEnricher(honeyfileManager: manager)
        let engine = try await stableRuleEngine()
        let honeyfileRuleID = "f1e2d3c4-b5a6-4987-9876-543210dec0de"

        for entry in deployed {
            let path = entry.path
            #expect(ESCollector.isCredentialReadPath(path),
                    "default honeyfile is not classified for READ admission: \(path)")
            #expect(!ESCollector.shouldDropBeforeWorker(
                eventType: ES_EVENT_TYPE_NOTIFY_OPEN.rawValue,
                path: path
            ), "callback drops a deployed honeyfile before IsHoneyfile enrichment: \(path)")

            let enriched = await enricher.enrich(fileEvent(path))
            #expect(enriched.file?.action == .open)
            #expect(enriched.enrichments["IsHoneyfile"] == "true",
                    "admitted OPEN was not tagged as a deployed honeyfile: \(path)")
            #expect(enriched.enrichments["HoneyfileType"] == entry.type.rawValue)
            #expect(await fires(honeyfileRuleID, event: enriched, engine: engine),
                    "stable HIGH honeyfile_accessed did not fire for admitted OPEN: \(path)")
        }
    }

    @Test("OPEN admission remains narrow and rule false-positive filters still suppress owners")
    func negativeControls() async throws {
        let ordinaryPaths = [
            "/Users/test/Library/Application Support/Google/Chrome/Default/History",
            "/Users/test/Library/Messages/Attachments/photo.jpg",
            "/private/tmp/Login Data",
            "/Users/test/project/.env.backup",
            "/Users/test/.config/random.json",
        ]
        for path in ordinaryPaths {
            #expect(ESCollector.shouldDropBeforeWorker(
                eventType: ES_EVENT_TYPE_NOTIFY_OPEN.rawValue,
                path: path
            ), "OPEN boundary broadened to an unrelated path: \(path)")
        }

        let engine = try await stableRuleEngine()
        let chromeID = "d1a2b3c4-0115-4000-a000-000000000115"
        let chromeOwnRead = fileEvent(
            "/Users/test/Library/Application Support/Google/Chrome/Default/Login Data",
            executable: "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
            signer: .devId
        )
        #expect(!(await fires(chromeID, event: chromeOwnRead, engine: engine)),
                "Chrome reading its own Login Data should be filtered")

        let tccID = "d1a2b3c4-0033-4000-a000-000000000033"
        let appleTCCRead = fileEvent(
            "/Users/test/Library/Application Support/com.apple.TCC/TCC.db",
            executable: "/System/Library/PrivateFrameworks/TCC.framework/Support/tccd",
            signer: .apple
        )
        #expect(!(await fires(tccID, event: appleTCCRead, engine: engine)),
                "Apple TCC owner should be filtered")

        let messagesID = "d1a2b3c4-0236-4000-a000-000000000236"
        let messagesOwnRead = fileEvent(
            "/Users/test/Library/Messages/chat.db",
            executable: "/System/Applications/Messages.app/Contents/MacOS/Messages",
            signer: .apple
        )
        #expect(!(await fires(messagesID, event: messagesOwnRead, engine: engine)),
                "Messages.app reading its own database should be filtered")
    }

    // MARK: - Cross-site drift guards

    @Test("all nine agent-config suffixes match OPEN, enrichment, and compiled predicates exactly")
    func agentConfigThreeSiteParity() throws {
        let expected: Set<String> = [
            "/.claude/claude_desktop_config.json", "/.claude.json", "/.cursor/mcp.json",
            "/.continue/config.json", "/.vscode/mcp.json", "/.windsurf/mcp.json",
            "/.claude/settings.json", "/.claude/project.json", "/.claude/local.json",
        ]
        #expect(Set(ESCollector.agentConfigReadFileSuffixes) == expected,
                "ES OPEN config admission drifted from the nine shipped predicates")
        #expect(Set(FileContentEnricher.agentConfigFileSuffixes) == expected,
                "FileContent enrichment drifted from the nine shipped predicates")

        try ensureRulesCompiled()
        let mcpRule = try jsonObject(
            at: compiledDir.appendingPathComponent("mcp_server_suspicious_command.json")
        )
        let claudeRule = try jsonObject(
            at: compiledDir.appendingPathComponent("claude_code_project_config_rce.json")
        )
        let compiledSuffixes = filePathValues(in: mcpRule)
            .union(filePathValues(in: claudeRule))
        #expect(compiledSuffixes == expected,
                "compiled FileContent rule predicates drifted from collector/enricher coverage")

        for suffix in expected {
            let probe = "/Users/test\(suffix)"
            #expect(ESCollector.isAgentContentReadPath(probe),
                    "OPEN admission omitted \(suffix)")
            #expect(FileContentEnricher.shouldScan(targetPath: probe),
                    "content enrichment omitted \(suffix)")
        }
    }

    @Test("stable HIGH CLOSE census contains only known modified-write rules; read rules use OPEN")
    func closeSemanticsCensus() throws {
        try ensureRulesCompiled()
        let expectedWriteCloseRules: Set<String> = [
            "690711f9-8a8d-49e4-9124-0710e7d26398", // executable write into .claude
            "d1a2b3c4-2031-4000-a000-000000002031", // config content write
            "21a8021e-abb7-4791-8d68-eab80a49edb4", // node-ipc package content write
        ]
        let expectedSequenceWriteCloseRules: Set<String> = [
            "e1f2a3b4-0020-4000-b000-000000000020", // npm descendant payload write
        ]
        let singleClose = try stableHighRulesUsingClose(in: compiledDir)
        let sequenceClose = try stableHighRulesUsingClose(
            in: compiledDir.appendingPathComponent("sequences")
        )
        #expect(singleClose == expectedWriteCloseRules,
                "stable/HIGH CLOSE census changed; classify new entries as read vs modified-write")
        #expect(sequenceClose == expectedSequenceWriteCloseRules,
                "stable/HIGH sequence CLOSE census changed; entries must require modified-write actions")

        let traceRule = try jsonObject(
            at: compiledDir.appendingPathComponent("agent_traceparent_credential_access.json")
        )
        let npmSequence = try jsonObject(
            at: compiledDir.appendingPathComponent(
                "sequences/npm_module_require_then_bulk_credential_read.json"
            )
        )
        let wormSequence = try jsonObject(
            at: compiledDir.appendingPathComponent("sequences/worm_self_propagation_signal.json")
        )
        #expect(fileActionValues(in: traceRule) == ["open"])
        #expect(fileActionValues(in: npmSequence) == ["open"])
        #expect(fileActionValues(in: wormSequence) == ["open"])
    }

    // MARK: - Sequence proof

    @Test("credential sequences advance on OPEN; CLOSE and benign OPEN do not")
    func credentialSequencesUseObservableReadSignal() async throws {
        let npmRule = "9c2d052b-a8ce-43fc-a1a9-5ee9c86f0682"
        let npmStart = processEvent(
            executable: "/usr/local/bin/node",
            pid: rootPid,
            commandLine: "node /repo/node_modules/evil/index.js",
            at: 0
        )
        #expect(try await sequenceFires(npmRule, events: [
            npmStart,
            fileEvent("/Users/test/.npmrc", pid: childPid, at: 1),
        ]))
        #expect(!(try await sequenceFires(npmRule, events: [
            npmStart,
            fileEvent("/Users/test/.npmrc", action: .close, pid: childPid, at: 1),
        ])), "modified CLOSE must not impersonate a credential read")
        #expect(!(try await sequenceFires(npmRule, events: [
            npmStart,
            fileEvent("/Users/test/Documents/notes.txt", pid: childPid, at: 1),
        ])), "an unrelated OPEN must not complete the credential sequence")

        let wormRule = "e1f2a3b4-0040-4000-b000-000000000040"
        let wormStart = processEvent(
            executable: "/private/tmp/postinstall",
            pid: rootPid,
            parentExecutable: "/usr/local/bin/npm",
            at: 0
        )
        #expect(try await sequenceFires(wormRule, events: [
            wormStart,
            fileEvent("/Users/test/.aws/credentials", pid: childPid, at: 1),
            networkEvent(at: 2),
        ]))
        #expect(!(try await sequenceFires(wormRule, events: [
            wormStart,
            fileEvent("/Users/test/.aws/credentials", action: .close, pid: childPid, at: 1),
            networkEvent(at: 2),
        ])), "CLOSE must not complete the worm credential-read leg")
    }

    @Test("pip credential harvest requires an admitted OPEN, never a write-family event")
    func pipCredentialHarvestUsesExactReadSignal() async throws {
        let ruleID = "e1f2a3b4-0021-4000-b000-000000000021"
        let credential = "/Users/test/.azure/azureProfile.json"
        let pipInstall = processEvent(
            executable: "/usr/bin/pip3",
            pid: rootPid,
            commandLine: "pip3 install litellm",
            at: 0
        )

        #expect(!ESCollector.shouldDropBeforeWorker(
            eventType: ES_EVENT_TYPE_NOTIFY_OPEN.rawValue,
            path: credential
        ), "the repaired sequence input must cross callback admission")
        #expect(try await sequenceFires(ruleID, events: [
            pipInstall,
            fileEvent(credential, action: .open, pid: childPid, at: 1),
        ]))

        for action in [FileAction.create, .write, .close] {
            #expect(!(try await sequenceFires(ruleID, events: [
                pipInstall,
                fileEvent(credential, action: action, pid: childPid, at: 1),
            ])), "\(action.rawValue) must not impersonate credential READ")
        }
    }

    @Test("every pip credential predicate is wholly covered by a narrow callback literal")
    func pipCredentialPredicatesMatchCallbackAdmission() throws {
        try ensureRulesCompiled()
        let object = try jsonObject(at: compiledDir.appendingPathComponent(
            "sequences/pip_install_to_credential_harvest.json"
        ))
        let steps = try #require(object["steps"] as? [[String: Any]])
        let credentialStep = try #require(
            steps.first { ($0["id"] as? String) == "cred_access" }
        )
        let predicates = try #require(credentialStep["predicates"] as? [[String: Any]])

        let pathPredicates = predicates.filter { ($0["field"] as? String) == "file.path" }
        #expect(pathPredicates.count == 2,
                "review callback reachability when the credential path expression changes")
        for predicate in pathPredicates {
            let modifier = try #require(predicate["modifier"] as? String)
            let values = try #require(predicate["values"] as? [String])
            for literal in values {
                let coveredBySubstring = ESCollector.credentialReadPathSubstrings.contains {
                    literal.contains($0)
                }
                let coveredBySuffix = modifier == "endswith"
                    && ESCollector.credentialReadPathSuffixes.contains {
                        literal.hasSuffix($0)
                    }
                #expect(coveredBySubstring || coveredBySuffix,
                        "compiled \(modifier) literal is not wholly callback-reachable: \(literal)")
            }
        }

        #expect(fileActionValues(in: credentialStep) == ["open"])
        #expect(credentialStep["condition_tree"] is [String: Any],
                "(path OR path) AND OPEN must retain its boolean condition tree")
    }

    // MARK: - Corpus helpers

    private func sequenceFires(_ ruleID: String, events: [Event]) async throws -> Bool {
        try ensureRulesCompiled()
        let lineage = ProcessLineage()
        await lineage.recordProcess(
            pid: rootPid, ppid: 1, path: "/private/tmp/root", name: "root", startTime: base
        )
        await lineage.recordProcess(
            pid: childPid, ppid: rootPid, path: "/private/tmp/child", name: "child", startTime: base
        )
        let engine = SequenceEngine(lineage: lineage)
        _ = try await engine.loadRules(
            from: compiledDir.appendingPathComponent("sequences"),
            enabledStatuses: ["stable"]
        )
        for event in events {
            if await engine.evaluate(event).contains(where: { $0.ruleId == ruleID }) {
                return true
            }
        }
        return false
    }

    private func jsonObject(at url: URL) throws -> [String: Any] {
        let data = try Data(contentsOf: url)
        guard let object = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw CorpusError.malformedJSON(url.path)
        }
        return object
    }

    private func filePathValues(in object: Any) -> Set<String> {
        guard let dictionary = object as? [String: Any] else { return [] }
        var result: Set<String> = []
        if dictionary["field"] as? String == "file.path",
           let values = dictionary["values"] as? [String] {
            result.formUnion(values)
        }
        for value in dictionary.values {
            if let nested = value as? [String: Any] {
                result.formUnion(filePathValues(in: nested))
            } else if let array = value as? [Any] {
                for item in array { result.formUnion(filePathValues(in: item)) }
            }
        }
        return result
    }

    private func fileActionValues(in object: Any) -> Set<String> {
        if let dictionary = object as? [String: Any] {
            var result: Set<String> = []
            if dictionary["field"] as? String == "FileAction",
               let values = dictionary["values"] as? [String] {
                result.formUnion(values)
            }
            for value in dictionary.values {
                result.formUnion(fileActionValues(in: value))
            }
            return result
        }
        if let array = object as? [Any] {
            return array.reduce(into: Set<String>()) { partial, item in
                partial.formUnion(fileActionValues(in: item))
            }
        }
        return []
    }

    private func stableHighRulesUsingClose(in directory: URL) throws -> Set<String> {
        var result: Set<String> = []
        for url in try FileManager.default.contentsOfDirectory(
            at: directory, includingPropertiesForKeys: nil
        ) where url.pathExtension == "json" {
            let object = try jsonObject(at: url)
            guard object["status"] as? String == "stable",
                  object["level"] as? String == "high",
                  let id = object["id"] as? String else { continue }
            if fileActionValues(in: object).contains("close") {
                result.insert(id)
            }
        }
        return result
    }
}
