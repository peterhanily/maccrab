import Dispatch
import Foundation
import SQLite3
import Testing
@testable import MacCrabCore

@Suite("Rule-derived file callback interest policy")
struct FileEventInterestPolicyTests {
    private let emptyDynamic = DynamicAIFileEventDemandSnapshot.current(
        validUntilUptimeNanoseconds: UInt64.max,
        demands: []
    )
    private let emptyHoneyfiles = HoneyfilePathSnapshot.current(
        paths: [],
        validUntilUptimeNanoseconds: UInt64.max
    )

    private func rule(
        id: String = UUID().uuidString,
        predicates: [MacCrabCore.Predicate],
        condition: RuleCondition = .allOf,
        tree: ConditionNode? = nil,
        category: String = "file_event",
        enabled: Bool = true,
        status: String? = "stable"
    ) -> CompiledRule {
        CompiledRule(
            id: id,
            title: id,
            description: "fixture",
            level: .medium,
            tags: [],
            logsource: LogSource(category: category, product: "macos"),
            predicates: predicates,
            condition: condition,
            conditionTree: tree,
            falsepositives: [],
            enabled: enabled,
            status: status
        )
    }

    private func snapshot(
        rules: [CompiledRule] = [],
        sequences: [SequenceRule] = [],
        graph: [GraphRule] = [],
        builtins: [BuiltinFileEventRequirement] = [],
        components: Set<FileEventInterestDescriptorSnapshot.Component>
            = Set(FileEventInterestDescriptorSnapshot.Component.allCases)
    ) -> FileEventInterestDescriptorSnapshot {
        FileEventInterestDescriptorSnapshot(
            singleEventRules: rules,
            sequenceRules: sequences,
            graphRules: graph,
            builtinRequirements: builtins,
            includedComponents: components
        )
    }

    private func facts(
        path: String,
        action: FileAction = .write,
        eventAction: String? = nil,
        pid: Int32? = 41,
        executable: String? = "/usr/bin/test",
        commandLine: FileEventFact<String> = .unknown,
        signer: FileEventFact<String> = .unknown,
        graphKind: FileEventFact<String> = .absent,
        untrusted: FileEventFact<Bool> = .absent,
        persistence: FileEventFact<String> = .absent
    ) -> FileEventAdmissionFacts {
        .endpointSecurity(
            path: path,
            fileAction: action,
            eventAction: eventAction ?? action.rawValue,
            eventType: action == .create ? .creation : (action == .delete ? .deletion : .change),
            processID: pid,
            processExecutable: executable,
            processName: executable.map { ($0 as NSString).lastPathComponent },
            processCommandLine: commandLine,
            signerType: signer,
            isPlatformBinary: false,
            graphFileKind: graphKind,
            graphUntrustedContent: untrusted,
            graphPersistenceType: persistence
        )
    }

    private func policy(
        rules: [CompiledRule] = [],
        sequences: [SequenceRule] = [],
        graph: [GraphRule] = [],
        builtins: [BuiltinFileEventRequirement] = []
    ) -> FileEventInterestPolicy {
        FileEventInterestPolicyCompiler.compile(snapshot(
            rules: rules,
            sequences: sequences,
            graph: graph,
            builtins: builtins
        )).policy
    }

    @Test("AND may reject on one known-false sibling; unknown leaves admit")
    func threeValuedAnd() {
        let candidate = rule(predicates: [
            Predicate(field: "file.path", modifier: .startswith,
                      values: ["/sensitive/"], negate: false),
            Predicate(field: "FileContent", modifier: .contains,
                      values: ["malicious"], negate: false),
        ])
        let compiled = policy(rules: [candidate])

        #expect(!compiled.shouldAdmit(
            facts(path: "/tmp/ordinary"), dynamicAI: emptyDynamic
        ))
        #expect(compiled.shouldAdmit(
            facts(path: "/sensitive/input"), dynamicAI: emptyDynamic
        ))
    }

    @Test("OR, NOT, unprojectable regex, and unknown fields remain fail-open")
    func unsupportedBooleanShapesAdmit() {
        let predicates = [
            Predicate(field: "file.path", modifier: .equals,
                      values: ["/never"], negate: false),
            Predicate(field: "plugin.future_field", modifier: .equals,
                      values: ["yes"], negate: false),
            Predicate(field: "file.path", modifier: .regex,
                      values: [".*secret.*"], negate: false),
        ]
        let orRule = rule(
            id: "or-unknown",
            predicates: predicates,
            tree: .or([.predicate(0), .predicate(1)])
        )
        let notRule = rule(
            id: "not-unknown",
            predicates: predicates,
            tree: .not(.predicate(1))
        )
        let regexRule = rule(id: "regex", predicates: [predicates[2]])
        let input = facts(path: "/tmp/ordinary")

        #expect(policy(rules: [orRule]).shouldAdmit(input, dynamicAI: emptyDynamic))
        #expect(policy(rules: [notRule]).shouldAdmit(input, dynamicAI: emptyDynamic))
        #expect(policy(rules: [regexRule]).shouldAdmit(input, dynamicAI: emptyDynamic))
    }

    @Test("safe path-regex projection disproves only necessary prefix/suffix failures")
    func safePathRegexProjection() {
        let hidden = rule(
            id: "hidden-non-home",
            predicates: [
                Predicate(
                    field: "TargetFilename",
                    modifier: .regex,
                    values: [#"^/(tmp|var|usr|opt|Library)/.*\/\.[^/]+$"#],
                    negate: false
                ),
                Predicate(
                    field: "FileAction",
                    modifier: .equals,
                    values: ["create"],
                    negate: false
                ),
            ]
        )
        let compilation = FileEventInterestPolicyCompiler.compile(snapshot(rules: [hidden]))
        #expect(compilation.census.projectedPathRegexPredicates == 1)
        #expect(compilation.census.unsupportedPathRegexPredicates == 0)
        #expect(!compilation.policy.shouldAdmit(
            facts(
                path: "/private/var/folders/x/.pytest-stage",
                action: .create
            ),
            dynamicAI: emptyDynamic
        ))
        // Passing the necessary prefix cannot prove the complete regex true.
        #expect(compilation.policy.shouldAdmit(
            facts(path: "/tmp/stage/.implant", action: .create),
            dynamicAI: emptyDynamic
        ))
        // The known-false action sibling still rejects without regex work.
        #expect(!compilation.policy.shouldAdmit(
            facts(path: "/tmp/stage/.implant", action: .write),
            dynamicAI: emptyDynamic
        ))

        for unsupported in [
            #"^/tmp/["#,                  // invalid
            #"^/tmp/(a+)+$"#,            // nested quantified group
            #"(?=^/tmp/).*secret"#,      // lookaround
            String(repeating: "a", count: 513),
        ] {
            let candidate = rule(predicates: [Predicate(
                field: "TargetFilename",
                modifier: .regex,
                values: [unsupported],
                negate: false
            )])
            let unsupportedCompilation = FileEventInterestPolicyCompiler.compile(
                snapshot(rules: [candidate])
            )
            #expect(unsupportedCompilation.census.unsupportedPathRegexPredicates == 1)
            #expect(unsupportedCompilation.policy.shouldAdmit(
                facts(path: "/private/ordinary"),
                dynamicAI: emptyDynamic
            ))
        }

        let overlongPath = "/private/" + String(repeating: "x", count: 8_192)
        #expect(compilation.policy.shouldAdmit(
            facts(path: overlongPath, action: .create),
            dynamicAI: emptyDynamic
        ), "over-bound callback input must remain unknown/fail-open")

        // Adversarial projection soundness: every path below is either a real
        // regex match or a shape whose case-fold/end-anchor semantics cannot be
        // disproved by the callback projection.
        for (pattern, matchingPath) in [
            (#"^/foo?bar$"#, "/fobar"),
            (#"^/(tmp|var)/foo?$"#, "/tmp/fo"),
            (#"secret$"#, "/tmp/secret\n"),
            (#"^/kelvin"#, "/Kelvin"),
        ] {
            let candidate = rule(predicates: [Predicate(
                field: "TargetFilename",
                modifier: .regex,
                values: [pattern],
                negate: false
            )])
            let projected = FileEventInterestPolicyCompiler.compile(
                snapshot(rules: [candidate])
            )
            #expect(projected.policy.shouldAdmit(
                facts(path: matchingPath),
                dynamicAI: emptyDynamic
            ), "sound projection rejected regex candidate \(pattern) → \(matchingPath)")
        }

        let topLevelAlternative = rule(predicates: [Predicate(
            field: "TargetFilename",
            modifier: .regex,
            values: [#"^/foo|^/bar"#],
            negate: false
        )])
        let alternativeCompilation = FileEventInterestPolicyCompiler.compile(
            snapshot(rules: [topLevelAlternative])
        )
        #expect(alternativeCompilation.census.unsupportedPathRegexPredicates == 1)
        #expect(alternativeCompilation.policy.shouldAdmit(
            facts(path: "/bar"),
            dynamicAI: emptyDynamic
        ))
    }

    @Test("honeyfile semantic snapshot is complete, expiring, and fail-open")
    func honeyfileSemanticSnapshot() {
        let honeyRule = rule(
            id: "honey",
            predicates: [Predicate(
                field: "IsHoneyfile",
                modifier: .equals,
                values: ["true"],
                negate: false
            )]
        )
        let compiled = policy(rules: [honeyRule])
        let ordinary = facts(path: "/tmp/ordinary")
        let canary = facts(path: "/Users/test/.aws/credentials.bak")

        #expect(compiled.shouldAdmit(
            ordinary,
            dynamicAI: emptyDynamic,
            honeyfiles: .unknown,
            nowUptimeNanoseconds: 2
        ))
        #expect(compiled.shouldAdmit(
            ordinary,
            dynamicAI: emptyDynamic,
            honeyfiles: .current(paths: [], validUntilUptimeNanoseconds: 1),
            nowUptimeNanoseconds: 2
        ))
        #expect(!compiled.shouldAdmit(
            ordinary,
            dynamicAI: emptyDynamic,
            honeyfiles: emptyHoneyfiles,
            nowUptimeNanoseconds: 2
        ))
        #expect(compiled.shouldAdmit(
            canary,
            dynamicAI: emptyDynamic,
            honeyfiles: .current(
                paths: ["/Users/test/.aws/credentials.bak"],
                validUntilUptimeNanoseconds: 3
            ),
            nowUptimeNanoseconds: 2
        ))

        let credential = HoneyfilePathSnapshot.current(
            paths: ["/credential-bait"],
            validUntilUptimeNanoseconds: 10
        )
        let prompt = HoneyfilePathSnapshot.current(
            paths: ["/prompt-bait"],
            validUntilUptimeNanoseconds: 8
        )
        #expect(credential.merging(prompt) == .current(
            paths: ["/credential-bait", "/prompt-bait"],
            validUntilUptimeNanoseconds: 8
        ))
        #expect(credential.merging(.unknown) == .unknown)
    }

    @Test("one_of_each preserves OR-within-field and AND-across-fields")
    func oneOfEach() {
        let candidate = rule(
            predicates: [
                Predicate(field: "file.path", modifier: .startswith,
                          values: ["/Library/"], negate: false),
                Predicate(field: "file.path", modifier: .startswith,
                          values: ["/etc/"], negate: false),
                Predicate(field: "FileAction", modifier: .equals,
                          values: ["write"], negate: false),
                Predicate(field: "FileAction", modifier: .equals,
                          values: ["create"], negate: false),
            ],
            condition: .oneOfEach
        )
        let compiled = policy(rules: [candidate])
        #expect(compiled.shouldAdmit(
            facts(path: "/etc/hosts", action: .create), dynamicAI: emptyDynamic
        ))
        #expect(!compiled.shouldAdmit(
            facts(path: "/tmp/x", action: .create), dynamicAI: emptyDynamic
        ))
        #expect(!compiled.shouldAdmit(
            facts(path: "/etc/hosts", action: .delete), dynamicAI: emptyDynamic
        ))
    }

    @Test("ordinary ES capability proves BTM-only rules impossible")
    func sourceCapabilitiesSeparateBTM() {
        let btmRule = rule(predicates: [
            Predicate(field: "BTMItemType", modifier: .equals,
                      values: ["agent", "daemon"], negate: false),
            Predicate(field: "SignerType", modifier: .equals,
                      values: ["apple"], negate: true),
        ])
        let compiled = policy(rules: [btmRule])

        #expect(!compiled.shouldAdmit(
            facts(path: "/Library/LaunchAgents/x", signer: .value("unsigned")),
            dynamicAI: emptyDynamic
        ))

        let btm = FileEventAdmissionFacts(
            source: .endpointSecurityBTM,
            filePath: .value("/Library/LaunchAgents/x"),
            fileAction: .value("create"),
            eventType: .value("creation"),
            eventAction: .value("btm_add"),
            signerType: .value("unsigned"),
            btmItemType: .value("agent"),
            btmLegacy: .value("false"),
            btmManaged: .value("false")
        )
        #expect(compiled.shouldAdmit(btm, dynamicAI: emptyDynamic))
    }

    @Test("known process image narrows an action-like chmod rule before command-line enrichment")
    func processImageCanProveImpossible() {
        let chmod = rule(predicates: [
            Predicate(field: "process.executable", modifier: .endswith,
                      values: ["/chmod"], negate: false),
            Predicate(field: "process.commandline", modifier: .contains,
                      values: ["u+s", "+s", "4755"], negate: false),
        ])
        let compiled = policy(rules: [chmod])
        #expect(!compiled.shouldAdmit(
            facts(path: "/tmp/x", executable: "/bin/cp"), dynamicAI: emptyDynamic
        ))
        #expect(compiled.shouldAdmit(
            facts(path: "/tmp/x", executable: "/bin/chmod"), dynamicAI: emptyDynamic
        ))
    }

    @Test("every file step matters, including a later ordered sequence step")
    func laterSequenceStepIsCompiled() {
        let sequence = SequenceRule(
            id: "later-file-step",
            title: "later file step",
            description: "fixture",
            level: .high,
            tags: [],
            window: 60,
            correlationType: .processSame,
            ordered: true,
            steps: [
                SequenceStep(
                    id: "exec",
                    logsourceCategory: "process_creation",
                    predicates: [Predicate(
                        field: "process.executable", modifier: .endswith,
                        values: ["/curl"], negate: false
                    )]
                ),
                SequenceStep(
                    id: "later-write",
                    logsourceCategory: "file_event",
                    predicates: [Predicate(
                        field: "file.path", modifier: .equals,
                        values: ["/tmp/later"], negate: false
                    )],
                    afterStep: "exec"
                ),
            ],
            trigger: .allSteps,
            status: "stable"
        )
        let compiled = policy(sequences: [sequence])
        #expect(compiled.shouldAdmit(
            facts(path: "/tmp/later"), dynamicAI: emptyDynamic
        ))
        #expect(!compiled.shouldAdmit(
            facts(path: "/tmp/other"), dynamicAI: emptyDynamic
        ))
    }

    @Test("graph requirements share the callback classifier and bound untrusted-content admission")
    func graphRequirements() {
        let credential = GraphRule(
            id: "graph-credential",
            title: "credential",
            severity: "high",
            nodes: [
                "file": .init(type: FileNode.entityType, where: [
                    "file_kind": .init(equals: FileKind.credentialFile.rawValue),
                ]),
            ],
            edges: [],
            status: "stable"
        )
        let untrusted = GraphRule(
            id: "graph-untrusted",
            title: "untrusted",
            severity: "high",
            nodes: [
                "file": .init(type: FileNode.entityType, where: [
                    "untrusted_content": .init(equalsBool: true),
                ]),
            ],
            edges: [],
            status: "stable"
        )
        let persistence = GraphRule(
            id: "graph-persistence",
            title: "persistence",
            severity: "high",
            nodes: [
                "persist": .init(type: PersistenceNode.entityType, where: [
                    "persistence_type": .init(in: [PersistenceType.launchAgent.rawValue]),
                ]),
            ],
            edges: [],
            status: "stable"
        )

        let credentialPolicy = policy(graph: [credential])
        #expect(!credentialPolicy.shouldAdmit(
            facts(path: "/x", graphKind: .unknown), dynamicAI: emptyDynamic
        ))
        #expect(credentialPolicy.shouldAdmit(
            facts(path: "/Users/test/.aws/credentials", graphKind: .unknown),
            dynamicAI: emptyDynamic
        ))
        #expect(credentialPolicy.shouldAdmit(
            FileEventAdmissionFacts(
                source: .endpointSecurityFile,
                filePath: .unknown,
                eventAction: .value("write"),
                graphFileKind: .unknown
            ),
            dynamicAI: emptyDynamic
        ))
        #expect(credentialPolicy.shouldAdmit(
            facts(path: "/x", graphKind: .value(FileKind.credentialFile.rawValue)),
            dynamicAI: emptyDynamic
        ))
        #expect(!credentialPolicy.shouldAdmit(
            facts(path: "/x", graphKind: .value(FileKind.unknown.rawValue)),
            dynamicAI: emptyDynamic
        ))

        let untrustedPolicy = policy(graph: [untrusted])
        #expect(!untrustedPolicy.shouldAdmit(
            facts(path: "/x", untrusted: .unknown), dynamicAI: emptyDynamic
        ))
        let attributedAI = DynamicAIFileEventDemandSnapshot.current(
            validUntilUptimeNanoseconds: UInt64.max,
            attributedProcessIDs: [41],
            demands: []
        )
        let agentContentOpen = facts(
            path: "/Users/test/.claude/skills/evil/SKILL.md",
            action: .open,
            eventAction: "open",
            untrusted: .unknown
        )
        #expect(untrustedPolicy.shouldAdmit(agentContentOpen, dynamicAI: attributedAI))
        #expect(!untrustedPolicy.shouldAdmit(agentContentOpen, dynamicAI: emptyDynamic))
        #expect(!untrustedPolicy.shouldAdmit(
            facts(path: "/x", untrusted: .value(false)), dynamicAI: emptyDynamic
        ))

        let persistencePolicy = policy(graph: [persistence])
        #expect(!persistencePolicy.shouldAdmit(
            facts(path: "/x", persistence: .absent), dynamicAI: emptyDynamic
        ))
        #expect(persistencePolicy.shouldAdmit(
            facts(path: "/x", persistence: .value(PersistenceType.launchAgent.rawValue)),
            dynamicAI: emptyDynamic
        ))
    }

    @Test("built-ins include CrossProcess's authoritative path gate")
    func crossProcessBuiltin() {
        let crossProcess = BuiltinFileEventRequirement(
            id: "cross-process",
            kind: .crossProcessCorrelation
        )
        let compiled = policy(builtins: [crossProcess])
        #expect(!compiled.shouldAdmit(
            facts(path: "/System/Library/ignored"), dynamicAI: emptyDynamic
        ))
        #expect(compiled.shouldAdmit(
            facts(path: "/Users/test/Documents/shared"), dynamicAI: emptyDynamic
        ))
    }

    @Test("dynamic AI process/path demand is atomic; unknown and stale state admit")
    func dynamicAIRegistry() {
        let registry = FileEventInterestPolicyRegistry()
        let compiled = registry.install(snapshot(builtins: [
            BuiltinFileEventRequirement(id: "ai", kind: .dynamicAIConsumers),
        ]))
        #expect(compiled.installedRestrictiveSnapshot)

        // Dynamic owner has not published yet: fail open.
        #expect(registry.shouldAdmit(
            facts(path: "/Users/test/outside/x", pid: 7),
            nowUptimeNanoseconds: 100
        ))

        #expect(registry.publishDynamicAI(.current(
            validUntilUptimeNanoseconds: 200,
            demands: [DynamicAIFileEventDemand(
                processID: 42,
                action: .fileActions(["open"]),
                path: .extensions(["md"], caseInsensitive: true)
            )]
        )))
        #expect(!registry.shouldAdmit(
            facts(path: "/tmp/a.md", action: .open, pid: 7),
            nowUptimeNanoseconds: 100
        ))
        #expect(registry.shouldAdmit(
            facts(path: "/tmp/a.MD", action: .open, pid: 42),
            nowUptimeNanoseconds: 100
        ))
        #expect(!registry.shouldAdmit(
            facts(path: "/tmp/a.txt", action: .open, pid: 42),
            nowUptimeNanoseconds: 100
        ))
        #expect(!registry.shouldAdmit(
            facts(path: "/tmp/a.md", action: .write, pid: 42),
            nowUptimeNanoseconds: 100
        ))

        let unknownPID = FileEventAdmissionFacts.endpointSecurity(
            path: "/tmp/a.md", fileAction: .open, eventAction: "open",
            eventType: .change, processID: nil
        )
        #expect(registry.shouldAdmit(unknownPID, nowUptimeNanoseconds: 100))
        #expect(registry.shouldAdmit(
            facts(path: "/Users/test/outside/a.txt", action: .write, pid: 7),
            nowUptimeNanoseconds: 201
        ))
    }

    @Test("canonical AI census uses owner classifiers without an admit-all lineage demand")
    func canonicalAIConsumerCensus() {
        let dynamic = DynamicAIFileEventDemandSnapshot.currentCanonical(
            validUntilUptimeNanoseconds: 200,
            sessions: [DynamicAIFileEventSession(
                rootProcessID: 42,
                childProcessIDs: [43],
                projectRoots: ["/Users/test/project"]
            )]
        )
        #expect(dynamic.attributedProcessIDs == [42, 43])
        #expect(dynamic.consumerCensus == Dictionary(
            uniqueKeysWithValues: AIFileEventConsumer.allCases.map { ($0, 2) }
        ))

        let registry = FileEventInterestPolicyRegistry()
        _ = registry.install(snapshot(builtins: [
            BuiltinFileEventRequirement(id: "ai", kind: .dynamicAIConsumers),
        ]))
        #expect(registry.publishDynamicAI(dynamic))

        // The scanner's exact owner classifier handles ordinary text and the
        // leading-dot `.env` case that NSString.pathExtension misses.
        for pid in [Int32(42), 43] {
            #expect(registry.shouldAdmit(
                facts(path: "/private/tmp/context.md", action: .open,
                      eventAction: "open", pid: pid),
                nowUptimeNanoseconds: 100
            ))
            #expect(registry.shouldAdmit(
                facts(path: "/Users/test/project/.env", action: .open,
                      eventAction: "open", pid: pid),
                nowUptimeNanoseconds: 100
            ))
            #expect(registry.shouldAdmit(
                facts(path: "/Users/test/project/notes.txt", action: .close,
                      eventAction: "close_modified", pid: pid),
                nowUptimeNanoseconds: 100
            ))
            #expect(registry.shouldAdmit(
                facts(path: "/Users/test/.aws/credentials", action: .open,
                      eventAction: "open", pid: pid),
                nowUptimeNanoseconds: 100
            ))
            #expect(registry.shouldAdmit(
                facts(path: "/Users/test/.zshrc", action: .write,
                      eventAction: "write", pid: pid),
                nowUptimeNanoseconds: 100
            ))
        }

        // ProjectBoundary only consumes mutations, and its canonical global
        // exceptions do not suppress an independent scanner demand.
        #expect(registry.shouldAdmit(
            facts(path: "/Users/test/outside/blob.bin", action: .write,
                  eventAction: "write", pid: 43),
            nowUptimeNanoseconds: 100
        ))
        #expect(registry.shouldAdmit(
            facts(path: "/Users/test/outside/blob.bin", action: .write,
                  eventAction: "setowner", pid: 43),
            nowUptimeNanoseconds: 100
        ))
        #expect(!registry.shouldAdmit(
            facts(path: "/Users/test/outside/blob.bin", action: .open,
                  eventAction: "open", pid: 43),
            nowUptimeNanoseconds: 100
        ))

        // Raw lineage volume is no longer a consumer. Unsupported binary temp
        // writes and callbacks from unrelated PIDs are provably irrelevant.
        #expect(!registry.shouldAdmit(
            facts(path: "/private/var/folders/hf/cache.bin", action: .write,
                  eventAction: "write", pid: 43),
            nowUptimeNanoseconds: 100
        ))
        #expect(!registry.shouldAdmit(
            facts(path: "/Users/test/project/README.md", action: .open,
                  eventAction: "open", pid: 7),
            nowUptimeNanoseconds: 100
        ))
    }

    @Test("unknown AI state is strictly fail-open; fresh empty uses bounded PID grace")
    func dynamicAIGraceRace() {
        let registry = FileEventInterestPolicyRegistry(limits: .init(
            maximumDynamicGraceProcessIDs: 2
        ))
        _ = registry.install(snapshot(builtins: [
            BuiltinFileEventRequirement(id: "ai", kind: .dynamicAIConsumers),
        ]))
        let temp = facts(
            path: "/private/var/folders/hf/cache.bin",
            action: .write,
            eventAction: "write",
            pid: 42
        )

        // Unknown and stale never special-case temp/cache paths to reject.
        #expect(registry.shouldAdmit(temp, nowUptimeNanoseconds: 100))
        #expect(registry.publishDynamicAI(.current(
            validUntilUptimeNanoseconds: 50,
            demands: []
        )))
        #expect(registry.shouldAdmit(temp, nowUptimeNanoseconds: 100))

        #expect(registry.publishDynamicAI(.current(
            validUntilUptimeNanoseconds: 500,
            demands: []
        )))
        #expect(!registry.shouldAdmit(temp, nowUptimeNanoseconds: 100))
        #expect(registry.grantDynamicAIGrace(
            processID: 42,
            validUntilUptimeNanoseconds: 200,
            nowUptimeNanoseconds: 100
        ))
        #expect(registry.isKnownDynamicAIProcess(
            42,
            nowUptimeNanoseconds: 100
        ))
        #expect(registry.shouldAdmit(temp, nowUptimeNanoseconds: 100))
        #expect(!registry.shouldAdmit(
            facts(path: "/private/var/folders/hf/cache.bin", pid: 7),
            nowUptimeNanoseconds: 100
        ))
        #expect(!registry.shouldAdmit(temp, nowUptimeNanoseconds: 201))
        #expect(!registry.isKnownDynamicAIProcess(
            42,
            nowUptimeNanoseconds: 201
        ))

        #expect(registry.grantDynamicAIGrace(
            processID: 42,
            validUntilUptimeNanoseconds: 300,
            nowUptimeNanoseconds: 201
        ))
        registry.revokeDynamicAIGrace(processID: 42)
        #expect(!registry.shouldAdmit(temp, nowUptimeNanoseconds: 202))
    }

    @Test("PID grace overflow fails open only until the next complete publication")
    func dynamicAIGraceOverflowRecovery() {
        let registry = FileEventInterestPolicyRegistry(limits: .init(
            maximumDynamicGraceProcessIDs: 1
        ))
        _ = registry.install(snapshot(builtins: [
            BuiltinFileEventRequirement(id: "ai", kind: .dynamicAIConsumers),
        ]))
        #expect(registry.publishDynamicAI(.current(
            validUntilUptimeNanoseconds: 1_000,
            demands: []
        )))
        #expect(registry.grantDynamicAIGrace(
            processID: 1,
            validUntilUptimeNanoseconds: 500,
            nowUptimeNanoseconds: 100
        ))
        #expect(!registry.grantDynamicAIGrace(
            processID: 2,
            validUntilUptimeNanoseconds: 500,
            nowUptimeNanoseconds: 100
        ))
        let unrelated = facts(path: "/Users/test/random.bin", pid: 99)
        #expect(registry.shouldAdmit(unrelated, nowUptimeNanoseconds: 100))

        // A complete owner publication restores restriction; overflow is not a
        // permanent global escape hatch.
        #expect(registry.publishDynamicAI(.current(
            validUntilUptimeNanoseconds: 1_000,
            demands: []
        )))
        #expect(!registry.shouldAdmit(unrelated, nowUptimeNanoseconds: 100))
    }

    @Test("honeyfile deploy/reload invalidates before mutation and publishes complete union")
    func honeyfileRegistryOrdering() async throws {
        let home = NSTemporaryDirectory()
            + "maccrab_interest_honey_\(UUID().uuidString)"
        try FileManager.default.createDirectory(atPath: home, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: home) }

        let honeyManifest = home + "/honeyfiles.json"
        let promptManifest = home + "/honeyprompts.json"
        let honeyManager = HoneyfileManager(
            homeDir: home,
            manifestPath: honeyManifest
        )
        let promptManager = HoneyPromptManager(
            homeDir: home,
            manifestPath: promptManifest
        )
        let honeyRule = rule(
            id: "honey",
            predicates: [Predicate(
                field: "IsHoneyfile",
                modifier: .equals,
                values: ["true"],
                negate: false
            )]
        )
        let registry = FileEventInterestPolicyRegistry()
        #expect(registry.install(snapshot(rules: [honeyRule])).installedRestrictiveSnapshot)
        registry.publishHoneyfiles(.current(
            paths: [],
            validUntilUptimeNanoseconds: 100
        ))
        let ordinary = facts(path: home + "/ordinary")
        #expect(!registry.shouldAdmit(ordinary, nowUptimeNanoseconds: 1))

        // Owner ordering: invalidate before either manager can add a path.
        registry.invalidateHoneyfiles()
        #expect(registry.shouldAdmit(ordinary, nowUptimeNanoseconds: 1))
        let honeyfiles = try await honeyManager.deploy()
        let prompts = try await promptManager.deploy()
        let honeySnapshot = await honeyManager.callbackPathSnapshot(
            validUntilUptimeNanoseconds: 100
        )
        let promptSnapshot = await promptManager.callbackPathSnapshot(
            validUntilUptimeNanoseconds: 100
        )
        let published = honeySnapshot.merging(promptSnapshot)
        registry.publishHoneyfiles(published)

        let honeyPath = try #require(honeyfiles.first?.path)
        let promptPath = try #require(prompts.first?.path)
        #expect(registry.shouldAdmit(facts(path: honeyPath), nowUptimeNanoseconds: 1))
        #expect(registry.shouldAdmit(facts(path: promptPath), nowUptimeNanoseconds: 1))
        #expect(!registry.shouldAdmit(ordinary, nowUptimeNanoseconds: 1))

        // Synchronous manifest initialization closes the old first-lookup
        // race: a new manager immediately exports the complete saved set.
        let reloadedManager = HoneyfileManager(
            homeDir: home,
            manifestPath: honeyManifest
        )
        let reloaded = await reloadedManager.callbackPathSnapshot(
            validUntilUptimeNanoseconds: 100
        )
        #expect(reloaded.paths.contains(honeyPath))

        // A rejected reload never causes a partial restrictive publication.
        registry.invalidateHoneyfiles()
        try Data("not-json".utf8).write(to: URL(fileURLWithPath: honeyManifest))
        let reloadAccepted = await reloadedManager.reloadManifest()
        #expect(!reloadAccepted)
        #expect(await reloadedManager.callbackPathSnapshot(
            validUntilUptimeNanoseconds: 100
        ) == .unknown)
        #expect(registry.shouldAdmit(ordinary, nowUptimeNanoseconds: 1))

        // Duplicate keys are rejected before dictionary construction (which
        // would otherwise trap), and a prompt-manifest rejection is unknown as
        // well — the complete deception union can never publish half a view.
        let duplicateHoney = try JSONEncoder().encode([honeyfiles[0], honeyfiles[0]])
        try duplicateHoney.write(to: URL(fileURLWithPath: honeyManifest))
        #expect(!(await reloadedManager.reloadManifest()))
        let reloadedPromptManager = HoneyPromptManager(
            homeDir: home,
            manifestPath: promptManifest
        )
        let duplicatePrompt = try JSONEncoder().encode([prompts[0], prompts[0]])
        try duplicatePrompt.write(to: URL(fileURLWithPath: promptManifest))
        #expect(!(await reloadedPromptManager.reloadManifest()))
        #expect(await reloadedPromptManager.callbackPathSnapshot(
            validUntilUptimeNanoseconds: 100
        ) == .unknown)

        // Removal follows the same pre-invalidate/post-complete ordering.
        _ = await honeyManager.remove()
        _ = await promptManager.remove()
        let emptyHoneySnapshot = await honeyManager.callbackPathSnapshot(
            validUntilUptimeNanoseconds: 100
        )
        let emptyPromptSnapshot = await promptManager.callbackPathSnapshot(
            validUntilUptimeNanoseconds: 100
        )
        let empty = emptyHoneySnapshot.merging(emptyPromptSnapshot)
        registry.publishHoneyfiles(empty)
        #expect(!registry.shouldAdmit(facts(path: honeyPath), nowUptimeNanoseconds: 1))
        #expect(!registry.shouldAdmit(facts(path: promptPath), nowUptimeNanoseconds: 1))
    }

    @Test("ProjectBoundary demand preserves temp/build/cache exceptions for active AI PIDs")
    func dynamicProjectBoundaryExceptions() {
        let registry = FileEventInterestPolicyRegistry()
        _ = registry.install(snapshot(builtins: [
            BuiltinFileEventRequirement(id: "ai", kind: .dynamicAIConsumers),
        ]))
        let projectBoundary = DynamicAIFileEventDemand(
            processID: 42,
            action: .fileActions(["create", "write", "close", "rename", "delete", "link"]),
            path: .outsideRootsExcluding(
                roots: ["/Users/test/project"],
                allowedExact: ["/dev/null", "/dev/zero", "/dev/random", "/dev/urandom"],
                allowedSubstrings: [
                    "/tmp/", "/private/tmp/", "/var/folders/", "/.build/",
                    "/build/", "/Library/Caches/", "/.cache/",
                ],
                caseInsensitive: false
            )
        )
        #expect(registry.publishDynamicAI(.current(
            validUntilUptimeNanoseconds: 200,
            demands: [projectBoundary]
        )))

        #expect(registry.shouldAdmit(
            facts(path: "/Users/test/outside/target", pid: 42),
            nowUptimeNanoseconds: 100
        ))
        for allowed in [
            "/Users/test/project/Sources/a.swift",
            "/private/var/folders/hf/build.o",
            "/private/tmp/build.o",
            "/Users/test/other/.build/debug/a.o",
            "/Users/test/Library/Caches/tool/a",
            "/dev/null",
        ] {
            #expect(!registry.shouldAdmit(
                facts(path: allowed, pid: 42),
                nowUptimeNanoseconds: 100
            ), "ProjectBoundary exception was re-admitted: \(allowed)")
        }
        #expect(!registry.shouldAdmit(
            facts(path: "/Users/test/outside/target", action: .open, pid: 42),
            nowUptimeNanoseconds: 100
        ))
        #expect(!registry.shouldAdmit(
            facts(path: "/Users/test/outside/target", pid: 7),
            nowUptimeNanoseconds: 100
        ))
    }

    @Test("no/incomplete/oversized snapshot never leaves a stale restrictive policy")
    func registryFailOpenTransitions() {
        let registry = FileEventInterestPolicyRegistry(limits: .init(
            maximumRequirements: 1,
            maximumPredicates: 8,
            maximumConditionNodes: 8,
            maximumDynamicDemands: 1,
            maximumDynamicPatterns: 1
        ))
        let ordinary = facts(path: "/tmp/ordinary")
        #expect(registry.shouldAdmit(ordinary))

        let restrictive = rule(predicates: [Predicate(
            field: "file.path", modifier: .startswith,
            values: ["/only/"], negate: false
        )])
        #expect(registry.install(snapshot(rules: [restrictive])).installedRestrictiveSnapshot)
        #expect(!registry.shouldAdmit(ordinary, nowUptimeNanoseconds: 1))

        let incomplete = snapshot(
            rules: [restrictive],
            components: [.singleEventRules, .sequenceRules, .builtins]
        )
        let incompleteResult = registry.install(incomplete)
        #expect(!incompleteResult.installedRestrictiveSnapshot)
        #expect(registry.shouldAdmit(ordinary, nowUptimeNanoseconds: 1))

        let twoRules = [restrictive, restrictive]
        let oversized = registry.install(snapshot(rules: twoRules))
        #expect(!oversized.installedRestrictiveSnapshot)
        #expect(registry.shouldAdmit(ordinary, nowUptimeNanoseconds: 1))

        #expect(!registry.publishDynamicAI(.current(
            validUntilUptimeNanoseconds: 100,
            demands: [
                DynamicAIFileEventDemand(processID: 1),
                DynamicAIFileEventDemand(processID: 2),
            ]
        )))
    }

    @Test("malformed tree becomes a broad requirement, never a truncated meaning")
    func malformedConditionFailsOpen() {
        let malformed = rule(
            predicates: [Predicate(
                field: "file.path", modifier: .equals,
                values: ["/only"], negate: false
            )],
            tree: .predicate(99)
        )
        let compilation = FileEventInterestPolicyCompiler.compile(snapshot(rules: [malformed]))
        #expect(compilation.installedRestrictiveSnapshot)
        #expect(compilation.census.malformedConditionsMadeBroad == 1)
        #expect(compilation.policy.shouldAdmit(
            facts(path: "/not-only"), dynamicAI: emptyDynamic
        ))
    }

    // MARK: Real corpus drift/effectiveness evidence

    private var projectRoot: URL {
        URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
    }

    private func realSnapshot(
        includeBuiltins: Bool = true,
        includeGraph: Bool = true
    ) async throws -> FileEventInterestDescriptorSnapshot {
        ensureRulesCompiled()
        let compiled = URL(fileURLWithPath: "/tmp/maccrab_v3")

        let ruleEngine = RuleEngine()
        _ = try await ruleEngine.loadRules(from: compiled)
        let rules = await ruleEngine.listRules()

        let sequenceEngine = SequenceEngine(lineage: ProcessLineage())
        _ = try await sequenceEngine.loadRules(
            from: compiled.appendingPathComponent("sequences")
        )
        let sequences = await sequenceEngine.listRules()

        let graph = includeGraph
            ? GraphRuleLoader.loadRules(from: projectRoot.appendingPathComponent("Rules/graph"))
            : []
        return snapshot(
            rules: rules,
            sequences: sequences,
            graph: graph,
            builtins: includeBuiltins ? BuiltinRuleCatalog.fileEventInterestRequirements : []
        )
    }

    private func signerType(_ raw: String?) -> SignerType {
        switch raw {
        case "apple": return .apple
        case "devId": return .devId
        case "adHoc": return .adHoc
        default: return .unsigned
        }
    }

    private func corpusEvent(_ fixture: RuleCorpusFixture) -> Event {
        let signer = signerType(fixture.process.signer)
        let signature = CodeSignatureInfo(
            signerType: signer,
            teamId: nil,
            signingId: nil,
            authorities: [],
            flags: 0,
            isNotarized: signer == .apple || signer == .devId,
            issuerChain: nil,
            certHashes: nil,
            isAdhocSigned: signer == .adHoc,
            entitlements: nil
        )
        let parent = fixture.process.parentExec ?? "/bin/bash"
        let process = MacCrabCore.ProcessInfo(
            pid: 4_321,
            ppid: 1,
            rpid: 1,
            name: (fixture.process.executable as NSString).lastPathComponent,
            executable: fixture.process.executable,
            commandLine: fixture.process.commandLine,
            args: [fixture.process.executable],
            workingDirectory: "/tmp",
            userId: 501,
            userName: "t",
            groupId: 20,
            startTime: Date(timeIntervalSince1970: 1_700_000_000),
            codeSignature: signature,
            ancestors: [ProcessAncestor(
                pid: 1,
                executable: parent,
                name: (parent as NSString).lastPathComponent
            )],
            architecture: "arm64",
            isPlatformBinary: signer == .apple
        )
        guard let file = fixture.file else {
            return Event(
                eventCategory: .process,
                eventType: .start,
                eventAction: "exec",
                process: process
            )
        }
        let action = FileAction(rawValue: file.action) ?? .write
        var enrichments: [String: String] = [:]
        if let content = file.content { enrichments["FileContent"] = content }
        return Event(
            eventCategory: .file,
            eventType: .change,
            eventAction: file.action,
            process: process,
            file: FileInfo(path: file.path, action: action),
            enrichments: enrichments
        )
    }

    private func corpusFacts(_ fixture: RuleCorpusFixture) -> FileEventAdmissionFacts? {
        guard let file = fixture.file,
              let action = FileAction(rawValue: file.action) else { return nil }
        let signer = signerType(fixture.process.signer)
        return .endpointSecurity(
            path: file.path,
            fileAction: action,
            eventAction: file.action,
            eventType: .change,
            processID: 4_321,
            processExecutable: fixture.process.executable,
            processName: (fixture.process.executable as NSString).lastPathComponent,
            processCommandLine: .value(fixture.process.commandLine),
            parentExecutable: .value(fixture.process.parentExec ?? "/bin/bash"),
            signerType: .value(signer.rawValue),
            isPlatformBinary: signer == .apple,
            graphFileKind: .absent,
            graphUntrustedContent: .absent,
            graphPersistenceType: .absent
        )
    }

    @Test("every real positive file fixture fires and crosses pre-callback admission")
    func everyPositiveFileFixtureIsAdmitted() async throws {
        // Isolate the single/sequence corpus for this guard.  A broad graph
        // unknown must not be allowed to make a broken single-rule compiler
        // look safe.
        let descriptors = try await realSnapshot(includeBuiltins: false, includeGraph: false)
        let compiled = FileEventInterestPolicyCompiler.compile(descriptors)
        let engine = RuleEngine()
        _ = try await engine.loadRules(from: URL(fileURLWithPath: "/tmp/maccrab_v3"))

        let fixtureURL = projectRoot
            .appendingPathComponent("Tests/MacCrabCoreTests/fixtures/rule_corpus.json")
        let fixtures = try JSONDecoder().decode(
            [RuleCorpusFixture].self,
            from: Data(contentsOf: fixtureURL)
        ).filter { $0.category == "file_event" && $0.shouldFire }
        #expect(fixtures.count == 7, "file-positive corpus census changed; review admission facts")

        for fixture in fixtures {
            let event = corpusEvent(fixture)
            let fired = await engine.evaluate(event).contains { $0.ruleId == fixture.ruleId }
            #expect(fired, "positive fixture no longer fires: \(fixture.name)")
            let input = try #require(corpusFacts(fixture))
            #expect(
                compiled.policy.shouldAdmit(input, dynamicAI: emptyDynamic),
                "rule-positive callback was rejected: \(fixture.name)"
            )
        }
    }

    @Test("real corpus census and effectiveness remain explicit per source/action")
    func realCorpusCensusAndEffectiveness() async throws {
        let compilation = FileEventInterestPolicyCompiler.compile(try await realSnapshot())
        let census = compilation.census

        #expect(census.enabledFileSingleRules == 137,
                "enabled file-rule census changed; review callback interest coverage")
        #expect(census.enabledFileSequenceSteps == 25,
                "file sequence-step census changed; review out-of-order admission")
        #expect(census.graphFileNodeRequirements == 6)
        #expect(census.graphPersistenceNodeRequirements == 4)
        #expect(census.builtinRequirements == 3)
        #expect(census.totalRequirements == 175)

        let paths = [
            "/Users/test/Documents/ordinary.tmp",
            "/System/Library/ordinary.log",
        ]
        var probes: [FileEventAdmissionFacts] = []
        for action in FileAction.allCases {
            for path in paths {
                probes.append(.endpointSecurity(
                    path: path,
                    fileAction: action,
                    eventAction: action == .close ? "close_modified" : action.rawValue,
                    eventType: action == .create ? .creation : (action == .delete ? .deletion : .change),
                    processID: 99,
                    processExecutable: "/usr/bin/test",
                    processName: "test",
                    processCommandLine: .value("/usr/bin/test"),
                    signerType: .value("unsigned"),
                    isPlatformBinary: false
                    // Graph generator facts are genuinely unknown at the raw
                    // callback boundary.  Current graph rules therefore admit.
                ))
            }
        }
        probes.append(FileEventAdmissionFacts(
            source: .endpointSecurityBTM,
            filePath: .value("/Library/LaunchAgents/example"),
            fileAction: .value("create"),
            eventType: .value("creation"),
            eventAction: .value("btm_add"),
            processID: .value(99),
            processExecutable: .value("/usr/bin/test"),
            processCommandLine: .value("/usr/bin/test"),
            signerType: .value("unsigned"),
            btmItemType: .value("agent"),
            btmLegacy: .value("false"),
            btmManaged: .value("false")
        ))

        let buckets = compilation.policy.effectiveness(
            probes: probes,
            dynamicAI: emptyDynamic,
            honeyfiles: emptyHoneyfiles,
            nowUptimeNanoseconds: 1
        )
        #expect(buckets.count == FileAction.allCases.count + 1)
        for bucket in buckets {
            print("FILE_INTEREST source=\(bucket.source.rawValue) action=\(bucket.action) "
                  + "admitted=\(bucket.admitted)/\(bucket.evaluated) rejected=\(bucket.rejected)")
        }

        // A complete empty deception snapshot must eliminate the previous
        // every-callback `IsHoneyfile` unknown without claiming overall
        // selectivity from this tiny synthetic probe set.
        let diagnostic = compilation.policy.diagnose(
            probes[0],
            dynamicAI: emptyDynamic,
            honeyfiles: emptyHoneyfiles,
            nowUptimeNanoseconds: 1
        )
        #expect(!diagnostic.possibleConsumers.contains {
            $0 == "f1e2d3c4-b5a6-4987-9876-543210dec0de"
        })
    }

    /// Opt-in, read-only host replay. Run with:
    /// `MACCRAB_PRODUCTION_REPLAY_DB=/path/events.db swift test --filter productionReplayDiagnostic`
    @Test("opt-in production file callback replay remains measured by action and reason")
    func productionReplayDiagnostic() async throws {
        guard let databasePath = ProcessInfo.processInfo.environment[
            "MACCRAB_PRODUCTION_REPLAY_DB"
        ] else { return }

        var database: OpaquePointer?
        guard sqlite3_open_v2(
            databasePath,
            &database,
            SQLITE_OPEN_READONLY | SQLITE_OPEN_NOMUTEX,
            nil
        ) == SQLITE_OK, let database else {
            Issue.record("could not open production replay DB read-only")
            return
        }
        defer { sqlite3_close(database) }

        var statement: OpaquePointer?
        guard sqlite3_prepare_v2(
            database,
            "SELECT raw_json FROM events WHERE event_category = 'file' ORDER BY timestamp",
            -1,
            &statement,
            nil
        ) == SQLITE_OK, let statement else {
            Issue.record("could not prepare production file replay query")
            return
        }
        defer { sqlite3_finalize(statement) }

        var probes: [FileEventAdmissionFacts] = []
        var inputByAction: [String: Int] = [:]
        var attributedProcessIDs = Set<Int32>()
        let decoder = JSONDecoder()
        while sqlite3_step(statement) == SQLITE_ROW {
            guard let pointer = sqlite3_column_text(statement, 0) else { continue }
            let event = try decoder.decode(Event.self, from: Data(String(cString: pointer).utf8))
            guard event.eventCategory == .file, let file = event.file else { continue }
            inputByAction[event.eventAction, default: 0] += 1
            if event.enrichments["ai_tool"] != nil
                || event.enrichments["ai_tool_child"] != nil {
                attributedProcessIDs.insert(event.process.pid)
            }
            probes.append(FileEventAdmissionFacts(
                source: .endpointSecurityFile,
                filePath: .value(file.path),
                fileName: .value(file.name),
                fileDirectory: .value(file.directory),
                fileExtension: .known(file.extension_),
                fileSize: .known(file.size.map { String($0) }),
                fileAction: .value(file.action.rawValue),
                fileSourcePath: file.action == .rename
                    ? .known(file.sourcePath) : .absent,
                eventCategory: .value(event.eventCategory.rawValue),
                eventType: .value(event.eventType.rawValue),
                eventAction: .value(event.eventAction),
                processID: .value(event.process.pid),
                processExecutable: .value(event.process.executable),
                processName: .value(event.process.name),
                // Neither argv nor parent executable is present in an ES file
                // callback. Supplying their stored/enriched values here would
                // make replay selectivity optimistically unsafe.
                processCommandLine: .unknown,
                parentExecutable: .unknown,
                signerType: .known(event.process.codeSignature?.signerType.rawValue),
                isPlatformBinary: .value(String(event.process.isPlatformBinary)),
                graphFileKind: .unknown,
                graphUntrustedContent: .unknown,
                graphPersistenceType: .unknown
            ))
        }

        let compilation = FileEventInterestPolicyCompiler.compile(try await realSnapshot())
        #expect(compilation.installedRestrictiveSnapshot)
        let deception = HoneyfilePathSnapshot.current(
            paths: [],
            validUntilUptimeNanoseconds: UInt64.max
        )
        // A union over every attributed PID in the replay window is more
        // permissive than any one live instant, but unlike an `.unknown`
        // snapshot it still exercises the actual consumer path/action census.
        let freshAI = DynamicAIFileEventDemandSnapshot.currentCanonical(
            validUntilUptimeNanoseconds: UInt64.max,
            sessions: attributedProcessIDs.sorted().map {
                DynamicAIFileEventSession(rootProcessID: $0)
            }
        )
        let mutationActions: Set<String> = [
            "create", "write", "close_modified", "rename", "unlink",
            "link", "setmode",
        ]
        let conservativeBoundaryDemands = attributedProcessIDs.sorted().map {
            DynamicAIFileEventDemand(
                processID: $0,
                consumer: .projectBoundary,
                action: .eventActions(mutationActions),
                // The historical DB does not persist ProjectBoundary's
                // separately-resolved root. Empty roots conservatively admit
                // every mutation except the owner's global temp/cache/build
                // exceptions, which can never produce a boundary violation.
                path: .projectBoundaryOutside(roots: [])
            )
        }
        let conservativeFreshAI = DynamicAIFileEventDemandSnapshot.current(
            validUntilUptimeNanoseconds: UInt64.max,
            attributedProcessIDs: freshAI.attributedProcessIDs,
            demands: freshAI.demands + conservativeBoundaryDemands
        )
        let scenarios: [(String, DynamicAIFileEventDemandSnapshot)] = [
            ("fail_open_unknown", .unknown),
            ("fresh_unknown_boundary_roots", conservativeFreshAI),
            ("optimistic_boundary_inactive", freshAI),
        ]

        for (scenario, dynamicAI) in scenarios {
            let started = DispatchTime.now().uptimeNanoseconds
            var admitted: [FileEventAdmissionFacts] = []
            var admittedByAction: [String: Int] = [:]
            admitted.reserveCapacity(probes.count / 10)
            for probe in probes {
                if compilation.policy.shouldAdmit(
                    probe,
                    dynamicAI: dynamicAI,
                    honeyfiles: deception,
                    nowUptimeNanoseconds: 1
                ) {
                    admitted.append(probe)
                    if case .value(let action) = probe.eventAction {
                        admittedByAction[action, default: 0] += 1
                    }
                }
            }
            let elapsed = DispatchTime.now().uptimeNanoseconds - started
            let decisionsPerSecond = elapsed == 0 ? 0
                : Double(probes.count) * 1_000_000_000 / Double(elapsed)
            let rejected = probes.count - admitted.count
            print("FILE_INTEREST_REPLAY scenario=\(scenario) input=\(probes.count) "
                  + "attributed_pids=\(attributedProcessIDs.count) admitted=\(admitted.count) "
                  + "rejected=\(rejected) admitted_pct="
                  + String(format: "%.3f", 100 * Double(admitted.count) / Double(max(1, probes.count)))
                  + " decisions_per_second=" + String(format: "%.1f", decisionsPerSecond))
            for action in inputByAction.keys.sorted() {
                let input = inputByAction[action, default: 0]
                let kept = admittedByAction[action, default: 0]
                print("FILE_INTEREST_REPLAY_ACTION scenario=\(scenario) action=\(action) "
                      + "input=\(input) admitted=\(kept) rejected=\(input - kept)")
            }

            var firstReasonCounts: [String: Int] = [:]
            for probe in admitted {
                let decision = compilation.policy.diagnose(
                    probe,
                    dynamicAI: dynamicAI,
                    honeyfiles: deception,
                    nowUptimeNanoseconds: 1
                )
                firstReasonCounts[decision.possibleConsumers.first ?? "<none>", default: 0] += 1
            }
            for reason in firstReasonCounts.sorted(by: {
                $0.value == $1.value ? $0.key < $1.key : $0.value > $1.value
            }).prefix(20) {
                print("FILE_INTEREST_REPLAY_REASON scenario=\(scenario) "
                      + "count=\(reason.value) id=\(reason.key)")
            }
        }
    }

    @Test("compiled callback decision has bounded synthetic worst-case throughput")
    func throughputDiagnostic() {
        let synthetic = (0..<512).map { index in
            rule(
                id: "perf-\(index)",
                predicates: [Predicate(
                    field: "file.path", modifier: .equals,
                    values: ["/never/\(index)"], negate: false
                )]
            )
        }
        let compiled = policy(rules: synthetic)
        let input = facts(path: "/does/not/match")
        let iterations = 20_000
        var admits = 0
        let start = DispatchTime.now().uptimeNanoseconds
        for _ in 0..<iterations {
            if compiled.shouldAdmit(input, dynamicAI: emptyDynamic, nowUptimeNanoseconds: 1) {
                admits += 1
            }
        }
        let elapsed = DispatchTime.now().uptimeNanoseconds - start
        let nsPerDecision = Double(elapsed) / Double(iterations)
        print("FILE_INTEREST_PERF requirements=512 iterations=\(iterations) "
              + "elapsed_ns=\(elapsed) ns_per_decision=\(nsPerDecision)")
        #expect(admits == 0)
        // The ceiling is deliberately far above any plausible healthy runtime.
        //
        // It was 5 s (250 us/decision), which reads generous but is not: this
        // assertion runs inside the release gate, on the same machine that has
        // just finished a from-scratch universal build, and wall-clock timing
        // there is a measure of how busy the Mac is as much as of the code.
        // Observed on this host at 5.08 s and 5.64 s — 1.6% and 13% over — and
        // the 5.64 s instance FAILED AN rc.8 RELEASE BUILD, costing a full
        // ~50-minute cycle for a test that was never about absolute speed.
        //
        // What this test is actually for is catching a pathological regression:
        // a linear scan turning quadratic, a per-decision allocation appearing
        // in the hot path. Those are order-of-magnitude effects. 20 s (1 ms per
        // decision, 4x the previous ceiling) still catches any of them while
        // leaving enough headroom that a loaded machine cannot manufacture a
        // release failure. The measured value is printed above either way, so
        // gradual drift stays visible to a human reading the log.
        #expect(elapsed < 20_000_000_000,
                "512-requirement negative decision exceeded 1ms/decision — a pathological regression, not machine load")
    }
}
