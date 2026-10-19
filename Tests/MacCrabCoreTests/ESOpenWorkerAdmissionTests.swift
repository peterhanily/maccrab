import Dispatch
import EndpointSecurity
import Foundation
import Testing
@testable import MacCrabCore

/// Inert policy tests: no ES client, files, timers, stores, or shared registry.
/// Full-facts comparison checks fact reduction, not evaluator correctness.
/// Separate explicit truth tables below independently check that evaluator.
@Suite("ES OPEN worker admission equivalence")
struct ESOpenWorkerAdmissionTests {
    private let dynamic = BuiltinFileEventRequirement(
        id: "fixture.dynamic", sources: [.endpointSecurityFile], kind: .dynamicAIConsumers)
    private let paths = [
        "/Users/fixture/project/main.swift", "/Users/fixture/project/README.md",
        "/private/tmp/fixture.bin", "/Users/fixture/project/.env",
        "/Users/fixture/.ssh/id_ed25519", "/Users/fixture/.claude/settings.json",
        "/Users/fixture/project/.github/workflows/ci.yml",
        "/Users/fixture/Library/Keychains/login.keychain-db",
        "/Users/fixture/project/../other/é.TXT", "/Users/fixture/project/e\u{301}.md",
        "/Users/fixture/project/文件.swift", "/Users/fixture/project/trailing/",
        "", "/", "/private/tmp/" + String(repeating: "x", count: 4_097),
    ]

    private func descriptor(_ builtins: [BuiltinFileEventRequirement]) -> FileEventInterestDescriptorSnapshot {
        .init(singleEventRules: [], sequenceRules: [], graphRules: [], builtinRequirements: builtins)
    }

    private func registry(_ snapshot: DynamicAIFileEventDemandSnapshot) -> FileEventInterestPolicyRegistry {
        let result = FileEventInterestPolicyRegistry()
        _ = result.install(descriptor([dynamic]))
        #expect(result.publishDynamicAI(snapshot))
        return result
    }

    private func facts(_ path: String, pid: Int32?, platform: Bool = false) -> FileEventAdmissionFacts {
        .endpointSecurity(path: path, fileAction: .open, eventAction: "open", eventType: .change,
                          processID: pid, isPlatformBinary: platform)
    }

    private func fast(_ registry: FileEventInterestPolicyRegistry, path: String,
                      pid: Int32?, platform: Bool = false, now: UInt64 = 100) -> Bool {
        registry.shouldAdmitEndpointSecurityOpen(
            path: path, processID: pid, isPlatformBinary: platform,
            fullFacts: facts(path, pid: pid, platform: platform), nowUptimeNanoseconds: now)
    }

    @Test("canonical current, unknown and expired demand preserve every OPEN verdict")
    func canonicalEquivalence() {
        let current = DynamicAIFileEventDemandSnapshot.currentCanonical(
            validUntilUptimeNanoseconds: 200,
            sessions: [.init(rootProcessID: 42, childProcessIDs: [43], projectRoots: ["/Users/fixture/project"])])
        for snapshot in [current, .unknown, .current(validUntilUptimeNanoseconds: 200, demands: [])] {
            let candidate = registry(snapshot)
            for now in [100, 200, 201] as [UInt64] {
                for pid in [nil, 42, 43, 99] as [Int32?] {
                    for path in paths {
                        for platform in [false, true] {
                            #expect(fast(candidate, path: path, pid: pid, platform: platform, now: now)
                                == candidate.shouldAdmit(facts(path, pid: pid, platform: platform), nowUptimeNanoseconds: now))
                        }
                    }
                }
            }
        }
    }

    @Test("all dynamic path/action forms keep their original Unicode and unknown semantics")
    func customDynamicDemands() {
        let demands: [DynamicFileEventPathDemand] = [
            .any, .supportedTextFile, .agentContentFile, .defaultCredentialFence,
            .projectBoundaryOutside(roots: ["/Users/fixture/project"]),
            .equals(["/Users/fixture/project/é.txt"], caseInsensitive: true),
            .prefixes(["/Users/fixture/project"], caseInsensitive: false),
            .suffixes([".TXT"], caseInsensitive: true),
            .contains(["文件", "e\u{301}"], caseInsensitive: false),
            .extensions(["swift", "TXT"], caseInsensitive: true),
            .outsideRoots(["/Users/fixture/project"], caseInsensitive: false),
            .outsideRootsExcluding(roots: ["/Users/fixture/project"], allowedExact: ["/dev/null"],
                                  allowedSubstrings: ["/private/tmp/"], caseInsensitive: true),
        ]
        let actions: [DynamicFileEventActionDemand] = [.any, .fileActions(["open"]),
            .eventActions(["open"]), .eventActions(["write"]), .fileActions([])]
        for pathDemand in demands {
            for action in actions {
                for owner in [nil, 43] as [Int32?] {
                    let candidate = registry(.current(validUntilUptimeNanoseconds: 200,
                        demands: [.init(processID: owner, action: action, path: pathDemand)]))
                    for pid in [nil, 43, 99] as [Int32?] {
                        for path in paths {
                            #expect(fast(candidate, path: path, pid: pid)
                                == candidate.shouldAdmit(facts(path, pid: pid), nowUptimeNanoseconds: 100))
                        }
                    }
                }
            }
        }
    }

    @Test("known-false action rejects; unknown action still considers a disproven or possible path")
    func actionTruthTable() {
        let candidate = registry(.current(validUntilUptimeNanoseconds: 200,
            demands: [.init(processID: 43, action: .eventActions(["write"]),
                            path: .equals(["/fixture/match"], caseInsensitive: false))]))
        let cases: [(FileEventFact<String>, FileEventFact<String>, Bool)] = [
            (.value("open"), .unknown, false), (.value("open"), .value("/fixture/match"), false),
            (.absent, .unknown, false), (.unknown, .value("/fixture/miss"), false),
            (.unknown, .value("/fixture/match"), true), (.unknown, .unknown, true),
            (.value("write"), .value("/fixture/match"), true),
            (.value("write"), .value("/fixture/miss"), false), (.value("write"), .unknown, true),
        ]
        for (action, path, expected) in cases {
            let input = FileEventAdmissionFacts(source: .endpointSecurityFile, filePath: path,
                eventAction: action, processID: .value(43))
            #expect(candidate.shouldAdmit(input, nowUptimeNanoseconds: 100) == expected)
        }
    }

    @Test("independent conjunction oracle covers absent, unknown, matching and disproven facts")
    func independentConjunctionOracle() {
        // The expected answers are fixture data, never another call into the
        // evaluator under test. A conjunction can be dropped iff at least one
        // input is known false; unknown must remain fail-open.
        let processes: [(FileEventFact<Int32>, Bool)] = [
            (.unknown, true), (.absent, false), (.value(43), true), (.value(99), false),
        ]
        let actions: [(FileEventFact<String>, Bool)] = [
            (.unknown, true), (.absent, false), (.value("open"), true), (.value("write"), false),
        ]
        let locations: [(FileEventFact<String>, Bool)] = [
            (.unknown, true), (.absent, false), (.value("/fixture/match"), true),
            (.value("/fixture/miss"), false),
        ]
        for demandAction in [DynamicFileEventActionDemand.fileActions(["open"]), .eventActions(["open"])] {
            let candidate = registry(.current(validUntilUptimeNanoseconds: 200,
                demands: [.init(processID: 43, action: demandAction,
                    path: .equals(["/fixture/match"], caseInsensitive: false))]))
            for (pid, processPossible) in processes {
                for (action, actionPossible) in actions {
                    for (path, pathPossible) in locations {
                        let input = FileEventAdmissionFacts(source: .endpointSecurityFile,
                            filePath: path, fileAction: action, eventAction: action, processID: pid)
                        #expect(candidate.shouldAdmit(input, nowUptimeNanoseconds: 100)
                            == (processPossible && actionPossible && pathPossible))
                    }
                }
            }
        }
        let matching = registry(.current(validUntilUptimeNanoseconds: 200,
            demands: [.init(processID: 43, action: .eventActions(["open"]),
                path: .equals(["/fixture/match"], caseInsensitive: false))]))
        #expect(fast(matching, path: "/fixture/match", pid: 43))
        #expect(!fast(matching, path: "/fixture/miss", pid: 43))
        #expect(!fast(matching, path: "/fixture/match", pid: 99))
        #expect(fast(matching, path: "/fixture/match", pid: nil))
    }

    @Test("custom/mixed/unknown policy uses the complete original facts, not an inferred dynamic shape")
    func fullFactFallback() {
        let empty = DynamicAIFileEventDemandSnapshot.current(validUntilUptimeNanoseconds: 200, demands: [])
        for (field, matching) in [("file.name", "match.swift"), ("file.directory", "/fixture"),
                                  ("file.extension", "swift")] {
            let candidate = registry(empty)
            let custom = BuiltinFileEventRequirement(id: "fixture.custom", kind: .predicates(
                predicates: [Predicate(field: field, modifier: .equals, values: [matching], negate: false)],
                condition: .allOf, conditionTree: nil))
            _ = candidate.install(descriptor([dynamic, custom]))
            var fullReads = 0
            func full() -> FileEventAdmissionFacts { fullReads += 1; return facts("/fixture/match.swift", pid: 43) }
            #expect(candidate.shouldAdmitEndpointSecurityOpen(path: "/fixture/match.swift", processID: 43,
                isPlatformBinary: false, fullFacts: full(), nowUptimeNanoseconds: 100))
            #expect(fullReads == 1)
            for path in paths {
                #expect(fast(candidate, path: path, pid: 43)
                    == candidate.shouldAdmit(facts(path, pid: 43), nowUptimeNanoseconds: 100))
            }
        }
        let unknown = FileEventInterestPolicyRegistry()
        var fullReads = 0
        func full() -> FileEventAdmissionFacts { fullReads += 1; return facts("/fixture/input", pid: nil) }
        #expect(unknown.shouldAdmitEndpointSecurityOpen(path: "/fixture/input", processID: nil,
            isPlatformBinary: false, fullFacts: full(), nowUptimeNanoseconds: 100))
        #expect(fullReads == 1)
    }

    @Test("dynamic-only publication avoids derived facts; policy replacement cannot reuse that proof")
    func lazyFactsAndReplacement() {
        let candidate = registry(.unknown)
        var fullReads = 0
        func full() -> FileEventAdmissionFacts { fullReads += 1; return facts("/fixture/input", pid: 43) }
        func read() -> Bool {
            candidate.shouldAdmitEndpointSecurityOpen(path: "/fixture/input", processID: 43,
                isPlatformBinary: false, fullFacts: full(), nowUptimeNanoseconds: 100)
        }
        #expect(read())
        #expect(fullReads == 0)
        _ = candidate.install(descriptor([.init(id: "fixture.other", kind: .unconditional)]))
        #expect(read())
        #expect(fullReads == 1)
        _ = candidate.install(descriptor([dynamic]))
        #expect(candidate.publishDynamicAI(.current(validUntilUptimeNanoseconds: 200, demands: [])))
        #expect(!read())
        #expect(fullReads == 1)
    }

    @Test("grace, revocation and oversized publication remain fail-open exactly as the general entry")
    func graceAndBounds() {
        let candidate = registry(.current(validUntilUptimeNanoseconds: 200, demands: []))
        #expect(candidate.grantDynamicAIGrace(processID: 43, validUntilUptimeNanoseconds: 150, nowUptimeNanoseconds: 100))
        for now in [100, 150, 151, 201] as [UInt64] {
            #expect(fast(candidate, path: "/fixture/input.bin", pid: 43, now: now)
                == candidate.shouldAdmit(facts("/fixture/input.bin", pid: 43), nowUptimeNanoseconds: now))
        }
        candidate.revokeDynamicAIGrace(processID: 43)
        #expect(!fast(candidate, path: "/fixture/input.bin", pid: 43))
        let bounded = FileEventInterestPolicyRegistry(limits: .init(maximumDynamicDemands: 0))
        _ = bounded.install(descriptor([dynamic]))
        #expect(!bounded.publishDynamicAI(.current(validUntilUptimeNanoseconds: 200, demands: [.init()])))
        #expect(fast(bounded, path: "/fixture/input.bin", pid: 43))
    }

    @Test("ES keychain/static protection gates match the original full-facts implementation")
    func esWorkerWiring() {
        // Include a known empty snapshot: unknown demand alone can never
        // exercise the dynamic drop path. Use a non-expiring fixture because
        // the production worker samples its own monotonic clock.
        for snapshot in [DynamicAIFileEventDemandSnapshot.unknown,
                         .current(validUntilUptimeNanoseconds: UInt64.max, demands: [])] {
            let candidate = registry(snapshot)
            for path in paths {
                for platform in [false, true] {
                    for protected in [nil, false, true] as [Bool?] {
                        let oldDrop: Bool
                        if platform && ESCollector.isKeychainPath(path) { oldDrop = true }
                        else if protected ?? (ESCollector.isCredentialReadPath(path) || ESCollector.isAgentContentReadPath(path)) {
                            oldDrop = false
                        } else { oldDrop = !candidate.shouldAdmit(facts(path, pid: 43)) }
                        #expect(ESCollector.shouldDropBeforeWorker(eventType: ES_EVENT_TYPE_NOTIFY_OPEN.rawValue,
                            path: path, isPlatformBinary: platform, processID: 43, protectedPath: protected,
                            dynamicAIRegistry: candidate) == oldDrop)
                    }
                }
            }
        }
        let noDemand = registry(.current(validUntilUptimeNanoseconds: UInt64.max, demands: []))
        #expect(ESCollector.shouldDropBeforeWorker(eventType: ES_EVENT_TYPE_NOTIFY_OPEN.rawValue,
            path: "/fixture/ordinary.bin", processID: 43, protectedPath: false, dynamicAIRegistry: noDemand))
        #expect(!ESCollector.shouldDropBeforeWorker(eventType: ES_EVENT_TYPE_NOTIFY_OPEN.rawValue,
            path: "/fixture/ordinary.bin", processID: 43, protectedPath: true, dynamicAIRegistry: noDemand))
    }

    @Test("demand expiring during full facts is unknown at the single late clock sample")
    func demandExpiryDuringFacts() {
        let candidate = registry(.current(validUntilUptimeNanoseconds: 200, demands: []))
        let custom = BuiltinFileEventRequirement(id: "fixture.custom", kind: .predicates(
            predicates: [Predicate(field: "file.name", modifier: .equals,
                                   values: ["never-matches"], negate: false)],
            condition: .allOf, conditionTree: nil))
        _ = candidate.install(descriptor([dynamic, custom]))
        let input = facts("/fixture/input.bin", pid: 43)
        #expect(!candidate.shouldAdmit(input, nowUptimeNanoseconds: 100))
        #expect(candidate.shouldAdmit(input, nowUptimeNanoseconds: 201))
        var now: UInt64 = 100
        var factReads = 0, clockReads = 0
        func full() -> FileEventAdmissionFacts { factReads += 1; now = 201; return input }
        func clock() -> UInt64 { clockReads += 1; #expect(factReads == 1); return now }
        #expect(candidate.shouldAdmitEndpointSecurityOpen(path: "/fixture/input.bin", processID: 43,
            isPlatformBinary: false, fullFacts: full(), nowUptimeNanoseconds: clock()))
        #expect(factReads == 1 && clockReads == 1)
    }

    @Test("grace expiring during full facts does not retain a prematurely resolved unknown demand")
    func graceExpiryDuringFacts() {
        let candidate = registry(.current(validUntilUptimeNanoseconds: 300, demands: []))
        let custom = BuiltinFileEventRequirement(id: "fixture.custom", kind: .predicates(
            predicates: [Predicate(field: "file.name", modifier: .equals,
                                   values: ["never-matches"], negate: false)],
            condition: .allOf, conditionTree: nil))
        _ = candidate.install(descriptor([dynamic, custom]))
        #expect(candidate.grantDynamicAIGrace(processID: 43,
            validUntilUptimeNanoseconds: 150, nowUptimeNanoseconds: 100))
        let input = facts("/fixture/input.bin", pid: 43)
        #expect(candidate.shouldAdmit(input, nowUptimeNanoseconds: 100))
        #expect(!candidate.shouldAdmit(input, nowUptimeNanoseconds: 151))
        var now: UInt64 = 100
        var factReads = 0, clockReads = 0
        func full() -> FileEventAdmissionFacts { factReads += 1; now = 151; return input }
        func clock() -> UInt64 { clockReads += 1; #expect(factReads == 1); return now }
        #expect(!candidate.shouldAdmitEndpointSecurityOpen(path: "/fixture/input.bin", processID: 43,
            isPlatformBinary: false, fullFacts: full(), nowUptimeNanoseconds: clock()))
        #expect(factReads == 1 && clockReads == 1)
    }

    @Test("fallback observes policy, demand or grace published while constructing full facts",
          arguments: ["policy", "demand", "grace"])
    func fallbackPublicationDuringFacts(publication: String) {
        let candidate = registry(.current(validUntilUptimeNanoseconds: 300, demands: []))
        let custom = BuiltinFileEventRequirement(id: "fixture.custom", kind: .predicates(
            predicates: [Predicate(field: "file.name", modifier: .equals,
                                   values: ["never-matches"], negate: false)],
            condition: .allOf, conditionTree: nil))
        _ = candidate.install(descriptor([dynamic, custom]))
        let input = facts("/fixture/input.bin", pid: 43)
        #expect(!candidate.shouldAdmit(input, nowUptimeNanoseconds: 100))
        var factReads = 0, clockReads = 0
        func full() -> FileEventAdmissionFacts {
            factReads += 1
            switch publication {
            case "policy":
                _ = candidate.install(descriptor([.init(id: "fixture.new", kind: .unconditional)]))
            case "demand":
                #expect(candidate.publishDynamicAI(.current(validUntilUptimeNanoseconds: 300,
                    demands: [.init(processID: 43, action: .any, path: .any)])))
            default:
                #expect(candidate.grantDynamicAIGrace(processID: 43,
                    validUntilUptimeNanoseconds: 200, nowUptimeNanoseconds: 100))
            }
            return input
        }
        func clock() -> UInt64 { clockReads += 1; #expect(factReads == 1); return 100 }
        #expect(candidate.shouldAdmitEndpointSecurityOpen(path: "/fixture/input.bin", processID: 43,
            isPlatformBinary: false, fullFacts: full(), nowUptimeNanoseconds: clock()))
        #expect(candidate.shouldAdmit(input, nowUptimeNanoseconds: 100))
        #expect(factReads == 1 && clockReads == 1)
    }

    @Test("bounded same-process full-facts versus specialized-facts cost; not installed throughput")
    func descriptiveFactCost() {
        let candidate = registry(.currentCanonical(validUntilUptimeNanoseconds: UInt64.max,
            sessions: [.init(rootProcessID: 42, childProcessIDs: [43], projectRoots: ["/Users/fixture/project"]) ]))
        let paths = ["/Users/fixture/project/main.swift", "/private/tmp/input.bin"]
        let count = 4_000
        var fullCount = 0, fastCount = 0
        let started = DispatchTime.now().uptimeNanoseconds
        for i in 0..<count where candidate.shouldAdmit(facts(paths[i % 2], pid: 43), nowUptimeNanoseconds: 100) { fullCount += 1 }
        let middle = DispatchTime.now().uptimeNanoseconds
        for i in 0..<count where fast(candidate, path: paths[i % 2], pid: 43) { fastCount += 1 }
        let ended = DispatchTime.now().uptimeNanoseconds
        #expect(fullCount == count / 2 && fastCount == fullCount)
        print("BENCH worker_open_facts full_ns=\(middle - started) specialized_ns=\(ended - middle) decisions=\(count)")
    }
}
