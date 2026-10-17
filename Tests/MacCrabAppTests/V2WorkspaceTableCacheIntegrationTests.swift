import Foundation
import MacCrabCore
import Testing
@testable import MacCrabApp

/// Pure value/model integration fixtures. No AppState, provider, native window,
/// stores, installed application, timers or rule mutation endpoints are used.
@MainActor
@Suite("Workspace table cache input and retention contracts")
struct V2WorkspaceTableCacheIntegrationTests {
    private final class ProviderIdentity {}

    private func rule(_ id: String = "fixture-rule", matches: Int = 0) -> V2MockRule {
        .init(id: id, title: "Synthetic rule", category: "File", severity: .low,
              mitre: [], isEnabled: true, lastFired: nil, firesLastWeek: matches,
              isCustom: false, description: "Inert metadata")
    }

    private func alert(payload: String = "") -> V2MockAlert {
        .init(id: "fixture-alert", title: "Synthetic alert", severity: .low, ruleId: "fixture-rule",
              process: "fixture", processPath: "/inert", pid: 1, parent: "fixture", user: "fixture",
              triggeringEventsJson: payload, timestamp: Date(timeIntervalSince1970: 1_000),
              mitre: [], category: "File", description: "Inert metadata", actionsTaken: [], suppressed: false)
    }

    private func engine(_ start: Double = 100) -> V2AlertsPresentationContext.Engine {
        .init(EngineTelemetryIdentity(pid: 123, startedAtUnix: start, version: "fixture", build: "unit"))
    }

    @Test("Rules exact key includes full rows, source, epoch, query, selection and override context")
    func ruleKey() {
        let provider = ProviderIdentity(), other = ProviderIdentity()
        let identity = V2DetectionPresentation.Identity(provider: ObjectIdentifier(provider),
                                                        directory: "/inert-not-read", epoch: 1)
        let item = rule()
        func key(identity keyIdentity: V2DetectionPresentation.Identity? = nil,
                 engine keyEngine: V2AlertsPresentationContext.Engine? = nil,
                 query: String = "", rows: [V2MockRule]? = nil,
                 selection: V2MockRule? = nil, disabled: Set<String> = []) -> V2RulesTableCacheKey {
            .init(identity: keyIdentity ?? identity, engine: keyEngine ?? engine(), query: query,
                  rows: rows ?? [item], selection: selection, disabledOverrideIDs: disabled)
        }
        let baseline = key()
        #expect(baseline == key())
        #expect(baseline.hasBoundedTransientInputs)
        #expect(key(query: String(repeating: "é", count: 4_096)).hasBoundedTransientInputs)
        #expect(!key(query: String(repeating: "é", count: 4_097)).hasBoundedTransientInputs)
        #expect(!key(selection: item).hasBoundedTransientInputs)
        #expect(baseline != key(rows: [rule(matches: 1)])) // Same ID is not an exact content hit.
        #expect(baseline != key(rows: []))
        #expect(baseline != key(query: "fixture"))
        #expect(baseline != key(selection: item))
        #expect(baseline != key(disabled: [item.id]))
        #expect(baseline != key(engine: engine(101)))
        for mismatch in [
            V2DetectionPresentation.Identity(provider: ObjectIdentifier(other), directory: identity.directory, epoch: 1),
            .init(provider: identity.provider, directory: "/other-inert-not-read", epoch: 1),
            .init(provider: identity.provider, directory: identity.directory, epoch: 2),
        ] { #expect(baseline != key(identity: mismatch)) }
    }

    @Test("Open Alerts exact key includes the entire population and every local selection/filter")
    func alertKey() {
        let provider = ProviderIdentity(), other = ProviderIdentity()
        func context(providerID: ObjectIdentifier? = nil, range: String = "7d",
                     directory: String = "/inert-not-read", start: Double = 100,
                     windowEnd: Date? = nil) -> V2AlertsPresentationContext {
            .init(query: .init(providerID: providerID ?? ObjectIdentifier(provider), timeRange: range,
                               windowStart: nil, windowEnd: windowEnd), directory: directory, engine: engine(start))
        }
        func key(context keyContext: V2AlertsPresentationContext? = nil, epoch: UInt64 = 1,
                 query: String = "", severity: V2Severity? = nil, rows: [V2MockAlert]? = nil,
                 selection: V2MockAlert? = nil, selectedIDs: Set<String> = []) -> V2OpenAlertsTableCacheKey {
            .init(context: keyContext ?? context(), epoch: epoch, query: query, severity: severity,
                  rows: rows ?? [alert()], selection: selection, multiSelection: selectedIDs)
        }
        let baseline = key()
        #expect(baseline == key())
        #expect(baseline.hasBoundedTransientInputs)
        #expect(key(query: String(repeating: "é", count: 4_096)).hasBoundedTransientInputs)
        #expect(!key(query: String(repeating: "é", count: 4_097)).hasBoundedTransientInputs)
        #expect(!key(selection: alert()).hasBoundedTransientInputs)
        #expect(!key(selectedIDs: ["fixture-alert"]).hasBoundedTransientInputs)
        #expect(baseline != key(rows: [alert(payload: "changed evidence, same ID")]))
        #expect(baseline != key(epoch: 2))
        #expect(baseline != key(query: "fixture"))
        #expect(baseline != key(severity: .high))
        #expect(baseline != key(selection: alert()))
        #expect(baseline != key(selectedIDs: ["fixture-alert"]))
        for mismatch in [context(providerID: ObjectIdentifier(other)), context(range: "24h"),
                         context(directory: "/other-inert-not-read"), context(start: 101),
                         context(windowEnd: Date(timeIntervalSince1970: 2_000))] {
            #expect(baseline != key(context: mismatch))
        }
    }

    @Test("Rules host admission refuses missing, oversized, empty, expired and mismatched snapshots")
    func ruleRetention() async {
        let provider = ProviderIdentity(), model = V2DetectionPresentation()
        let identity = V2DetectionPresentation.Identity(provider: ObjectIdentifier(provider),
                                                        directory: "/inert-not-read", epoch: 1)
        #expect(!model.canRetainTable(for: identity))
        await model.refresh(identity: identity) { .success([rule()]) }
        #expect(model.canRetainTable(for: identity))
        model.leave()
        #expect(!model.isCurrent(for: identity))
        #expect(model.canRetainTable(for: identity)) // Retainable is explicitly not current.
        #expect(!model.canRetainTable(for: identity, now: .distantFuture))
        #expect(!model.canRetainTable(for: identity, now: .distantPast))
        #expect(!model.canRetainTable(for: identity, now: Date(timeIntervalSince1970: .nan)))
        #expect(!model.canRetainTable(for: .init(provider: identity.provider, directory: identity.directory, epoch: 2)))
        let oversized = V2DetectionPresentation()
        await oversized.refresh(identity: identity) {
            .success(Array(repeating: rule(), count: V2DetectionPresentation.maximumRows + 1))
        }
        #expect(!oversized.canRetainTable(for: identity))
        await model.refresh(identity: identity) { .success([]) }
        #expect(!model.canRetainTable(for: identity))
        model.leave()
        #expect(model.snapshot(for: identity) == nil)
    }

    @Test("Alerts host admission reuses the exact existing string-budget and known-source policy")
    func alertRetention() async {
        let provider = ProviderIdentity(), model = V2AlertsPresentationModel()
        let query = V2AlertsLoadContext(providerID: ObjectIdentifier(provider), timeRange: "7d",
                                       windowStart: nil, windowEnd: nil)
        let context = V2AlertsPresentationContext(query: query, directory: "/inert-not-read", engine: engine())
        let now = Date(timeIntervalSince1970: 1_000)
        #expect(!model.canRetainTable(for: context))
        await model.refresh(context: context, now: now, isCurrent: { true }) { _, _ in .success([alert()]) }
        #expect(model.canRetainTable(for: context))
        model.pause()
        #expect(!model.isFresh(for: context))
        #expect(model.canRetainTable(for: context))
        #expect(!model.canRetainTable(for: .init(query: query, directory: "/other-inert-not-read", engine: engine())))
        let unknown = V2AlertsPresentationContext(query: query, directory: nil, engine: nil)
        let unknownModel = V2AlertsPresentationModel()
        await unknownModel.refresh(context: unknown, now: now, isCurrent: { true }) { _, _ in .success([alert()]) }
        #expect(!unknownModel.canRetainTable(for: unknown))
        let oversized = V2AlertsPresentationModel()
        let large = alert(payload: String(repeating: "x", count: V2AlertsPresentationModel.maximumRetainedStringBytes))
        await oversized.refresh(context: context, now: now, isCurrent: { true }) { _, _ in .success([large]) }
        #expect(oversized.rows(for: context) == [large]) // Visible success is not silently truncated.
        #expect(!oversized.canRetainTable(for: context))
        oversized.pause()
        #expect(oversized.rows(for: context).isEmpty)
    }
}
