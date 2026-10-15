import Foundation
import Combine

struct V2DetectionRuleSnapshot: Sendable {
    let rules: [V2MockRule]
    let haystack: [String: String]
    let compositeLabels: [String: String]
    let disabledOverrideIDs: Set<String>

    static func prepare(_ rules: [V2MockRule], directory: String?) -> Self {
        let haystack = Dictionary(rules.map { ($0.id, V2DetectionWorkspace.ruleSearchHaystack(for: $0)) },
                                 uniquingKeysWith: { first, _ in first })
        let labels = Dictionary(rules.filter { $0.category == "Sequence" || $0.category == "Graph" }
            .map { ($0.id.lowercased(), $0.title) }, uniquingKeysWith: { _, last in last })
        return .init(rules: rules, haystack: haystack, compositeLabels: labels,
                     disabledOverrideIDs: directory.map { disabledIDs(in: $0 + "/user_rules") } ?? [])
    }

    static func disabledIDs(in directory: String) -> Set<String> {
        struct Stub: Decodable { let id: String; let enabled: Bool }
        guard let urls = try? FileManager.default.contentsOfDirectory(
            at: URL(fileURLWithPath: directory), includingPropertiesForKeys: nil) else { return [] }
        return Set(urls.compactMap { url in
            guard url.pathExtension == "json", let data = try? Data(contentsOf: url),
                  let stub = try? JSONDecoder().decode(Stub.self, from: data), !stub.enabled else { return nil }
            return stub.id
        })
    }
}

/// Selected-tab reads only. One underlying operation per tab survives polling
/// ticks, so a read slower than the poll interval is not restarted or starved.
/// Superseded callers cannot publish, and hidden tabs start no additional work.
@MainActor
final class V2DetectionLoadSession: ObservableObject {
    enum Tab: Hashable {
        case rules, browser, mcp, agents
        init(_ tab: V2WorkspaceTab) {
            switch tab {
            case .detectionBrowser: self = .browser
            case .detectionMCP: self = .mcp
            case .detectionAIGuard: self = .agents
            default: self = .rules
            }
        }
    }
    struct Key: Equatable {
        let provider: ObjectIdentifier
        let tab: Tab
        let tick: Int
    }
    enum Snapshot: Sendable {
        case rules(V2DetectionRuleSnapshot)
        case browser([V2MockExtension])
        case mcp([V2MockMCP])
        case agents([V2AgentSession])
    }
    struct Operations {
        var rules: () async -> V2DetectionRuleSnapshot
        var browser: () async -> [V2MockExtension]
        var mcp: () async -> [V2MockMCP]
        var agents: () async -> [V2AgentSession]
    }
    private struct Flight {
        let id: UUID
        let provider: ObjectIdentifier
        let task: Task<Snapshot, Never>
    }
    private var flights: [Tab: Flight] = [:]
    private var generation = UUID()
    private let onJoin: ((Tab) -> Void)?

    init(onJoin: ((Tab) -> Void)? = nil) { self.onJoin = onJoin }

    func invalidate() {
        generation = UUID()
        for flight in flights.values { flight.task.cancel() }
    }

    func load(tab: Tab, provider: any V2DataProvider) async -> Snapshot? {
        let directory = provider.dataDir
        return await load(tab: tab, providerID: ObjectIdentifier(provider), operations: Operations(
            rules: {
                let rules = await provider.rules()
                guard !Task.isCancelled else { return V2DetectionRuleSnapshot.prepare([], directory: nil) }
                return await Task.detached(priority: .userInitiated) {
                    V2DetectionRuleSnapshot.prepare(rules, directory: directory)
                }.value
            }, browser: { await provider.extensions() }, mcp: { await provider.mcpServers() },
            agents: { await provider.agentSessions(limit: 50) }))
    }

    func load(tab: Tab, providerID: ObjectIdentifier, operations: Operations) async -> Snapshot? {
        guard !Task.isCancelled else { return nil }
        let request = UUID()
        generation = request
        for (other, flight) in flights where other != tab { flight.task.cancel() }
        while let current = flights[tab] {
            if current.provider != providerID { current.task.cancel() }
            onJoin?(tab)
            let result = await current.task.value
            if flights[tab]?.id == current.id { flights[tab] = nil }
            guard !Task.isCancelled, generation == request else { return nil }
            if current.provider == providerID, !current.task.isCancelled { return result }
        }
        let task = Task { @MainActor in
            switch tab {
            case .rules: return Snapshot.rules(await operations.rules())
            case .browser: return Snapshot.browser(await operations.browser())
            case .mcp: return Snapshot.mcp(await operations.mcp())
            case .agents: return Snapshot.agents(await operations.agents())
            }
        }
        let current = Flight(id: UUID(), provider: providerID, task: task)
        flights[tab] = current
        let result = await task.value
        if flights[tab]?.id == current.id { flights[tab] = nil }
        guard !Task.isCancelled, generation == request, !task.isCancelled else { return nil }
        return result
    }
}

/// The same latest-result guard used by the actual detached rule filter. The
/// operation seam lets tests control completion order without sleeps.
@MainActor
final class V2DetectionRuleFilter: ObservableObject {
    private var generation = UUID()

    func invalidate() { generation = UUID() }

    func filter(rules: [V2MockRule], haystack: [String: String], query: String) async -> [V2MockRule]? {
        await filter {
            await Task.detached(priority: .userInitiated) {
                guard !query.isEmpty else { return rules }
                return rules.filter { (haystack[$0.id] ?? V2DetectionWorkspace.ruleSearchHaystack(for: $0)).contains(query) }
            }.value
        }
    }

    func filter(operation: () async -> [V2MockRule]) async -> [V2MockRule]? {
        guard !Task.isCancelled else { return nil }
        let request = UUID()
        generation = request
        let result = await operation()
        guard !Task.isCancelled, generation == request else { return nil }
        return result
    }
}
