import Foundation
import Testing
@testable import MacCrabApp

@Suite("Privacy-safe workspace content readiness")
struct UIContentReadinessTests {
    @Test("A new presentation is unavailable, never implicitly loaded-empty")
    func initialState() {
        for workspace in UIContentReadiness.Workspace.allCases {
            let state = UIContentReadiness(workspace: workspace)
            #expect(state.phase == .unavailable)
            #expect(!state.phase.isFreshCompletion)
            #expect(state.workspace == workspace)
        }
    }

    @Test("Loading and retained-content refresh are distinguishable", arguments: [false, true])
    func beginState(retainingCachedContent: Bool) {
        var state = UIContentReadiness(workspace: .events)
        let previous = state.generation
        let ticket = state.begin(retainingCachedContent: retainingCachedContent)
        #expect(state.generation != previous)
        #expect(state.phase == (retainingCachedContent ? .refreshingCached : .loading))
        #expect(!state.phase.isFreshCompletion)
        let accepted = state.complete(.loadedNonempty, for: ticket)
        #expect(accepted)
        #expect(state.phase == .loadedNonempty)
    }

    @Test("Every explicit completion preserves its honest phase")
    func completionPhases() {
        let cases: [(UIContentReadiness.Completion, UIContentReadiness.Phase)] = [
            (.loadedNonempty, .loadedNonempty), (.loadedEmpty, .loadedEmpty),
            (.partial, .partial), (.deferred, .deferred),
            (.unavailable, .unavailable), (.failed, .failed)
        ]
        for (completion, expected) in cases {
            var state = UIContentReadiness(workspace: .alerts)
            let ticket = state.begin(retainingCachedContent: true)
            let generation = state.generation
            let accepted = state.complete(completion, for: ticket)
            #expect(accepted)
            #expect(state.phase == expected)
            #expect(state.generation == generation)
            #expect(state.phase.isFreshCompletion == (expected == .loadedEmpty || expected == .loadedNonempty))
        }
    }

    @Test("A superseded read cannot publish over a later presentation")
    func latestGenerationWins() {
        var state = UIContentReadiness(workspace: .detection)
        let old = state.begin(retainingCachedContent: false)
        let current = state.begin(retainingCachedContent: true)
        let pending = state
        let acceptedOld = state.complete(.loadedEmpty, for: old)
        #expect(!acceptedOld)
        #expect(state == pending)
        let acceptedCurrent = state.complete(.loadedNonempty, for: current)
        #expect(acceptedCurrent && state.phase == .loadedNonempty)
        let completed = state
        let lateFailure = state.complete(.failed, for: old)
        #expect(!lateFailure && state == completed)
    }

    @Test("Completion is once-only, including failures with cached content")
    func completionCannotBeReclassified() {
        var state = UIContentReadiness(workspace: .alerts)
        let ticket = state.begin(retainingCachedContent: true)
        let first = state.complete(.failed, for: ticket)
        let failed = state
        let duplicate = state.complete(.loadedEmpty, for: ticket)
        #expect(first && !duplicate)
        #expect(state == failed && !state.phase.isFreshCompletion)
    }

    @Test("Invalidation retires both outstanding and completed generations")
    func invalidation() {
        var state = UIContentReadiness(workspace: .events)
        let ticket = state.begin(retainingCachedContent: true)
        let previous = state.generation
        state.invalidate()
        #expect(state.generation != previous && state.phase == .unavailable)
        let invalidated = state
        let late = state.complete(.loadedNonempty, for: ticket)
        #expect(!late && state == invalidated)
        let next = state.begin(retainingCachedContent: false)
        let accepted = state.complete(.loadedEmpty, for: next)
        #expect(accepted && state.phase == .loadedEmpty)
        let completedGeneration = state.generation
        state.invalidate()
        #expect(state.generation != completedGeneration && state.phase == .unavailable)
    }

    @Test("Independent windows cannot accept one another's tickets")
    func windowsAreIndependent() {
        var first = UIContentReadiness(workspace: .events)
        var second = UIContentReadiness(workspace: .events)
        let firstTicket = first.begin(retainingCachedContent: false)
        let secondTicket = second.begin(retainingCachedContent: false)
        let before = second
        let crossed = second.complete(.loadedNonempty, for: firstTicket)
        #expect(!crossed && second == before)
        let accepted = second.complete(.loadedEmpty, for: secondTicket)
        #expect(accepted && second.phase == .loadedEmpty && first.phase == .loading)
    }

    @Test("Displayed-content projection changes only fresh empty/nonempty phases")
    func displayedContentProjection() {
        var states = [UIContentReadiness(workspace: .events)]
        for cached in [false, true] {
            var state = UIContentReadiness(workspace: .events)
            state.begin(retainingCachedContent: cached)
            states.append(state)
        }
        for completion in UIContentReadiness.Completion.allCases {
            var state = UIContentReadiness(workspace: .events)
            let ticket = state.begin(retainingCachedContent: false)
            state.complete(completion, for: ticket)
            states.append(state)
        }
        #expect(Set(states.map(\.phase)) == Set(UIContentReadiness.Phase.allCases))
        for state in states {
            for empty in [false, true] {
                let projected = state.forDisplayedContent(isEmpty: empty)
                #expect(projected.generation == state.generation && projected.workspace == state.workspace)
                if state.phase.isFreshCompletion {
                    #expect(projected.phase == (empty ? .loadedEmpty : .loadedNonempty))
                } else {
                    #expect(projected == state)
                }
            }
        }
    }

    @Test("Projection neither mutates the source nor reopens a closed completion")
    func projectionKeepsClosedTicket() {
        var state = UIContentReadiness(workspace: .alerts)
        let ticket = state.begin(retainingCachedContent: false)
        state.complete(.loadedNonempty, for: ticket)
        var projected = state.forDisplayedContent(isEmpty: true)
        #expect(state.phase == .loadedNonempty && projected.phase == .loadedEmpty)
        let before = projected
        let reopened = projected.complete(.failed, for: ticket)
        #expect(!reopened && projected == before)
    }

    @Test("Marker grammar contains only fixed enums and an opaque bounded token")
    func identifierGrammar() throws {
        for workspace in UIContentReadiness.Workspace.allCases {
            for completion in UIContentReadiness.Completion.allCases {
                var state = UIContentReadiness(workspace: workspace)
                let ticket = state.begin(retainingCachedContent: false)
                _ = state.complete(completion, for: ticket)
                let identifier = state.accessibilityIdentifier
                let pieces = identifier.split(separator: ".")
                try #require(pieces.count == 6)
                #expect(Array(pieces.prefix(3)) == ["maccrab", "content", "v1"])
                #expect(pieces[3] == Substring(workspace.rawValue))
                #expect(UUID(uuidString: String(pieces[4])) == state.generation)
                #expect(String(pieces[4]) == state.generation.uuidString.lowercased())
                #expect(pieces[5] == Substring(state.phase.rawValue))
                #expect(identifier.utf8.count <= 96)
                #expect(!state.phase.displayText.isEmpty && state.phase.displayText.utf8.count <= 32)
            }
        }
    }
}
