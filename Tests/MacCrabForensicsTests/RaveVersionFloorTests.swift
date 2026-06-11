// RaveVersionFloor (O3a / S2-05) policy tests — the shared fail-closed
// version-floor rule both rave clients call.
//
// Cases:
//   - running >= floor → proceeds (allow-at-or-above)
//   - running <  floor → refuse (.belowFloor)  [refuse-below]
//   - running == floor → proceeds (boundary)
//   - rc of the floor release < floor → refuse (rc-suffix)
//   - floor absent / empty → proceeds (no gate)
//   - floor unparseable → refuse (.unparseableFloor)  [FAIL-CLOSED]
//   - running unparseable → refuse (.unparseableRunning)  [FAIL-CLOSED]

import Testing
@testable import MacCrabForensics

@Suite("RaveVersionFloor (S2-05 version floor)")
struct RaveVersionFloorTests {

    @Test("allow at-or-above the floor")
    func allowAtOrAbove() throws {
        try RaveVersionFloor.enforce(pluginID: "com.t.a", floor: "1.17.0", running: "1.19.0")
        try RaveVersionFloor.enforce(pluginID: "com.t.b", floor: "1.17.0", running: "1.17.0") // boundary
    }

    @Test("refuse below the floor (.belowFloor)")
    func refuseBelow() {
        do {
            try RaveVersionFloor.enforce(pluginID: "com.t.c", floor: "1.19.0", running: "1.18.1")
            Issue.record("expected belowFloor refusal")
        } catch let e as RaveVersionFloorError {
            guard case .belowFloor(let id, let running, let floor) = e else {
                Issue.record("expected .belowFloor, got \(e)"); return
            }
            #expect(id == "com.t.c")
            #expect(running == "1.18.1")
            #expect(floor == "1.19.0")
        } catch { Issue.record("unexpected error \(error)") }
    }

    @Test("rc of the floor release is refused")
    func rcSuffixRefused() {
        // Running 1.19.0-rc.1 against a 1.19.0 floor: rc is below the release.
        #expect(throws: RaveVersionFloorError.self) {
            try RaveVersionFloor.enforce(pluginID: "com.t.rc", floor: "1.19.0", running: "1.19.0-rc.1")
        }
        // But an rc of a LATER release satisfies an earlier floor.
        try? RaveVersionFloor.enforce(pluginID: "com.t.rc2", floor: "1.19.0", running: "1.20.0-rc.1")
        // (no throw expected; if it threw, the line above swallows it — assert explicitly)
        var threw = false
        do {
            try RaveVersionFloor.enforce(pluginID: "com.t.rc2", floor: "1.19.0", running: "1.20.0-rc.1")
        } catch { threw = true }
        #expect(!threw)
    }

    @Test("absent / empty floor → no gate")
    func absentFloorProceeds() throws {
        try RaveVersionFloor.enforce(pluginID: "com.t.d", floor: nil, running: "1.0.0")
        try RaveVersionFloor.enforce(pluginID: "com.t.e", floor: "", running: "1.0.0")
    }

    @Test("unparseable floor → FAIL-CLOSED refusal")
    func unparseableFloorFailsClosed() {
        do {
            try RaveVersionFloor.enforce(pluginID: "com.t.f", floor: "not-a-version", running: "1.19.0")
            Issue.record("expected unparseableFloor refusal")
        } catch let e as RaveVersionFloorError {
            guard case .unparseableFloor = e else {
                Issue.record("expected .unparseableFloor, got \(e)"); return
            }
        } catch { Issue.record("unexpected error \(error)") }
    }

    @Test("unparseable running version → FAIL-CLOSED refusal")
    func unparseableRunningFailsClosed() {
        #expect(throws: RaveVersionFloorError.self) {
            try RaveVersionFloor.enforce(pluginID: "com.t.g", floor: "1.17.0", running: "garbage")
        }
    }
}
