// MacCrabSemver (S2-05 / O3a) comparator tests.
//
// Focus: ordering correctness across MAJOR/MINOR/PATCH and pre-release
// (-rc) suffixes, and the satisfiesFloor helper's fail-closed nil on
// unparseable input. The -rc cases are load-bearing for the version floor:
// an -rc of the floor release MUST compare below the floor.

import Testing
@testable import MacCrabCore

@Suite("MacCrabSemver (S2-05 version comparator)")
struct MacCrabSemverTests {

    @Test("parses MAJOR.MINOR.PATCH")
    func parsesCore() throws {
        let v = try #require(MacCrabSemver("1.19.0"))
        #expect(v.major == 1)
        #expect(v.minor == 19)
        #expect(v.patch == 0)
        #expect(v.prerelease.isEmpty)
    }

    @Test("parses leading v and build metadata")
    func parsesLeadingVAndBuild() throws {
        let a = try #require(MacCrabSemver("v1.19.0"))
        #expect(a == MacCrabSemver("1.19.0"))
        let b = try #require(MacCrabSemver("1.19.0+build.7"))
        #expect(b == MacCrabSemver("1.19.0"))  // build metadata ignored
    }

    @Test("rejects malformed")
    func rejectsMalformed() {
        #expect(MacCrabSemver("1.19") == nil)
        #expect(MacCrabSemver("1.19.0.1") == nil)
        #expect(MacCrabSemver("1.19.x") == nil)
        #expect(MacCrabSemver("") == nil)
        #expect(MacCrabSemver("1.19.0-") == nil)       // empty prerelease
        #expect(MacCrabSemver("1.19.0-rc..1") == nil)  // empty identifier
    }

    @Test("core ordering")
    func coreOrdering() throws {
        #expect(try #require(MacCrabSemver("1.18.1")) < #require(MacCrabSemver("1.19.0")))
        #expect(try #require(MacCrabSemver("1.19.0")) < #require(MacCrabSemver("1.19.1")))
        #expect(try #require(MacCrabSemver("1.19.0")) < #require(MacCrabSemver("2.0.0")))
        #expect(try #require(MacCrabSemver("1.19.0")) == #require(MacCrabSemver("1.19.0")))
    }

    @Test("rc suffix is LOWER precedence than the release")
    func rcBelowRelease() throws {
        // SemVer §11: 1.19.0-rc.1 < 1.19.0
        #expect(try #require(MacCrabSemver("1.19.0-rc.1")) < #require(MacCrabSemver("1.19.0")))
        #expect(try #require(MacCrabSemver("1.19.0-rc1")) < #require(MacCrabSemver("1.19.0")))
        // And ordered among themselves: rc.1 < rc.2
        #expect(try #require(MacCrabSemver("1.19.0-rc.1")) < #require(MacCrabSemver("1.19.0-rc.2")))
        // numeric identifier < alphanumeric
        #expect(try #require(MacCrabSemver("1.19.0-rc.1")) < #require(MacCrabSemver("1.19.0-rc.beta")))
    }

    // MARK: - satisfiesFloor

    @Test("satisfiesFloor: at-or-above passes, below fails")
    func floorAtOrAbove() {
        #expect(MacCrabSemverCompare.satisfiesFloor(running: "1.19.0", floor: "1.17.0") == true)
        #expect(MacCrabSemverCompare.satisfiesFloor(running: "1.17.0", floor: "1.17.0") == true) // equal
        #expect(MacCrabSemverCompare.satisfiesFloor(running: "1.16.9", floor: "1.17.0") == false)
    }

    @Test("satisfiesFloor: rc of the floor release does NOT satisfy")
    func floorRcDoesNotSatisfy() {
        // 1.19.0-rc.1 < 1.19.0, so it does not meet a 1.19.0 floor.
        #expect(MacCrabSemverCompare.satisfiesFloor(running: "1.19.0-rc.1", floor: "1.19.0") == false)
        // But an rc of a LATER release does satisfy an earlier floor.
        #expect(MacCrabSemverCompare.satisfiesFloor(running: "1.20.0-rc.1", floor: "1.19.0") == true)
    }

    @Test("satisfiesFloor: unparseable input → nil (fail-closed signal)")
    func floorUnparseable() {
        #expect(MacCrabSemverCompare.satisfiesFloor(running: "garbage", floor: "1.17.0") == nil)
        #expect(MacCrabSemverCompare.satisfiesFloor(running: "1.19.0", floor: "1.x") == nil)
    }
}
