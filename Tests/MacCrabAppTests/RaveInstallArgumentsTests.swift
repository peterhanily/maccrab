// RaveInstallConsentSheet.installArguments — the verified-install argv.
//
// Pins the one behavioural difference the update-apply wiring introduces:
// an update re-installs over the existing copy with --force, a fresh
// install does not. Every trust gate (serial, signer pin, version floor,
// revocation, artifact hash) is re-enforced by maccrabctl regardless of
// --force — the flag only permits overwriting an already-present
// destination, so the argv is the whole surface worth pinning here.

import Testing
@testable import MacCrabApp

@Suite("RaveInstallConsentSheet — install argv construction")
struct RaveInstallArgumentsTests {

    @Test("fresh install → plugin install <id>, no --force")
    func freshInstall() {
        #expect(RaveInstallConsentSheet.installArguments(id: "com.example.foo", isUpdate: false)
                == ["plugin", "install", "com.example.foo"])
    }

    @Test("update → appends --force (re-install over the existing copy)")
    func update() {
        #expect(RaveInstallConsentSheet.installArguments(id: "com.example.foo", isUpdate: true)
                == ["plugin", "install", "com.example.foo", "--force"])
    }

    @Test("--force is the ONLY difference between install and update")
    func forceIsOnlyDelta() {
        let fresh = RaveInstallConsentSheet.installArguments(id: "x", isUpdate: false)
        let upd = RaveInstallConsentSheet.installArguments(id: "x", isUpdate: true)
        #expect(Array(upd.prefix(fresh.count)) == fresh)   // same prefix
        #expect(upd.last == "--force")
        #expect(upd.count == fresh.count + 1)              // exactly one extra arg
    }

    @Test("catalogBase override appends --catalog-base; nil/empty omits it")
    func catalogBaseArgv() {
        #expect(RaveInstallConsentSheet.installArguments(id: "x", isUpdate: false, catalogBase: nil)
                == ["plugin", "install", "x"])
        #expect(RaveInstallConsentSheet.installArguments(id: "x", isUpdate: false, catalogBase: "")
                == ["plugin", "install", "x"])   // empty = no override
        #expect(RaveInstallConsentSheet.installArguments(id: "x", isUpdate: true, catalogBase: "https://mirror.example/")
                == ["plugin", "install", "x", "--force", "--catalog-base", "https://mirror.example/"])
    }
}
