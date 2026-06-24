// PackageInstallParseHardeningTests.swift
//
// v1.19.1 (HN-audit) regression for the supply-chain parser that minted a
// CRITICAL "Fresh Package Installed" alert from the substring "install"
// appearing inside a `python3 -c "<json blob>"` argv. The parser now requires
// a real pip-install shape and validates extracted names against a PEP-508 /
// npm charset before any registry query.

import Testing
import Foundation
@testable import MacCrabCore

@Suite("Package install parse hardening (v1.19.1)")
struct PackageInstallParseHardeningTests {

    typealias PFC = PackageFreshnessChecker

    // MARK: - The reported FP

    @Test("`python3 -c` with the token install in the code string is NOT an install")
    func pythonDashCNotInstall() {
        // The exact audit shape: a benign python one-liner whose code string
        // happens to contain the word install (here also a JSON fragment).
        #expect(PFC.parseInstallCommand(#"python3 -c import json; d={"cmd":"install"}; print(d)"#).isEmpty)
        #expect(PFC.parseInstallCommand("python3 -c print('please install foo')").isEmpty)
    }

    @Test("Garbage argv after a bare `install` token yields no package")
    func garbageNamesRejected() {
        // A JSON/array fragment must never reach a registry query nor escalate.
        #expect(PFC.parseInstallCommand(#"pip install lineage","type":"array""#).isEmpty)
        #expect(PFC.parseInstallCommand("brew install evil;rm").isEmpty)
    }

    // MARK: - Real installs still parse

    @Test("`python3 -m pip install` is parsed")
    func pythonModulePipParsed() {
        let r = PFC.parseInstallCommand("python3 -m pip install requests")
        #expect(r.count == 1)
        #expect(r.first?.name == "requests")
    }

    @Test("`pip3 install name==ver` strips the version")
    func pipVersionStripped() {
        let r = PFC.parseInstallCommand("pip3 install flask==2.0.1")
        #expect(r.first?.name == "flask")
    }

    @Test("`pip install -r requirements.txt` is a file install (skipped)")
    func pipRequirementsSkipped() {
        #expect(PFC.parseInstallCommand("pip install -r requirements.txt").isEmpty)
    }

    @Test("npm scoped + unscoped names still parse")
    func npmNamesParsed() {
        #expect(PFC.parseInstallCommand("npm install lodash").first?.name == "lodash")
        #expect(PFC.parseInstallCommand("npm install @scope/widget@1.2.3").first?.name == "@scope/widget")
    }

    @Test("`brew install --cask firefox` parses the cask name")
    func brewCaskParsed() {
        let r = PFC.parseInstallCommand("brew install --cask firefox")
        #expect(r.first?.name == "firefox")
    }

    // MARK: - Name validators

    @Test("isValidPackageName accepts PEP-508 names, rejects argv noise")
    func packageNameValidator() {
        #expect(PFC.isValidPackageName("requests"))
        #expect(PFC.isValidPackageName("flask-cors"))
        #expect(PFC.isValidPackageName("a.b_c-1"))
        #expect(!PFC.isValidPackageName(""))
        #expect(!PFC.isValidPackageName("-leading"))
        #expect(!PFC.isValidPackageName("with space"))
        #expect(!PFC.isValidPackageName(#"{"json":1}"#))
        #expect(!PFC.isValidPackageName("evil;rm"))
    }

    @Test("isValidNpmName accepts an optional @scope/ prefix")
    func npmNameValidator() {
        #expect(PFC.isValidNpmName("lodash"))
        #expect(PFC.isValidNpmName("@scope/widget"))
        #expect(!PFC.isValidNpmName("@/oops"))
        #expect(!PFC.isValidNpmName("@scope/"))
    }
}
