// PackageScannerEnrichmentTests.swift
// v1.12.0 — verifies the new intelligence fields on PackageInfo
// (typosquatScore, isLikelyTyposquat, attestationStatus, contentRedFlags)
// behave correctly without needing to actually shell out to
// brew / npm / pip. Tests construct PackageInfo directly and exercise
// the field invariants.

import Foundation
import Testing
@testable import MacCrabCore

@Suite("v1.12.0: PackageScanner enrichment fields")
struct PackageScannerEnrichmentTests {

    @Test("isLikelyTyposquat derives from typosquatScore ≥ 80")
    func isLikelyTyposquatThreshold() {
        let high = PackageInfo(name: "axion", installedVersion: "1.0.0", manager: "npm", typosquatScore: 95)
        #expect(high.isLikelyTyposquat)
        let mid = PackageInfo(name: "axion", installedVersion: "1.0.0", manager: "npm", typosquatScore: 79)
        #expect(!mid.isLikelyTyposquat)
        let none = PackageInfo(name: "react", installedVersion: "18.0.0", manager: "npm", typosquatScore: nil)
        #expect(!none.isLikelyTyposquat)
    }

    @Test("PackageInfo without intelligence fields keeps nil defaults")
    func defaultsAreNil() {
        let info = PackageInfo(name: "react", installedVersion: "18.0.0", manager: "npm")
        #expect(info.typosquatScore == nil)
        #expect(info.typosquatSimilarTo == nil)
        #expect(info.attestationStatus == nil)
        #expect(info.contentRedFlags == nil)
        #expect(!info.isLikelyTyposquat)
    }

    @Test("Typosquat similarTo + score populated together")
    func typosquatPair() {
        let info = PackageInfo(
            name: "raect", installedVersion: "0.0.1", manager: "npm",
            typosquatScore: 90, typosquatSimilarTo: "react"
        )
        #expect(info.typosquatScore == 90)
        #expect(info.typosquatSimilarTo == "react")
        #expect(info.isLikelyTyposquat)
    }

    @Test("Attestation status round-trips a string value")
    func attestationStatusRoundTrip() {
        let info = PackageInfo(
            name: "vite", installedVersion: "5.0.0", manager: "npm",
            attestationStatus: "verified"
        )
        #expect(info.attestationStatus == "verified")
    }

    @Test("Content red flags accept arbitrary string list")
    func contentRedFlags() {
        let info = PackageInfo(
            name: "shady", installedVersion: "0.0.1", manager: "npm",
            contentRedFlags: ["obfuscated_bundle", "mach_o_dropped"]
        )
        #expect(info.contentRedFlags == ["obfuscated_bundle", "mach_o_dropped"])
    }

    @Test("PackageScanner.enrich on a brew package leaves it unchanged (no registry mapping)")
    func brewPackageUnchanged() async {
        let scanner = PackageScanner()
        let info = PackageInfo(name: "git", installedVersion: "2.42", manager: "brew")
        let enriched = await scanner.enrich(info)
        #expect(enriched.typosquatScore == info.typosquatScore)
        #expect(enriched.attestationStatus == info.attestationStatus)
        #expect(enriched.contentRedFlags == info.contentRedFlags)
    }
}
