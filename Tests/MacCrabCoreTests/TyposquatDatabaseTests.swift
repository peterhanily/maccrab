// TyposquatDatabaseTests.swift
// v1.12.0 — Damerau-Levenshtein + Unicode-confusable typosquat scorer.

import Testing
import Foundation
@testable import MacCrabCore

@Suite("v1.12.0: TyposquatDatabase")
struct TyposquatDatabaseTests {

    @Test("Damerau-Levenshtein counts adjacent transposition as 1 edit")
    func damerauLevenshteinTransposition() {
        // `raect` <-> `react` differs by adjacent transposition (e <-> a).
        #expect(TyposquatDatabase.damerauLevenshtein("raect", "react") == 1)
        // Plain Levenshtein would say 2 (one substitution + one insertion).
        // We expect 1 because Damerau handles the transposition.
        #expect(TyposquatDatabase.damerauLevenshtein("react", "react") == 0)
        #expect(TyposquatDatabase.damerauLevenshtein("axios", "axion") == 1)
    }

    @Test("Confusable fold maps Cyrillic look-alikes to Latin")
    func confusableFoldCyrillic() {
        // Cyrillic 'а' (U+0430) folds to Latin 'a'.
        let cyrillicA: Character = "а"
        let cyrillic = "p\(cyrillicA)ndas"
        #expect(TyposquatDatabase.confusableFold(cyrillic) == "pandas")
        // Greek omicron 'ο' (U+03BF) folds to Latin 'o'.
        let greekO: Character = "ο"
        let greek = "lod\(greekO)sh"
        #expect(TyposquatDatabase.confusableFold(greek) == "lodosh")
    }

    @Test("Catches `axios` typosquat `axion` (single substitution)")
    func axiosTyposquat() async {
        let db = TyposquatDatabase(maxDistance: 2)
        let result = await db.score(candidate: "axion", registry: .npm)
        #expect(result.similarTo == "axios")
        #expect(result.distance == 1)
        #expect(result.score >= 80)
        #expect(!result.reasons.isEmpty)
    }

    @Test("Catches `react` typosquat `raect` (adjacent transposition)")
    func reactTransposition() async {
        let db = TyposquatDatabase(maxDistance: 2)
        let result = await db.score(candidate: "raect", registry: .npm)
        #expect(result.similarTo == "react")
        #expect(result.distance == 1)
    }

    @Test("Catches PyPI `requets` typosquat of `requests`")
    func requestsPyPITyposquat() async {
        let db = TyposquatDatabase(maxDistance: 2)
        let result = await db.score(candidate: "requets", registry: .pypi)
        #expect(result.similarTo == "requests")
    }

    @Test("Confusable encoding of `axios` (Cyrillic a) is flagged as homoglyph")
    func cyrillicAxiosHomoglyph() async {
        let db = TyposquatDatabase(maxDistance: 2)
        let cyrillicA: Character = "а" // U+0430
        let payload = "\(cyrillicA)xios"
        let result = await db.score(candidate: payload, registry: .npm)
        #expect(result.isHomoglyph)
        #expect(result.similarTo == "axios")
        #expect(result.score == 100)
    }

    @Test("Exact match in top-1000 is NOT flagged as typosquat")
    func exactMatchNotFlagged() async {
        let db = TyposquatDatabase()
        let result = await db.score(candidate: "react", registry: .npm)
        #expect(result.distance != 1)
        // Either no match within range (score=0) or exact match (which we
        // intentionally don't flag as typosquat — distance == 0 with ASCII
        // input means it IS the popular package).
        #expect(result.score == 0)
    }

    @Test("v1.12.5 regression: pip is a top package, not a typosquat of pipx")
    func pipIsNotTyposquatOfPipx() async {
        // Pre-v1.12.5 the exact-match-is-popular check ran AFTER the
        // homoglyph branch, which only matched on confusable folds —
        // so ASCII `pip` fell through to the distance loop and tripped
        // `pipx` at distance 1, surfacing "⚠️ Likely typosquat — score
        // 80 (similar to pipx)" on the most-popular PyPI installer.
        // Same shape would have affected cli→clip / pkg→pkgx /
        // dns→dnsx etc. Lock both in.
        let db = TyposquatDatabase(maxDistance: 2)
        let pipResult = await db.score(candidate: "pip", registry: .pypi)
        #expect(pipResult.score == 0)
        #expect(pipResult.similarTo == nil)

        let pipxResult = await db.score(candidate: "pipx", registry: .pypi)
        #expect(pipxResult.score == 0)
        #expect(pipxResult.similarTo == nil)

        // npm parallel — `next` is a top-100 package. Pre-fix it might
        // have scored against `nest`, `nuxt`, `nx`.
        let nextResult = await db.score(candidate: "next", registry: .npm)
        #expect(nextResult.score == 0)
    }

    @Test("Unrelated short name is not flagged")
    func unrelatedShortNameNotFlagged() async {
        let db = TyposquatDatabase(maxDistance: 2)
        let result = await db.score(candidate: "foobar", registry: .npm)
        #expect(result.score == 0)
    }

    @Test("Bundled JSON corpus loads and catches typosquats from the expanded list")
    func bundledCorpusCoversExpandedNames() async {
        // v1.12.0: the bundled JSON corpus is ~200 entries per registry,
        // 4× the in-source starter set. These five candidates would have
        // been ZERO-score under the 50-entry starter list but DO score
        // under the expanded JSON corpus — guards against regression if
        // someone disables the resource-loading path.
        let db = TyposquatDatabase(maxDistance: 2)
        let expandedNpmCandidates = [
            "next-router",         // close to "next"
            "redux-tools",         // close to "@reduxjs/toolkit" — checks longer names
            "fastify-cors",        // close to "fastify"
            "tailwindcsss",        // close to "tailwindcss"
            "@types/lodaash"       // close to "@types/lodash"
        ]
        var anyMatched = false
        for candidate in expandedNpmCandidates {
            let result = await db.score(candidate: candidate, registry: .npm)
            if result.score > 0 { anyMatched = true; break }
        }
        #expect(anyMatched, "Expanded npm corpus should catch at least one of the candidates not present in the 50-entry starter set")

        let expandedPyPiCandidates = [
            "tensorlfow",          // close to "tensorflow"
            "pytourch",            // close to "torch"
            "fastapi-cors",        // close to "fastapi"
            "openai-python",       // close to "openai"
            "anthropic-sdk"        // close to "anthropic"
        ]
        var anyPyMatched = false
        for candidate in expandedPyPiCandidates {
            let result = await db.score(candidate: candidate, registry: .pypi)
            if result.score > 0 { anyPyMatched = true; break }
        }
        #expect(anyPyMatched, "Expanded PyPI corpus should catch at least one expanded-list candidate")
    }
}
