// ESCredentialReadAllowlistTests.swift
// v1.17.4 — the credential-read allowlist that bounds NOTIFY_OPEN emission.
// The OPEN stream is enormous; this allowlist is the load-bearing safety
// bound on what reaches the detection pipeline. ES delivery itself is
// live-only (no unit test possible), but this filter — the part that
// decides what we emit — is pure and MUST be tested.

import Testing
@testable import MacCrabCore

@Suite("ESCollector credential-read allowlist (v1.17.4)")
struct ESCredentialReadAllowlistTests {

    @Test("Credential / secret / wallet paths are emitted")
    func allowed() {
        let yes = [
            "/Users/x/.ssh/id_rsa",
            "/Users/x/.ssh/id_ed25519",
            "/Users/x/.aws/credentials",
            "/Users/x/.aws/config",
            "/Users/x/.config/gcloud/credentials.db",
            "/Users/x/.config/gcloud/access_tokens.db",
            "/Users/x/.kube/config",
            "/Users/x/.docker/config.json",
            "/Users/x/.npmrc",
            "/Users/x/.pypirc",
            "/Users/x/.netrc",
            "/Users/x/.gnupg/secring.gpg",
            "/Users/x/Library/Keychains/login.keychain-db",
            "/Users/x/Library/Application Support/Electrum/wallets/default_wallet",
            "/Users/x/Library/Application Support/Exodus/exodus.wallet/seed.seco",
            "/Users/x/.ethereum/keystore/UTC--2026--abc",
            "/Users/x/Library/Application Support/Google/Chrome/Default/Local Extension Settings/hnfanknocfeofbddgcijnmhnfnkdnaad/000003.log",
        ]
        for p in yes { #expect(ESCollector.isCredentialReadPath(p), "expected emit: \(p)") }
    }

    @Test("Ordinary paths are NOT emitted (the firehose is bounded)")
    func rejected() {
        let no = [
            "/Users/x/Documents/notes.txt",
            "/usr/lib/libSystem.B.dylib",
            "/Users/x/project/Sources/main.swift",
            "/private/var/folders/ab/T/tmp1234",
            "/Applications/Xcode.app/Contents/MacOS/Xcode",
            "/Users/x/Library/Caches/com.apple.Safari/cache.db",
            "/Users/x/Library/Application Support/Google/Chrome/Default/History",
        ]
        for p in no { #expect(!ESCollector.isCredentialReadPath(p), "expected NO emit: \(p)") }
    }
}
