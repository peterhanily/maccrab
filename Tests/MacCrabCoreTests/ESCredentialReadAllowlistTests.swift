// ESCredentialReadAllowlistTests.swift
// v1.17.4 — the credential-read allowlist that bounds NOTIFY_OPEN emission.
// The OPEN stream is enormous; this allowlist is the load-bearing safety
// bound on what reaches the detection pipeline. ES delivery itself is
// live-only (no unit test possible), but this filter — the part that
// decides what we emit — is pure and MUST be tested.

import Testing
import Foundation
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
            // v1.17.4 ES-OPEN-2: the previously-missed wallets that read as
            // "covered" but were undetected on read.
            "/Users/x/Library/Application Support/Atomic/Local Storage/leveldb/000005.ldb",
            "/Users/x/Library/Application Support/Coinomi/wallets/x.wallet",
            "/Users/x/Library/Application Support/Daedalus/wallet.db",
            "/Users/x/Library/Application Support/monero-project/wallet.keys",
            "/Users/x/Library/Application Support/Trezor Suite/db",
            "/Users/x/Library/Application Support/Ledger Live/app.json",
            "/Users/x/Library/Containers/io.trezor.TrezorSuite/Data/store",
            "/Users/x/Library/Application Support/Google/Chrome/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn/000003.log", // MetaMask
            "/Users/x/Library/Application Support/Google/Chrome/Default/Local Extension Settings/bfnaelmomeimhlpmgjnjophhpkkoljpa/000003.log", // Phantom
            "/Users/x/Library/Application Support/Google/Chrome/Default/Local Extension Settings/lmenefjjbnabbnchedhpaichpfphndbg/000003.log", // WalletConnect
            // v1.17.4 ES-OPEN-1: a read of a deployed decoy / honey-prompt
            // is the signal itself.
            "/Library/Application Support/MacCrab/decoys/CLAUDE.md.canary",
            "/Users/x/Library/Application Support/MacCrab/decoys/passwords.txt",
            // v1.18 read-detection: the credential-read rules' target paths.
            "/Users/x/Library/Safari/History.db",
            "/Users/x/Library/Safari/Passwords",
            "/Users/x/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite",
            "/Users/x/Library/Application Support/1Password/data.db",
            "/Users/x/Library/Application Support/Bitwarden/data.json",
            "/Users/x/Documents/keepass.kdbx",
            "/var/db/dslocal/nodes/Default/users/admin.plist",
            "/private/var/db/dslocal/nodes/Default/users/admin.plist",
        ]
        for p in yes { #expect(ESCollector.isCredentialReadPath(p), "expected emit: \(p)") }
    }

    /// ES-OPEN-2 drift guard: the OPEN allowlist comment promises it mirrors
    /// crypto_wallet_data_access.yml. Parse that rule's selection
    /// TargetFilename substrings straight from disk and assert the allowlist
    /// is a SUPERSET — so adding a wallet to the rule without updating the
    /// allowlist (the exact regression the audit found) fails the build.
    @Test("Allowlist is a superset of crypto_wallet_data_access.yml selection paths")
    func allowlistSupersetsWalletRule() throws {
        // <repo>/Tests/MacCrabCoreTests/<thisfile> → up 3 → <repo>
        let repoRoot = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let ruleURL = repoRoot
            .appendingPathComponent("Rules/credential_access/crypto_wallet_data_access.yml")
        let yaml = try String(contentsOf: ruleURL, encoding: .utf8)

        // Collect every `- '...'` value that lives under a `selection_*:`
        // block (the selection blocks in this rule contain only
        // TargetFilename lists). Stop at filter_*/condition.
        var inSelection = false
        var ruleSubstrings: [String] = []
        for raw in yaml.split(separator: "\n", omittingEmptySubsequences: false) {
            let line = String(raw)
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed.hasPrefix("selection_") && trimmed.hasSuffix(":") {
                inSelection = true; continue
            }
            if trimmed.hasPrefix("filter_") || trimmed.hasPrefix("condition:") {
                inSelection = false; continue
            }
            guard inSelection, trimmed.hasPrefix("- '"),
                  let open = line.firstIndex(of: "'"),
                  let close = line.lastIndex(of: "'"), open < close else { continue }
            ruleSubstrings.append(String(line[line.index(after: open)..<close]))
        }

        #expect(ruleSubstrings.count >= 16,
                "parsed too few wallet paths (\(ruleSubstrings.count)) — parser or rule changed shape")
        for sub in ruleSubstrings {
            // A read of a path containing this rule substring must produce
            // an OPEN event, i.e. the allowlist must admit it.
            #expect(ESCollector.isCredentialReadPath("/Users/x/Library/" + sub + "/probe"),
                    "wallet rule targets '\(sub)' but the OPEN allowlist does not admit it (ES-OPEN-2 drift)")
        }
    }

    @Test("isKeychainPath matches the keychain DBs the read-rules target")
    func keychainPathClassification() {
        #expect(ESCollector.isKeychainPath("/Users/x/Library/Keychains/login.keychain-db"))
        #expect(ESCollector.isKeychainPath("/Library/Keychains/System.keychain"))
        #expect(!ESCollector.isKeychainPath("/Users/x/Library/Keychains/metadata.plist"))
        #expect(!ESCollector.isKeychainPath("/Users/x/.ssh/id_rsa"))
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
