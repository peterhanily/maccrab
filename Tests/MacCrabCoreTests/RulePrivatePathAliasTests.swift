// RulePrivatePathAliasTests.swift
// Endpoint Security reports real paths. /tmp, /var and /etc are links into
// /private, so a payload in $TMPDIR arrives as /private/var/folders/… and a
// periodic script as /private/etc/periodic/…. A startswith or equals value
// that names only the /var or /etc form can never match an ES event; ten
// rules shipped with such a dead branch, one of them the only selection of
// shadow_hash_access.

import Testing
import Foundation
@testable import MacCrabCore

@Suite("Rule paths cover the /private forms ES reports")
struct RulePrivatePathAliasTests {

    private func process(
        executable: String,
        signer: SignerType = .unsigned,
        isAdhocSigned: Bool? = nil,
        userId: UInt32 = 501,
        userName: String = "alice",
        parentExec: String = "/bin/bash"
    ) -> MacCrabCore.ProcessInfo {
        let sig = CodeSignatureInfo(
            signerType: signer, teamId: nil, signingId: nil, authorities: [], flags: 0,
            isNotarized: false, issuerChain: nil, certHashes: nil,
            isAdhocSigned: isAdhocSigned, entitlements: nil)
        return MacCrabCore.ProcessInfo(
            pid: 4321, ppid: 1, rpid: 1,
            name: (executable as NSString).lastPathComponent,
            executable: executable, commandLine: executable, args: [executable],
            workingDirectory: "/private/tmp", userId: userId, userName: userName, groupId: 20,
            startTime: Date(), codeSignature: sig,
            ancestors: [ProcessAncestor(pid: 1, executable: parentExec, name: (parentExec as NSString).lastPathComponent)],
            architecture: "arm64", isPlatformBinary: false)
    }

    private func exec(_ p: MacCrabCore.ProcessInfo) -> Event {
        Event(eventCategory: .process, eventType: .start, eventAction: "exec", process: p)
    }

    private func create(_ path: String, by p: MacCrabCore.ProcessInfo) -> Event {
        let file = FileInfo(
            path: path, name: (path as NSString).lastPathComponent,
            directory: (path as NSString).deletingLastPathComponent,
            extension_: nil, size: 4096, action: .create)
        return Event(eventCategory: .file, eventType: .creation, eventAction: FileAction.create.rawValue,
                     process: p, file: file)
    }

    private func loadEngine() async throws -> RuleEngine {
        try ensureRulesCompiled()
        let engine = RuleEngine()
        _ = try await engine.loadRules(from: compiledRulesDirectory)
        return engine
    }

    private func fires(_ engine: RuleEngine, _ event: Event, _ id: String) async -> Bool {
        await engine.evaluate(event).contains { $0.ruleId == id }
    }

    @Test("every startswith or equals path under /tmp, /var or /etc also lists its /private form")
    func everyPathValueListsPrivateForm() throws {
        let directory = try ensureRulesCompiled()
        let files = (FileManager.default.enumerator(at: directory, includingPropertiesForKeys: nil)?
            .allObjects as? [URL] ?? []).filter { $0.pathExtension == "json" }
        #expect(files.count > 300, "compiled rule floor (got \(files.count))")
        var checked = 0
        for file in files {
            guard let rule = try JSONSerialization.jsonObject(with: Data(contentsOf: file)) as? [String: Any]
            else { continue }
            let scopes = rule["steps"] as? [[String: Any]] ?? [rule]
            let predicates = scopes.flatMap { $0["predicates"] as? [[String: Any]] ?? [] }
            for predicate in predicates where ["startswith", "equals"].contains(predicate["modifier"] as? String) {
                let values = predicate["values"] as? [String] ?? []
                let lowered = Set(values.map { $0.lowercased() })
                for value in values where ["/tmp/", "/var/", "/etc/"].contains(where: { value.lowercased().hasPrefix($0) }) {
                    checked += 1
                    #expect(lowered.contains("/private" + value.lowercased()),
                            "\(file.lastPathComponent): \(predicate["field"] ?? "?") \(predicate["modifier"] ?? "?") '\(value)' lacks '/private\(value)'")
                }
            }
        }
        #expect(checked > 20, "the check must see the corpus's /tmp, /var and /etc values (saw \(checked))")
    }

    @Test("staged fetch fires on a payload run from $TMPDIR")
    func stagedFetchFromTmpdir() async throws {
        let engine = try await loadEngine()
        let payload = process(executable: "/private/var/folders/zz/abc123/T/stage/payload",
                              parentExec: "/opt/homebrew/bin/node")
        #expect(await fires(engine, exec(payload), "d1a2b3c4-0500-4000-a000-000000000506"))
    }

    @Test("ad-hoc signed program in $TMPDIR fires")
    func adhocFromTmpdir() async throws {
        let engine = try await loadEngine()
        let app = process(executable: "/private/var/folders/zz/abc123/T/Update.app/Contents/MacOS/Update",
                          signer: .adHoc, isAdhocSigned: true)
        #expect(await fires(engine, exec(app), "d1a2b3c4-0500-4000-a000-000000000511"))
        // go run and go test build ad-hoc signed binaries in $TMPDIR/go-build*/.
        let goTest = process(executable: "/private/var/folders/zz/abc123/T/go-build4182/b001/pkg.test",
                             signer: .adHoc, isAdhocSigned: true)
        #expect(!(await fires(engine, exec(goTest), "d1a2b3c4-0500-4000-a000-000000000511")))
    }

    @Test("login item added by a program in $TMPDIR fires")
    func loginItemFromTmpdir() async throws {
        let engine = try await loadEngine()
        let dropper = process(executable: "/private/var/folders/zz/abc123/T/helper")
        let btm = "/Users/alice/Library/Application Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm"
        #expect(await fires(engine, create(btm, by: dropper), "d1a2b3c4-0014-4000-a000-000000000014"))
    }

    @Test("root payload run from /var/tmp fires")
    func rootPayloadInVarTmp() async throws {
        let engine = try await loadEngine()
        let payload = process(executable: "/private/var/tmp/x", userId: 0, userName: "root")
        #expect(await fires(engine, exec(payload), "d1a2b3c4-0407-4000-a000-000000000407"))
    }

    @Test("periodic script written under /etc/periodic fires")
    func periodicScript() async throws {
        let engine = try await loadEngine()
        let writer = process(executable: "/private/tmp/installer")
        #expect(await fires(engine, create("/private/etc/periodic/daily/500.update", by: writer),
                            "d1a2b3c4-0015-4000-a000-000000000015"))
    }

    @Test("shadow hash plist access fires")
    func shadowHashAccess() async throws {
        let engine = try await loadEngine()
        let dumper = process(executable: "/private/tmp/dumper")
        #expect(await fires(engine, create("/private/var/db/dslocal/nodes/Default/users/alice.plist", by: dumper),
                            "d1a2b3c4-0403-4000-a000-000000000403"))
    }
}
