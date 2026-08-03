import Foundation
import Darwin
import Testing
@testable import MacCrabCore

@Suite("Privileged subprocess trust boundaries")
struct PrivilegedExecutionSecurityTests {
    private func temporaryDirectory() throws -> URL {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("maccrab-privexec-\(UUID().uuidString)")
        try FileManager.default.createDirectory(
            at: url,
            withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o700]
        )
        return url
    }

    @Test("complete component walk accepts immutable fixtures and rejects links or writable ancestors")
    func componentWalk() throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let scripts = root.appendingPathComponent("scripts")
        try FileManager.default.createDirectory(
            at: scripts,
            withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o700]
        )
        let script = scripts.appendingPathComponent("response.sh")
        try "#!/bin/sh\nexit 0\n".write(to: script, atomically: false, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: script.path)

        let owner = geteuid()
        let accepted = PrivilegedExecutablePolicy.validatedPath(
            script.path,
            kind: .regularFile(requireExecutable: true, maximumSize: 1024),
            allowedPrefixes: [scripts.path],
            requiredOwnerUID: owner,
            validationRoot: root.path
        )
        #expect(accepted == script.path)

        let link = scripts.appendingPathComponent("link.sh")
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: script)
        #expect(PrivilegedExecutablePolicy.validatedPath(
            link.path,
            kind: .regularFile(requireExecutable: true),
            allowedPrefixes: [scripts.path],
            requiredOwnerUID: owner,
            validationRoot: root.path
        ) == nil)

        try FileManager.default.setAttributes([.posixPermissions: 0o770], ofItemAtPath: scripts.path)
        #expect(PrivilegedExecutablePolicy.validatedPath(
            script.path,
            kind: .regularFile(requireExecutable: true),
            allowedPrefixes: [scripts.path],
            requiredOwnerUID: owner,
            validationRoot: root.path
        ) == nil)
    }

    @Test("production policy accepts Apple shell and rejects a user-owned executable")
    func productionOwnershipBoundary() throws {
        #expect(PrivilegedExecutablePolicy.validatedExecutable("/bin/sh") == "/bin/sh")

        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let executable = root.appendingPathComponent("owned-by-test-user")
        try "#!/bin/sh\nexit 0\n".write(to: executable, atomically: false, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: executable.path)
        #expect(PrivilegedExecutablePolicy.validatedExecutable(executable.path) == nil)
    }

    @Test("bounded local reader refuses links, FIFOs, devices, oversize, and concurrent mutation")
    func boundedRegularFileReaderBoundary() throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }

        let regular = root.appendingPathComponent("Info.plist")
        try Data("abc".utf8).write(to: regular)
        #expect(BoundedRegularFileReader.read(at: regular.path, maximumBytes: 3) == Data("abc".utf8))

        let symlink = root.appendingPathComponent("Info-link.plist")
        try FileManager.default.createSymbolicLink(at: symlink, withDestinationURL: regular)
        #expect(BoundedRegularFileReader.read(at: symlink.path, maximumBytes: 1_048_576) == nil)

        let realParent = root.appendingPathComponent("real-parent")
        try FileManager.default.createDirectory(at: realParent, withIntermediateDirectories: false)
        let nested = realParent.appendingPathComponent("nested")
        try FileManager.default.createDirectory(at: nested, withIntermediateDirectories: false)
        try Data("nested".utf8).write(to: nested.appendingPathComponent("file"))
        let parentLink = root.appendingPathComponent("parent-link")
        try FileManager.default.createSymbolicLink(at: parentLink, withDestinationURL: realParent)
        #expect(BoundedRegularFileReader.read(
            at: parentLink.appendingPathComponent("nested/file").path,
            maximumBytes: 1_048_576
        ) == nil,
        "every intermediate component must be opened O_DIRECTORY|O_NOFOLLOW")

        for malformed in [
            regular.path + "/",
            root.path + "//Info.plist",
            root.path + "/./Info.plist",
            root.path + "/nested/../Info.plist",
            root.path + "/Info.plist\0suffix",
            "relative/Info.plist",
        ] {
            #expect(BoundedRegularFileReader.read(
                at: malformed,
                maximumBytes: 1_048_576
            ) == nil)
        }

        let fifo = root.appendingPathComponent("Info-fifo.plist")
        try #require(mkfifo(fifo.path, 0o600) == 0)
        let fifoStart = Date()
        #expect(BoundedRegularFileReader.read(at: fifo.path, maximumBytes: 1_048_576) == nil)
        #expect(Date().timeIntervalSince(fifoStart) < 1,
                "O_NONBLOCK must keep an attacker FIFO from hanging the root inventory")

        #expect(BoundedRegularFileReader.read(at: "/dev/zero", maximumBytes: 1_048_576) == nil)

        let oversized = root.appendingPathComponent("oversized.plist")
        try Data(repeating: 0x41, count: 1_048_577).write(to: oversized)
        #expect(BoundedRegularFileReader.read(at: oversized.path, maximumBytes: 1_048_576) == nil)

        let truncated = root.appendingPathComponent("truncated.plist")
        try Data("before".utf8).write(to: truncated)
        let truncatedResult = BoundedRegularFileReader.read(
            at: truncated.path,
            maximumBytes: 1_048_576,
            afterMetadataValidated: { _ in
                _ = truncated.path.withCString { Darwin.truncate($0, 0) }
            }
        )
        #expect(truncatedResult == nil)

        let grown = root.appendingPathComponent("grown.plist")
        try Data("old".utf8).write(to: grown)
        let grownResult = BoundedRegularFileReader.read(
            at: grown.path,
            maximumBytes: 1_048_576,
            afterMetadataValidated: { _ in
                let appendFD = grown.path.withCString {
                    Darwin.open($0, O_WRONLY | O_APPEND | O_CLOEXEC)
                }
                if appendFD >= 0 {
                    var byte: UInt8 = 0x21
                    _ = Darwin.write(appendFD, &byte, 1)
                    Darwin.close(appendFD)
                }
            }
        )
        #expect(grownResult == nil)
    }

    @Test("descriptor-relative reader stays on a pinned parent during path replacement")
    func boundedRegularFileReaderParentSwap() throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }

        let parent = root.appendingPathComponent("parent", isDirectory: true)
        let originalParent = root.appendingPathComponent("original-parent", isDirectory: true)
        let child = parent.appendingPathComponent("child", isDirectory: true)
        try FileManager.default.createDirectory(at: child, withIntermediateDirectories: true)
        let requested = child.appendingPathComponent("value")
        try Data("trusted".utf8).write(to: requested)

        var seamRan = false
        var seamError: Error?
        let result = BoundedRegularFileReader.read(
            at: requested.path,
            maximumBytes: 64,
            afterDirectoryOpened: { openedPath, _ in
                guard !seamRan, openedPath.hasSuffix("/parent") else { return }
                seamRan = true
                do {
                    try FileManager.default.moveItem(at: parent, to: originalParent)
                    let replacementChild = parent.appendingPathComponent(
                        "child", isDirectory: true
                    )
                    try FileManager.default.createDirectory(
                        at: replacementChild,
                        withIntermediateDirectories: true
                    )
                    try Data("attacker".utf8).write(
                        to: replacementChild.appendingPathComponent("value")
                    )
                } catch {
                    seamError = error
                }
            }
        )

        #expect(seamRan)
        #expect(seamError == nil)
        #expect(result == Data("trusted".utf8),
                "openat must continue through the directory inode pinned before the swap")
    }

    @Test("bounded runner caps output and enforces a hard timeout")
    func boundedRunner() {
        let success = BoundedPrivilegedProcessRunner.run(
            executable: "/bin/sh",
            arguments: ["-c", "printf 12345"],
            timeout: 2,
            maximumOutputBytes: 32
        )
        #expect(success?.succeeded == true)
        #expect(String(data: success?.output ?? Data(), encoding: .utf8) == "12345")

        let oversized = BoundedPrivilegedProcessRunner.run(
            executable: "/bin/sh",
            arguments: ["-c", "printf 123456789"],
            timeout: 2,
            maximumOutputBytes: 4
        )
        #expect(oversized?.outputLimitExceeded == true)
        #expect(oversized?.succeeded == false)

        let start = Date()
        let timed = BoundedPrivilegedProcessRunner.run(
            executable: "/bin/sh",
            arguments: ["-c", "exec /bin/sleep 5"],
            timeout: 0.1,
            maximumOutputBytes: 32
        )
        #expect(timed?.timedOut == true)
        #expect(timed?.succeeded == false)
        #expect(Date().timeIntervalSince(start) < 2)

        let retainedPipeStart = Date()
        let retainedPipe = BoundedPrivilegedProcessRunner.run(
            executable: "/bin/sh",
            arguments: ["-c", "/bin/sleep 5 & printf done"],
            timeout: 1,
            maximumOutputBytes: 32
        )
        #expect(retainedPipe?.succeeded == true)
        #expect(String(data: retainedPipe?.output ?? Data(), encoding: .utf8) == "done")
        #expect(Date().timeIntervalSince(retainedPipeStart) < 2,
                "a descendant retaining stdout must not hold the nonblocking reader open")

        let floodingDescendantStart = Date()
        let floodingDescendant = BoundedPrivilegedProcessRunner.run(
            executable: "/bin/sh",
            arguments: ["-c", "/usr/bin/yes descendant-output & printf done"],
            timeout: 0.25,
            maximumOutputBytes: 32
        )
        #expect(floodingDescendant?.outputLimitExceeded == true)
        #expect(floodingDescendant?.succeeded == false)
        #expect(Date().timeIntervalSince(floodingDescendantStart) < 2,
                "a descendant continuously refilling stdout must not trap the drain loop")

        setenv("MACCRAB_RUNNER_SECRET", "must-not-cross", 1)
        defer { unsetenv("MACCRAB_RUNNER_SECRET") }
        let environment = BoundedPrivilegedProcessRunner.run(
            executable: "/bin/sh",
            arguments: ["-c", "printf %s \"${MACCRAB_RUNNER_SECRET-unset}\""],
            timeout: 2,
            maximumOutputBytes: 32
        )
        #expect(String(data: environment?.output ?? Data(), encoding: .utf8) == "unset",
                "the child must not inherit caller secrets")

        let stdin = BoundedPrivilegedProcessRunner.run(
            executable: "/bin/sh",
            arguments: ["-c", "if IFS= read -r value; then printf got; else printf eof; fi"],
            timeout: 2,
            maximumOutputBytes: 32
        )
        #expect(stdin?.succeeded == true)
        #expect(String(data: stdin?.output ?? Data(), encoding: .utf8) == "eof",
                "short privileged commands must receive immediate stdin EOF")

        let suppliedInput = Data(repeating: 0x41, count: 1 * 1_024 * 1_024)
        let stdinRoundTrip = BoundedPrivilegedProcessRunner.run(
            executable: "/bin/sh",
            // Emit before reading, then copy stdin. A runner that writes all
            // input synchronously before draining stdout can deadlock here.
            arguments: ["-c", "printf prefix; /bin/cat"],
            timeout: 3,
            maximumOutputBytes: suppliedInput.count + 6,
            standardInputData: suppliedInput
        )
        var expectedRoundTrip = Data("prefix".utf8)
        expectedRoundTrip.append(suppliedInput)
        #expect(stdinRoundTrip?.succeeded == true)
        #expect(stdinRoundTrip?.output == expectedRoundTrip,
                "bounded stdin must round-trip exactly and reach EOF")

        let closesInputEarly = BoundedPrivilegedProcessRunner.run(
            executable: "/bin/sh",
            arguments: ["-c", "exit 0"],
            timeout: 2,
            maximumOutputBytes: 0,
            standardInputData: suppliedInput
        )
        #expect(closesInputEarly?.succeeded == true,
                "a child closing stdin early must yield EPIPE, not SIGPIPE MacCrab")

        let hardKillStart = Date()
        let ignoresTerm = BoundedPrivilegedProcessRunner.run(
            executable: "/bin/sh",
            arguments: ["-c", "trap '' TERM; while :; do /bin/sleep 1; done"],
            timeout: 0.1,
            maximumOutputBytes: 32
        )
        #expect(ignoresTerm?.timedOut == true)
        #expect(Date().timeIntervalSince(hardKillStart) < 2,
                "a command that ignores SIGTERM must still meet the hard deadline")

        #expect(BoundedPrivilegedProcessRunner.run(
            executable: "/bin/sh",
            arguments: ["-c", "exit 0"],
            timeout: .nan,
            maximumOutputBytes: 32
        ) == nil)
        #expect(BoundedPrivilegedProcessRunner.run(
            executable: "/bin/sh",
            arguments: ["-c", "exit 0"],
            timeout: .infinity,
            maximumOutputBytes: 32
        ) == nil)
        #expect(BoundedPrivilegedProcessRunner.run(
            executable: "/bin/sh",
            arguments: ["-c", "exit 0"],
            timeout: 1,
            maximumOutputBytes:
                BoundedPrivilegedProcessRunner.maximumCapturedOutputBytes + 1
        ) == nil)
    }

    @Test("privileged command files are private, identity-pinned, and cleaned")
    func privatePrivilegedCommandFile() throws {
        let command = try #require(PrivatePrivilegedCommandFile.create(
            contents: Data("anchor rules".utf8)
        ))
        let rootPath = URL(fileURLWithPath: command.path).deletingLastPathComponent().path

        var rootInfo = stat()
        var fileInfo = stat()
        #expect(lstat(rootPath, &rootInfo) == 0)
        #expect((rootInfo.st_mode & S_IFMT) == S_IFDIR)
        #expect((rootInfo.st_mode & 0o777) == 0o700)
        #expect(lstat(command.path, &fileInfo) == 0)
        #expect((fileInfo.st_mode & S_IFMT) == S_IFREG)
        #expect((fileInfo.st_mode & 0o777) == 0o600)
        #expect(fileInfo.st_nlink == 1)
        #expect(command.hasStableIdentity())

        #expect(unlink(command.path) == 0)
        let replacementFD = command.path.withCString {
            Darwin.open(
                $0,
                O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                mode_t(S_IRUSR | S_IWUSR)
            )
        }
        #expect(replacementFD >= 0)
        if replacementFD >= 0 {
            var replacement = Array("anchor rules".utf8)
            _ = replacement.withUnsafeMutableBytes { bytes in
                Darwin.write(replacementFD, bytes.baseAddress, bytes.count)
            }
            Darwin.close(replacementFD)
        }
        #expect(!command.hasStableIdentity(),
                "same-path replacement must not pass the descriptor identity check")

        command.cleanup()
        #expect(lstat(command.path, &fileInfo) != 0)
        #expect(lstat(rootPath, &rootInfo) != 0)
    }

    @Test("Homebrew CLI versions come from Cellar link metadata without execution")
    func homebrewMetadataVersion() throws {
        let prefix = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: prefix) }
        let bin = prefix.appendingPathComponent("bin")
        let target = prefix
            .appendingPathComponent("Cellar")
            .appendingPathComponent("node")
            .appendingPathComponent("22.14.0")
            .appendingPathComponent("bin")
            .appendingPathComponent("node")
        try FileManager.default.createDirectory(
            at: target.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )
        try Data().write(to: target)
        try FileManager.default.createDirectory(at: bin, withIntermediateDirectories: false)
        let link = bin.appendingPathComponent("node")
        try FileManager.default.createSymbolicLink(
            atPath: link.path,
            withDestinationPath: "../Cellar/node/22.14.0/bin/node"
        )

        #expect(VulnerabilityScanner.homebrewVersionFromSymlink(
            link.path,
            prefix: prefix.path,
            formulaPrefixes: ["node", "node@"]
        ) == "22.14.0")

        try FileManager.default.removeItem(at: link)
        try FileManager.default.createSymbolicLink(
            atPath: link.path,
            withDestinationPath: "../../outside/99.0/bin/node"
        )
        #expect(VulnerabilityScanner.homebrewVersionFromSymlink(
            link.path,
            prefix: prefix.path,
            formulaPrefixes: ["node", "node@"]
        ) == nil)
    }

    @Test("root engine never enables YARA and dynamic sandbox execution stays retired")
    func privilegedDynamicAnalysisDisabled() {
        #expect(YARAEnricher.shouldEnable(
            effectiveUID: 0,
            binaryTrusted: true,
            rulesTrusted: true
        ) == false)
        #expect(YARAEnricher.shouldEnable(
            effectiveUID: 501,
            binaryTrusted: true,
            rulesTrusted: true
        ) == true)
        #expect(SandboxAnalyzer.dynamicExecutionEnabled == false)
    }

    @Test("installed package inventory is non-root and exact-command-only")
    func installedInventoryCommandPolicy() {
        #expect(!PackageFreshnessChecker.allowsInstalledInventoryExecution(effectiveUID: 0))
        #expect(PackageFreshnessChecker.allowsInstalledInventoryExecution(effectiveUID: 501))

        let accepted = [
            ["npm", "ls", "-g", "--depth=0", "--json"],
            ["pip3", "list", "--format=json", "--user"],
            ["brew", "list", "--formula", "-1"],
            ["brew", "list", "--formula", "--versions"],
        ]
        for arguments in accepted {
            #expect(PackageFreshnessChecker.isAllowedInstalledInventoryCommand(
                path: "/usr/bin/env",
                arguments: arguments
            ))
        }

        let refused = [
            ["sh", "-c", "id"],
            ["npm", "exec", "evil"],
            ["pip3", "install", "evil"],
            ["brew", "install", "evil"],
        ]
        for arguments in refused {
            #expect(!PackageFreshnessChecker.isAllowedInstalledInventoryCommand(
                path: "/usr/bin/env",
                arguments: arguments
            ))
        }
        #expect(!PackageFreshnessChecker.isAllowedInstalledInventoryCommand(
            path: "/opt/homebrew/bin/npm",
            arguments: accepted[0]
        ))

        var response = PackageRegistryBodyAccumulator(maximumBytes: 2)
        let acceptedFirstByte = response.append(0x41)
        let acceptedSecondByte = response.append(0x42)
        let acceptedOverflowByte = response.append(0x43)
        #expect(acceptedFirstByte)
        #expect(acceptedSecondByte)
        #expect(!acceptedOverflowByte)
        #expect(response.data == Data([0x41, 0x42]))
    }

    @Test("drift guard covers every known root-reachable dynamic execution site")
    func sourceDriftGuard() throws {
        let repo = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        func source(_ relative: String) throws -> String {
            try String(contentsOf: repo.appendingPathComponent(relative), encoding: .utf8)
        }

        let vulnerability = try source("Sources/MacCrabCore/Detection/VulnerabilityScanner.swift")
        #expect(!vulnerability.contains("Process()"))
        #expect(vulnerability.contains("homebrewVersionFromSymlink"))
        #expect(vulnerability.contains("maximumOSVResponseBytes"))

        let yara = try source("Sources/MacCrabCore/Enrichment/YARAEnricher.swift")
        #expect(!yara.contains("Process()"))
        #expect(yara.contains("effectiveUID != 0"))
        #expect(yara.contains("BoundedPrivilegedProcessRunner.run"))

        let scripts = try source("Sources/MacCrabCore/Detection/ResponseAction.swift")
        #expect(!scripts.contains("process.executableURL = URL(fileURLWithPath: path)"))
        #expect(scripts.contains("PrivilegedExecutablePolicy.validatedPath"))
        #expect(scripts.contains("executable: \"/bin/sh\""))

        let sandbox = try source("Sources/MacCrabCore/Prevention/SandboxAnalyzer.swift")
        #expect(!sandbox.contains("Process()"))
        #expect(!sandbox.contains("/usr/bin/sandbox-exec"))
        #expect(sandbox.contains("dynamicExecutionEnabled = false"))

        let eventLoop = try source("Sources/MacCrabAgentKit/EventLoop.swift")
        #expect(eventLoop.contains("SandboxAnalyzer.dynamicExecutionEnabled"),
                "root EventLoop must not call retired dynamic analysis without the static kill switch")
        let startup = try source("Sources/MacCrabAgentKit/StartupBanner.swift")
        #expect(startup.contains("dynamic execution: disabled (unprivileged broker required)"),
                "the prevention banner must not claim the retired root analyzer is active")

        let inventory = try source("Sources/MacCrabCore/Integrations/SecurityToolIntegrations.swift")
        let reader = try source("Sources/MacCrabCore/Utilities/BoundedRegularFileReader.swift")
        #expect(vulnerability.contains("BoundedRegularFileReader.read("))
        #expect(inventory.contains("BoundedRegularFileReader.read("))
        #expect(reader.contains("Darwin.openat("))
        #expect(reader.contains("O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC"))
        #expect(reader.contains("path == \"/var\" || path.hasPrefix(\"/var/\")"))
        #expect(reader.contains("path == \"/tmp\" || path.hasPrefix(\"/tmp/\")"))
        #expect(reader.components(separatedBy: "Darwin.fstat(").count - 1 == 2,
                "the reader must re-stat after reading to reject mid-read mutation")

        let packageFreshness = try source("Sources/MacCrabCore/Detection/PackageFreshnessChecker.swift")
        #expect(packageFreshness.components(
            separatedBy: "runCommand(\"/usr/bin/env\", args:"
        ).count - 1 == 6,
                "every installed-inventory caller must remain visible to this allowlist guard")
        #expect(packageFreshness.components(separatedBy: "runCommand(").count - 1 == 7,
                "no unreviewed runCommand caller may bypass the exact-command guard")
        #expect(packageFreshness.contains(
            "guard Self.allowsInstalledInventoryExecution(effectiveUID: geteuid())"
        ))
        #expect(packageFreshness.contains("mergeStandardErrorIntoOutput: false"))
        #expect(packageFreshness.contains("packages.prefix(Self.maximumPackagesPerCheck)"))
        #expect(packageFreshness.contains("SecureURLSession.shared.bytes(for: request)"))
        #expect(!packageFreshness.contains("SecureURLSession.shared.data(for: request)"),
                "root registry responses must remain streamed and byte-bounded")
    }
}
