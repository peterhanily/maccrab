import Foundation
import Testing
@testable import MacCrabCore

/// The stored command line must never carry a credential that the stored
/// argv redacts, and both must cover the common password-argument shapes.
@Suite("Command-line redaction matches argv redaction")
struct CommandLineRedactionParityTests {
    private func stored(_ argv: [String]) throws -> MacCrabCore.ProcessInfo {
        let process = MacCrabCore.ProcessInfo(
            pid: 7, ppid: 1, rpid: 1, name: (argv[0] as NSString).lastPathComponent,
            executable: argv[0], commandLine: argv.joined(separator: " "), args: argv,
            workingDirectory: "/", userId: 501, userName: "u", groupId: 20, startTime: Date())
        let event = Event(timestamp: Date(), eventCategory: .process, eventType: .start,
                          eventAction: "exec", process: process)
        return try EventPrivacySanitizer.sanitize(event).event.process
    }

    @Test("a separated password value is redacted in the command line as in argv")
    func separatedValues() throws {
        for (argv, secret) in [
            (["/usr/local/bin/sshpass", "-p", "S3cret", "ssh", "host"], "S3cret"),
            (["/usr/local/bin/sshpass", "-p", "letmein", "ssh", "host"], "letmein"),
            (["/usr/bin/tool", "--key", "abcdef123456"], "abcdef123456"),
            (["/usr/bin/tool", "--passwd", "hunter2"], "hunter2"),
            (["/usr/bin/tool", "--private-key", "MIIEvQIBADAN"], "MIIEvQIBADAN"),
            (["/usr/bin/tool", "--private_key=MIIEvQIBADAN"], "MIIEvQIBADAN"),
            (["/usr/bin/curl", "-u", "alice:wonderland", "https://x.invalid"], "wonderland"),
            (["/usr/bin/curl", "--user=alice:wonderland", "https://x.invalid"], "wonderland"),
            (["/usr/bin/curl", "-ualice:wonderland", "https://x.invalid"], "wonderland"),
            (["/usr/bin/openssl", "enc", "-aes-256-cbc", "-pass", "pass:wonderland"], "wonderland"),
        ] {
            let process = try stored(argv)
            #expect(!process.commandLine.contains(secret), "\(process.commandLine)")
            #expect(!process.args.contains { $0.contains(secret) }, "\(process.args)")
        }
    }

    @Test("paths after a standalone -p and numeric uid:gid pairs stay visible")
    func structuralValuesStayVisible() throws {
        let mkdir = try stored(["/bin/mkdir", "-p", "/Users/u/project/build"])
        #expect(mkdir.commandLine == "/bin/mkdir -p /Users/u/project/build")
        #expect(mkdir.args.last == "/Users/u/project/build")
        let docker = try stored(["/usr/local/bin/docker", "run", "-u", "501:20", "image"])
        #expect(docker.commandLine.contains("501:20"))
        let sudo = try stored(["/usr/bin/sudo", "-u", "alice", "id"])
        #expect(sudo.commandLine == "/usr/bin/sudo -u alice id")
    }

    @Test("bare strings without argv still cover sshpass, -u pairs and pass:")
    func bareStrings() {
        for (line, secret) in [
            ("sshpass -p letmein ssh host", "letmein"),
            ("sshpass -pletmein ssh host", "letmein"),
            ("curl -u alice:wonderland https://x.invalid", "wonderland"),
            ("openssl rsa -passin pass:wonderland -in key.pem", "wonderland"),
            ("tool --passwd=hunter2", "hunter2"),
            ("tool --key abcdef123456", "abcdef123456"),
        ] {
            #expect(!CommandSanitizer.sanitize(line).contains(secret), "\(line)")
        }
        #expect(CommandSanitizer.sanitize(commandLine: "a b", arguments: ["a", "c"]) == "a b")
        #expect(CommandSanitizer.sanitize(
            commandLine: "/usr/local/bin/sshpass -p letmein ssh",
            arguments: ["/usr/local/bin/sshpass", "-p", "letmein", "ssh"]
        ) == "/usr/local/bin/sshpass -p [REDACTED] ssh")
    }
}
