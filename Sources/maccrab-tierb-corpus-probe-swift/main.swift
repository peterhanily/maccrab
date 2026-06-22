// maccrab-tierb-corpus-probe-swift — the SWIFT containment corpus fixture.
//
// A real third-party forensic collector is a SWIFT binary: it pulls in the Swift
// runtime, Foundation, and the dyld shared cache, which need a broader SBPL allow
// set than the minimal C fixtures. The C probe proves the broker + boundary; this
// proves containment for the workload the marketplace ACTUALLY ships (audit #3):
//
//   - the Swift runtime + Foundation START under the deny-default sandbox and the
//     plugin emits (ALLOW — if the SBPL base is too tight the binary SIGABRTs at
//     startup and this test fails, which is exactly the signal to widen the base);
//   - a DECLARED read is served through the broker over fd 3 (ALLOW);
//   - undeclared file open / network egress / fork+exec (posix_spawn) /
//     metadata-stat are all OS-denied (DENY → host sees ZERO leak.* artifacts).
//
// (The undeclared mach-lookup probe lives in the C fixture — bootstrap_look_up
// isn't exposed in Swift's Darwin overlay, and mach denial is language-
// independent, so the C probe covers that boundary for both fixtures.)
//
// Speaks the frozen TierBIPC contract (TierBIPC.swift): one request JSON line on
// stdin, artifact/result JSONL on stdout, file broker on fd 3. Test/operator
// tooling (ContainmentCorpusTests + the on-device corpus run), NOT a shipped
// plugin — built so the corpus runs against the EXACT shipped runner/broker.

import Foundation
import Darwin
import CTierBBroker

/// Hand-rolled JSONL so the line shape exactly matches the C fixture the host
/// parser already accepts (the values here are fixed/derived, no escaping needed).
func emit(_ contentType: String, _ summary: String) {
    let line = "{\"kind\":\"artifact\",\"artifact\":{\"contentType\":\"\(contentType)\","
        + "\"privacyClass\":\"metadata\",\"summary\":\"\(summary)\",\"data\":{}}}\n"
    FileHandle.standardOutput.write(Data(line.utf8))
}

// Exercise Foundation + JSON on the startup path (this is the point of a Swift
// fixture — if Foundation can't initialize under the SBPL base, we never get here).
let requestData = FileHandle.standardInput.readDataToEndOfFile()
let scratch = (try? JSONSerialization.jsonObject(with: requestData) as? [String: Any])
    .flatMap { $0?["scratchDir"] as? String }

// ---- ALLOW: a DECLARED read served through the broker over fd 3. ----
if let scratch {
    let path = scratch + "/allowed.txt"
    let bytes = Array(path.utf8)
    let hdr: [UInt8] = [UInt8((bytes.count >> 8) & 0xFF), UInt8(bytes.count & 0xFF)]
    let sentHdr = hdr.withUnsafeBytes { write(3, $0.baseAddress, 2) }
    let sentPath = bytes.withUnsafeBytes { write(3, $0.baseAddress, bytes.count) }
    if sentHdr == 2, sentPath == bytes.count {
        var fd: Int32 = -1
        if maccrab_tierb_recv_fd(3, &fd) == 0, fd >= 0 {
            var buf = [UInt8](repeating: 0, count: 64)
            let n = read(fd, &buf, 63)
            if n > 0 { emit("broker.read.ok", String(decoding: buf[0..<n], as: UTF8.self)) }
            close(fd)
        }
    }
}

// ---- DENY battery: each MUST fail under containment. ----

// F4: open a file outside any declared root (filesystem escape).
do {
    let f = open("/tmp/maccrab-corpus-secret", O_RDONLY)
    if f >= 0 { emit("leak.file_escape", "opened an undeclared file directly"); close(f) }
}

// F9: undeclared network egress.
do {
    let s = socket(AF_INET, SOCK_STREAM, 0)
    if s >= 0 {
        _ = fcntl(s, F_SETFL, O_NONBLOCK)
        var sa = sockaddr_in()
        sa.sin_family = sa_family_t(AF_INET)
        sa.sin_port = in_port_t(443).bigEndian
        inet_pton(AF_INET, "1.1.1.1", &sa.sin_addr)
        let rc = withUnsafePointer(to: &sa) { p in
            p.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                connect(s, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        if rc == 0 || errno == EINPROGRESS { emit("leak.network", "outbound connect not denied") }
        close(s)
    }
}

// F11: fork + exec (default fork-deny AND exec-deny). Swift's Darwin overlay
// blocks raw fork(); posix_spawn exercises both denials — the manifest declares
// no exec/fork, so under containment it must fail.
do {
    var pid: pid_t = 0
    let argv: [UnsafeMutablePointer<CChar>?] = [strdup("/usr/bin/true"), nil]
    defer { for p in argv where p != nil { free(p) } }
    let rc = posix_spawn(&pid, "/usr/bin/true", nil, nil, argv, environ)
    if rc == 0 { emit("leak.fork", "posix_spawn succeeded (fork/exec not denied)"); var st: Int32 = 0; waitpid(pid, &st, 0) }
}

// F-META: read metadata of a metadata-denied crown-jewel (existence/size/mtime
// side channel). Foundation's attributesOfItem does a stat under the hood — under
// the (deny file-read-metadata) rule it throws, so a non-nil return is a leak.
do {
    if (try? FileManager.default.attributesOfItem(atPath: "/Library/Keychains")) != nil {
        emit("leak.metadata", "read metadata of a metadata-denied crown-jewel")
    }
}

FileHandle.standardOutput.write(Data(
    "{\"kind\":\"result\",\"result\":{\"status\":\"ok\",\"notes\":[\"swift corpus probe complete\"]}}\n".utf8))
