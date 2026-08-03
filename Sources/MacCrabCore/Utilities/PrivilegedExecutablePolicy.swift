// PrivilegedExecutablePolicy.swift
// MacCrabCore
//
// Shared trust boundary for subprocesses that can be reached from the root
// system extension.  A path being executable (or merely existing) says
// nothing about who controls it: Homebrew's normal prefix is owned by the
// console user, and a final-file-only check misses writable/symlinked parent
// directories.  This policy walks every component without following links and
// accepts only a root-owned, non-ACL, non-group/world-writable chain.

import Foundation
import Darwin

enum PrivilegedExecutablePolicy {
    enum ExpectedKind {
        case directory
        case regularFile(requireExecutable: Bool, maximumSize: UInt64? = nil)
    }

    /// Return a canonical path only when the complete path is controlled by
    /// `requiredOwnerUID`.  `validationRoot` exists to make the same component
    /// walk testable in a private fixture; production callers leave it as `/`.
    static func validatedPath(
        _ path: String,
        kind: ExpectedKind,
        allowedPrefixes: [String],
        requiredOwnerUID: uid_t = 0,
        validationRoot: String = "/"
    ) -> String? {
        guard !path.isEmpty, path.first == "/", !path.utf8.contains(0) else {
            return nil
        }

        let canonical = (path as NSString).standardizingPath
        let root = (validationRoot as NSString).standardizingPath
        guard canonical.first == "/", root.first == "/",
              isWithin(canonical, root: root),
              allowedPrefixes.contains(where: {
                  isWithin(canonical, root: ($0 as NSString).standardizingPath)
              }) else {
            return nil
        }

        let relative: String
        if canonical == root {
            relative = ""
        } else if root == "/" {
            relative = String(canonical.dropFirst())
        } else {
            relative = String(canonical.dropFirst(root.count + 1))
        }

        var current = root
        guard componentIsTrusted(
            current,
            expectedType: relative.isEmpty ? kind : .directory,
            requiredOwnerUID: requiredOwnerUID
        ) else {
            return nil
        }

        let components = relative.split(separator: "/", omittingEmptySubsequences: true)
        for (index, component) in components.enumerated() {
            current = (current as NSString).appendingPathComponent(String(component))
            let isLeaf = index == components.count - 1
            guard componentIsTrusted(
                current,
                expectedType: isLeaf ? kind : .directory,
                requiredOwnerUID: requiredOwnerUID
            ) else {
                return nil
            }
        }
        return canonical
    }

    static func validatedExecutable(
        _ path: String,
        allowedPrefixes: [String]? = nil
    ) -> String? {
        validatedPath(
            path,
            kind: .regularFile(requireExecutable: true),
            allowedPrefixes: allowedPrefixes ?? [path]
        )
    }

    private static func isWithin(_ path: String, root: String) -> Bool {
        if root == "/" { return path.first == "/" }
        return path == root || path.hasPrefix(root + "/")
    }

    private static func componentIsTrusted(
        _ path: String,
        expectedType: ExpectedKind,
        requiredOwnerUID: uid_t
    ) -> Bool {
        var metadata = stat()
        guard path.withCString({ Darwin.lstat($0, &metadata) }) == 0,
              metadata.st_uid == requiredOwnerUID,
              (metadata.st_mode & (S_IWGRP | S_IWOTH)) == 0,
              hasNoExtendedACL(path) else {
            return false
        }

        switch expectedType {
        case .directory:
            return (metadata.st_mode & S_IFMT) == S_IFDIR

        case .regularFile(let requireExecutable, let maximumSize):
            guard (metadata.st_mode & S_IFMT) == S_IFREG,
                  (metadata.st_mode & (S_ISUID | S_ISGID)) == 0 else {
                return false
            }
            if requireExecutable,
               (metadata.st_mode & (S_IXUSR | S_IXGRP | S_IXOTH)) == 0 {
                return false
            }
            if let maximumSize {
                guard metadata.st_size >= 0,
                      UInt64(metadata.st_size) <= maximumSize else {
                    return false
                }
            }
            return true
        }
    }

    /// POSIX mode bits do not describe macOS extended ACL grants.  Reject any
    /// extended ACL rather than trying to prove that every ACE is harmless.
    /// `acl_get_file` reports ENOENT when no extended ACL is present.
    private static func hasNoExtendedACL(_ path: String) -> Bool {
        errno = 0
        guard let acl = acl_get_file(path, ACL_TYPE_EXTENDED) else {
            return errno == ENOENT || errno == ENOTSUP
        }
        acl_free(UnsafeMutableRawPointer(acl))
        return false
    }
}

/// Synchronous, bounded subprocess runner for short privileged probes.
///
/// It never inherits the caller environment, drains output while the child is
/// live, caps retained bytes, and applies a hard SIGKILL deadline.  The output
/// pipe is non-blocking so a malicious grandchild retaining the descriptor
/// cannot hold the caller open after the direct child exits.
public enum BoundedPrivilegedProcessRunner {
    /// A caller-supplied capture limit is itself untrusted configuration. Keep
    /// the shared runner bounded even if a future call site accidentally passes
    /// `Int.max`; archive resolution needs at most the trace format's bounded
    /// 128-MiB expanded payload so it can bind semantics to immutable stdin
    /// bytes instead of a same-uid-writable extraction pathname.
    public static let maximumCapturedOutputBytes = 128 * 1_024 * 1_024
    /// Keep caller-supplied stdin bounded too. Archive consumers use this to
    /// feed already-authenticated bytes to a system parser without first
    /// exposing those bytes through a same-uid-mutable temporary pathname.
    public static let maximumStandardInputBytes = 128 * 1_024 * 1_024

    public struct Result {
        public let terminationStatus: Int32?
        public let output: Data
        public let timedOut: Bool
        public let outputLimitExceeded: Bool

        public var succeeded: Bool {
            terminationStatus == 0 && !timedOut && !outputLimitExceeded
        }
    }

    public static let minimalEnvironment: [String: String] = [
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        "HOME": "/var/empty",
        "TMPDIR": "/private/tmp",
        "LANG": "C",
        "LC_ALL": "C",
    ]

    public static func run(
        executable: String,
        arguments: [String],
        environment: [String: String] = minimalEnvironment,
        workingDirectory: String = "/",
        timeout: TimeInterval,
        maximumOutputBytes: Int?,
        mergeStandardErrorIntoOutput: Bool = true,
        standardInputData: Data? = nil
    ) -> Result? {
        guard let trustedExecutable = PrivilegedExecutablePolicy.validatedExecutable(executable),
              timeout.isFinite,
              timeout > 0,
              timeout <= 3_600,
              maximumOutputBytes.map({
                  $0 >= 0 && $0 <= maximumCapturedOutputBytes
              }) ?? true,
              standardInputData.map({
                  $0.count <= maximumStandardInputBytes
              }) ?? true else {
            return nil
        }

        let process = Process()
        process.executableURL = URL(fileURLWithPath: trustedExecutable)
        process.arguments = arguments
        process.environment = environment
        process.currentDirectoryURL = URL(fileURLWithPath: workingDirectory, isDirectory: true)
        // Never inherit a launchd/terminal descriptor. Most callers observe
        // immediate EOF. Archive consumers can instead supply an immutable,
        // bounded Data value through a pipe that has no filesystem pathname.
        // The write end is nonblocking and is serviced alongside stdout below,
        // so a child that alternates reads and writes cannot deadlock us.
        var inputPipe: Pipe?
        var inputFD: Int32 = -1
        if standardInputData != nil {
            let pipe = Pipe()
            inputPipe = pipe
            inputFD = pipe.fileHandleForWriting.fileDescriptor
            let existingFlags = Darwin.fcntl(inputFD, F_GETFL)
            guard existingFlags >= 0,
                  Darwin.fcntl(inputFD, F_SETFL, existingFlags | O_NONBLOCK) == 0,
                  // A child may close stdin before consuming every byte. Do
                  // not let that ordinary EPIPE deliver SIGPIPE to MacCrab.
                  Darwin.fcntl(inputFD, F_SETNOSIGPIPE, 1) == 0 else {
                return nil
            }
            process.standardInput = pipe
        } else {
            process.standardInput = FileHandle.nullDevice
        }

        var outputPipe: Pipe?
        var outputFD: Int32 = -1
        if maximumOutputBytes != nil {
            let pipe = Pipe()
            outputPipe = pipe
            outputFD = pipe.fileHandleForReading.fileDescriptor
            let existingFlags = Darwin.fcntl(outputFD, F_GETFL)
            guard existingFlags >= 0,
                  Darwin.fcntl(outputFD, F_SETFL, existingFlags | O_NONBLOCK) == 0 else {
                return nil
            }
            // Merge stderr: both streams are untrusted and share one global cap.
            process.standardOutput = pipe
            process.standardError = mergeStandardErrorIntoOutput
                ? pipe
                : FileHandle.nullDevice
        } else {
            process.standardOutput = FileHandle.nullDevice
            process.standardError = FileHandle.nullDevice
        }

        do {
            try process.run()
        } catch {
            try? inputPipe?.fileHandleForReading.close()
            try? inputPipe?.fileHandleForWriting.close()
            try? outputPipe?.fileHandleForReading.close()
            try? outputPipe?.fileHandleForWriting.close()
            return nil
        }
        // Process.run() has duplicated the child's stdin endpoint. Close the
        // parent's copy of the read end so EOF is governed solely by our write
        // end, then close stdout's parent write endpoint as before.
        try? inputPipe?.fileHandleForReading.close()
        try? outputPipe?.fileHandleForWriting.close()

        // Use the monotonic clock. Wall-clock corrections must not extend a
        // security deadline or make it fire early.
        let start = DispatchTime.now().uptimeNanoseconds
        let timeoutNanoseconds = UInt64(timeout * 1_000_000_000)
        let (deadline, deadlineOverflow) = start.addingReportingOverflow(timeoutNanoseconds)
        let (hardStop, hardStopOverflow) = deadline.addingReportingOverflow(1_000_000_000)
        guard !deadlineOverflow, !hardStopOverflow else {
            if process.isRunning { Darwin.kill(process.processIdentifier, SIGKILL) }
            try? outputPipe?.fileHandleForReading.close()
            return nil
        }
        let ceiling = maximumOutputBytes ?? 0
        var output = Data()
        var timedOut = false
        var outputLimitExceeded = false
        var inputOffset = 0

        func closeInput() {
            guard inputFD >= 0 else { return }
            try? inputPipe?.fileHandleForWriting.close()
            inputFD = -1
        }

        func feedInput() {
            guard inputFD >= 0, let input = standardInputData else { return }
            if inputOffset >= input.count {
                closeInput()
                return
            }

            // Bound each pass just like stdout draining. This gives both pipe
            // directions and the deadline/process-state checks a turn even for
            // a child that continuously reads stdin while continuously writing
            // stdout.
            let maximumWritesPerPass = 64
            let chunkBytes = 16 * 1_024
            var writes = 0
            while writes < maximumWritesPerPass, inputOffset < input.count {
                let remaining = input.count - inputOffset
                let count = input.withUnsafeBytes { bytes -> Int in
                    guard let base = bytes.baseAddress else { return 0 }
                    return Darwin.write(
                        inputFD,
                        base.advanced(by: inputOffset),
                        min(chunkBytes, remaining)
                    )
                }
                if count > 0 {
                    inputOffset += count
                    writes += 1
                    continue
                }
                if count < 0 && errno == EINTR { continue }
                if count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK) {
                    break
                }
                // EPIPE means the direct child no longer wants input; any
                // semantic failure remains visible in its termination status.
                // Other descriptor errors are also fail-safe: close our end so
                // the runner cannot block, then let status/deadline decide.
                closeInput()
                break
            }
            if inputOffset >= input.count { closeInput() }
        }

        func drainOutput() {
            guard outputFD >= 0 else { return }
            var buffer = [UInt8](repeating: 0, count: 16 * 1024)
            // A nonblocking descriptor prevents an empty pipe from hanging,
            // but it does not bound a pipe that is continuously refilled. A
            // child can fork a descendant which retains stdout and writes
            // forever after the direct child exits. Limit each pass so control
            // always returns to the deadline/process-state checks; the final
            // post-exit pass is bounded for the same reason.
            let maximumReadsPerPass = 64
            var reads = 0
            while reads < maximumReadsPerPass {
                let count = buffer.withUnsafeMutableBytes { bytes in
                    Darwin.read(outputFD, bytes.baseAddress, bytes.count)
                }
                if count > 0 {
                    reads += 1
                    let byteCount = Int(count)
                    if !outputLimitExceeded,
                       byteCount <= ceiling,
                       output.count <= ceiling - byteCount {
                        output.append(contentsOf: buffer.prefix(byteCount))
                    } else {
                        outputLimitExceeded = true
                        if process.isRunning {
                            Darwin.kill(process.processIdentifier, SIGKILL)
                        }
                    }
                    continue
                }
                if count < 0 && errno == EINTR { continue }
                // EOF or EAGAIN: nothing immediately available.
                break
            }
        }

        while process.isRunning {
            feedInput()
            drainOutput()
            let now = DispatchTime.now().uptimeNanoseconds
            if !timedOut && now >= deadline {
                timedOut = true
                Darwin.kill(process.processIdentifier, SIGKILL)
            }
            if now >= hardStop { break }
            usleep(10_000)
        }
        closeInput()
        drainOutput()

        let status: Int32?
        if process.isRunning {
            Darwin.kill(process.processIdentifier, SIGKILL)
            status = nil
        } else {
            process.waitUntilExit()
            status = process.terminationStatus
        }
        closeInput()
        try? outputPipe?.fileHandleForReading.close()

        return Result(
            terminationStatus: status,
            output: output,
            timedOut: timedOut,
            outputLimitExceeded: outputLimitExceeded
        )
    }
}

/// One immutable command-input file under an atomically-created root-only
/// workspace. This is for privileged tools such as pfctl that insist on a path
/// rather than accepting an already-open descriptor. Call `hasStableIdentity`
/// immediately before launching the tool and retain the object until the tool
/// exits; deinit performs deterministic best-effort cleanup.
public final class PrivatePrivilegedCommandFile {
    public let path: String

    private let rootPath: String
    private let expectedDevice: dev_t
    private let expectedInode: ino_t
    private let expectedSize: off_t
    private var cleaned = false

    private init(rootPath: String, metadata: stat) {
        self.rootPath = rootPath
        self.path = rootPath + "/input"
        self.expectedDevice = metadata.st_dev
        self.expectedInode = metadata.st_ino
        self.expectedSize = metadata.st_size
    }

    public static func create(contents: Data, maximumBytes: Int = 1 * 1_024 * 1_024) -> PrivatePrivilegedCommandFile? {
        guard maximumBytes >= 0, contents.count <= maximumBytes else { return nil }

        var template = Array("/private/tmp/maccrab-privileged-command.XXXXXX".utf8CString)
        let rootPath: String? = template.withUnsafeMutableBufferPointer { buffer in
            guard let base = buffer.baseAddress,
                  let created = Darwin.mkdtemp(base) else {
                return nil
            }
            return String(cString: created)
        }
        guard let rootPath else { return nil }

        let path = rootPath + "/input"
        let descriptor = path.withCString {
            Darwin.open(
                $0,
                O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                mode_t(S_IRUSR | S_IWUSR)
            )
        }
        guard descriptor >= 0 else {
            _ = rootPath.withCString { Darwin.rmdir($0) }
            return nil
        }

        var succeeded = contents.withUnsafeBytes { bytes -> Bool in
            guard let base = bytes.baseAddress else { return contents.isEmpty }
            var offset = 0
            while offset < bytes.count {
                let count = Darwin.write(
                    descriptor,
                    base.advanced(by: offset),
                    bytes.count - offset
                )
                if count < 0 {
                    if errno == EINTR { continue }
                    return false
                }
                guard count > 0 else { return false }
                offset += count
            }
            return true
        }
        if succeeded && Darwin.fsync(descriptor) != 0 { succeeded = false }

        var metadata = stat()
        if succeeded {
            succeeded = Darwin.fstat(descriptor, &metadata) == 0
                && (metadata.st_mode & S_IFMT) == S_IFREG
                && (metadata.st_mode & 0o777) == 0o600
                && metadata.st_uid == geteuid()
                && metadata.st_nlink == 1
                && metadata.st_size == off_t(contents.count)
        }
        Darwin.close(descriptor)

        guard succeeded else {
            _ = path.withCString { Darwin.unlink($0) }
            _ = rootPath.withCString { Darwin.rmdir($0) }
            return nil
        }
        return PrivatePrivilegedCommandFile(rootPath: rootPath, metadata: metadata)
    }

    /// Reopen the private root and leaf without following links and prove that
    /// the path still names the exact file created above.
    public func hasStableIdentity() -> Bool {
        let rootDescriptor = rootPath.withCString {
            Darwin.open($0, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
        }
        guard rootDescriptor >= 0 else { return false }
        defer { Darwin.close(rootDescriptor) }

        let descriptor = "input".withCString {
            Darwin.openat(
                rootDescriptor,
                $0,
                O_RDONLY | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW
            )
        }
        guard descriptor >= 0 else { return false }
        defer { Darwin.close(descriptor) }

        var metadata = stat()
        return Darwin.fstat(descriptor, &metadata) == 0
            && (metadata.st_mode & S_IFMT) == S_IFREG
            && (metadata.st_mode & 0o777) == 0o600
            && metadata.st_uid == geteuid()
            && metadata.st_nlink == 1
            && metadata.st_dev == expectedDevice
            && metadata.st_ino == expectedInode
            && metadata.st_size == expectedSize
    }

    public func cleanup() {
        guard !cleaned else { return }
        cleaned = true
        _ = path.withCString { Darwin.unlink($0) }
        _ = rootPath.withCString { Darwin.rmdir($0) }
    }

    deinit {
        cleanup()
    }
}
