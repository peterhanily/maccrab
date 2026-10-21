import Foundation
import Testing

/// The root engine is a session leader with no controlling terminal. A tty it
/// opens without O_NOCTTY becomes its controlling terminal, after which the
/// holder of that pty's master can send it SIGINT (graceful shutdown), SIGQUIT
/// or SIGHUP. A path swapped onto /dev/ttysNNN during a read is enough, so
/// every non-directory POSIX open in engine code passes O_NOCTTY.
@Suite("Engine opens never adopt a controlling terminal")
struct ControllingTerminalSafetyTests {
    private static let root = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()

    /// Engine opens allowed to omit O_NOCTTY, keyed by file and a snippet of
    /// the call, each with its reason. Directory-only opens (O_DIRECTORY)
    /// cannot open a tty and need no entry.
    private static let allowlist: [String: String] = [:]

    struct OpenCall {
        let file: String
        let snippet: String
        let passesNoCTTY: Bool
    }

    /// POSIX open/openat calls in one Swift file, skipping directory-only
    /// opens. A call is POSIX when written `Darwin.open(at)` or when its
    /// arguments carry an `O_` flag; a flags variable is judged by the lines
    /// that define it just above the call.
    static func nonDirectoryOpens(inFile relative: String) throws -> [OpenCall] {
        let text = try String(contentsOf: root.appendingPathComponent(relative), encoding: .utf8)
        let lines = text.components(separatedBy: "\n").map { line -> String in
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed.hasPrefix("//") || trimmed.hasPrefix("*") { return "" }
            if let comment = line.range(of: " //") { return String(line[..<comment.lowerBound]) }
            return line
        }
        let source = lines.joined(separator: "\n")
        let pattern = try NSRegularExpression(pattern: #"(?<![A-Za-z0-9_.])(Darwin\.)?(open|openat)\("#)
        let ns = source as NSString
        var calls: [OpenCall] = []
        for match in pattern.matches(in: source, range: NSRange(location: 0, length: ns.length)) {
            let lineStart = ns.lineRange(for: NSRange(location: match.range.location, length: 0)).location
            let prefix = ns.substring(with: NSRange(location: lineStart, length: match.range.location - lineStart))
            if prefix.contains("func ") { continue }
            // Balanced arguments from the opening parenthesis.
            var depth = 0
            var index = match.range.location + match.range.length - 1
            let start = index + 1
            repeat {
                let character = ns.character(at: index)
                if character == 0x28 { depth += 1 }
                if character == 0x29 { depth -= 1 }
                index += 1
            } while depth > 0 && index < ns.length
            let arguments = ns.substring(with: NSRange(location: start, length: max(0, index - 1 - start)))
            let isDarwin = match.range(at: 1).location != NSNotFound
            guard isDarwin || arguments.range(of: #"O_[A-Z]"#, options: .regularExpression) != nil else { continue }
            if arguments.contains("O_DIRECTORY"), !arguments.contains("?") { continue }
            let lineNumber = ns.substring(to: match.range.location).components(separatedBy: "\n").count
            let window = lines[max(0, lineNumber - 9)..<min(lines.count, lineNumber - 1)].joined(separator: "\n")
                + arguments
            calls.append(OpenCall(
                file: relative,
                snippet: (ns.substring(with: match.range) + arguments)
                    .replacingOccurrences(of: "\n", with: " ")
                    .replacingOccurrences(of: "  ", with: ""),
                passesNoCTTY: window.contains("O_NOCTTY")
            ))
        }
        return calls
    }

    static func engineSwiftFiles() throws -> [String] {
        var files: [String] = []
        for directory in ["Sources/MacCrabCore", "Sources/MacCrabAgentKit"] {
            let base = root.appendingPathComponent(directory)
            let enumerator = FileManager.default.enumerator(atPath: base.path)
            while let entry = enumerator?.nextObject() as? String {
                if entry.hasSuffix(".swift") { files.append(directory + "/" + entry) }
            }
        }
        return files.sorted()
    }

    @Test("the hasher and the bounded reader open files with O_NOCTTY")
    func hasherAndReaderFlags() throws {
        let hasher = try Self.nonDirectoryOpens(inFile: "Sources/MacCrabCore/Enrichment/FileHasher.swift")
        #expect(hasher.count >= 2, "both SHA-256 entry points open a descriptor")
        let hasherMissing = hasher.filter { !$0.passesNoCTTY }.map(\.snippet)
        #expect(hasherMissing.isEmpty, "\(hasherMissing)")
        let reader = try Self.nonDirectoryOpens(inFile: "Sources/MacCrabCore/Utilities/BoundedRegularFileReader.swift")
        #expect(reader.count == 1, "the leaf open; the walk's directory opens cannot reach a tty")
        let readerMissing = reader.filter { !$0.passesNoCTTY }.map(\.snippet)
        #expect(readerMissing.isEmpty, "\(readerMissing)")
    }

    @Test("every non-directory open in engine code passes O_NOCTTY")
    func everyEngineOpen() throws {
        var offenders: [String] = []
        var examined = 0
        for file in try Self.engineSwiftFiles() {
            for call in try Self.nonDirectoryOpens(inFile: file) {
                examined += 1
                guard !call.passesNoCTTY else { continue }
                let allowed = Self.allowlist.contains { key, _ in
                    key.hasPrefix(file + ":") && call.snippet.contains(key.dropFirst(file.count + 1))
                }
                if !allowed { offenders.append("\(file): \(call.snippet.prefix(120))") }
            }
        }
        #expect(examined >= 25, "the scan found the engine's opens (\(examined))")
        #expect(offenders.isEmpty, "opens without O_NOCTTY: \(offenders)")
    }
}
