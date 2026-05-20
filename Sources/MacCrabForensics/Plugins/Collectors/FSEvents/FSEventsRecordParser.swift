// FSEventsRecordParser — parses an `.fseventsd` gzip-compressed
// binary record log into individual fsevents.record entries.
//
// Format (community-derived from Apple-internal):
//   - File is gzip-compressed.
//   - Decompressed stream starts with magic bytes:
//       "1SLD" / "2SLD" / "3SLD" — version identifier
//   - Followed by a stream of records. Per-record layout per
//     version:
//       v1 ("1SLD"): null-terminated path, 8-byte event_id, 4-byte flags
//       v2 ("2SLD"): null-terminated path, 8-byte event_id, 4-byte flags, 8-byte node_id
//       v3 ("3SLD"): null-terminated path, 8-byte event_id, 4-byte flags, 8-byte node_id, 4-byte reserved
//
// Decompression uses `gunzip -c` as a subprocess — Apple's
// Compression.framework supports raw zlib but the gzip header
// handshake is fiddlier than the few-millisecond overhead of a
// shell-out for the once-per-log-file work.

import Foundation

public struct FSEventsRecord: Sendable {
    public let path: String
    public let eventID: UInt64
    public let flags: UInt32
    public let nodeID: UInt64?

    /// Decoded flag tokens. Subset of common Apple FSEvents flags:
    ///   0x00000001 Created
    ///   0x00000002 Removed
    ///   0x00000004 InodeMetaMod
    ///   0x00000008 Renamed
    ///   0x00000010 Modified
    ///   0x00000020 Exchange
    ///   0x00000040 FinderInfoMod
    ///   0x00000080 ChangedOwner
    ///   0x00000100 XattrMod
    ///   0x00000200 IsFile
    ///   0x00000400 IsDir
    ///   0x00000800 IsSymlink
    ///   0x00001000 IsHardlink
    ///   0x00002000 ItemFinderInfoModifier
    ///   0x00004000 ItemXattrModifier
    ///   0x00010000 OwnerChange
    ///   0x00020000 LinkChange
    ///   0x00040000 MountStatusChange
    public var decodedFlags: [String] {
        var tokens: [String] = []
        if flags & 0x01 != 0 { tokens.append("Created") }
        if flags & 0x02 != 0 { tokens.append("Removed") }
        if flags & 0x04 != 0 { tokens.append("InodeMetaMod") }
        if flags & 0x08 != 0 { tokens.append("Renamed") }
        if flags & 0x10 != 0 { tokens.append("Modified") }
        if flags & 0x20 != 0 { tokens.append("Exchange") }
        if flags & 0x40 != 0 { tokens.append("FinderInfoMod") }
        if flags & 0x80 != 0 { tokens.append("ChangedOwner") }
        if flags & 0x100 != 0 { tokens.append("XattrMod") }
        if flags & 0x200 != 0 { tokens.append("IsFile") }
        if flags & 0x400 != 0 { tokens.append("IsDir") }
        if flags & 0x800 != 0 { tokens.append("IsSymlink") }
        if flags & 0x1000 != 0 { tokens.append("IsHardlink") }
        return tokens
    }
}

public enum FSEventsRecordParser {

    public enum ParseError: Error, CustomStringConvertible {
        case decompressFailed(message: String)
        case magicUnknown(bytes: [UInt8])
        case truncated

        public var description: String {
            switch self {
            case .decompressFailed(let m): return "FSEvents decompress failed: \(m)"
            case .magicUnknown(let b): return "FSEvents unknown magic bytes: \(b)"
            case .truncated: return "FSEvents record stream truncated"
            }
        }
    }

    public static func parse(gzippedFile path: String, cap: Int = 5000) throws -> [FSEventsRecord] {
        // Decompress via gunzip -c into memory.
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: "/usr/bin/gunzip")
        proc.arguments = ["-c", path]
        let out = Pipe()
        proc.standardOutput = out
        proc.standardError = Pipe()
        do { try proc.run() } catch {
            throw ParseError.decompressFailed(message: error.localizedDescription)
        }
        proc.waitUntilExit()
        let data = out.fileHandleForReading.readDataToEndOfFile()
        guard data.count >= 4 else {
            throw ParseError.truncated
        }

        // Magic bytes determine the record layout.
        let magic = data.prefix(4)
        let version: Int
        switch Array(magic) {
        case Array("1SLD".utf8): version = 1
        case Array("2SLD".utf8): version = 2
        case Array("3SLD".utf8): version = 3
        default:
            throw ParseError.magicUnknown(bytes: Array(magic))
        }

        // After magic comes 4 bytes of padding/header before
        // records begin (observed across macOS revisions). Skip
        // through the magic word to find the first null-terminated
        // path.
        var cursor = 4
        var records: [FSEventsRecord] = []

        // Helper closures over the byte buffer.
        func readNullTerminatedString(from offset: inout Int) -> String? {
            guard offset < data.count else { return nil }
            var end = offset
            while end < data.count, data[end] != 0 {
                end += 1
            }
            guard end < data.count else { return nil }
            let str = String(data: data[offset..<end], encoding: .utf8)
            offset = end + 1
            return str
        }
        func readUInt64LE(from offset: inout Int) -> UInt64? {
            guard offset + 8 <= data.count else { return nil }
            var value: UInt64 = 0
            for i in 0..<8 {
                value |= UInt64(data[offset + i]) << (i * 8)
            }
            offset += 8
            return value
        }
        func readUInt32LE(from offset: inout Int) -> UInt32? {
            guard offset + 4 <= data.count else { return nil }
            var value: UInt32 = 0
            for i in 0..<4 {
                value |= UInt32(data[offset + i]) << (i * 8)
            }
            offset += 4
            return value
        }

        while cursor < data.count, records.count < cap {
            guard let path = readNullTerminatedString(from: &cursor),
                  let eventID = readUInt64LE(from: &cursor),
                  let flags = readUInt32LE(from: &cursor) else {
                break
            }
            var nodeID: UInt64? = nil
            if version >= 2 {
                nodeID = readUInt64LE(from: &cursor)
            }
            if version >= 3 {
                // 4-byte reserved field — read + discard.
                _ = readUInt32LE(from: &cursor)
            }
            records.append(FSEventsRecord(
                path: path,
                eventID: eventID,
                flags: flags,
                nodeID: nodeID
            ))
        }
        return records
    }
}
