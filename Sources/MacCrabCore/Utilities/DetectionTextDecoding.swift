import Foundation

/// Lossy, bounded UTF-8 decoding for file content that detection evaluates.
///
/// Strict decoding returns nil for a single ill-formed byte. One stray byte in
/// a plist, hook script or package file therefore marked its content
/// unavailable, which skipped every `FileContent` rule and the injection
/// scanners, while node, launchd or an agent still read the rest of the file.
/// Ill-formed sequences now decode as U+FFFD. A prefix read that cut a
/// multi-byte character is trimmed to the last complete one, and the result
/// never exceeds `maximumBytes` of UTF-8, even though each replaced byte
/// widens to three.
public enum DetectionTextDecoding {
    public static func lossyUTF8(
        _ data: Data,
        maximumBytes: Int,
        endsAtTruncation: Bool
    ) -> String {
        var bytes = [UInt8](data)
        if endsAtTruncation {
            bytes.removeLast(bytes.count - completePrefixLength(bytes))
        }
        return clamped(String(decoding: bytes, as: UTF8.self), maximumBytes: maximumBytes)
    }

    /// Length of `bytes` without a final multi-byte sequence the read cut short.
    static func completePrefixLength(_ bytes: [UInt8]) -> Int {
        var lead = bytes.count - 1
        while lead >= 0, lead >= bytes.count - 4, bytes[lead] & 0xC0 == 0x80 {
            lead -= 1
        }
        guard lead >= 0 else { return bytes.count }
        let expected: Int
        switch bytes[lead] {
        case 0xC0...0xDF: expected = 2
        case 0xE0...0xEF: expected = 3
        case 0xF0...0xF7: expected = 4
        default: return bytes.count
        }
        return bytes.count - lead < expected ? lead : bytes.count
    }

    /// The longest prefix of `text` that fits `maximumBytes`, cut on a scalar
    /// boundary.
    static func clamped(_ text: String, maximumBytes: Int) -> String {
        let utf8 = text.utf8
        guard utf8.count > maximumBytes else { return text }
        guard maximumBytes > 0 else { return "" }
        let bytes = Array(utf8)
        var end = maximumBytes
        while end > 0, bytes[end] & 0xC0 == 0x80 {
            end -= 1
        }
        return String(decoding: bytes[..<end], as: UTF8.self)
    }
}
