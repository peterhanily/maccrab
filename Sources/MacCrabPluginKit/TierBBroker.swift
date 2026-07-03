// MacCrabPluginKit — the plugin-author SDK for MacCrab Tier-B forensic plugins.
//
// A Tier-B plugin runs on one of two lanes:
//   • first-party (signed by the app publisher key): unsandboxed, reads files
//     directly with Full Disk Access;
//   • community / store: sandboxed deny-default — the plugin CANNOT open() its
//     declared paths itself; instead the host serves each declared read over a
//     broker socket (a fd the host passes in the environment).
//
// This kit hides the difference. Call `TierBBroker.readDeclared(path)` (or
// `openHandle`) for any path your manifest declares; it routes through the
// broker when sandboxed and reads directly when first-party. It NEVER grants
// access beyond your declared, consented read-set — on the sandboxed lane the
// host broker validates every request (manifest allowlist, per-component
// O_NOFOLLOW safe-open, TCC-guard) before passing back a read-only descriptor.

import Foundation
import CTierBBroker

public enum TierBBroker {

    /// Environment variable the sandboxed host sets to the broker socket fd.
    /// Absent → the plugin is on the first-party lane (no broker; read directly).
    public static let brokerFDEnv = "MACCRAB_TIERB_BROKER_FD"

    /// The broker socket fd when running sandboxed, else nil (first-party lane).
    public static var brokerFD: Int32? {
        guard let raw = ProcessInfo.processInfo.environment[brokerFDEnv],
              let fd = Int32(raw), fd >= 0 else { return nil }
        return fd
    }

    /// True when running on the sandboxed (community/store) lane.
    public static var isSandboxed: Bool { brokerFD != nil }

    /// Open a DECLARED read path as a read-only `FileHandle`.
    /// Sandboxed lane → served over the broker (the path must be in your
    /// manifest's `fileReadSubpaths` and consented); first-party lane → opened
    /// directly. Returns nil if denied / missing. Use this — not open()/
    /// FileManager — for your declared reads so the plugin works on both lanes.
    public static func openHandle(_ path: String) -> FileHandle? {
        if let sock = brokerFD {
            let fd = path.withCString { maccrab_tierb_broker_open(sock, $0) }
            return fd >= 0 ? FileHandle(fileDescriptor: fd, closeOnDealloc: true) : nil
        }
        return FileHandle(forReadingAtPath: path)
    }

    /// Read the full contents of a DECLARED path (broker or direct, per lane).
    public static func readDeclared(_ path: String) -> Data? {
        guard let h = openHandle(path) else { return nil }
        defer { try? h.close() }
        return h.readDataToEndOfFile()
    }
}
