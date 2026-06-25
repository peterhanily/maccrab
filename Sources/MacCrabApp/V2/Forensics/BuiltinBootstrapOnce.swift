// BuiltinBootstrapOnce — register the built-in forensic plugins at most once per
// process. Shared by the Overview forensics card and the unified Run-a-scan
// inventory. (Extracted from the former My-Plugins view, removed in v1.19.3 when
// the installed-plugin inventory was unified into Run a scan.)

import Foundation
import MacCrabForensics

actor BuiltinBootstrapOnce {
    static let shared = BuiltinBootstrapOnce()
    private var done = false
    func ensure() async {
        guard !done else { return }
        try? await MacCrabForensicsBootstrap.registerBuiltins()
        done = true
    }
}
