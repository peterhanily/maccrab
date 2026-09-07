# Third-Party Licenses

MacCrab is licensed under the Apache License 2.0 (see [LICENSE](LICENSE)).
The following inventory describes the external components linked or bundled
with this source tree. Exact upstream notices are preserved in
[ThirdPartyNotices](ThirdPartyNotices/), including Sparkle's additional bundled
component notices. Their origins and file digests are recorded in
[PROVENANCE.json](ThirdPartyNotices/PROVENANCE.json).

| Component | Version | License / notice | Linked / bundled |
|-----------|---------|------------------|------------------|
| [Sparkle](https://github.com/sparkle-project/Sparkle) | 2.9.6 | [Full upstream notice](ThirdPartyNotices/Sparkle-LICENSE): MIT and bundled external licenses | App update framework; linked by MacCrabApp only |
| [SQLCipher](https://github.com/sqlcipher/sqlcipher) | 4.18.0 | [BSD-3-Clause](ThirdPartyNotices/SQLCipher-LICENSE.md); [amalgamation notice](ThirdPartyNotices/SQLCipher-source-notice.txt) | Vendored CSQLCipher target linked by the app, engine, CLI, and MCP server |
| [SQLite](https://sqlite.org/) | 3.53.4, within SQLCipher | [Public-domain notice](ThirdPartyNotices/SQLite-NOTICE.txt) | SQLCipher's bundled SQLite baseline |
| [PyYAML](https://github.com/yaml/pyyaml) | 6.0.3 | [MIT](ThirdPartyNotices/PyYAML-LICENSE) | Pure-Python modules bundled with the in-app rule compiler |
| [Swift Testing](https://github.com/swiftlang/swift-testing) | Supplied by the qualified Swift toolchain | Apache-2.0 with Runtime Library Exception | Test targets only; not shipped |
| [SwiftSyntax](https://github.com/swiftlang/swift-syntax) | Supplied within the toolchain macro implementation | Apache-2.0 with Runtime Library Exception | Build tooling; no independent SwiftPM dependency or shipped library |

SwiftPM pins are recorded in [Package.resolved](Package.resolved). SQLCipher
source provenance is recorded in [Sources/CSQLCipher/PROVENANCE](Sources/CSQLCipher/PROVENANCE).
PyYAML and release-tool hashes are recorded in
[scripts/release-dependencies.lock](scripts/release-dependencies.lock) and
[scripts/release-pyyaml.sha256](scripts/release-pyyaml.sha256).

Release assembly copies this index, MacCrab's license, and `ThirdPartyNotices/`
into `MacCrab.app/Contents/Resources/` before code signing, and also includes
them at the DMG root. Sparkle's full license is retained here even when its
framework packaging layout changes.

## Swift Testing and SwiftSyntax build tooling

Tests import the `Testing` module included with the selected Swift toolchain;
MacCrab does not resolve separate swift-testing or swift-syntax source packages.
The compiler version and build identity in [scripts/swift-toolchain.json](scripts/swift-toolchain.json)
identify the testing toolchain used for qualification. These tools are not bundled
in MacCrab releases.

Both upstream projects are copyright the Swift project authors and licensed
under Apache-2.0 with the Runtime Library Exception. Their full notices are
available in the [Swift Testing license](https://github.com/swiftlang/swift-testing/blob/main/LICENSE.txt)
and [SwiftSyntax license](https://github.com/swiftlang/swift-syntax/blob/main/LICENSE.txt).

---

## Detection Rules

The detection rules in `Rules/` are **not** covered by MacCrab's Apache-2.0
license. They are licensed under the **Detection Rule License 1.1 (DRL 1.1)**.
See `Rules/README.md` and
<https://github.com/SigmaHQ/Detection-Rule-License> for the full terms.
