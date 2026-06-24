# Third-Party Licenses

MacCrab is licensed under the Apache License 2.0 (see [LICENSE](LICENSE)). It
bundles and links the third-party components listed below. This file provides
the attribution and license notices required by those components.

The pinned versions are recorded in [`Package.resolved`](Package.resolved).

| Component | Version | License | Linked / Bundled |
|-----------|---------|---------|------------------|
| [Sparkle](https://github.com/sparkle-project/Sparkle) | 2.9.2 | MIT (with bundled external licenses) | Bundled in `MacCrab.app` only (auto-update framework) |
| [swift-testing](https://github.com/swiftlang/swift-testing) | 6.2.4 | Apache-2.0 | Test target only — not shipped in release builds |
| [swift-syntax](https://github.com/swiftlang/swift-syntax) | 602.0.0 | Apache-2.0 | Transitive dependency of swift-testing (test only) — not shipped |

Notes:

- **Sparkle** is the only third-party component bundled into the shipped
  application. It is linked by the `MacCrabApp` target only; the System
  Extension (`com.maccrab.agent.systemextension`) and the CLI/daemon targets do
  not link it.
- **swift-testing** and its transitive dependency **swift-syntax** are pulled in
  only by the unit-test targets and are not present in release artifacts.

---

## Sparkle

Sparkle 2 is distributed under the MIT License. Sparkle additionally bundles a
small number of files under their own permissive licenses (bsdiff/BSD-2-Clause,
sais-lite/MIT, a portable Ed25519 implementation/zlib, and SUSignatureVerifier/
BSD-2-Clause). The full upstream notice is reproduced below.

```
Copyright (c) 2006-2013 Andy Matuschak.
Copyright (c) 2009-2013 Elgato Systems GmbH.
Copyright (c) 2011-2014 Kornel Lesiński.
Copyright (c) 2015-2017 Mayur Pawashe.
Copyright (c) 2014 C.W. Betts.
Copyright (c) 2014 Petroules Corporation.
Copyright (c) 2014 Big Nerd Ranch.
All rights reserved.

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
```

Sparkle's external/bundled-file licenses (bsdiff, sais-lite, Ed25519,
SUSignatureVerifier) are listed in full in the `LICENSE` file shipped inside the
Sparkle distribution.

---

## swift-testing

Copyright the Swift project authors. Licensed under the Apache License,
Version 2.0. The full license text is identical to MacCrab's [LICENSE](LICENSE)
(Apache-2.0). Used by the unit-test targets only; not distributed in release
builds. See <https://github.com/swiftlang/swift-testing/blob/main/LICENSE.txt>.

---

## swift-syntax

Copyright the Swift project authors. Licensed under the Apache License,
Version 2.0. The full license text is identical to MacCrab's [LICENSE](LICENSE)
(Apache-2.0). Transitive dependency of swift-testing (test targets only); not
distributed in release builds. See
<https://github.com/swiftlang/swift-syntax/blob/main/LICENSE.txt>.

---

## Detection Rules

The detection rules in `Rules/` are **not** covered by MacCrab's Apache-2.0
license. They are licensed under the **Detection Rule License 1.1 (DRL 1.1)**.
See `Rules/README.md` and
<https://github.com/SigmaHQ/Detection-Rule-License> for the full terms.
