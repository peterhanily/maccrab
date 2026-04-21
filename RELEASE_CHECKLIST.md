# Release checklist

Pre-flight checks that MUST pass before cutting any MacCrab release. Most
are automated by `scripts/prerelease-check.sh`, which `scripts/release.sh`
runs before touching any signing key. Anything marked **manual** still
needs a human pass.

## Version sync

- [ ] `Xcode/project.yml` `CFBundleVersion` + `CFBundleShortVersionString`
      match the release version for both MacCrabApp and MacCrabAgent entries.
- [ ] `Xcode/Resources/MacCrabApp-Info.plist` matches.
- [ ] `Xcode/Resources/MacCrabAgent-Info.plist` matches.
- [ ] `README.md` version badge matches.
- [ ] `CHANGELOG.md` has a dated section for the version.
- [ ] `RELEASE_NOTES/v{VERSION}.md` exists and has at least 10 lines of
      user-facing (not developer-facing) content.

## Site sync — manual if site repo not present

- [ ] `maccrab-site/index.html` `softwareVersion` schema.org field.
- [ ] `maccrab-site/index.html` hero pill version.
- [ ] `maccrab-site/index.html` terminal demo version string.
- [ ] `maccrab-site/index.html` "What ships in vX.Y.Z" heading.
- [ ] `maccrab-site/index.html` `dateModified` schema.org field.

## Stats sync

- [ ] `README.md` tests badge matches actual test count (`swift test` row
      count). Off-by-a-few is fine; off by 30+ is stale.
- [ ] `README.md` rules badge matches `find Rules -name "*.yml" | wc -l`.
- [ ] Same two stats in `maccrab-site/index.html` stats tiles.

## Localization coverage

- [ ] `en.lproj/Localizable.strings` has a key for every `String(localized:
      "key", defaultValue: "English")` call in `Sources/MacCrabApp/`.
- [ ] Each non-English locale has at least 50% of the English keys
      translated. Below 50%, flag in release notes.
- [ ] New user-visible strings introduced in this release have default
      values in code AND entries in `en.lproj`. Missing translations in
      other locales fall back to English — that's fine — but missing
      English entries surface as the raw key at runtime.

## Rules

- [ ] `python3 Compiler/compile_rules.py --input-dir Rules/ --output-dir
      .build/compiled_rules` succeeds with 0 rules skipped.
- [ ] Every `status: experimental` or `status: stable` rule ships
      `enabled: true`; every `status: deprecated` ships `enabled: false`.

## Testing

- [ ] `swift test` passes (0 failures).
- [ ] Field regression tests for recent FP classes still pass
      (`CrossProcessCorrelatorTests`, `FPRegressionTests`).
- [ ] `make lint-rules` passes.

## Security / supply chain

- [ ] `Package.resolved` committed and matches `swift package resolve`
      output.
- [ ] Sparkle dependency still pinned exact (`.exact(...)`), not `from:`.
- [ ] No uncommitted changes in `~/.maccrab.env` paths baked
      into scripts.
- [ ] `.gitignore` still excludes signing keys, PATs, and notary creds.

## Release artifacts — manual

- [ ] DMG is signed (`codesign -dv` shows Developer ID).
- [ ] DMG is notarized AND stapled (`spctl -a -v` accepts the .app on
      an offline machine).
- [ ] `generate-appcast-entry.sh` produced a valid ed25519 signature.
- [ ] Cask sha256 matches the DMG's actual shasum.

## Post-release — manual

- [ ] Tag + GitHub release published.
- [ ] Appcast entry published, Cloudflare Pages redeployed, `curl
      https://maccrab.com/appcast.xml` shows the new entry.
- [ ] `brew update && brew info --cask maccrab` reports the new version.
- [ ] Smoke test: install from brew on a fresh user, click Enable
      Protection, confirm sysext activates and dashboard shows events.

## When something fails

Pre-release check failures block the release pipeline — fix the issue,
re-run the check, then proceed. `release.sh` exits non-zero if the check
fails, so no CI-based release can sneak past a broken checklist.
