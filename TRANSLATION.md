# MacCrab Translation Guide

*Created v1.18.1. One entry point for human reviewers and translation
agents — this consolidates policy that previously lived in scattered code
comments. The source of truth is `Sources/MacCrabApp/Resources/<locale>.lproj/Localizable.strings`
(14 locales, classic `.strings` — do NOT migrate to `.xcstrings`: plain
`swift build` ships catalogs inert).*

## Hard rules

1. **Detection content stays English.** Sigma rule titles/IDs, MITRE
   technique names, and rule YAML are the international SOC vocabulary;
   only the UI layer translates (display-layer mapping lives in
   `RuleTranslations.swift` via `mitre.*` / `category.*` keys).
2. **Never delete keys.** The `severity.*` key family is looked up with
   runtime-built keys (`ViewModels.swift` —
   `Bundle.main.localizedString(forKey: "severity.\(rawValue)")`) and is
   invisible to extraction tooling. A key that looks unused may not be.
3. **Preserve format specifiers exactly** — same count, same types, same
   order: `%@` (text), `%lld` (numbers). If grammar demands reordering,
   use positional forms (`%1$@`, `%2$lld`) — never drop or retype one.
4. **Preserve `\n`, `\"` escapes and trailing punctuation.**
5. **Keep region casing in directory names**: `zh-Hans.lproj`,
   `pt-BR.lproj` (SPM lowercases them in Bundle.module; the build copies
   from the source tree and asserts the casing).

## Do not translate (product + trade names)

MacCrab · TraceGraph · AI Guard · Sparkle · Homebrew · Ollama · MITRE ·
ATT&CK · Sigma · YARA · XProtect · Gatekeeper · TCC (expand on first use
if the language convention prefers) · DNS · MCP · CVE IDs · file paths ·
URLs · CLI commands (anything in backticks or starting `maccrabctl`).

## Security-term glossary (translate consistently)

| English | Guidance |
|---|---|
| alert | the noun a SOC uses for a triaged finding — not "warning" |
| event | telemetry record, neutral |
| campaign | coordinated attack campaign (military/security register) |
| rule / detection | detection rule |
| suppress / unsuppress | hide-as-noise (reversible) — distinct from delete |
| quarantine | the macOS file-quarantine mechanism, use the OS's own term |
| sinkhole (DNS) | use the established networking term for the locale |
| severity: critical/high/medium/low/informational | match the locale's established CVSS/SOC ladder |
| persistence | ATT&CK sense — attacker foothold across reboots |
| lateral movement | ATT&CK sense |
| kill chain | established term; transliterate if that's the norm |
| false positive | established QA/security term |
| trace | TraceGraph causal trace (noun) — keep consistent with TraceGraph branding |

## Tone

Professional, terse, operator-facing. Match the system language of macOS
itself (e.g. German Sie-form, Japanese です/ます). Headers and buttons are
short — prefer the established platform word over a literal translation.
Plural handling: every locale ships a `Localizable.stringsdict` with the
same plural keys as `en`, and each of those keys keeps a `.strings` row as
its fallback. Give each key exactly the plural categories its locale uses
(`scripts/check-localizations.py` lists them, e.g. only `other` for ja, ko
and Chinese, `one`/`few`/`many`/`other` for pl and ru) and keep its format
specifiers. Do not invent plural syntax in `.strings` values.

## Provenance / review state

`translation-state.json` (repo root) records a per-key,
per-locale state: `legacy` (pre-v1.18.1, unaudited), `machine-translated`
(agent fill, awaiting native review), `reviewed` (human-confirmed),
`source-english` (intentionally untranslated). It has not been updated
since it was created in v1.18.1, so most current keys are missing from it
and no entry is `reviewed` yet; treat a key it does not list as unreviewed.
Record a key as `reviewed` when a native speaker confirms it.
The prerelease gate (`prerelease-check.sh` section 4) measures real value
divergence; machine fills must keep it honest, not game it.
