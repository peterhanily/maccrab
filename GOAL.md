# GOAL.md — Execution Companion

This file tells agents (and future-Peter) **how** to execute the forward plan. The plan at `plans/2026-05-19-plugin-platform-plan.md` says **what** to build. This says how, operationally.

## §1 — Authoritative Plan

`plans/2026-05-19-plugin-platform-plan.md` (2026-05-19). It supersedes every other planning artifact in `plans/` for forward execution. Earlier files there describe shipped work and historical context — read for background, not direction.

`plans/` is intentionally gitignored (`.gitignore` line 187). Planning artifacts live on the maintainer's machine and are not part of the public repo. GOAL.md is the public-facing summary of execution mechanics; the underlying plans stay local.

Codenames retired. Versions only.

## §2 — Four Committed Releases

| Release | Scope | Window |
|---|---|---|
| **v1.13a** | Mac Context Platform Substrate (CLI-only). Plugin runtime + encrypted ArtifactStore + TCC-lite + launchd-lite + codesign-resolve + audit Passes 2026-A/B/C/D. | 3-6 months |
| **v1.13b** | Operator surface. Dashboard Forensics tab + Touch ID + scheduled-run consent UX. | 1-3 months after v1.13a |
| **v1.14** | MCFP R0 (dyld paradox) + R1 (static spec + reference). | 2-4 months |
| **v1.15** | MCFP R2 + composition-proof posture Analyzer + conditional MCFP plugin. | 2-4 months after v1.14 |

Past v1.15 is uncommitted. The explicit v1.16 candidate (only if Track 2 continues) is `com.maccrab.forensics.applescript-runtime` — plan §13.5.

**Until the full v1.13a → v1.15 arc lands, every release is an RC.** No Sparkle appcast publication. No Homebrew cask bump. RCs install via direct DMG only.

## §3 — v1.13a Sub-Slice Order

v1.13a is built as five internal slices. Cumulative; nothing skips.

1. **v1.13a-1** — Local store + CLI skeleton. SPM target, encrypted ArtifactStore, plugin manifest registry, fixture plugin. Pass 2026-A + 2026-B.
2. **v1.13a-2** — codesign-resolve enricher (`SecRequirement` / `SecStaticCode`). Wired into Track 1's event pipeline so existing Sigma rules can match on `codesign.signing_status` and `codesign.team_id`. Pass 2026-C.
3. **v1.13a-3** — TCC-lite collector. Snapshot TCC.db before parse. Risk-score table per plan §4.1.
4. **v1.13a-4** — launchd-lite collector. BAM snapshot. codesign-resolve auto-enriches `program_path`.
5. **v1.13a-5** — Audit hardening + release gate. Pass 2026-D. Plaintext-rejects-non-metadata at INSERT.

Each slice is internally self-contained. v1.13a ships as one release once slice 5 passes.

## §4 — Branching

| Release | Branch |
|---|---|
| v1.13a | `release/v1.13a` |
| v1.13b | `release/v1.13b` (off v1.13a merge into main) |
| v1.14 | `release/v1.14` |
| v1.15 | `release/v1.15` |
| Tactical patch | `release/v1.X-rcN-fix` |

Branch from latest `main`. Squash-merge to `main` when release ships. Tag the merge commit (`v1.13.0`, `v1.13.0-rc.1`, etc.).

## §5 — Commit Conventions

Conventional Commits: `<type>(<scope>): <subject>`.

| Type | When |
|---|---|
| `feat` | New feature |
| `fix` | Bug fix |
| `test` | Tests only |
| `docs` | Docs only |
| `refactor` | No feature, no fix |
| `perf` | Performance |
| `build` | SPM / signing / notarization |
| `audit` | Pre-release-audit script changes |
| `chore` | Release-tagging, build/cask cleanups |

Scopes match SPM target directory names: `maccrab-core`, `maccrab-agent-kit`, `maccrab-agent`, `maccrabd`, `maccrabctl`, `maccrab-mcp`, `maccrab-app`, `maccrab-forensics` (new), `csqlcipher` (new), `rules`, `scripts`, `docs`, `plans`, `site` (separate repo).

## §6 — Version Numbering

Public-facing version strings carry SemVer pre-release suffix until v1.13a→v1.15 GA.

| Identifier | Until GA | At GA |
|---|---|---|
| `release.json` `version` | `1.13.0-rc.N` | `1.13.0` |
| `MacCrabVersion.swift` `current` | `1.13.0-rc.N` | `1.13.0` |
| `CFBundleShortVersionString` | `1.13.0` (3 numbers only — Apple constraint) | `1.13.0` |
| `CFBundleVersion` | `1.13.0.<N>` (RC counter as build number) | `1.13.0.<final>` |
| Git tag | `v1.13.0-rc.N` | `v1.13.0` |

Sparkle appcast and Homebrew cask are NOT updated during the RC run. The Sparkle public channel stays on v1.12.9 until v1.13.0 ships as a non-RC.

## §7 — Audit Passes

Year-prefix scheme. New passes from this plan:

| Pass | Invariant | Added in |
|---|---|---|
| **2026-A** | Plugin manifest integrity: unique id; declared TCC requirements match `Info.plist`; `outputs[].contentType` namespace matches plugin id; `com.maccrab.*` reserved for first-party; every output declares `privacyClass`. | v1.13a-1 |
| **2026-B** | Single ArtifactStore writer: no code outside `Sources/MacCrabForensics/Storage/ArtifactStore.swift` INSERTs into `artifacts` / `artifact_data` / `plugin_invocations`. | v1.13a-1 |
| **2026-C** | Enricher idempotency: every Enricher's `enrich` is byte-identical across re-runs on `(subject, stage)` pairs. | v1.13a-2 |
| **2026-D** | privacy_class consistency: every artifact's `privacy_class` matches manifest declaration; plaintext cases reject `content` / `personalComms` / `credentialAdjacent` / `secret` artifacts at INSERT time. | v1.13a-5 |

Year-prefix avoids collision with the pre-existing v1.12.5 `Pass A` / `B` / `C` / `D` letter-only names — those keep their numbering. Future passes use `<year>-<letter>`.

Pass changes never ship in the same PR as the release that needs them — per the v1.6.19 precedent. Add the Pass in a docs-style PR first; let it pass for one release; then add the change that uses it.

(For v1.13a-1: Pass 2026-A + 2026-B can ship in the same PR as the foundational substrate because there is no prior release for them to retroactively gate. Documented exception.)

## §8 — RC Ship Checklist

When a sub-slice is ready to tag:

1. ✅ `swift test` green
2. ✅ `swift build -c release` green for every target
3. ✅ `scripts/prerelease-check.sh` clean (version parity across release.json / Info.plist / MacCrabVersion.swift / cask file)
4. ✅ `scripts/pre-release-audit.sh` clean (every existing Pass + every 2026-X Pass introduced by sub-slices already shipped)
5. ✅ `RELEASE_NOTES/v1.13.0-rc.N.md` written
6. ✅ `release.json` bumped to `1.13.0-rc.N`
7. ✅ Commit on `release/v1.13a`: `chore(release): v1.13.0-rc.N — <one-line sub-slice description>`
8. ✅ Tag: `git tag v1.13.0-rc.N -m "v1.13a-X.Y substrate skeleton"` then `git push origin v1.13.0-rc.N`
9. ✅ Build artifact via `make release` produces signed + notarized + stapled DMG
10. ❌ **Sparkle appcast.xml** — not updated for RCs
11. ❌ **Homebrew `homebrew/maccrab.rb` + `Casks/maccrab.rb`** — not updated for RCs
12. ✅ `wiki log "Tagged v1.13.0-rc.N — <sub-slice>"`

## §9 — Failure Modes

- **A coverage gate fails**: add fixtures until it passes. Do not lower the threshold.
- **A 2026-X Pass fails**: fix the underlying invariant. Do not disable the Pass.
- **A pre-existing Pass fails**: same — investigate before working around. The Pass exists because something bit MacCrab before.
- **A sub-slice produces a kill-criterion result** (per plan §7 per-release kill criterion): stop, write up the result, escalate to user. Do not silently proceed.

## §10 — Where to Find What

| Question | Where |
|---|---|
| What does v1.13a actually do? | `plans/2026-05-19-plugin-platform-plan.md` §4-§5 + §7 v1.13a card |
| What's the privacy model? | Plan §10 |
| What's the MCFP research arc? | Plan §6 |
| What are the audit Pass invariants? | This file §7 + plan §3.8 |
| What's the current RC number? | `release.json` `version` |
| What's the next sub-slice? | Task list (`/task list` or `TaskList`) |
| What did the prior plan say? | `plans/2026-04-15-maccrab-v2-roadmap.md` and earlier files in `plans/` are historical, not active |

## §11 — Three Operational Reminders

1. **RCs do not publish.** `appcast.xml`, `homebrew/maccrab.rb`, `Casks/maccrab.rb` are GA-only artifacts until v1.13.0 ships non-RC.
2. **Don't `pkill` MacCrab's own daemons** when adding a signal-based reload (SIGHUP / SIGUSR1 / SIGUSR2) — exclude maccrab daemons from `security_tool_killed` and similar rules. v1.6.18 lesson.
3. **Track 1 stays load-bearing.** Anything in Track 2 that breaks Track 1 is reverted immediately. Plan §14.6.

---

End of GOAL.md.
