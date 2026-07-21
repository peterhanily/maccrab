# Release Notes

One curated Markdown file per release, named `v<VERSION>.md` (e.g. `v1.21.4.md`).

These files are the single authoritative source for user-facing release notes:

- **GitHub release** — `scripts/release.sh` Step 5 passes
  `--notes-file RELEASE_NOTES/v<VERSION>.md` to `gh release create` (it falls
  back to GitHub auto-generated notes with a warning if the file is missing).
- **Sparkle update sheet** — `scripts/generate-appcast-entry.sh` prefers this
  file (converted Markdown → HTML) over its CHANGELOG.md fallback.
- **Pre-release gate** — `scripts/prerelease-check.sh` requires the file to
  exist and not be a stub for GA releases (warns only for RCs).

Write the file *before* running `scripts/release.sh`. Style: brief and
professional — what changed and what's new (see the recent `v1.21.x` files
for the format). `CHANGELOG.md` at the repo root carries the dense dated
history; these files carry the polished per-release summary.

The repo-root `RELEASE_NOTES.md` was removed in v1.21.5 — it was a stale
single-version snapshot that no tooling read.
