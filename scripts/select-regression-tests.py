#!/usr/bin/env python3
"""Report changed-file/reference test candidates; never execute or certify safety.

This intentionally overselects. A reviewer must classify every candidate as
safe locally or requiring isolation. Neither this search nor targeted tests
replace the unfiltered clean suite. Runtime/transitive dependencies can escape
textual search; retain the changed-file inventory for independent review.
"""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess


def discover(root, changed):
    references = {}
    for relative in sorted(set(changed)):
        path = root / relative
        needles = {relative, path.name, path.stem}
        if path.is_file() and path.suffix == ".swift":
            # Named production types catch call sites that don't spell paths.
            # Short generic types (State/View/etc.) are too noisy to help.
            needles.update(name for name in re.findall(
                r"\b(?:struct|class|enum|actor|protocol)\s+(\w+)", path.read_text())
                if len(name) >= 8)
        references[relative] = needles
    # Compile once rather than overflowing re's small global cache for every
    # (test × changed-file × needle) combination. The lookahead permits
    # overlapping full-path/basename/type references. At one position the
    # longest alternative wins; expand its boundary-valid prefixes so shorter
    # needles still contribute all of their original change/reason mappings.
    owners = {}
    for relative, needles in references.items():
        for needle in needles:
            owners.setdefault(needle, set()).add(relative)
    prefixes = {}
    for needle in owners:
        prefixes[needle] = [needle[:end] for end in range(1, len(needle) + 1)
                           if needle[:end] in owners and
                           (end == len(needle) or not re.match(r'[A-Za-z0-9_]', needle[end]))]
    pattern = re.compile(r'(?<![A-Za-z0-9_])(?=(' + '|'.join(
        re.escape(needle) for needle in sorted(owners, key=lambda item: (-len(item), item))
    ) + r')(?![A-Za-z0-9_]))') if owners else None
    files = set((root / "Tests").rglob("*.swift"))
    files.update((root / "scripts").glob("test-*"))
    candidates = []
    for path in sorted(files):
        if not path.is_file():
            continue
        relative = str(path.relative_to(root))
        source = path.read_text(errors="replace")
        hits_by_change = {}
        if pattern:
            hits = {prefix for match in pattern.finditer(source) for prefix in prefixes[match[1]]}
            for needle in hits:
                for owner in owners[needle]:
                    hits_by_change.setdefault(owner, set()).add(needle)
        reasons = []
        for changed_path, needles in references.items():
            if relative == changed_path:
                reasons.append({"changed": changed_path, "kind": "changed-test"})
            else:
                hits = sorted(hits_by_change.get(changed_path, ()))
                if hits:
                    reasons.append({"changed": changed_path, "kind": "reference", "matches": hits})
        if reasons:
            candidates.append({"path": relative, "reasons": reasons, "execution": "unreviewed"})
    return {"schema_version": 1, "scope": "advisory changed-file/reference selection, not full CI",
            "changed_files": sorted(set(changed)), "candidates": candidates}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, default=Path.cwd())
    parser.add_argument("--base", required=True)
    args = parser.parse_args()
    root = args.source_root.resolve()
    environment = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    environment["GIT_NO_REPLACE_OBJECTS"] = "1"
    def git(*arguments):
        return subprocess.run(["/usr/bin/git", "-C", str(root), *arguments],
                              env=environment, check=True, capture_output=True, timeout=30).stdout
    # Resolve untrusted revision spelling once, without treating it as flags.
    # All later selection uses the immutable object identity.
    base = git("rev-parse", "--verify", "--end-of-options", args.base + "^{commit}").decode().strip()
    changed = git("diff", "--name-only", "-z", base, "--").split(b"\0")
    changed += git("ls-files", "--others", "--exclude-standard", "-z").split(b"\0")
    manifest = discover(root, [name.decode() for name in changed if name])
    manifest["base"] = base
    manifest["head"] = git("rev-parse", "--verify", "HEAD").decode().strip()
    print(json.dumps(manifest, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
