#!/bin/bash
# Copy only hash-locked PyYAML source into a private release staging tree.
# The source is never imported; the copy is verified before another process can
# import it. An exact source path may be supplied for an offline build, but its
# bytes still have to match the checked manifest.

set -euo pipefail
umask 077

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DEST="${1:-}"
MANIFEST="$SCRIPT_DIR/release-pyyaml.sha256"

fail() { echo "ERROR: prepare PyYAML: $*" >&2; exit 1; }
[[ -n "$DEST" && "$DEST" == /* && "$DEST" != "/" ]] || fail "destination must be an absolute, non-root path"
if [[ -e "$DEST" ]]; then
    [[ -d "$DEST" && ! -L "$DEST" ]] || fail "destination exists but is not a real directory"
    [[ -z "$(/usr/bin/find "$DEST" -mindepth 1 -maxdepth 1 -print -quit)" ]] || fail "destination must be empty"
else
    /bin/mkdir -p "$DEST"
fi

if [[ -n "${MACCRAB_PYYAML_SOURCE_DIR:-}" ]]; then
    SOURCE="$MACCRAB_PYYAML_SOURCE_DIR"
else
    user_site=$(/usr/bin/env -i PATH=/usr/bin:/bin HOME="${HOME:?}" LC_ALL=C \
        /usr/bin/python3 -I -c 'import site; print(site.getusersitepackages())')
    SOURCE="$user_site/yaml"
fi
[[ -d "$SOURCE" && ! -L "$SOURCE" ]] || fail "PyYAML 6.0.3 source directory not found: $SOURCE"

/bin/mkdir "$DEST/yaml"
while read -r digest relative; do
    [[ -z "$digest" || "$digest" == \#* ]] && continue
    name="${relative#yaml/}"
    src="$SOURCE/$name"
    [[ -f "$src" && ! -L "$src" ]] || fail "source file missing or linked: $src"
    /bin/cp "$src" "$DEST/$relative"
    /bin/chmod 0644 "$DEST/$relative"
done < "$MANIFEST"
/bin/chmod 0755 "$DEST" "$DEST/yaml"

"$SCRIPT_DIR/check-release-pyyaml.sh" "$DEST" >/dev/null
echo "$DEST"
