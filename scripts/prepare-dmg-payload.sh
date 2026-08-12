#!/bin/bash
# Prepare the final, user-facing DMG payload after MacCrab.app has been signed.
#
# The unsigned/reproducible build handoff intentionally contains loose bin/ and
# compiled_rules/ trees.  Once the signed app has absorbed those inputs they are
# duplicate release payload: Homebrew/manual installs consume the in-app tools,
# while the sysext consumes its own sealed rule copy at boot. Validate that
# handoff before pruning it, then normalize modes so a sudo install does not
# turn owner-only HFS files into a root-only application.

set -euo pipefail

fail() {
    echo "ERROR: $*" >&2
    exit 1
}

# A signed bundle legitimately contains framework symlinks.  Their mode is not
# part of the code-signature byte seal, and an umask-077 build can leave them
# owner-only even after every regular file and directory has been normalized.
# Operate on link objects only: BSD find's explicit -P refuses directory-link
# traversal and chmod -h refuses to apply the mode to an arbitrary link target.
normalize_payload_symlink_modes_no_follow() {
    local root="$1"
    /usr/bin/find -P "$root" -type l -exec /bin/chmod -h 0755 {} + \
        || fail "could not normalize payload symbolic-link modes"
    if /usr/bin/find -P "$root" -type l ! -perm 0755 -print -quit \
            | /usr/bin/grep . >/dev/null; then
        fail "payload retains a symbolic link with an unsafe mode"
    fi
}

# Keep the release-time corpus gate behaviorally aligned with the root System
# Extension verifier.  Byte equality between the app and sysext is insufficient:
# two identically malformed trees would otherwise pass packaging and make the
# engine fail closed on first boot.  Use only Apple's fixed interpreter in
# isolated mode; the validator needs no third-party modules or ambient Python
# configuration.
validate_compiled_rule_corpus() {
    local corpus="$1"
    /usr/bin/env -i \
        PATH=/usr/bin:/bin \
        TMPDIR=/tmp \
        LC_ALL=C \
        LANG=C \
        PYTHONDONTWRITEBYTECODE=1 \
        /usr/bin/python3 -I -B - "$corpus" <<'PY'
import hashlib
import json
import os
import stat
import sys


def reject(message):
    print(f"ERROR: invalid compiled-rule corpus: {message}", file=sys.stderr)
    raise SystemExit(1)


def strict_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            reject(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


root = sys.argv[1]
# Keep this mask byte-for-byte equivalent to BundledRuleSynchronizer's
# unsafeBSDFlags: UF_IMMUTABLE, UF_APPEND, UF_DATAVAULT, SF_IMMUTABLE,
# SF_APPEND, SF_NOUNLINK and SF_DATALESS.  Some of the latter flags do not
# have portable chflags(1) spellings, so metadata normalization below clears
# the common four and the post-check rejects any unsafe remainder.
unsafe_bsd_flags = (
    0x00000002
    | 0x00000004
    | 0x00000080
    | 0x00020000
    | 0x00040000
    | 0x00100000
    | 0x40000000
)
try:
    root_stat = os.lstat(root)
except OSError as error:
    reject(f"cannot stat {root!r}: {error}")
if not stat.S_ISDIR(root_stat.st_mode):
    reject(f"root is not a real directory: {root!r}")
if getattr(root_stat, "st_flags", 0) & unsafe_bsd_flags:
    reject(f"root carries immutable/append-only flags: {root!r}")

files = set()
directories = set()
regular_file_bytes = 0
maximum_entries = 4096
maximum_file_bytes = 16 * 1024 * 1024
maximum_aggregate_bytes = 64 * 1024 * 1024
maximum_depth = 32


def inventory(directory, relative_directory="", depth=0):
    global regular_file_bytes
    try:
        entries = sorted(os.scandir(directory), key=lambda entry: entry.name)
    except OSError as error:
        reject(f"cannot enumerate {directory!r}: {error}")
    for entry in entries:
        relative = (
            entry.name
            if not relative_directory
            else f"{relative_directory}/{entry.name}"
        )
        if depth + 1 > maximum_depth:
            reject(f"rule tree exceeds depth {maximum_depth}: {relative!r}")
        try:
            metadata = entry.stat(follow_symlinks=False)
        except OSError as error:
            reject(f"cannot stat {relative!r}: {error}")
        if getattr(metadata, "st_flags", 0) & unsafe_bsd_flags:
            reject(f"immutable/append-only entry refused: {relative!r}")
        if stat.S_ISDIR(metadata.st_mode):
            directories.add(relative)
            if len(files) + len(directories) > maximum_entries:
                reject(f"rule tree exceeds {maximum_entries} entries")
            inventory(entry.path, relative, depth + 1)
        elif stat.S_ISREG(metadata.st_mode):
            if metadata.st_nlink != 1:
                reject(f"hard-linked file refused: {relative!r}")
            if metadata.st_size > maximum_file_bytes:
                reject(f"rule file exceeds {maximum_file_bytes} bytes: {relative!r}")
            regular_file_bytes += metadata.st_size
            if regular_file_bytes > maximum_aggregate_bytes:
                reject(f"rule tree exceeds {maximum_aggregate_bytes} bytes")
            files.add(relative)
            if len(files) + len(directories) > maximum_entries:
                reject(f"rule tree exceeds {maximum_entries} entries")
        else:
            reject(f"symlink or special entry refused: {relative!r}")


inventory(root)
manifest_name = "manifest.json"
version_name = ".bundle_version"
for required in (manifest_name, version_name):
    if required not in files:
        reject(f"missing regular metadata file {required!r}")

manifest_path = os.path.join(root, manifest_name)
version_path = os.path.join(root, version_name)
try:
    if os.path.getsize(manifest_path) > 2 * 1024 * 1024:
        reject("manifest exceeds 2 MiB")
    if os.path.getsize(version_path) > 4 * 1024:
        reject("version marker exceeds 4 KiB")
    with open(manifest_path, "rb") as handle:
        manifest_bytes = handle.read()
    with open(version_path, "rb") as handle:
        version_bytes = handle.read()
except OSError as error:
    reject(f"cannot read corpus metadata: {error}")

try:
    manifest = json.loads(manifest_bytes, object_pairs_hook=strict_object)
except (UnicodeDecodeError, json.JSONDecodeError) as error:
    reject(f"manifest is not strict UTF-8 JSON: {error}")
if not isinstance(manifest, dict):
    reject("manifest root must be an object")
required_keys = {"schema_version", "bundle_version", "hashes"}
if set(manifest) != required_keys:
    reject(
        "manifest keys disagree "
        f"(missing={sorted(required_keys - set(manifest))}, "
        f"extra={sorted(set(manifest) - required_keys)})"
    )
if type(manifest["schema_version"]) is not int or manifest["schema_version"] != 1:
    reject("schema_version must be the integer 1")
if not isinstance(manifest["bundle_version"], str) or not manifest["bundle_version"]:
    reject("bundle_version must be a non-empty string")
if not isinstance(manifest["hashes"], dict) or not manifest["hashes"]:
    reject("hashes must be a non-empty object")

try:
    marker_version = version_bytes.decode("utf-8").strip()
except UnicodeDecodeError as error:
    reject(f"version marker is not UTF-8: {error}")
if not marker_version or marker_version != manifest["bundle_version"]:
    reject("bundle version marker and manifest disagree")

expected_files = {manifest_name, version_name}
expected_directories = set()
for relative, expected_hash in sorted(manifest["hashes"].items()):
    if not isinstance(relative, str):
        reject("manifest paths must be strings")
    try:
        encoded_length = len(relative.encode("utf-8"))
    except UnicodeEncodeError as error:
        reject(f"manifest path is not UTF-8 encodable: {error}")
    components = relative.split("/")
    if (
        not relative
        or encoded_length > 1024
        or relative.startswith("/")
        or "\\" in relative
        or not relative.endswith(".json")
        or any(component in ("", ".", "..") for component in components)
        or components[0] in ("auto_generated", "pushed")
    ):
        reject(f"unsafe manifest path {relative!r}")
    if (
        not isinstance(expected_hash, str)
        or len(expected_hash) != 64
        or any(character not in "0123456789abcdef" for character in expected_hash)
    ):
        reject(f"invalid SHA-256 for {relative!r}")
    if relative in expected_files:
        reject(f"duplicate or reserved manifest path {relative!r}")
    expected_files.add(relative)
    for index in range(1, len(components)):
        expected_directories.add("/".join(components[:index]))

if files != expected_files:
    reject(
        "manifest file set mismatch "
        f"(missing={sorted(expected_files - files)[:3]}, "
        f"extra={sorted(files - expected_files)[:3]})"
    )
if directories != expected_directories:
    reject(
        "manifest directory set mismatch "
        f"(missing={sorted(expected_directories - directories)[:3]}, "
        f"extra={sorted(directories - expected_directories)[:3]})"
    )

for relative, expected_hash in sorted(manifest["hashes"].items()):
    digest = hashlib.sha256()
    path = os.path.join(root, *relative.split("/"))
    try:
        if os.path.getsize(path) > maximum_file_bytes:
            reject(f"rule exceeds {maximum_file_bytes} bytes: {relative!r}")
        with open(path, "rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as error:
        reject(f"cannot hash {relative!r}: {error}")
    if digest.hexdigest() != expected_hash:
        reject(f"hash mismatch for {relative!r}")
PY
}

normalize_payload_security_metadata() {
    local root="$1"
    # ACLs and immutable/append-only flags are not runtime content, but ditto
    # preserves them. A metadata-tainted signed rule tree would consequently
    # pass byte hashes and then fail closed in the sysext's descriptor checks.
    # Clear the seven runtime-refused BSD flags, strip extended ACLs from regular
    # files/directories without following bundle symlinks, and prove both took.
    /usr/bin/find "$root" \( -type d -o -type f \) \
        -exec /usr/bin/chflags \
            nouchg,nouappnd,nodatavault,noschg,nosappnd,nosunlnk,nodataless {} +
    /usr/bin/find "$root" \( -type d -o -type f \) \
        -exec /bin/chmod -N {} +
    if /usr/bin/find "$root" \
            \( -flags +uchg -o -flags +uappnd -o -flags +datavault \
               -o -flags +schg -o -flags +sappnd -o -flags +sunlnk \
               -o -flags +dataless \) \
            -print | /usr/bin/grep . >/dev/null; then
        fail "payload retains immutable or append-only BSD flags"
    fi
    if /usr/bin/find "$root" \( -type d -o -type f \) \
            -exec /bin/ls -lde {} + \
            | /usr/bin/grep -E '^[[:space:]][[:digit:]]+: ' >/dev/null; then
        fail "payload retains an extended ACL"
    fi
    # Independently inspect the numeric flags without following bundle symlinks.
    # This prevents a future chflags(1) spelling/behavior drift from packaging an
    # app whose sealed corpus will fail closed on first boot.
    /usr/bin/env -i \
        PATH=/usr/bin:/bin \
        TMPDIR=/tmp \
        LC_ALL=C \
        LANG=C \
        PYTHONDONTWRITEBYTECODE=1 \
        /usr/bin/python3 -I -B - "$root" <<'PY'
import os
import stat
import sys


unsafe_bsd_flags = (
    0x00000002
    | 0x00000004
    | 0x00000080
    | 0x00020000
    | 0x00040000
    | 0x00100000
    | 0x40000000
)
root = sys.argv[1]
paths = [root]
for directory, directory_names, file_names in os.walk(root, followlinks=False):
    paths.extend(os.path.join(directory, name) for name in directory_names)
    paths.extend(os.path.join(directory, name) for name in file_names)
for path in paths:
    try:
        metadata = os.lstat(path)
    except OSError as error:
        print(f"ERROR: cannot verify BSD flags at {path!r}: {error}", file=sys.stderr)
        raise SystemExit(1)
    if (stat.S_ISDIR(metadata.st_mode) or stat.S_ISREG(metadata.st_mode)) \
            and getattr(metadata, "st_flags", 0) & unsafe_bsd_flags:
        print(f"ERROR: payload retains unsafe BSD flags at {path!r}", file=sys.stderr)
        raise SystemExit(1)
PY
}

if [ "$#" -ne 1 ]; then
    fail "usage: prepare-dmg-payload.sh STAGING_ROOT"
fi

PAYLOAD_ROOT="$1"
if [ -L "$PAYLOAD_ROOT" ] || [ ! -d "$PAYLOAD_ROOT" ]; then
    fail "payload root must be a real directory: $PAYLOAD_ROOT"
fi
PAYLOAD_ROOT="$(cd "$PAYLOAD_ROOT" && /bin/pwd -P)"
case "$PAYLOAD_ROOT" in
    /|/Applications|/Library|/System|/Users|/Volumes)
        fail "refusing unsafe payload root: $PAYLOAD_ROOT"
        ;;
esac

APP="$PAYLOAD_ROOT/MacCrab.app"
APP_RULES="$APP/Contents/Resources/compiled_rules"
APP_BIN="$APP/Contents/Resources/bin"
APP_RULE_SOURCES="$APP/Contents/Resources/rules"
APP_COMPILER_YAML="$APP/Contents/Resources/Compiler/yaml"
APP_MAIN="$APP/Contents/MacOS/MacCrab"
SYSEXT_MAIN="$APP/Contents/Library/SystemExtensions/com.maccrab.agent.systemextension/Contents/MacOS/com.maccrab.agent"
SYSEXT_RULES="$APP/Contents/Library/SystemExtensions/com.maccrab.agent.systemextension/Contents/Resources/compiled_rules"
[ -d "$APP" ] && [ ! -L "$APP" ] \
    && [ -f "$APP/Contents/Info.plist" ] && [ ! -L "$APP/Contents/Info.plist" ] \
    || fail "payload does not contain a real MacCrab.app bundle"
APP_ID=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' \
    "$APP/Contents/Info.plist" 2>/dev/null || true)

[ "$APP_ID" = "com.maccrab.app" ] \
    || fail "payload does not contain the canonical MacCrab.app"
normalize_payload_security_metadata "$PAYLOAD_ROOT"
[ -f "$APP_MAIN" ] && [ ! -L "$APP_MAIN" ] \
    || fail "signed app is missing its primary executable"
validate_compiled_rule_corpus "$APP_RULES"
validate_compiled_rule_corpus "$SYSEXT_RULES"
/usr/bin/diff -qr "$APP_RULES" "$SYSEXT_RULES" >/dev/null \
    || fail "app and System Extension compiled-rule corpora differ"
for required_cli in maccrabctl maccrab-mcp; do
    [ -f "$APP_BIN/$required_cli" ] && [ ! -L "$APP_BIN/$required_cli" ] \
        || fail "signed app is missing bundled $required_cli"
done

# Every loose binary must have a signed in-app counterpart before the loose
# tree can be dropped.  Reject links and unexpected directory structure rather
# than silently omitting a release-only tool.
if [ -e "$PAYLOAD_ROOT/bin" ] || [ -L "$PAYLOAD_ROOT/bin" ]; then
    [ -d "$PAYLOAD_ROOT/bin" ] && [ ! -L "$PAYLOAD_ROOT/bin" ] \
        || fail "loose bin payload is not a real directory"
    while IFS= read -r loose_binary; do
        [ -f "$loose_binary" ] && [ ! -L "$loose_binary" ] \
            || fail "unexpected entry in loose bin payload: $loose_binary"
        case "$(/usr/bin/basename "$loose_binary")" in
            MacCrabApp)   bundled_binary="$APP_MAIN" ;;
            MacCrabAgent) bundled_binary="$SYSEXT_MAIN" ;;
            *)            bundled_binary="$APP_BIN/$(/usr/bin/basename "$loose_binary")" ;;
        esac
        [ -f "$bundled_binary" ] && [ ! -L "$bundled_binary" ] \
            || fail "loose binary has no signed in-app counterpart: $loose_binary"
    done < <(/usr/bin/find "$PAYLOAD_ROOT/bin" -mindepth 1 -maxdepth 1 -print)
    /bin/rm -rf "${PAYLOAD_ROOT:?}/bin"
fi

# The rule corpus is ordinary signed resources, so the two trees must be
# byte-for-byte equivalent.  If assembly drifted, stop instead of packaging a
# corpus different from the one install.sh/Homebrew will seed.
if [ -e "$PAYLOAD_ROOT/compiled_rules" ] || [ -L "$PAYLOAD_ROOT/compiled_rules" ]; then
    [ -d "$PAYLOAD_ROOT/compiled_rules" ] && [ ! -L "$PAYLOAD_ROOT/compiled_rules" ] \
        || fail "loose compiled_rules payload is not a real directory"
    if /usr/bin/find "$PAYLOAD_ROOT/compiled_rules" "$APP_RULES" -type l -print -quit \
            | /usr/bin/grep -q .; then
        fail "compiled-rule payload contains a symbolic link"
    fi
    /usr/bin/diff -qr "$PAYLOAD_ROOT/compiled_rules" "$APP_RULES" >/dev/null \
        || fail "loose and signed in-app compiled-rule corpora differ"
    /bin/rm -rf "${PAYLOAD_ROOT:?}/compiled_rules"
fi

# rules_source/ is an unsigned-build input. Assembly copies every YAML into the
# signed Resources/rules directory (both slug and UUID names) and every graph
# JSON into the signed compiled corpus. Validate those exact counterparts and
# reject any new unhandled file type before dropping the intermediate tree.
if [ -e "$PAYLOAD_ROOT/rules_source" ] || [ -L "$PAYLOAD_ROOT/rules_source" ]; then
    [ -d "$PAYLOAD_ROOT/rules_source" ] && [ ! -L "$PAYLOAD_ROOT/rules_source" ] \
        || fail "loose rules_source payload is not a real directory"
    unhandled_rule_entry=$(/usr/bin/find "$PAYLOAD_ROOT/rules_source" -mindepth 1 \
        ! -type f ! -type d ! -type l -print -quit)
    [ -z "$unhandled_rule_entry" ] \
        || fail "special entry in loose rule-source payload: $unhandled_rule_entry"
    while IFS= read -r source_rule; do
        [ -f "$source_rule" ] && [ ! -L "$source_rule" ] \
            || fail "unexpected entry in loose rule-source payload: $source_rule"
        case "$source_rule" in
            *.yml)
                signed_rule="$APP_RULE_SOURCES/$(/usr/bin/basename "$source_rule")"
                if [ ! -f "$signed_rule" ] || [ -L "$signed_rule" ] \
                        || ! /usr/bin/cmp -s "$source_rule" "$signed_rule"; then
                    fail "rule YAML lacks an identical signed in-app copy: $source_rule"
                fi
                ;;
            */graph/*.json)
                signed_rule="$APP_RULES/graph/$(/usr/bin/basename "$source_rule")"
                if [ ! -f "$signed_rule" ] || [ -L "$signed_rule" ] \
                        || ! /usr/bin/cmp -s "$source_rule" "$signed_rule"; then
                    fail "graph rule lacks an identical signed in-app copy: $source_rule"
                fi
                ;;
            */README.md)
                # Source-corpus documentation is useful in the repository but
                # is not a runtime input and has no published counterpart.
                ;;
            *)
                fail "unhandled file in loose rule-source payload: $source_rule"
                ;;
        esac
    done < <(/usr/bin/find "$PAYLOAD_ROOT/rules_source" -type f -o -type l)
    /bin/rm -rf "${PAYLOAD_ROOT:?}/rules_source"
fi

# release-python/ is the hash-locked PyYAML input used by the compiler. The
# runtime editor receives the same module under Resources/Compiler/yaml. Do not
# discard a new dependency or a drifted module silently.
if [ -e "$PAYLOAD_ROOT/release-python" ] || [ -L "$PAYLOAD_ROOT/release-python" ]; then
    [ -d "$PAYLOAD_ROOT/release-python" ] && [ ! -L "$PAYLOAD_ROOT/release-python" ] \
        || fail "release-python payload is not a real directory"
    release_python_entries=$(/usr/bin/find "$PAYLOAD_ROOT/release-python" \
        -mindepth 1 -maxdepth 1 -print)
    [ "$release_python_entries" = "$PAYLOAD_ROOT/release-python/yaml" ] \
        || fail "release-python contains an unhandled staged dependency"
    [ -d "$APP_COMPILER_YAML" ] && [ ! -L "$APP_COMPILER_YAML" ] \
        || fail "signed app is missing its bundled compiler YAML module"
    if /usr/bin/find "$PAYLOAD_ROOT/release-python/yaml" "$APP_COMPILER_YAML" \
            -type l -print -quit | /usr/bin/grep -q .; then
        fail "bundled compiler YAML payload contains a symbolic link"
    fi
    /usr/bin/diff -qr "$PAYLOAD_ROOT/release-python/yaml" "$APP_COMPILER_YAML" >/dev/null \
        || fail "staged and signed in-app compiler YAML modules differ"
    /bin/rm -rf "${PAYLOAD_ROOT:?}/release-python"
fi

# Build hosts commonly run with umask 077.  Preserve which files are executable
# while granting every user read/traverse access; then remove group/other write
# permissions.  `find` deliberately does not follow the DMG's Applications
# symlink (or framework-internal symlinks).  This is run both before and after
# ditto copies into HFS because the mounted image is what users consume.
/usr/bin/find "$PAYLOAD_ROOT" -type d -exec /bin/chmod a+rx,go-w {} +
/usr/bin/find "$PAYLOAD_ROOT" -type f -exec /bin/chmod a+r,go-w {} +
/usr/bin/find "$PAYLOAD_ROOT" -type f -perm -u+x -exec /bin/chmod a+x {} +
normalize_payload_symlink_modes_no_follow "$PAYLOAD_ROOT"
/bin/chmod 0755 "$PAYLOAD_ROOT/install.sh"
/bin/chmod 0755 "$APP_MAIN"
if [ -d "$APP_BIN" ]; then
    /usr/bin/find "$APP_BIN" -type f -exec /bin/chmod 0755 {} +
fi

echo "  ✓ Published payload contains no internal handoff copies and has user-readable modes"
