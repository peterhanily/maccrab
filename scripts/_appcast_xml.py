#!/usr/bin/python3
"""Generate and validate the exact Sparkle appcast XML MacCrab publishes."""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import sys
import xml.etree.ElementTree as ET


SPARKLE_NS = "http://www.andymatuschak.org/xml-namespaces/sparkle"
MAX_ITEM_BYTES = 1024 * 1024
MAX_FEED_BYTES = 4 * 1024 * 1024
VERSION_RE = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(?:-rc\.[0-9]+)?\Z")
BUILD_RE = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(?:-rc\.[0-9]+)?(?:\.[0-9]+)?\Z")
PUBDATE_RE = re.compile(r"[A-Z][a-z]{2}, [0-9]{2} [A-Z][a-z]{2} [0-9]{4} [0-9]{2}:[0-9]{2}:[0-9]{2} \+0000\Z")


def fail(message: str) -> "None":
    raise ValueError(message)


def local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def read_bounded(path: str, maximum: int) -> bytes:
    st = os.lstat(path)
    if not os.path.isfile(path) or os.path.islink(path):
        fail(f"not a regular no-link file: {path}")
    if st.st_size > maximum:
        fail(f"{path} exceeds {maximum} bytes")
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        opened = os.fstat(fd)
        if (opened.st_dev, opened.st_ino) != (st.st_dev, st.st_ino):
            fail(f"{path} changed before open")
        data = bytearray()
        while len(data) <= maximum:
            chunk = os.read(fd, min(65536, maximum + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        after = os.fstat(fd)
        if len(data) > maximum:
            fail(f"{path} exceeds {maximum} bytes")
        if (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ) or len(data) != after.st_size:
            fail(f"{path} changed while read")
        return bytes(data)
    finally:
        os.close(fd)


def parse_xml(data: bytes, fragment: bool) -> ET.Element:
    upper = data.upper()
    if b"<!DOCTYPE" in upper or b"<!ENTITY" in upper:
        fail("DOCTYPE/ENTITY is forbidden")
    if fragment:
        if b"<?XML" in upper:
            fail("XML declaration is forbidden in an item fragment")
        data = (
            f'<maccrab-root xmlns:sparkle="{SPARKLE_NS}">'.encode()
            + data
            + b"</maccrab-root>"
        )
    try:
        return ET.fromstring(data)
    except ET.ParseError as exc:
        fail(f"XML parse failed: {exc}")


def one_child(item: ET.Element, name: str) -> ET.Element:
    matches = [child for child in item if local_name(child.tag) == name]
    if len(matches) != 1:
        fail(f"item must contain exactly one {name} element")
    return matches[0]


def validate_item_bytes(
    data: bytes,
    expected_version: str | None = None,
    expected_build: str | None = None,
) -> str:
    if len(data) > MAX_ITEM_BYTES:
        fail("appcast item is too large")
    wrapper = parse_xml(data, fragment=True)
    if len(wrapper) != 1 or local_name(wrapper[0].tag) != "item":
        fail("fragment must contain exactly one item")
    item = wrapper[0]
    allowed = {
        "title",
        "link",
        "version",
        "shortVersionString",
        "minimumSystemVersion",
        "pubDate",
        "phasedRolloutInterval",
        "description",
        "enclosure",
    }
    unknown = [local_name(child.tag) for child in item if local_name(child.tag) not in allowed]
    if unknown:
        fail(f"unknown item elements: {unknown}")

    title = one_child(item, "title").text or ""
    link = one_child(item, "link").text or ""
    build = one_child(item, "version").text or ""
    version = one_child(item, "shortVersionString").text or ""
    minimum = one_child(item, "minimumSystemVersion").text or ""
    pub_date = one_child(item, "pubDate").text or ""
    one_child(item, "description")
    enclosure = one_child(item, "enclosure")

    if not VERSION_RE.fullmatch(version):
        fail("invalid shortVersionString")
    if not BUILD_RE.fullmatch(build):
        fail("invalid Sparkle build version")
    if expected_version is not None and version != expected_version:
        fail(f"shortVersionString {version!r} != expected {expected_version!r}")
    if expected_build is not None and build != expected_build:
        fail(f"Sparkle build {build!r} != expected {expected_build!r}")
    if title != f"MacCrab {version}":
        fail("title/version mismatch")
    expected_link = f"https://github.com/peterhanily/maccrab/releases/tag/v{version}"
    if link != expected_link:
        fail("release link/version mismatch")
    if minimum != "13.0" or not PUBDATE_RE.fullmatch(pub_date):
        fail("invalid minimumSystemVersion or pubDate")

    phased = [child for child in item if local_name(child.tag) == "phasedRolloutInterval"]
    if len(phased) > 1 or (phased and not re.fullmatch(r"[1-9][0-9]{0,9}", phased[0].text or "")):
        fail("invalid phasedRolloutInterval")

    attrs = enclosure.attrib
    signature = attrs.get(f"{{{SPARKLE_NS}}}edSignature", "")
    length = attrs.get("length", "")
    expected_url = f"https://github.com/peterhanily/maccrab/releases/download/v{version}/MacCrab-v{version}.dmg"
    if attrs.get("url") != expected_url or attrs.get("type") != "application/octet-stream":
        fail("invalid enclosure URL/type")
    if not re.fullmatch(r"[1-9][0-9]{0,15}", length):
        fail("invalid enclosure length")
    if not re.fullmatch(r"[A-Za-z0-9+/]{86}==", signature):
        fail("invalid Ed25519 signature base64 shape")
    try:
        decoded = base64.b64decode(signature, validate=True)
    except ValueError as exc:
        fail(f"invalid Ed25519 signature base64: {exc}")
    if len(decoded) != 64:
        fail("Ed25519 signature must decode to 64 bytes")
    return build


def validate_feed_bytes(data: bytes) -> tuple[ET.Element, ET.Element]:
    if len(data) > MAX_FEED_BYTES:
        fail("appcast feed is too large")
    root = parse_xml(data, fragment=False)
    if local_name(root.tag) != "rss":
        fail("appcast root must be rss")
    channels = [child for child in root if local_name(child.tag) == "channel"]
    if len(channels) != 1:
        fail("appcast must contain exactly one channel")
    return root, channels[0]


def cmd_generate(args: argparse.Namespace) -> None:
    if not VERSION_RE.fullmatch(args.version):
        fail("--version must be MAJOR.MINOR.PATCH or MAJOR.MINOR.PATCH-rc.N")
    if not BUILD_RE.fullmatch(args.build_number):
        fail("--build-number has an unsafe shape")
    if not PUBDATE_RE.fullmatch(args.pub_date):
        fail("--pub-date has an unsafe shape")
    if args.dmg_name != f"MacCrab-v{args.version}.dmg":
        fail("DMG filename must exactly match the release version")
    if not re.fullmatch(r"[1-9][0-9]{0,15}", args.length):
        fail("--length must be a positive decimal")
    if args.phased_interval is not None and not re.fullmatch(r"[1-9][0-9]{0,9}", args.phased_interval):
        fail("--phased-interval must be a positive decimal")

    notes = read_bounded(args.notes_file, MAX_ITEM_BYTES).decode("utf-8")
    safe_notes = notes.replace("]]>", "]]]]><![CDATA[>")
    phased = ""
    if args.phased_interval is not None:
        phased = f"  <sparkle:phasedRolloutInterval>{args.phased_interval}</sparkle:phasedRolloutInterval>\n"
    item = f"""<item>
  <title>MacCrab {args.version}</title>
  <link>https://github.com/peterhanily/maccrab/releases/tag/v{args.version}</link>
  <sparkle:version>{args.build_number}</sparkle:version>
  <sparkle:shortVersionString>{args.version}</sparkle:shortVersionString>
  <sparkle:minimumSystemVersion>13.0</sparkle:minimumSystemVersion>
  <pubDate>{args.pub_date}</pubDate>
{phased}  <description><![CDATA[
{safe_notes}
]]></description>
  <enclosure
    url="https://github.com/peterhanily/maccrab/releases/download/v{args.version}/{args.dmg_name}"
    length="{args.length}"
    type="application/octet-stream"
    sparkle:edSignature="{args.signature}" />
</item>
"""
    validate_item_bytes(item.encode(), args.version, args.build_number)
    sys.stdout.write(item)


def cmd_validate_item(args: argparse.Namespace) -> None:
    data = read_bounded(args.item, MAX_ITEM_BYTES)
    build = validate_item_bytes(data, args.expected_version, args.expected_build)
    print(build)


def cmd_decode_response(args: argparse.Namespace) -> None:
    response = json.loads(read_bounded(args.response, 6 * 1024 * 1024))
    if not isinstance(response, dict):
        fail("GitHub response must be an object")
    sha = response.get("sha")
    content = response.get("content")
    if not isinstance(sha, str) or not re.fullmatch(r"[a-f0-9]{40}", sha):
        fail("GitHub response has no valid blob SHA")
    if not isinstance(content, str):
        fail("GitHub response has no base64 content")
    try:
        decoded = base64.b64decode("".join(content.split()), validate=True)
    except ValueError as exc:
        fail(f"GitHub response content is not base64: {exc}")
    validate_feed_bytes(decoded)
    fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
    try:
        os.write(fd, decoded)
    finally:
        os.close(fd)
    print(sha)


def cmd_inject(args: argparse.Namespace) -> None:
    item = read_bounded(args.item, MAX_ITEM_BYTES)
    build = validate_item_bytes(item, args.expected_version, args.expected_build)
    current = read_bounded(args.current, MAX_FEED_BYTES)
    _, channel = validate_feed_bytes(current)
    existing = [
        (node.text or "")
        for node in channel.iter()
        if local_name(node.tag) == "version"
    ]
    if build in existing:
        fail(f"appcast already contains Sparkle build {build}")

    text = current.decode("utf-8")
    fragment = item.decode("utf-8").strip()
    anchors = (
        r"(<language>[^<]*</language>)",
        r"(<description>[^<]*</description>)",
        r"(<channel(?:\s[^>]*)?>)",
    )
    updated = None
    for pattern in anchors:
        if re.search(pattern, text):
            updated = re.sub(pattern, lambda match: match.group(1) + "\n    " + fragment, text, count=1)
            break
    if updated is None:
        fail("could not find a channel insertion anchor")
    validate_feed_bytes(updated.encode("utf-8"))
    fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
    try:
        os.write(fd, updated.encode("utf-8"))
    finally:
        os.close(fd)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)

    generate = sub.add_parser("generate")
    generate.add_argument("--version", required=True)
    generate.add_argument("--build-number", required=True)
    generate.add_argument("--pub-date", required=True)
    generate.add_argument("--phased-interval")
    generate.add_argument("--signature", required=True)
    generate.add_argument("--length", required=True)
    generate.add_argument("--dmg-name", required=True)
    generate.add_argument("--notes-file", required=True)
    generate.set_defaults(function=cmd_generate)

    validate = sub.add_parser("validate-item")
    validate.add_argument("--item", required=True)
    validate.add_argument("--expected-version")
    validate.add_argument("--expected-build")
    validate.set_defaults(function=cmd_validate_item)

    decode = sub.add_parser("decode-github-response")
    decode.add_argument("--response", required=True)
    decode.add_argument("--output", required=True)
    decode.set_defaults(function=cmd_decode_response)

    inject = sub.add_parser("inject")
    inject.add_argument("--item", required=True)
    inject.add_argument("--current", required=True)
    inject.add_argument("--output", required=True)
    inject.add_argument("--expected-version", required=True)
    inject.add_argument("--expected-build", required=True)
    inject.set_defaults(function=cmd_inject)
    return parser


def main() -> int:
    try:
        args = build_parser().parse_args()
        args.function(args)
        return 0
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
        print(f"ERROR: appcast XML rejected: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
