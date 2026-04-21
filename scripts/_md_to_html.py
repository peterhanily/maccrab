#!/usr/bin/env python3
"""
Convert the subset of Markdown used by RELEASE_NOTES/vX.Y.Z.md into HTML
for Sparkle's <description> field.

Sparkle renders <description> as HTML, not Markdown. Shipping raw
Markdown produced the v1.4.0 update sheet showing **bold** as literal
text with every line collapsed into one paragraph. This script is
invoked from scripts/generate-appcast-entry.sh and covers:

    headings (# through ######)
    horizontal rules (---)
    paragraphs (blank-line separated)
    bulleted lists (- or *)
    **bold**, *italic*, `code`, [text](url)

If you introduce new Markdown constructs in the release notes, add
handling here — otherwise they'll render as literal text in the
Sparkle sheet.

Reads Markdown from argv[1] (file path) or stdin. Writes HTML to stdout.
"""

import html
import re
import sys


def inline(text: str) -> str:
    text = html.escape(text, quote=False)
    # [text](url) — escape the URL's quotes only
    text = re.sub(
        r"\[([^\]]+)\]\(([^)]+)\)",
        lambda m: f'<a href="{html.escape(m.group(2), quote=True)}">{m.group(1)}</a>',
        text,
    )
    # **bold** (match before *italic* so ** doesn't collide)
    text = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", text)
    # *italic* — require word-adjacent asterisks so stray punctuation
    # doesn't accidentally italicize paragraphs
    text = re.sub(r"(?<!\w)\*([^*\n]+)\*(?!\w)", r"<em>\1</em>", text)
    # `code`
    text = re.sub(r"\x60([^\x60]+)\x60", r"<code>\1</code>", text)
    return text


def convert(md: str) -> str:
    out: list[str] = []
    lines = md.split("\n")
    i = 0
    in_list = False
    in_para = False

    def close_list() -> None:
        nonlocal in_list
        if in_list:
            out.append("</ul>")
            in_list = False

    def close_para() -> None:
        nonlocal in_para
        if in_para:
            out.append("</p>")
            in_para = False

    while i < len(lines):
        line = lines[i].rstrip()

        if not line.strip():
            close_list()
            close_para()
            i += 1
            continue

        if re.match(r"^-{3,}\s*$", line):
            close_list()
            close_para()
            out.append("<hr/>")
            i += 1
            continue

        m = re.match(r"^(#{1,6})\s+(.*)$", line)
        if m:
            close_list()
            close_para()
            level = len(m.group(1))
            out.append(f"<h{level}>{inline(m.group(2).strip())}</h{level}>")
            i += 1
            continue

        m = re.match(r"^[-*]\s+(.*)$", line)
        if m:
            close_para()
            if not in_list:
                out.append("<ul>")
                in_list = True
            item = m.group(1)
            j = i + 1
            while j < len(lines):
                nxt = lines[j]
                if not nxt.strip():
                    break
                if re.match(r"^[-*]\s+", nxt) or re.match(r"^#{1,6}\s+", nxt):
                    break
                item += " " + nxt.strip()
                j += 1
            out.append(f"<li>{inline(item)}</li>")
            i = j
            continue

        close_list()
        if not in_para:
            out.append("<p>")
            in_para = True
        out.append(inline(line))
        i += 1

    close_list()
    close_para()
    return "\n".join(out)


if __name__ == "__main__":
    if len(sys.argv) >= 2 and sys.argv[1] != "-":
        with open(sys.argv[1], encoding="utf-8") as fh:
            md = fh.read()
    else:
        md = sys.stdin.read()
    sys.stdout.write(convert(md))
