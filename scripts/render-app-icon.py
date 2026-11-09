"""Render MacCrab's app icon (the website's pixel crab on a warm black tile).

usage: python3 -I render-app-icon.py <output .iconset directory>

Deterministic: the same script always writes the same PNG bytes. Every size
draws the 16 x 16 crab at a whole-pixel scale; the 16-point size is the bare
sprite (as on the website's favicon) because a tile would leave the crab half
a pixel per cell.
"""
import os
import struct
import sys
import zlib

# The website's sprite (maccrab-site assets/play.js), legs frame A.
CLAWS = [(1, 1, 3, 3), (0, 2, 1, 1), (4, 2, 1, 1), (2, 4, 2, 1),
         (12, 1, 3, 3), (11, 2, 1, 1), (15, 2, 1, 1), (12, 4, 2, 1)]
BODY = [(6, 4, 1, 1), (9, 4, 1, 1), (4, 5, 8, 1), (3, 6, 10, 3), (4, 9, 8, 1)]
LEGS = [(2, 10, 1, 2), (5, 10, 1, 2), (10, 10, 1, 2), (13, 10, 1, 2),
        (1, 12, 1, 1), (4, 12, 1, 1), (11, 12, 1, 1), (14, 12, 1, 1)]
EYES = [(5, 6, 2, 1), (9, 6, 2, 1)]
PUPILS = [(6, 6, 1, 1), (9, 6, 1, 1)]
SHELL, WHITE, BLACK = (0xFF, 0x6A, 0x3D), (0xFF, 0xFF, 0xFF), (0x00, 0x00, 0x00)
FACE_TOP, FACE_BOTTOM = (0x24, 0x1E, 0x1C), (0x15, 0x12, 0x11)

# Apple's macOS icon grid: an 824-point tile with 185.4-point corners on a
# 1024-point canvas.
TILE, RADIUS = 824 / 1024, 185.4 / 1024


def sprite_cells():
    cells = {}
    for colour, rects in ((SHELL, CLAWS + BODY + LEGS), (WHITE, EYES), (BLACK, PUPILS)):
        for x, y, w, h in rects:
            for i in range(x, x + w):
                for j in range(y, y + h):
                    cells[(i, j)] = colour
    return cells


def tile_coverage(px, py, size):
    """Fraction of pixel (px, py) inside the rounded tile, 4 x 4 supersampled."""
    t0 = (1 - TILE) / 2 * size
    t1 = size - t0
    r = RADIUS * size

    def inside(x, y):
        cx = min(max(x, t0 + r), t1 - r)
        cy = min(max(y, t0 + r), t1 - r)
        return (x - cx) ** 2 + (y - cy) ** 2 <= r * r and t0 <= x <= t1 and t0 <= y <= t1

    # Pixels well inside or outside need no supersampling.
    corners = [inside(px + dx, py + dy) for dx in (0, 1) for dy in (0, 1)]
    if all(corners) and inside(px + 0.5, py + 0.5):
        return 1.0
    if not any(corners) and not inside(px + 0.5, py + 0.5):
        near = (t0 - 1 <= px <= t1 and t0 - 1 <= py <= t1)
        if not near:
            return 0.0
    hits = sum(inside(px + (i + 0.5) / 4, py + (j + 0.5) / 4) for i in range(4) for j in range(4))
    return hits / 16


def render(size):
    """RGBA rows for one icon size."""
    cells = sprite_cells()
    if size == 16:
        rows = []
        for y in range(16):
            row = bytearray()
            for x in range(16):
                c = cells.get((x, y - 1))  # one cell down, so the crab sits centred
                row += bytes(c + (255,)) if c else b"\0\0\0\0"
            rows.append(bytes(row))
        return rows
    scale = size // 32  # 32 -> 1, 64 -> 2, 128 -> 4, ... 1024 -> 32
    ox = (size - 16 * scale) // 2
    oy = ox + scale  # optical centre: the sprite's legs end at row 12
    t0 = (1 - TILE) / 2 * size
    span = TILE * size
    rows = []
    for y in range(size):
        g = min(max((y + 0.5 - t0) / span, 0.0), 1.0)
        face = tuple(round(a + (b - a) * g) for a, b in zip(FACE_TOP, FACE_BOTTOM))
        row = bytearray()
        for x in range(size):
            cover = tile_coverage(x, y, size)
            if cover == 0.0:
                row += b"\0\0\0\0"
                continue
            colour = face
            sx, sy = (x - ox) // scale if x >= ox else -1, (y - oy) // scale if y >= oy else -1
            crab = cells.get((sx, sy)) if 0 <= sx < 16 and 0 <= sy < 16 else None
            if crab:
                colour = crab
            row += bytes(colour) + bytes((round(255 * cover),))
        rows.append(bytes(row))
    return rows


def png(rows, size):
    raw = b"".join(b"\0" + r for r in rows)

    def chunk(kind, data):
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)

    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0)) +
            chunk(b"sRGB", b"\0") + chunk(b"IDAT", zlib.compress(raw, 9)) + chunk(b"IEND", b""))


def main():
    out = sys.argv[1]
    os.makedirs(out, exist_ok=True)
    names = {16: ["icon_16x16.png"], 32: ["icon_16x16@2x.png", "icon_32x32.png"], 64: ["icon_32x32@2x.png"],
             128: ["icon_128x128.png"], 256: ["icon_128x128@2x.png", "icon_256x256.png"],
             512: ["icon_256x256@2x.png", "icon_512x512.png"], 1024: ["icon_512x512@2x.png"]}
    for size, files in sorted(names.items()):
        data = png(render(size), size)
        for name in files:
            with open(os.path.join(out, name), "wb") as f:
                f.write(data)
        print(size, len(data), "bytes")


if __name__ == "__main__":
    main()
