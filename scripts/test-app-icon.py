#!/usr/bin/env python3
"""The committed app icon is exactly what scripts/render-app-icon.py draws.

Decodes every image in Sources/MacCrabApp/Resources/AppIcon.icns (the PNG sizes
and the 16- and 32-point ARGB sizes) and compares its pixels with the
generator's, so the shipped icon cannot drift from the reviewed artwork even if
iconutil encodes it differently. Also checks the element inventory and that the
build pins the same bytes.
"""
import hashlib
import importlib.util
import re
import struct
import unittest
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ICON = ROOT / "Sources/MacCrabApp/Resources/AppIcon.icns"
GENERATOR = ROOT / "scripts/render-app-icon.py"
STYLER = ROOT / "scripts/style-dmg-window.py"
PNG_SIZES = {b"ic11": 32, b"ic12": 64, b"ic07": 128, b"ic08": 256, b"ic13": 256,
             b"ic09": 512, b"ic14": 512, b"ic10": 1024}
ARGB_SIZES = {b"ic04": 16, b"ic05": 32}


def load_generator():
    spec = importlib.util.spec_from_file_location("render_app_icon", GENERATOR)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def icns_elements(data):
    assert data[:4] == b"icns" and struct.unpack(">I", data[4:8])[0] == len(data)
    offset, elements = 8, {}
    while offset < len(data):
        kind, size = data[offset:offset + 4], struct.unpack(">I", data[offset + 4:offset + 8])[0]
        assert size >= 8 and kind not in elements
        elements[kind] = data[offset + 8:offset + size]
        offset += size
    return elements


def png_rows(png):
    assert png[:8] == b"\x89PNG\r\n\x1a\n"
    offset, idat, header = 8, b"", None
    while offset < len(png):
        size = struct.unpack(">I", png[offset:offset + 4])[0]
        kind, body = png[offset + 4:offset + 8], png[offset + 8:offset + 8 + size]
        if kind == b"IHDR":
            header = struct.unpack(">IIBBBBB", body)
        elif kind == b"IDAT":
            idat += body
        offset += size + 12
    width, height, depth, colour, _, _, interlace = header
    assert (depth, colour, interlace) == (8, 6, 0)
    raw, stride, rows, previous, i = zlib.decompress(idat), width * 4, [], bytearray(width * 4), 0
    for _ in range(height):
        kind, line = raw[i], bytearray(raw[i + 1:i + 1 + stride])
        i += 1 + stride
        for x in range(stride):
            a = line[x - 4] if x >= 4 else 0
            b, c = previous[x], previous[x - 4] if x >= 4 else 0
            if kind == 1:
                line[x] = (line[x] + a) & 255
            elif kind == 2:
                line[x] = (line[x] + b) & 255
            elif kind == 3:
                line[x] = (line[x] + ((a + b) >> 1)) & 255
            elif kind == 4:
                p = a + b - c
                pa, pb, pc = abs(p - a), abs(p - b), abs(p - c)
                line[x] = (line[x] + (a if pa <= pb and pa <= pc else b if pb <= pc else c)) & 255
        rows.append(bytes(line))
        previous = line
    return width, height, rows


def argb_rows(data, size):
    """Decode an ICNS 'ARGB' element: four run-length encoded planes, A R G B."""
    assert data[:4] == b"ARGB"
    planes, i, plane = [], 4, bytearray()
    while len(planes) < 4:
        n = data[i]
        if n < 0x80:
            plane += data[i + 1:i + 2 + n]
            i += 2 + n
        else:
            plane += bytes([data[i + 1]]) * (n - 0x80 + 3)
            i += 2
        if len(plane) >= size * size:
            assert len(plane) == size * size
            planes.append(bytes(plane))
            plane = bytearray()
    a, r, g, b = planes
    return [bytes(v for x in range(y * size, (y + 1) * size) for v in (r[x], g[x], b[x], a[x]))
            for y in range(size)]


class AppIconTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = ICON.read_bytes()
        cls.elements = icns_elements(cls.data)
        cls.generator = load_generator()

    def test_inventory(self):
        self.assertEqual(set(self.elements), set(PNG_SIZES) | set(ARGB_SIZES) | {b"info"})

    def test_png_sizes_match_the_generator(self):
        for kind, size in PNG_SIZES.items():
            with self.subTest(element=kind.decode(), size=size):
                width, height, rows = png_rows(self.elements[kind])
                self.assertEqual((width, height), (size, size))
                self.assertEqual(rows, self.generator.render(size))

    def test_argb_sizes_match_the_generator(self):
        # iconutil stores these sizes premultiplied, so a semi-transparent edge
        # pixel's colour comes back within the 8-bit rounding of its alpha.
        # Alpha, and the colour of every opaque pixel, must match exactly.
        for kind, size in ARGB_SIZES.items():
            with self.subTest(element=kind.decode(), size=size):
                got, want = argb_rows(self.elements[kind], size), self.generator.render(size)
                self.assertEqual(len(got), len(want))
                for y, (row, expected) in enumerate(zip(got, want)):
                    for x in range(0, len(row), 4):
                        a = expected[x + 3]
                        self.assertEqual(row[x + 3], a, (x // 4, y))
                        if a == 255:
                            self.assertEqual(row[x:x + 3], expected[x:x + 3], (x // 4, y))
                        elif a:
                            bound = -(-255 // a)
                            for c in range(3):
                                self.assertLessEqual(abs(row[x + c] - expected[x + c]), bound, (x // 4, y))

    def test_dmg_styler_pins_these_bytes(self):
        pin = re.search(r'^ICON_SHA256 = "([0-9a-f]{64})"$', STYLER.read_text(), re.M).group(1)
        self.assertEqual(hashlib.sha256(self.data).hexdigest(), pin)


if __name__ == "__main__":
    unittest.main()
