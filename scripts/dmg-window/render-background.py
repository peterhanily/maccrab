"""Render the disk-image window background from its SVG source.

usage: python3 -I render-dmg-background.py <background.svg> <IBM Plex font dir> <out.tiff>

A maintainer tool, not a release step: the release build copies the committed
TIFF. It renders the SVG at 1x and 2x with headless Chrome, using IBM Plex Sans
and Mono (OFL 1.1, as on maccrab.com), then joins both into one HiDPI TIFF with
tiffutil so Finder shows the sharp version on Retina displays.
"""
import base64
import os
import subprocess
import sys
import tempfile

CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
WIDTH, HEIGHT = 660, 400


def font_face(family, path, weight):
    data = base64.b64encode(open(path, "rb").read()).decode()
    return ('@font-face{font-family:"%s";src:url(data:font/woff2;base64,%s) format("woff2");font-weight:%s;}'
            % (family, data, weight))


def main():
    svg_path, font_dir, out = sys.argv[1:4]
    svg = open(svg_path, encoding="utf-8").read()
    css = (font_face("IBM Plex Sans", os.path.join(font_dir, "plex-sans-var.woff2"), "100 700") +
           font_face("IBM Plex Mono", os.path.join(font_dir, "plex-mono-500.woff2"), "500") +
           "html,body{margin:0;background:#110E0D}svg{display:block}")
    with tempfile.TemporaryDirectory() as work:
        page = os.path.join(work, "background.html")
        with open(page, "w", encoding="utf-8") as f:
            f.write("<!DOCTYPE html><html><head><meta charset='utf-8'><style>%s</style></head><body>%s</body></html>"
                    % (css, svg))
        shots = []
        for scale in (1, 2):
            shot = os.path.join(work, "background%s.png" % ("" if scale == 1 else "@2x"))
            subprocess.run([CHROME, "--headless=new", "--disable-gpu", "--hide-scrollbars",
                            "--user-data-dir=" + os.path.join(work, "profile"),
                            "--force-device-scale-factor=%d" % scale,
                            "--window-size=%d,%d" % (WIDTH, HEIGHT), "--virtual-time-budget=2000",
                            "--screenshot=" + shot, "file://" + page],
                           check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            dpi = str(72 * scale)
            subprocess.run(["/usr/bin/sips", "-s", "dpiWidth", dpi, "-s", "dpiHeight", dpi, shot],
                           check=True, stdout=subprocess.DEVNULL)
            shots.append(shot)
        subprocess.run(["/usr/bin/tiffutil", "-cathidpicheck"] + shots + ["-out", out], check=True,
                       stdout=subprocess.DEVNULL)
    print("wrote", out, os.path.getsize(out), "bytes")


if __name__ == "__main__":
    main()
