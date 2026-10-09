#!/bin/bash
# build-rave-icon-atlas.sh — rebuild Sources/MacCrabApp/Resources/RaveIcons.heic
# from the Rave store's plugin icons (maccrab-rave: site/static/icons/*.svg).
#
# Each 1024-pixel SVG is rendered by headless Chrome into a 160-pixel tile cropped
# to its 824-unit squircle, then the tiles are packed five to a row with 8-pixel
# transparent gutters into one HEIC (quality 0.8, alpha kept). Store plugins come
# first in name order and the crab fallback last. The script prints the tile
# order and the atlas SHA-256: copy the order into RavePluginIconAtlas.order and
# both into RavePluginIconTests.
#
# Usage: scripts/build-rave-icon-atlas.sh <rave site/static/icons dir> [out.heic]
# CHROME may name the Chrome binary.
set -euo pipefail

ICONS_DIR="${1:?usage: $0 <rave site/static/icons dir> [out.heic]}"
OUT="${2:-Sources/MacCrabApp/Resources/RaveIcons.heic}"
CHROME="${CHROME:-/Applications/Google Chrome.app/Contents/MacOS/Google Chrome}"
TILE=160 GUTTER=8 COLUMNS=5 QUALITY=0.8

WORK=$(/usr/bin/mktemp -d)
trap '/bin/rm -rf "$WORK"' EXIT

scaled=$(/usr/bin/python3 -c "print(round($TILE * 1024 / 824, 3))")
offset=$(/usr/bin/python3 -c "print(round($TILE * 100 / 824, 3))")
: > "$WORK/order.txt"
for svg in $(/bin/ls "$ICONS_DIR"/com-*.svg | /usr/bin/sort) "$ICONS_DIR/_fallback.svg"; do
    name=$(/usr/bin/basename "$svg" .svg)
    /bin/cp "$svg" "$WORK/$name.svg"
    printf '<!doctype html><style>html,body{margin:0;background:transparent;overflow:hidden}div{width:%spx;height:%spx;overflow:hidden;position:relative}img{position:absolute;width:%spx;height:%spx;left:-%spx;top:-%spx}</style><div><img src="%s.svg"></div>' \
        "$TILE" "$TILE" "$scaled" "$scaled" "$offset" "$offset" "$name" > "$WORK/$name.html"
    # Chrome can hang after writing the screenshot, so bound each render
    # (macOS has no timeout(1); perl's alarm does the same).
    /usr/bin/perl -e 'alarm shift; exec @ARGV' 45 "$CHROME" --headless=new --disable-gpu --hide-scrollbars \
        --force-device-scale-factor=1 --default-background-color=00000000 \
        --window-size="$TILE,$TILE" --screenshot="$WORK/$name.png" "file://$WORK/$name.html" >/dev/null 2>&1 || true
    [ -s "$WORK/$name.png" ] || { echo "ERROR: Chrome did not render $svg" >&2; exit 1; }
    echo "$WORK/$name.png" >> "$WORK/order.txt"
done

cat > "$WORK/pack.swift" <<'SWIFT'
import CoreGraphics
import Foundation
import ImageIO
import UniformTypeIdentifiers

let a = CommandLine.arguments
let (out, quality, tile, gutter, columns) = (URL(fileURLWithPath: a[1]), Double(a[2])!, Int(a[3])!, Int(a[4])!, Int(a[5])!)
let files = Array(a[6...])
let pitch = tile + gutter
let width = columns * pitch - gutter
let height = ((files.count + columns - 1) / columns) * pitch - gutter
let context = CGContext(data: nil, width: width, height: height, bitsPerComponent: 8, bytesPerRow: 0,
                        space: CGColorSpace(name: CGColorSpace.sRGB)!,
                        bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue)!
for (i, file) in files.enumerated() {
    let source = CGImageSourceCreateWithURL(URL(fileURLWithPath: file) as CFURL, nil)!
    let image = CGImageSourceCreateImageAtIndex(source, 0, nil)!
    precondition(image.width == tile && image.height == tile, "\(file) is \(image.width)x\(image.height)")
    // CoreGraphics draws from the bottom-left; tile row 0 is the top row.
    context.draw(image, in: CGRect(x: (i % columns) * pitch, y: height - (i / columns + 1) * pitch + gutter,
                                   width: tile, height: tile))
}
let destination = CGImageDestinationCreateWithURL(out as CFURL, UTType.heic.identifier as CFString, 1, nil)!
CGImageDestinationAddImage(destination, context.makeImage()!,
                           [kCGImageDestinationLossyCompressionQuality: quality] as CFDictionary)
precondition(CGImageDestinationFinalize(destination), "HEIC encode failed")
SWIFT

/usr/bin/xargs /usr/bin/swift "$WORK/pack.swift" "$OUT" "$QUALITY" "$TILE" "$GUTTER" "$COLUMNS" < "$WORK/order.txt"
echo "Tile order:"
/usr/bin/sed -e 's#.*/##' -e 's#\.png$##' -e 's#^com-maccrab-forensics-#com.maccrab.forensics.#' "$WORK/order.txt"
echo "SHA-256: $(/usr/bin/shasum -a 256 "$OUT" | /usr/bin/awk '{print $1}')"
