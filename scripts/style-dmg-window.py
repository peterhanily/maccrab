#!/usr/bin/env python3
"""Lay out the release disk image's Finder window.

build-release.sh runs this on the mounted read-write image after the payload is
copied in and before the payload is validated and the image converted. It adds
three hidden items at the volume root (.background.tiff, .VolumeIcon.icns and
.DS_Store), marks the volume as having a custom icon, and hides the extras so
the window shows only MacCrab and the Applications link. Finder draws the icons
and their names; the background picture carries the arrow and the three steps.

The extras stay on the volume: install.sh keeps its documented path, and the
licence files also ship inside the app bundle.

Every input is pinned: the background, the volume icon and each file of the
vendored ds_store and mac_alias libraries (vendor/dmg-layout). A mismatch stops
the build before anything is written.

usage: style-dmg-window.py --mount PATH --volume-name NAME --background TIFF --icon ICNS
"""
import argparse
import ctypes
import ctypes.util
import hashlib
import os
import shutil
import struct
import sys

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VENDOR = os.path.join(PROJECT_ROOT, "vendor", "dmg-layout")
VENDOR_SHA256 = {
    "ds_store/__init__.py": "a929478a3c647548151d08557a1c8d77b136e1354e8a1a20cad12e978c1a1dda",
    "ds_store/__main__.py": "a56ce2bd7739eace7961f0c87d38988dcc996cb10893b21a701cbf1ab5553b42",
    "ds_store/buddy.py": "794c59af2caf7007f96adba593115568775fcde024b25d16bf7ba19165d26fc1",
    "ds_store/LICENSE": "7d0f4e9418ac55d7e6e03d4aead4cce9ecafe9ea533cf7fb89574193adcf9016",
    "ds_store/store.py": "c6e2b2a4868cb0937c1e74fabda6b4fe9697ea15f7637f8c0095341d2bb907f3",
    "mac_alias/__init__.py": "5ecc74284ebce59f69d06a405629b0acc82eaf5dec1d615803a776b1ec3aa788",
    "mac_alias/alias.py": "db022ce4c54612416c3762cd442a8d530944308f91d5a95a8bec20df7c44456b",
    "mac_alias/bookmark.py": "092754896c3fc32b4260cf552e0f2337c562aad125e849e72ff70760cd37c7ed",
    "mac_alias/LICENSE": "b2eede0626e8dc9fa6f108c896345dbb193282156537c2025d8f5daedc4e58fe",
    "mac_alias/osx.py": "8a8be6c5efef3339cbb15fb80fc376aec23c74b15808c9741d7b4c5e72fd0cea",
    "mac_alias/utils.py": "35f52ec21392e1945e0e9a3877dc85adf64ca1a7940f08aca652fd3d94530fa7",
}
BACKGROUND_SHA256 = "c3b3adfc174e8fb904b74f76b347d8cdafea5ff38848dfae66370da730af9bec"
ICON_SHA256 = "70aeb0f11b13d29c427d703f3baef2d52c85527083a0d0a52aa37f2dac49a084"

APP = "MacCrab.app"
APPLICATIONS = "Applications"
EXTRAS = ("README.md", "install.sh", "LICENSE", "THIRD_PARTY_LICENSES.md", "ThirdPartyNotices")
BACKGROUND, VOLUME_ICON, DS_STORE = ".background.tiff", ".VolumeIcon.icns", ".DS_Store"

# The window's content matches the 660 x 400-point background picture, and the
# icon centres match the picture's arrow.
WINDOW_BOUNDS = "{{200, 120}, {660, 400}}"
ICON_SIZE, TEXT_SIZE = 128.0, 14.0
LOCATIONS = {APP: (180, 142), APPLICATIONS: (480, 142)}
# Below the visible area, in case someone shows hidden files.
for column, name in enumerate(EXTRAS):
    LOCATIONS[name] = (110 + 110 * column, 560)

UF_HIDDEN = 0x8000
FINDER_INFO = b"com.apple.FinderInfo"
HAS_CUSTOM_ICON = 0x0400


def fail(message):
    raise SystemExit("style-dmg-window: " + message)


def sha256_file(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def verify_inputs(background, icon):
    present = sorted(os.path.relpath(os.path.join(d, f), VENDOR)
                     for d, _, files in os.walk(VENDOR) for f in files
                     if f != "SOURCE.txt" and "__pycache__" not in d)
    if present != sorted(VENDOR_SHA256):
        fail("vendored layout libraries changed: %r" % present)
    for rel, digest in VENDOR_SHA256.items():
        path = os.path.join(VENDOR, rel)
        if os.path.islink(path) or sha256_file(path) != digest:
            fail("vendored file does not match its pin: %s" % rel)
    for path, digest in ((background, BACKGROUND_SHA256), (icon, ICON_SHA256)):
        if not os.path.isfile(path) or os.path.islink(path) or sha256_file(path) != digest:
            fail("input does not match its pin: %s" % path)


def set_custom_icon_flag(path):
    """Set kHasCustomIcon in the folder's Finder info, keeping its other bytes."""
    libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
    libc.getxattr.restype = libc.setxattr.restype = ctypes.c_ssize_t
    buf = ctypes.create_string_buffer(32)
    size = libc.getxattr(os.fsencode(path), FINDER_INFO, buf, 32, 0, 0)
    info = bytearray(buf.raw if size == 32 else bytes(32))
    flags = struct.unpack(">H", info[8:10])[0] | HAS_CUSTOM_ICON
    info[8:10] = struct.pack(">H", flags)
    if libc.setxattr(os.fsencode(path), FINDER_INFO, bytes(info), 32, 0, 0) != 0:
        fail("cannot set the custom-icon flag: %s" % os.strerror(ctypes.get_errno()))


def copy_file(source, target):
    shutil.copyfile(source, target)
    os.chmod(target, 0o644)


def style(mount, volume_name, background, icon, app=APP):
    verify_inputs(background, icon)
    sys.path.insert(0, VENDOR)
    from ds_store import DSStore
    from mac_alias import Alias, osx

    mount = os.path.realpath(mount)
    st = osx.statfs(mount)
    if os.fsdecode(st.f_mntonname) != mount:
        fail("%s is not a mount point" % mount)
    if os.fsdecode(st.f_fstypename) != "hfs":
        fail("the image must be HFS+ (Finder window backgrounds are reliable only there)")
    name = osx.getattrlist(mount, [0, osx.ATTR_VOL_NAME, 0, 0, 0], 0)[0]
    if name != volume_name:
        fail("volume is named %r, expected %r" % (name, volume_name))

    visible = sorted(n for n in os.listdir(mount) if not n.startswith("."))
    if visible != sorted((app, APPLICATIONS) + EXTRAS):
        fail("unexpected top-level payload %r; update the window layout first" % visible)
    applications = os.path.join(mount, APPLICATIONS)
    if not os.path.islink(applications) or os.readlink(applications) != "/Applications":
        fail("Applications must be a link to /Applications")
    for existing in (BACKGROUND, VOLUME_ICON, DS_STORE):
        if os.path.lexists(os.path.join(mount, existing)):
            fail("%s already exists on the volume" % existing)

    copy_file(background, os.path.join(mount, BACKGROUND))
    copy_file(icon, os.path.join(mount, VOLUME_ICON))
    set_custom_icon_flag(mount)
    for extra in EXTRAS:
        path = os.path.join(mount, extra)
        os.chflags(path, os.lstat(path).st_flags | UF_HIDDEN)

    alias = Alias.for_file(os.path.join(mount, BACKGROUND))
    # Record what a normal attach shows (the volume root and its mount point),
    # not this build's private mount directory.
    alias.target.folder_name = volume_name.encode("utf-8")
    alias.volume.posix_path = ("/Volumes/" + volume_name).encode("utf-8")

    locations = dict(LOCATIONS)
    locations[app] = locations.pop(APP)
    with DSStore.open(os.path.join(mount, DS_STORE), "w+") as d:
        d["."]["vSrn"] = ("long", 1)
        d["."]["bwsp"] = {
            "WindowBounds": WINDOW_BOUNDS,
            "ShowSidebar": False, "ContainerShowSidebar": False, "SidebarWidth": 180,
            "ShowToolbar": False, "ShowStatusBar": False, "ShowPathbar": False,
            "ShowTabView": False, "PreviewPaneVisibility": False,
        }
        d["."]["icvp"] = {
            "viewOptionsVersion": 1,
            "backgroundType": 2,
            "backgroundImageAlias": alias.to_bytes(),
            "backgroundColorRed": 0.0, "backgroundColorGreen": 0.0, "backgroundColorBlue": 0.0,
            "arrangeBy": "none",
            "gridOffsetX": 0.0, "gridOffsetY": 0.0, "gridSpacing": 100.0,
            "iconSize": ICON_SIZE, "textSize": TEXT_SIZE, "labelOnBottom": True,
            "showIconPreview": False, "showItemInfo": False,
            "scrollPositionX": 0.0, "scrollPositionY": 0.0,
        }
        d["."]["icvl"] = (b"type", b"icnv")
        for item, (x, y) in sorted(locations.items()):
            d[item]["Iloc"] = (x, y)
    os.chmod(os.path.join(mount, DS_STORE), 0o644)
    shutil.rmtree(os.path.join(mount, ".Trashes"), ignore_errors=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--mount", required=True)
    parser.add_argument("--volume-name", required=True)
    parser.add_argument("--background", required=True)
    parser.add_argument("--icon", required=True)
    args = parser.parse_args()
    style(args.mount, args.volume_name, args.background, args.icon)
    print("    ✓ Disk image window laid out (background, icon positions, volume icon)")


if __name__ == "__main__":
    main()
