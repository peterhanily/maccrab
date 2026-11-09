#!/usr/bin/env python3
"""scripts/style-dmg-window.py lays out the disk image window and fails closed.

Builds small read-write disk images the way build-release.sh does (attached
with -nobrowse at a private mount point), runs the styler, converts the image
and checks the layout survives conversion. Also checks every refusal: a wrong
volume name, an unexpected payload, an Applications folder that is not the
/Applications link, an existing layout, an APFS image, and unpinned inputs.
"""
import hashlib
import os
import plistlib
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
STYLER = ROOT / "scripts/style-dmg-window.py"
VENDOR = ROOT / "vendor/dmg-layout"
BACKGROUND = ROOT / "scripts/dmg-window/background.tiff"
ICON = ROOT / "Sources/MacCrabApp/Resources/AppIcon.icns"
EXTRAS = ("README.md", "install.sh", "LICENSE", "THIRD_PARTY_LICENSES.md", "ThirdPartyNotices")
VOLUME = "MacCrab v0.0.0-test"


def hdiutil(*args):
    return subprocess.run(["/usr/bin/hdiutil", *args], check=True, capture_output=True, text=True).stdout


def attach(image, mount, readonly=False):
    hdiutil("attach", *(["-readonly"] if readonly else []), "-nobrowse", "-noautoopen", "-mountpoint", mount, image)


def detach(mount):
    subprocess.run(["/usr/bin/hdiutil", "detach", mount, "-force"], capture_output=True)


def payload(mount, extra=None, applications_link=True):
    app = Path(mount, "MacCrab.app/Contents")
    app.mkdir(parents=True)
    (app / "Info.plist").write_bytes(plistlib.dumps({"CFBundleIdentifier": "com.maccrab.app"}))
    if applications_link:
        os.symlink("/Applications", os.path.join(mount, "Applications"))
    else:
        os.mkdir(os.path.join(mount, "Applications"))
    for name in EXTRAS:
        if name == "ThirdPartyNotices":
            Path(mount, name).mkdir()
            Path(mount, name, "NOTICE").write_text("notice\n")
        else:
            Path(mount, name).write_text(name + "\n")
    if extra:
        Path(mount, extra).write_text("unexpected\n")


def run_styler(mount, volume=VOLUME, styler=STYLER, background=BACKGROUND, icon=ICON):
    return subprocess.run(["/usr/bin/python3", "-I", "-B", str(styler), "--mount", mount, "--volume-name", volume,
                           "--background", str(background), "--icon", str(icon)],
                          capture_output=True, text=True)


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


class Volume:
    """A fresh read-write image attached at a private mount point."""

    def __init__(self, fs="HFS+", volume=VOLUME):
        self.dir = tempfile.mkdtemp(prefix="maccrab-dmg-style-test.")
        self.image = os.path.join(self.dir, "work.dmg")
        self.mount = os.path.join(self.dir, "maccrab-dmg-mnt.private")
        os.mkdir(self.mount)
        hdiutil("create", "-size", "8m", "-fs", fs, "-volname", volume, "-ov", self.image)
        attach(self.image, self.mount)

    def close(self):
        detach(self.mount)
        shutil.rmtree(self.dir, ignore_errors=True)


class StyleDMGWindowTests(unittest.TestCase):
    def check_layout(self, mount):
        sys.path.insert(0, str(VENDOR))
        try:
            from ds_store import DSStore
            from mac_alias import Alias
        finally:
            sys.path.remove(str(VENDOR))
        with DSStore.open(os.path.join(mount, ".DS_Store"), "r") as d:
            bwsp, icvp = d["."]["bwsp"], d["."]["icvp"]
            self.assertEqual(bwsp["WindowBounds"], "{{200, 120}, {660, 400}}")
            self.assertFalse(bwsp["ShowToolbar"] or bwsp["ShowSidebar"] or bwsp["ShowStatusBar"] or bwsp["ShowPathbar"])
            self.assertEqual((icvp["backgroundType"], icvp["iconSize"], icvp["arrangeBy"]), (2, 128.0, "none"))
            alias = Alias.from_bytes(icvp["backgroundImageAlias"])
            self.assertEqual(alias.volume.name, VOLUME)
            self.assertEqual(alias.volume.posix_path, "/Volumes/" + VOLUME)
            self.assertEqual(alias.target.filename, ".background.tiff")
            self.assertEqual(alias.target.folder_name, VOLUME)
            self.assertEqual(d["MacCrab.app"]["Iloc"], (180, 142))
            self.assertEqual(d["Applications"]["Iloc"], (480, 142))
            for name in EXTRAS:
                self.assertGreater(d[name]["Iloc"][1], 400, name)
        # The build's private mount directory must not reach the published image.
        layout = Path(mount, ".DS_Store").read_bytes()
        for marker in ("maccrab-dmg-mnt", "maccrab-dmg-style-test", "/private/"):
            for encoding in ("utf-8", "utf-16-be"):
                self.assertNotIn(marker.encode(encoding), layout, (marker, encoding))
        self.assertEqual(sha256(os.path.join(mount, ".background.tiff")), sha256(BACKGROUND))
        self.assertEqual(sha256(os.path.join(mount, ".VolumeIcon.icns")), sha256(ICON))
        for name in EXTRAS:
            self.assertTrue(os.lstat(os.path.join(mount, name)).st_flags & 0x8000, name + " is not hidden")
        for name in ("MacCrab.app", "Applications"):
            self.assertFalse(os.lstat(os.path.join(mount, name)).st_flags & 0x8000, name + " is hidden")
        info = subprocess.run(["/usr/bin/xattr", "-px", "com.apple.FinderInfo", mount],
                              capture_output=True, text=True, check=True).stdout.split()
        self.assertEqual(int(info[8], 16) & 0x04, 0x04, "volume custom-icon flag missing")

    def test_layout_survives_conversion(self):
        v = Volume()
        try:
            payload(v.mount)
            result = run_styler(v.mount)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.check_layout(v.mount)
            detach(v.mount)
            final = os.path.join(v.dir, "final.dmg")
            hdiutil("convert", v.image, "-format", "ULMO", "-ov", "-o", final)
            attach(final, v.mount, readonly=True)
            self.check_layout(v.mount)
        finally:
            v.close()

    def assert_refused(self, v, message, **kwargs):
        result = run_styler(v.mount, **kwargs)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(message, result.stderr)
        self.assertFalse(os.path.lexists(os.path.join(v.mount, ".DS_Store")), "refusal wrote a layout")

    def test_refuses_wrong_volume_name(self):
        v = Volume()
        try:
            payload(v.mount)
            self.assert_refused(v, "expected", volume="MacCrab v9.9.9")
        finally:
            v.close()

    def test_refuses_unexpected_payload(self):
        v = Volume()
        try:
            payload(v.mount, extra="Surprise.txt")
            self.assert_refused(v, "unexpected top-level payload")
        finally:
            v.close()

    def test_refuses_applications_folder_that_is_not_the_link(self):
        v = Volume()
        try:
            payload(v.mount, applications_link=False)
            self.assert_refused(v, "link to /Applications")
        finally:
            v.close()

    def test_refuses_existing_layout(self):
        v = Volume()
        try:
            payload(v.mount)
            Path(v.mount, ".DS_Store").write_bytes(b"")
            result = run_styler(v.mount)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("already exists", result.stderr)
        finally:
            v.close()

    def test_refuses_apfs(self):
        v = Volume(fs="APFS")
        try:
            payload(v.mount)
            self.assert_refused(v, "HFS+")
        finally:
            v.close()

    def test_refuses_unpinned_inputs(self):
        v = Volume()
        work = tempfile.mkdtemp(prefix="maccrab-dmg-style-pins.")
        try:
            payload(v.mount)
            other = Path(work, "background.tiff")
            other.write_bytes(BACKGROUND.read_bytes() + b"\0")
            self.assert_refused(v, "does not match its pin", background=other)
            # A tampered vendored library is refused before it is imported.
            tree = Path(work, "tree")
            (tree / "scripts").mkdir(parents=True)
            shutil.copy2(STYLER, tree / "scripts")
            shutil.copytree(VENDOR, tree / "vendor/dmg-layout")
            with open(tree / "vendor/dmg-layout/mac_alias/alias.py", "a") as f:
                f.write("\n# tampered\n")
            self.assert_refused(v, "vendored file does not match its pin", styler=tree / "scripts/style-dmg-window.py")
        finally:
            v.close()
            shutil.rmtree(work, ignore_errors=True)

    def test_background_has_1x_and_2x_representations(self):
        info = subprocess.run(["/usr/bin/tiffutil", "-info", str(BACKGROUND)],
                              capture_output=True, text=True, check=True).stdout
        sizes = [line.split() for line in info.splitlines() if "Image Width" in line]
        self.assertEqual([(s[2], s[5]) for s in sizes], [("660", "400"), ("1320", "800")])


if __name__ == "__main__":
    unittest.main()
