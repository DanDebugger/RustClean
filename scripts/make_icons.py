#!/usr/bin/env python3
"""Generates RustClean's app icons into assets/.

The icon is the in-app brand mark: a white Phosphor "broom" on the accent
orange (theme.rs LIGHT.accent, #C2410C) in a rounded square.

    python3 scripts/make_icons.py [path/to/Phosphor-Bold.ttf]

Without an argument the font is taken from the egui-phosphor crate in the
local Cargo registry (MIT licensed). Requires Pillow. Writes:

    assets/icon.png        1024 px master
    assets/icon-256.png    window icon (embedded with include_bytes!)
    assets/RustClean.ico   Windows .exe icon (16-256 px)
    assets/RustClean.icns  macOS app icon (only when `iconutil` exists)

The outputs are committed, so building RustClean never needs Python.
"""

import glob
import os
import shutil
import subprocess
import sys
import tempfile

from PIL import Image, ImageDraw, ImageFont

ACCENT = (0xC2, 0x41, 0x0C, 255)
WHITE = (255, 255, 255, 255)
BROOM = ""  # egui_phosphor::regular::BROOM
MASTER = 1024
ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
ASSETS = os.path.join(ROOT, "assets")


def find_font():
    if len(sys.argv) > 1:
        return sys.argv[1]
    home = os.path.expanduser("~/.cargo/registry/src")
    hits = sorted(glob.glob(f"{home}/*/egui-phosphor-*/res/Phosphor-Bold.ttf"))
    if not hits:
        sys.exit("Phosphor-Bold.ttf not found; pass its path as an argument")
    return hits[-1]


def master(font_path, margin=0.06, glyph=0.58):
    """`margin` and `glyph` are fractions of the size. Small sizes use no
    margin and a bigger glyph so the broom stays legible at 16-32 px."""
    img = Image.new("RGBA", (MASTER, MASTER), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    m = int(MASTER * margin)
    d.rounded_rectangle(
        (m, m, MASTER - m, MASTER - m), radius=int(MASTER * 0.2), fill=ACCENT
    )
    font = ImageFont.truetype(font_path, int(MASTER * glyph))
    # Centre on the glyph's ink box, not its advance box.
    l, t, r, b = d.textbbox((0, 0), BROOM, font=font)
    x = (MASTER - (r - l)) / 2 - l
    y = (MASTER - (b - t)) / 2 - t
    d.text((x, y), BROOM, font=font, fill=WHITE)
    return img


def main():
    os.makedirs(ASSETS, exist_ok=True)
    font = find_font()
    img = master(font)
    small = master(font, margin=0.0, glyph=0.74)
    img.save(os.path.join(ASSETS, "icon.png"))
    img.resize((256, 256), Image.LANCZOS).save(os.path.join(ASSETS, "icon-256.png"))
    # One exact image per size (the small variant up to 32 px).
    sizes = (256, 128, 64, 48, 32, 24, 16)
    frames = [
        (small if s <= 32 else img).resize((s, s), Image.LANCZOS) for s in sizes
    ]
    frames[0].save(
        os.path.join(ASSETS, "RustClean.ico"),
        sizes=[(s, s) for s in sizes],
        append_images=frames[1:],
    )
    if shutil.which("iconutil"):
        with tempfile.TemporaryDirectory() as tmp:
            iconset = os.path.join(tmp, "RustClean.iconset")
            os.makedirs(iconset)
            for s in (16, 32, 128, 256, 512):
                img.resize((s, s), Image.LANCZOS).save(f"{iconset}/icon_{s}x{s}.png")
                img.resize((s * 2, s * 2), Image.LANCZOS).save(
                    f"{iconset}/icon_{s}x{s}@2x.png"
                )
            subprocess.run(
                ["iconutil", "-c", "icns", iconset, "-o",
                 os.path.join(ASSETS, "RustClean.icns")],
                check=True,
            )
    print("icons written to", os.path.normpath(ASSETS))


if __name__ == "__main__":
    main()
