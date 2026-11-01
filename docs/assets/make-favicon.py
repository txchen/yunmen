#!/usr/bin/env python3
"""Generate the web app icons in web/public from the 门 glyph of Noto Sans
CJK SC Bold (SIL OFL 1.1), outlined so no font is needed at runtime.

    /tmp/venv/bin/python docs/assets/make-favicon.py

Writes favicon.svg, and with ImageMagick available also favicon-32.png and
apple-touch-icon.png.
"""
import os
import shutil
import subprocess

from fontTools.pens.boundsPen import BoundsPen
from fontTools.pens.svgPathPen import SVGPathPen
from fontTools.pens.transformPen import TransformPen
from fontTools.subset import Options, Subsetter
from fontTools.ttLib import TTCollection
from fontTools.varLib.instancer import instantiateVariableFont

CJK = "/usr/share/fonts/google-noto-sans-cjk-vf-fonts/NotoSansCJK-VF.ttc"
PUBLIC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "web", "public")
CREAM, INK, ACCENT = "#f5f3ed", "#252b29", "#bd4b38"

font = TTCollection(CJK).fonts[2]
sub = Subsetter(Options(notdef_outline=True, layout_features=[]))
sub.populate(text="门")
sub.subset(font)
font = instantiateVariableFont(font, {"wght": 800})
glyphs, cmap, upem = font.getGlyphSet(), font.getBestCmap(), font["head"].unitsPerEm
glyph = glyphs[cmap[ord("门")]]

bounds = BoundsPen(glyphs)
glyph.draw(bounds)
x0, y0, x1, y1 = bounds.bounds
s = 46 / upem
tx = (64 - (x1 - x0) * s) / 2 - x0 * s
ty = (64 + (y1 - y0) * s) / 2 + y0 * s
pen = SVGPathPen(glyphs, ntos=lambda v: f"{v:.1f}".rstrip("0").rstrip("."))
glyph.draw(TransformPen(pen, (s, 0, 0, -s, tx, ty)))

svg = (
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">'
    f'<rect width="64" height="64" rx="14" fill="{CREAM}"/>'
    f'<rect x="1.5" y="1.5" width="61" height="61" rx="12.5" fill="none" stroke="{INK}" stroke-width="3"/>'
    f'<path fill="{ACCENT}" d="{pen.getCommands()}"/></svg>'
)
svg_path = os.path.join(PUBLIC, "favicon.svg")
with open(svg_path, "w") as f:
    f.write(svg)
print("wrote", os.path.normpath(svg_path))

# iOS masks home-screen icons itself, so that one is a full square without
# the rounded corners and border.
square = svg.replace(' rx="14"', "").replace(
    f'<rect x="1.5" y="1.5" width="61" height="61" rx="12.5" fill="none" stroke="{INK}" stroke-width="3"/>', "")

if shutil.which("magick"):
    for name, px, source in (("favicon-32.png", 32, svg), ("apple-touch-icon.png", 180, square)):
        out = os.path.join(PUBLIC, name)
        subprocess.run(["magick", "-background", "none", "-density", "1200", "svg:-", "-resize", f"{px}x{px}", "-strip", out],
                       input=source.encode(), check=True)
        print("wrote", os.path.normpath(out))
