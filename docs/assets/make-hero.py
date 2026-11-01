#!/usr/bin/env python3
"""Generate docs/assets/yunmen.svg, the README illustration.

All lettering is converted to outlines so the image looks the same on every
viewer. Requires fonttools and the Noto fonts (SIL OFL 1.1) at the paths
below, as installed by Fedora's google-noto packages:

    python3 -m venv /tmp/venv && /tmp/venv/bin/pip install fonttools
    /tmp/venv/bin/python docs/assets/make-hero.py
"""
import os

from fontTools.pens.svgPathPen import SVGPathPen
from fontTools.pens.transformPen import TransformPen
from fontTools.subset import Options, Subsetter
from fontTools.ttLib import TTCollection, TTFont
from fontTools.varLib.instancer import instantiateVariableFont

NOTO = "/usr/share/fonts/google-noto-vf"
CJK = "/usr/share/fonts/google-noto-sans-cjk-vf-fonts/NotoSansCJK-VF.ttc"
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "yunmen.svg")

BG, INK, MUTED, LINE = "#f5f3ed", "#252b29", "#6f746c", "#d9d6cb"
ACCENT, ACCENT_SOFT = "#bd4b38", "#f1ddd6"
TERM_BG, TERM_FG, TERM_DIM, TERM_OK = "#1f2422", "#e9e6dd", "#8f978f", "#8fbf8a"
TMUX_BAR = "#4f7f5b"


def load(path, wght, index=None, text=None):
    font = TTCollection(path).fonts[index] if index is not None else TTFont(path)
    if text:
        # The CJK collection is large; keep only the glyphs this image uses.
        sub = Subsetter(Options(notdef_outline=True, layout_features=[]))
        sub.populate(text=text)
        sub.subset(font)
    return instantiateVariableFont(font, {"wght": wght}) if "fvar" in font else font


GLYPH_DEFS = {}


class Face:
    """One font at one weight. Each glyph is defined once in <defs> and
    placed with <use>, which keeps the repeated terminal text small."""

    def __init__(self, font, name):
        self.glyphs = font.getGlyphSet()
        self.cmap = font.getBestCmap()
        self.upem = font["head"].unitsPerEm
        self.name = name

    def width(self, text, size):
        return sum(self.glyphs[self.cmap[ord(c)]].width for c in text) * size / self.upem

    def glyph_id(self, c):
        gid = f"{self.name}-{ord(c):x}"
        if gid not in GLYPH_DEFS:
            pen = SVGPathPen(self.glyphs, ntos=lambda v: str(round(v)))
            self.glyphs[self.cmap[ord(c)]].draw(pen)
            d = pen.getCommands()
            GLYPH_DEFS[gid] = f'<path id="{gid}" d="{d}"/>' if d else ""
        return gid if GLYPH_DEFS[gid] else None

    def path(self, text, x, y, size, fill, anchor="start"):
        if anchor == "middle":
            x -= self.width(text, size) / 2
        elif anchor == "end":
            x -= self.width(text, size)
        s = size / self.upem
        uses = []
        for c in text:
            gid = self.glyph_id(c)
            if gid:
                uses.append(f'<use href="#{gid}" transform="translate({x:.1f} {y:.1f}) scale({s:.5f} -{s:.5f})"/>')
            x += self.glyphs[self.cmap[ord(c)]].width * s
        return f'<g fill="{fill}">{"".join(uses)}</g>' if uses else ""


sans = Face(load(f"{NOTO}/NotoSans[wght].ttf", 400), "s")
sans_med = Face(load(f"{NOTO}/NotoSans[wght].ttf", 600), "sm")
sans_bold = Face(load(f"{NOTO}/NotoSans[wght].ttf", 760), "sb")
mono = Face(load(f"{NOTO}/NotoSansMono[wght].ttf", 420), "m")
mono_bold = Face(load(f"{NOTO}/NotoSansMono[wght].ttf", 650), "mb")
cjk_bold = Face(load(CJK, 760, index=2, text="云门"), "cb")

W, H = 960, 600
out = []
add = out.append


def rect(x, y, w, h, fill="none", stroke=None, sw=2, rx=0):
    s = f' stroke="{stroke}" stroke-width="{sw}"' if stroke else ""
    add(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="{rx}" fill="{fill}"{s}/>')


add(f'<rect width="{W}" height="{H}" rx="18" fill="{BG}"/>')

# Title: 云门 Yunmen, and what it is for.
add(cjk_bold.path("云门", 52, 104, 56, INK))
add(sans_bold.path("Yunmen", 182, 100, 44, INK))
add(sans.path("Your own servers from any browser or terminal.", 54, 140, 19, MUTED))
add(sans.path("SSH keys stay on the gateway, never on the device in your hands.", 54, 166, 19, MUTED))

# Browser window: hosts on the left, terminal tabs on the right.
bx, by, bw, bh = 52, 198, 540, 290
rect(bx, by, bw, bh, "#ffffff", INK, 2.5, 12)
for i, c in enumerate(["#e3a093", "#e8cf8f", "#a9c9a0"]):
    add(f'<circle cx="{bx + 22 + i * 18}" cy="{by + 20}" r="5" fill="{c}"/>')
rect(bx + 84, by + 9, 220, 22, BG, None, rx=11)
add(sans.path("yunmen.example.com", bx + 96, by + 25, 13, MUTED))
add(f'<path d="M{bx} {by + 40}H{bx + bw}" stroke="{LINE}" stroke-width="1.5"/>')

sx = bx + 132
add(f'<path d="M{sx} {by + 40}V{by + bh - 1}" stroke="{LINE}" stroke-width="1.5"/>')
add(sans_med.path("Hosts", bx + 16, by + 66, 13, MUTED))
hosts = [("home", True), ("vps", False), ("nas", False), ("pi", False)]
for i, (name, active) in enumerate(hosts):
    hy = by + 80 + i * 34
    if active:
        rect(bx + 8, hy, 116, 28, ACCENT_SOFT, None, rx=6)
        rect(bx + 8, hy + 5, 4, 18, ACCENT, None, rx=2)
    add(f'<circle cx="{bx + 26}" cy="{hy + 14}" r="4" fill="{TERM_OK if name != "pi" else LINE}"/>')
    add(sans_med.path(name, bx + 38, hy + 19, 14, INK))
add(sans.path("Keys · Devices", bx + 16, by + bh - 18, 12, MUTED))

tabs = [("home", True), ("home #2", False), ("Files · nas", False)]
tx = sx + 10
for label, active in tabs:
    tw = sans_med.width(label, 13) + 26
    rect(tx, by + 48, tw, 26, TERM_BG if active else BG, None, rx=6)
    add(sans_med.path(label, tx + 13, by + 66, 13, TERM_FG if active else INK))
    tx += tw + 6

px, py, pw, ph = sx + 10, by + 80, bx + bw - sx - 20, bh - 92
rect(px, py, pw, ph, TERM_BG, None, rx=8)
lines = [
    [("me@home", TERM_OK), (":~$ ", TERM_FG), ("tmux new -A -s main", TERM_FG)],
    [("me@home", TERM_OK), (":~$ ", TERM_FG), ("git pull", TERM_FG)],
    [("Already up to date.", TERM_DIM)],
    [("me@home", TERM_OK), (":~$ ", TERM_FG), ("echo 你好, café", TERM_FG)],
    [("你好, café", TERM_FG)],
    [("me@home", TERM_OK), (":~$ ", TERM_FG)],
]


def term_line(x, y, parts, size=13.5):
    for text, color in parts:
        for chunk, f in split_cjk(text):
            add(f.path(chunk, x, y, size, color))
            x += f.width(chunk, size) if f is mono else size * len(chunk)
    return x


def split_cjk(text):
    runs, cur, cur_cjk = [], "", None
    for c in text:
        is_cjk = 0x2E80 <= ord(c) <= 0x9FFF
        if cur and is_cjk != cur_cjk:
            runs.append((cur, cjk_regular if cur_cjk else mono))
            cur = ""
        cur, cur_cjk = cur + c, is_cjk
    if cur:
        runs.append((cur, cjk_regular if cur_cjk else mono))
    return runs


cjk_regular = Face(load(CJK, 400, index=2, text="你好"), "c")
for i, parts in enumerate(lines):
    end = term_line(px + 14, py + 26 + i * 22, parts)
rect(end + 1, py + 26 + 5 * 22 - 13, 8, 16, TERM_FG, None)
rect(px, py + ph - 24, pw, 24, TMUX_BAR, None, rx=0)
add(f'<rect x="{px}" y="{py + ph - 10}" width="{pw}" height="10" rx="8" fill="{TMUX_BAR}"/>')
add(mono_bold.path("[main] 0:bash*", px + 12, py + ph - 8, 12.5, "#f4f1e8"))
add(mono.path('"home" 21:04', px + pw - 12, py + ph - 8, 12.5, "#f4f1e8", anchor="end"))

# CLI window on another machine.
cx, cy, cw, ch = 620, 236, 290, 252
rect(cx, cy, cw, ch, TERM_BG, INK, 2.5, 12)
for i, c in enumerate(["#e3a093", "#e8cf8f", "#a9c9a0"]):
    add(f'<circle cx="{cx + 22 + i * 18}" cy="{cy + 20}" r="5" fill="{c}"/>')
add(sans_med.path("work laptop", cx + cw - 16, cy + 25, 13, TERM_DIM, anchor="end"))
cli = [
    [("$ ", TERM_DIM), ("yunmen connect", TERM_FG)],
    [("  1) home  ", TERM_FG), ("me@10.0.0.2", TERM_DIM)],
    [("  2) vps   ", TERM_FG), ("root@vps.example", TERM_DIM)],
    [("  3) nas   ", TERM_FG), ("me@nas.lan", TERM_DIM)],
    [("Select host: ", TERM_FG), ("vps", TERM_OK)],
    [("root@vps", TERM_OK), (":~# ", TERM_FG), ("vim app.conf", TERM_FG)],
    [("", TERM_FG)],
    [("Enter ~ . to disconnect", TERM_DIM)],
]
for i, parts in enumerate(cli):
    term_line(cx + 18, cy + 60 + i * 23, parts, 13.5)

# What you get, in four short lines.
features = [
    ("key", "Keys and passwords", "stay on the gateway"),
    ("shield", "Cloudflare Access", "plus password + TOTP"),
    ("files", "Browse, upload and", "download files"),
    ("revoke", "Revoke one device;", "its terminals close"),
]
fy, fw, gap = 512, 204, 16
for i, (icon, l1, l2) in enumerate(features):
    fx = 52 + i * (fw + gap)
    rect(fx, fy, fw, 58, "#ffffff", LINE, 1.5, 10)
    ix, iy = fx + 26, fy + 29
    stroke = f'fill="none" stroke="{ACCENT}" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"'
    if icon == "key":
        add(f'<g {stroke}><circle cx="{ix - 5}" cy="{iy}" r="6"/><path d="M{ix + 1} {iy}H{ix + 13}M{ix + 9} {iy}V{iy + 5}M{ix + 13} {iy}V{iy + 4}"/></g>')
    elif icon == "shield":
        add(f'<g {stroke}><path d="M{ix} {iy - 11}L{ix + 10} {iy - 7}V{iy}C{ix + 10} {iy + 6} {ix + 5} {iy + 10} {ix} {iy + 12}C{ix - 5} {iy + 10} {ix - 10} {iy + 6} {ix - 10} {iy}V{iy - 7}Z"/><path d="M{ix - 4} {iy}L{ix - 1} {iy + 3}L{ix + 5} {iy - 4}"/></g>')
    elif icon == "files":
        add(f'<g {stroke}><path d="M{ix - 11} {iy - 7}H{ix - 3}L{ix} {iy - 4}H{ix + 11}V{iy + 9}H{ix - 11}Z"/><path d="M{ix} {iy + 5}V{iy - 1}M{ix - 3} {iy + 2}L{ix} {iy - 1}L{ix + 3} {iy + 2}"/></g>')
    else:
        add(f'<g {stroke}><rect x="{ix - 11}" y="{iy - 9}" width="22" height="14" rx="2"/><path d="M{ix - 14} {iy + 9}H{ix + 14}M{ix - 4} {iy - 5}L{ix + 4} {iy + 1}M{ix + 4} {iy - 5}L{ix - 4} {iy + 1}"/></g>')
    for text, face in ((l1, sans_med), (l2, sans)):
        assert face.width(text, 13.5) <= fw - 62, f"feature text too wide: {text!r}"
    add(sans_med.path(l1, fx + 50, fy + 25, 13.5, INK))
    add(sans.path(l2, fx + 50, fy + 44, 13.5, INK))

svg = (
    f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}" role="img" aria-labelledby="title desc">'
    '<title id="title">Yunmen</title>'
    '<desc id="desc">Yunmen in a browser, with a host list and terminal tabs running tmux, next to a work laptop '
    'terminal running yunmen connect. SSH keys stay on the gateway; access needs Cloudflare Access, a password and TOTP; '
    'files can be browsed, uploaded and downloaded; a single device can be revoked.</desc>'
    '<metadata>Original Yunmen artwork. Lettering outlined from Noto Sans, Noto Sans Mono and Noto Sans CJK SC, '
    'licensed under SIL OFL 1.1. This SVG is artwork, not a redistributed font. Generated by docs/assets/make-hero.py.</metadata>'
    + "<defs>" + "".join(GLYPH_DEFS.values()) + "</defs>"
    + "".join(out)
    + "</svg>"
)
with open(OUT, "w") as f:
    f.write(svg)
print(f"wrote {OUT} ({len(svg)} bytes)")
