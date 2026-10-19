#!/usr/bin/env bash
# Every text in a diagram sits inside a box it fits in, with at least six
# pixels to spare on every side, and every one of them is measured, not
# assumed. Default: the .svg files in docs/. Arguments: files or directories.
#
# WHAT IT MEASURES
#
# Each <text> is given the advance width of its string in Helvetica (the Adobe
# Core 14 AFM widths, which Arial matches by design), its font size, its anchor
# and its baseline. Its box is the cap height above the baseline to the
# descender below it. The box that holds its centre is the smallest <rect> that
# contains that centre; the slack is the least distance from the text box to
# that rect's edges. A text that no rect holds is a finding, never skipped.
#
# WHAT IT REFUSES TO PASS ON
#
# No SVG file, an unparseable one, a text with no measurable font (only
# Helvetica or Arial, and no bold), a tspan or a transform (the layout would
# not be the one measured), a non-ASCII character, or zero texts in all of the
# files: each is "measured nothing" and exits 1.
#
# WHAT IT DOES NOT MEASURE
#
# How a browser shapes the glyphs. The widths are the design font's, not a
# render's, so a renderer that falls back to another face is not checked here.
# That is named in NOT PROVEN in README.md.
set -uo pipefail
cd "$(git rev-parse --show-toplevel)" || exit 1

python3 - "$@" <<'PY'
import pathlib, sys
import xml.etree.ElementTree as ET

SVG = "{http://www.w3.org/2000/svg}"
MIN_SLACK = 6.0
CAP_HEIGHT = 0.718   # Helvetica cap height, per em
DESCENDER = 0.207    # Helvetica descender, per em

# Helvetica advance widths in 1/1000 em, printable ASCII.
W = {
    " ": 278, "!": 278, '"': 355, "#": 556, "$": 556, "%": 889, "&": 667, "'": 191,
    "(": 333, ")": 333, "*": 389, "+": 584, ",": 278, "-": 333, ".": 278, "/": 278,
    "0": 556, "1": 556, "2": 556, "3": 556, "4": 556, "5": 556, "6": 556, "7": 556,
    "8": 556, "9": 556, ":": 278, ";": 278, "<": 584, "=": 584, ">": 584, "?": 556,
    "@": 1015, "A": 667, "B": 667, "C": 722, "D": 722, "E": 667, "F": 611, "G": 778,
    "H": 722, "I": 278, "J": 500, "K": 667, "L": 556, "M": 833, "N": 722, "O": 778,
    "P": 667, "Q": 778, "R": 722, "S": 667, "T": 611, "U": 722, "V": 667, "W": 944,
    "X": 667, "Y": 667, "Z": 611, "[": 278, "\\": 278, "]": 278, "^": 469, "_": 556,
    "`": 333, "a": 556, "b": 556, "c": 500, "d": 556, "e": 556, "f": 278, "g": 556,
    "h": 556, "i": 222, "j": 222, "k": 500, "l": 222, "m": 833, "n": 556, "o": 556,
    "p": 556, "q": 556, "r": 333, "s": 500, "t": 278, "u": 556, "v": 500, "w": 722,
    "x": 500, "y": 500, "z": 500, "{": 334, "|": 260, "}": 334, "~": 584,
}
assert len(W) == 95, "the width table must cover printable ASCII"


def nothing(why):
    print(f"FAIL: {why}, so this check measured nothing.")
    sys.exit(1)


def num(el, name, default=None):
    raw = el.get(name, default)
    if raw is None:
        return None
    try:
        return float(raw.replace("px", ""))
    except ValueError:
        return None


args = sys.argv[1:] or ["docs"]
files = []
for a in args:
    p = pathlib.Path(a)
    if p.is_dir():
        files += sorted(p.glob("*.svg"))
    elif p.is_file():
        files.append(p)
    else:
        nothing(f"{a} is not there")
if not files:
    nothing("no .svg file to measure")

fails = []
measured = []  # (slack, file, text, box)
for f in files:
    try:
        root = ET.parse(f).getroot()
    except ET.ParseError as e:
        nothing(f"{f} does not parse ({e})")
    if root.tag != SVG + "svg":
        nothing(f"{f} is not an SVG document")
    for el in root.iter():
        if "transform" in el.attrib:
            fails.append(f"{f}: a transform on <{el.tag.replace(SVG, '')}> is not measured; lay it out with plain coordinates")
    if any(True for _ in root.iter(SVG + "tspan")):
        fails.append(f"{f}: a tspan is not measured; give each line its own <text>")

    rects = []
    for r in root.iter(SVG + "rect"):
        x, y = num(r, "x", "0"), num(r, "y", "0")
        w, h = num(r, "width"), num(r, "height")
        if None in (x, y, w, h):
            fails.append(f"{f}: a rect without numeric x, y, width and height")
            continue
        rects.append((x, y, w, h))

    for t in root.iter(SVG + "text"):
        text = "".join(t.itertext())
        size = num(t, "font-size")
        family = t.get("font-family", "")
        weight = t.get("font-weight", "normal")
        anchor = t.get("text-anchor", "start")
        x, y = num(t, "x"), num(t, "y")
        if size is None or x is None or y is None:
            fails.append(f"{f}: a text without numeric x, y and font-size: {text!r}")
            continue
        if "Helvetica" not in family and "Arial" not in family:
            fails.append(f"{f}: {text!r} is set in {family!r}, a face with no measured widths")
            continue
        if weight not in ("normal", "400"):
            fails.append(f"{f}: {text!r} is {weight}, and only the regular widths are measured")
            continue
        if anchor not in ("start", "middle", "end"):
            fails.append(f"{f}: {text!r} has text-anchor {anchor!r}")
            continue
        bad = [c for c in text if c not in W]
        if bad:
            fails.append(f"{f}: {text!r} holds {bad!r}, outside printable ASCII; no width is measured for it")
            continue
        width = sum(W[c] for c in text) / 1000.0 * size
        left = {"start": x, "middle": x - width / 2, "end": x - width}[anchor]
        right = left + width
        top, bottom = y - CAP_HEIGHT * size, y + DESCENDER * size
        cx, cy = (left + right) / 2, (top + bottom) / 2
        holding = [r for r in rects if r[0] <= cx <= r[0] + r[2] and r[1] <= cy <= r[1] + r[3]]
        if not holding:
            fails.append(f"{f}: no box holds the centre of {text!r} at ({cx:.1f}, {cy:.1f})")
            continue
        box = min(holding, key=lambda r: r[2] * r[3])
        bx, by, bw, bh = box
        slack = min(left - bx, bx + bw - right, top - by, by + bh - bottom)
        measured.append((slack, str(f), text, box))
        if slack < MIN_SLACK:
            fails.append(f"{f}: {text!r} has {slack:.1f}px to spare in its box, the minimum is {MIN_SLACK:g}px")

if not measured and not fails:
    nothing("the diagrams hold no text")
if fails:
    for line in fails:
        print("FAIL: " + line)
    sys.exit(1)

measured.sort()
slack, where, text, _ = measured[0]
print(f"OK: {len(measured)} text(s) in {len(files)} diagram(s) fit their boxes; smallest slack {slack:.1f}px ({text!r} in {where}).")
PY
