"""App icon: the top of an MSM-style chip package whose laser marking carries this build's data.

python3 branding/chip_icon.py --platform "WIN X64" --out DIR [--version 0.1.0] [--date 2026-11-14] [--commit SHA]
Defaults: version from pyproject.toml, commit = git HEAD of this checkout, date = today (SOURCE_DATE_EPOCH if set).

Writes 1024x1024 SVG layers to DIR:
  full.svg          plate + marking (main icon)        small.svg          plate + "MSM5" + pin-1 dot
  plate.svg         background layer only              small-marking.svg  "MSM5" + dot only
  marking.svg       marking + dot only (light gray; recolour for tinted/themed/symbolic use)
Platform builds turn these into .ico/.icns/.icon/asset catalogs/adaptive icons. The marking font is
Hershey Sans 1-stroke (single-stroke, like laser marking), read from Inkscape's svg_fonts folder.
Layout ratios follow a real MSM5100 package; date codes are YYWW (ISO year/week) as on the part."""
from __future__ import annotations

import argparse
import datetime
import os
import re
import subprocess
from pathlib import Path

S = 1024
INK, DOT = "#9fa2a5", "#9fa1a3"
HERSHEY = Path("/usr/share/inkscape/extensions/svg_fonts/HersheySans1.svg")
DEFS = ('<defs><linearGradient id="pkg" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#46494d"/>'
        '<stop offset="1" stop-color="#2c2e31"/></linearGradient><filter id="grain"><feTurbulence type="fractalNoise" '
        'baseFrequency="1.6" numOctaves="2" seed="3"/><feColorMatrix values="0 0 0 0 0.6  0 0 0 0 0.6  0 0 0 0 0.62  '
        '0 0 0 0.10 0"/><feComposite in2="SourceGraphic" operator="in"/></filter></defs>')
PLATE = f'<rect width="{S}" height="{S}" fill="url(#pkg)"/><rect width="{S}" height="{S}" filter="url(#grain)"/>'


def marking_lines(version: str, day: datetime.date, commit: str, platform: str) -> list[str]:
    """Six marking lines below the wordmark (QEM = QEMU backend, final A = release build)."""
    major, minor, patch = (int(x) for x in (version.split(".") + ["0", "0"])[:3])
    year, week, _ = day.isocalendar()
    yyww = f"{year % 100:02d}{week:02d}"
    return ["EMULATOR", f"QT10-V{major}{minor:02d}{patch}-0", f"14 {yyww}{commit[:5].upper()}",
            f"BM {yyww}K{day:%m%d}", f"{day:%y%m%d}QEM A", platform.upper()]


def _glyphs() -> dict[str, tuple[float, str]]:
    text = HERSHEY.read_text(encoding="utf-8")
    return {m[0]: (float(m[1]), m[2]) for m in
            re.findall(r'<glyph unicode="(.)"[^>]*?horiz-adv-x="([\d.]+)"(?: d="([^"]*)")?', text)}


def stroke_text(glyphs, text, x, baseline, color, width, *, cap=0.0, cell=None, fit=None) -> str:
    """Hershey glyphs as stroked paths (cap height 662 units): fixed pitch with cell, else proportional; fit sets total width."""
    k = fit / sum(glyphs.get(ch, (500, ""))[0] * 1.12 for ch in text) if fit else cap / 662
    parts, pen = [], x
    for ch in text:
        advance, path = glyphs.get(ch, (500, ""))
        left = pen + (cell - advance * k) / 2 if cell else pen
        pen += cell if cell else advance * k * 1.12
        if path:
            parts.append(f'<path transform="translate({left:.1f} {baseline:.1f}) scale({k:.4f} {-k:.4f})" d="{path}"/>')
    return (f'<g fill="none" stroke="{color}" stroke-width="{width / k:.1f}" stroke-linecap="round" '
            f'stroke-linejoin="round">{"".join(parts)}</g>')


def centered_text(glyphs, text, center_x, baseline, ink_width, color, width) -> str:
    """Proportional Hershey text whose drawn strokes (not advances) are ink_width wide and centred on center_x."""
    pen, left, right = 0.0, None, 0.0
    for ch in text:
        advance, path = glyphs.get(ch, (500, ""))
        xs = [float(v) for v in re.findall(r"-?[\d.]+", path)][0::2]
        if xs:
            left = pen + min(xs) if left is None else left
            right = pen + max(xs)
        pen += advance * 1.12
    k = ink_width / (right - left)
    return stroke_text(glyphs, text, center_x - (left + right) / 2 * k, baseline, color, width, fit=pen * k)


def layers(version: str, day: datetime.date, commit: str, platform: str) -> dict[str, str]:
    glyphs = _glyphs()
    marking = stroke_text(glyphs, "MSM5xxx", 0.17 * S, 0.235 * S, INK, 0.014 * S, cap=0.078 * S)
    marking += "".join(stroke_text(glyphs, line, 0.17 * S, (0.356 + 0.089 * i) * S, INK, 0.0065 * S, cap=0.052 * S, cell=0.051 * S)
                       for i, line in enumerate(marking_lines(version, day, commit, platform)))
    marking += f'<circle cx="{0.125 * S:.0f}" cy="{0.885 * S:.0f}" r="{0.029 * S:.0f}" fill="{DOT}"/>'
    small = (centered_text(glyphs, "MSM5", 0.5 * S, 0.62 * S, 0.68 * S, "#c4c6c8", 0.034 * S)
             + f'<circle cx="{0.17 * S:.0f}" cy="{0.85 * S:.0f}" r="{0.065 * S:.0f}" fill="#b0b2b4"/>')
    svg = lambda body: f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {S} {S}">{DEFS}{body}</svg>'
    return {"full": svg(PLATE + marking), "plate": svg(PLATE), "marking": svg(marking),
            "small": svg(PLATE + small), "small-marking": svg(small)}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    root = Path(__file__).resolve().parents[1]
    version = re.search(r'^version = "(\d+\.\d+\.\d+)', (root / "pyproject.toml").read_text(), re.M).group(1)
    epoch = os.environ.get("SOURCE_DATE_EPOCH")
    today = datetime.datetime.fromtimestamp(int(epoch), datetime.timezone.utc).date() if epoch else datetime.date.today()
    parser.add_argument("--version", default=version)
    parser.add_argument("--date", default=today, type=datetime.date.fromisoformat)
    parser.add_argument("--commit", default=None, help="default: git HEAD of this checkout")
    parser.add_argument("--platform", required=True, help='e.g. "WIN X64", "MAC X64", "LNX X64", "AND A64", "IOS A64"')
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args(argv)
    if args.commit is None:
        args.commit = subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()
    args.out.mkdir(parents=True, exist_ok=True)
    for name, text in layers(args.version, args.date, args.commit, args.platform).items():
        (args.out / f"{name}.svg").write_text(text, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
