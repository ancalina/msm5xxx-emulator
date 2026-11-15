"""Generate mobile icon build resources from chip_icon.py using Inkscape.

All output belongs in ignored build directories. Android's 108 dp adaptive
canvas shows its central 72 dp: the marking occupies 0.96 of that visible area.
iOS keeps single-size Any/Dark/Tinted fallbacks alongside layered Composer icons.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import xml.etree.ElementTree as ET

import chip_icon


def write_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def render(source: Path, target: Path, size: int, *, opaque: bool = False) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ)
    env.setdefault("INKSCAPE_PROFILE_DIR", str(source.parent / "inkscape-profile"))
    env.setdefault("GSETTINGS_BACKEND", "memory")
    subprocess.run([os.environ.get("INKSCAPE", "inkscape"), str(source),
                    "--export-area-page", f"--export-width={size}", f"--export-height={size}",
                    f"--export-filename={target}",
                    "--export-png-color-mode=RGB_8" if opaque else "--export-png-color-mode=RGBA_8"],
                   check=True, env=env)


def marking_svg(source: Path, target: Path, *, adaptive: bool = False,
                monochrome: bool = False, opaque: bool = False) -> None:
    root = ET.fromstring(source.read_text())
    ns = "{http://www.w3.org/2000/svg}"
    ET.register_namespace("", ns[1:-1])
    if monochrome:
        for element in root.iter():
            for name in ("fill", "stroke"):
                if element.get(name, "none") != "none":
                    element.set(name, "#ffffff")
    if adaptive:
        group = ET.Element(ns + "g", {"transform": "translate(184.32 184.32) scale(0.64)"})
        for child in list(root):
            if child.tag != ns + "defs":
                root.remove(child)
                group.append(child)
        root.append(group)
    if opaque:
        root.insert(0, ET.Element(ns + "rect", {"width": "1024", "height": "1024", "fill": "#000000"}))
    target.write_text(ET.tostring(root, encoding="unicode"), encoding="utf-8")


def android(out: Path, layers: Path) -> None:
    resources = out / "res"
    render(layers / "plate.svg", resources / "drawable-nodpi/chip_plate.png", 432)
    for name, source in (("full", "marking"), ("simple", "small-marking")):
        for themed in (False, True):
            suffix = "monochrome" if themed else "marking"
            svg = layers / f"android-{name}-{suffix}.svg"
            marking_svg(layers / f"{source}.svg", svg, adaptive=True, monochrome=themed)
            render(svg, resources / f"drawable-nodpi/chip_{name}_{suffix}.png", 432)
        # v33 adds themed icons, while API 28–32 retain the adaptive colour icon.
        for qualifier, monochrome in (("v26", ""), ("v33", f'    <monochrome android:drawable="@drawable/chip_{name}_monochrome" />\n')):
            path = resources / f"mipmap-anydpi-{qualifier}/ic_launcher_{name}.xml"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('<?xml version="1.0" encoding="utf-8"?>\n'
                            '<adaptive-icon xmlns:android="http://schemas.android.com/apk/res/android">\n'
                            '    <background android:drawable="@drawable/chip_plate" />\n'
                            f'    <foreground android:drawable="@drawable/chip_{name}_marking" />\n'
                            + monochrome + '</adaptive-icon>\n', encoding="utf-8")


def ios(out: Path, layers: Path) -> None:
    catalog = out / "Assets.xcassets"
    write_json(catalog / "Contents.json", {"info": {"version": 1, "author": "xcode"}})
    for name, full, marking in (("AppIcon", "full", "marking"), ("Simple", "small", "small-marking")):
        iconset = catalog / f"{name}.appiconset"
        images = []
        for appearance in ("any", "dark", "tinted"):
            source = layers / f"{full}.svg"
            if appearance == "tinted":
                source = layers / f"{name}-tinted.svg"
                marking_svg(layers / f"{marking}.svg", source, monochrome=True, opaque=True)
            filename = f"{appearance}.png"
            render(source, iconset / filename, 1024, opaque=True)
            entry = {"filename": filename, "idiom": "universal", "platform": "ios", "size": "1024x1024"}
            if appearance != "any":
                entry["appearances"] = [{"appearance": "luminosity", "value": appearance}]
            images.append(entry)
        write_json(iconset / "Contents.json", {"images": images, "info": {"version": 1, "author": "xcode"}})
        composer = out / f"{name}.icon"
        render(layers / "plate.svg", composer / "Assets/plate.png", 1024, opaque=True)
        render(layers / f"{marking}.svg", composer / "Assets/marking.png", 1024)
        write_json(composer / "icon.json", {
            "fill": {"solid": "srgb:0.17255,0.18039,0.19216,1.00000"},
            # Composer lists groups from front to back.
            "groups": [
                {"layers": [{"image-name": "marking.png", "name": "Marking"}],
                 "shadow": {"kind": "neutral", "opacity": 0.25},
                 "translucency": {"enabled": True, "value": 0.15}},
                {"layers": [{"image-name": "plate.png", "name": "Plate"}],
                 "shadow": {"kind": "neutral", "opacity": 0},
                 "translucency": {"enabled": False, "value": 0}}
            ],
            "supported-platforms": {"squares": "shared"}
        })


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("platform", choices=("ios", "android"))
    parser.add_argument("out", type=Path)
    args = parser.parse_args()
    out = args.out.resolve()
    layers = out / "layers"
    chip_icon.main(["--platform", "IOS A64" if args.platform == "ios" else "AND A64", "--out", str(layers)])
    (ios if args.platform == "ios" else android)(out, layers)


if __name__ == "__main__":
    main()
