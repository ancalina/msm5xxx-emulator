"""Generate the owner's chip layers with metadata from this checkout/build."""
from __future__ import annotations
import argparse
import datetime
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess

HERE = Path(__file__).resolve().parents[1]
ROOT = HERE.parents[1]

def metadata():
    transfer = HERE / ".build-metadata.json"
    fallback = json.loads(transfer.read_text()) if transfer.exists() else {}
    project = ROOT / "pyproject.toml"
    version = os.environ.get("MSM5XXX_APP_VERSION")
    if not version and project.exists():
        version = re.search(r'^version = "([^"]+)"', project.read_text(), re.M).group(1)
    version = version or fallback.get("version")
    commit = os.environ.get("MSM5XXX_APP_COMMIT")
    if not commit and (ROOT / ".git").exists():
        commit = subprocess.check_output(["git", "-C", str(ROOT), "rev-parse", "HEAD"], text=True).strip()
    commit = commit or fallback.get("commit")
    epoch = os.environ.get("SOURCE_DATE_EPOCH")
    day = datetime.datetime.fromtimestamp(int(epoch), datetime.timezone.utc).date() if epoch else datetime.datetime.now(datetime.timezone.utc).date()
    if not version or not commit:
        raise SystemExit("Build from a checkout, provide .build-metadata.json for a source transfer, or set MSM5XXX_APP_VERSION and MSM5XXX_APP_COMMIT.")
    return {"version": version, "commit": commit, "date": str(day), "platform": "MAC X64"}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--metadata-only", action="store_true")
    args = parser.parse_args()
    info = metadata()
    if args.metadata_only:
        args.out.write_text(json.dumps(info, indent=2) + "\n")
        return
    args.out.mkdir(parents=True, exist_ok=True)
    spec = importlib.util.spec_from_file_location("chip_icon", HERE / "Branding/chip_icon.py")
    generator = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(generator)
    generator.HERSHEY = HERE / "Branding/HersheySans1.svg"
    for name, svg in generator.layers(re.match(r"\d+\.\d+\.\d+", info["version"]).group(0), datetime.date.fromisoformat(info["date"]), info["commit"], info["platform"]).items():
        (args.out / (name + ".svg")).write_text(svg)
    (args.out / "metadata.json").write_text(json.dumps(info, indent=2) + "\n")

if __name__ == "__main__":
    main()
