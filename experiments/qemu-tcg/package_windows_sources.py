#!/usr/bin/env python3
"""Package pinned MSYS2 DLL sources corresponding to a Windows runtime bundle."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
from pathlib import Path


PINS = Path(__file__).with_name("windows_dependency_sources.json")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run(*args: str, cwd: Path | None = None) -> bytes:
    try:
        return subprocess.run(args, cwd=cwd, check=True, capture_output=True).stdout
    except FileNotFoundError as exc:
        raise RuntimeError(f"required source-archive tool missing: {args[0]}") from exc
    except subprocess.CalledProcessError as exc:
        detail = exc.stderr.decode(errors="replace").strip()
        raise RuntimeError(f"command failed: {' '.join(args)}\n{detail}") from exc


def verify_package(archive: Path, pin: dict) -> None:
    if archive.stat().st_size != pin["source_archive_bytes"]:
        raise RuntimeError(f"unexpected source archive size: {archive.name}")
    if sha256(archive) != pin["source_archive_sha256"]:
        raise RuntimeError(f"unexpected source archive SHA-256: {archive.name}")
    run("zstd", "-t", str(archive))
    listing = run("tar", "--zstd", "-tf", archive.name, cwd=archive.parent).decode(errors="replace").splitlines()
    root = pin["source_root"]
    for name in (f"{root}/PKGBUILD", f"{root}/.SRCINFO"):
        if name not in listing:
            raise RuntimeError(f"source archive missing {name}: {archive.name}")
    recipe = run("tar", "--zstd", "-xOf", archive.name, f"{root}/PKGBUILD", cwd=archive.parent)
    if hashlib.sha256(recipe).hexdigest() != pin["recipe_sha256"]:
        raise RuntimeError(f"PKGBUILD SHA-256 does not match pin: {archive.name}")


def fetch(pin: dict, cache: Path | None, destination: Path) -> None:
    name = Path(pin["source_archive"]).name
    cached = (cache / pin["source_archive"] if cache and (cache / pin["source_archive"]).is_file()
              else cache / name if cache else None)
    if cached and cached.is_file():
        shutil.copyfile(cached, destination)
    else:
        request = urllib.request.Request(pin["source_only_url"], headers={"User-Agent": "MSM5xxx-source-packager/1"})
        with urllib.request.urlopen(request, timeout=60) as response, destination.open("wb") as out:
            shutil.copyfileobj(response, out)
    verify_package(destination, pin)


def add_to_tar(tar: tarfile.TarFile, path: Path, arcname: str) -> None:
    info = tar.gettarinfo(str(path), arcname)
    info.uid = info.gid = 0
    info.uname = info.gname = ""
    info.mtime = 0
    if info.isfile():
        with path.open("rb") as stream:
            tar.addfile(info, stream)
    else:
        tar.addfile(info)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bundle_dir", type=Path)
    parser.add_argument("empty_output_dir", type=Path)
    parser.add_argument("--source-cache-dir", type=Path,
                        default=Path(os.environ["SOURCE_CACHE_DIR"]) if os.environ.get("SOURCE_CACHE_DIR") else None)
    args = parser.parse_args()
    bundle = args.bundle_dir.resolve()
    output = args.empty_output_dir.resolve()
    if not bundle.is_dir():
        parser.error(f"bundle directory not found: {bundle}")
    output.mkdir(parents=True, exist_ok=True)
    if not output.is_dir() or any(output.iterdir()):
        parser.error("EMPTY_OUTPUT_DIR must exist and be empty")
    tar_path = output.parent / "MSM5xxx-QEMU-windows-runtime-sources.tar.xz"
    if tar_path.exists():
        parser.error(f"source archive already exists: {tar_path}")

    pins = json.loads(PINS.read_text(encoding="utf-8"))
    packages = pins["packages"]
    mapped = {dll["file"]: dll["sha256"] for package in packages for dll in package["bundled_dlls"]}
    actual = {f"bin/{path.name}": sha256(path) for path in (bundle / "bin").glob("*.dll")}
    if actual != mapped:
        raise RuntimeError("bundled DLL set or hashes differ from windows_dependency_sources.json; refresh pins explicitly")

    with tempfile.TemporaryDirectory(prefix="windows-source-companion-", dir=output.parent) as temp:
        stage = Path(temp) / "windows-runtime-sources"
        (stage / "sources").mkdir(parents=True)
        (stage / "licenses").mkdir()
        for package in packages:
            target = stage / package["source_archive"]
            target.parent.mkdir(parents=True, exist_ok=True)
            fetch(package, args.source_cache_dir, target)
            for relative in package["runtime_license_files"]:
                source = bundle / relative
                if not source.is_file():
                    raise RuntimeError(f"runtime license text missing: {relative}")
                dest = stage / relative
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, dest)

        shutil.copyfile(PINS, stage / "PACKAGE-SOURCE-MAP.json")
        manifest = {
            "format": pins["format"],
            "bundle_filename": pins["bundle_filename"],
            "runtime_dll_sha256": dict(sorted(actual.items())),
            "source_archives": [
                {"path": p["source_archive"], "sha256": p["source_archive_sha256"],
                 "bytes": p["source_archive_bytes"], "package": p["package"],
                 "version": p["version"], "recipe_sha256": p["recipe_sha256"]}
                for p in packages
            ],
        }
        (stage / "SOURCE-MANIFEST.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        (stage / "README.md").write_text(
            "# MSM5xxx Windows runtime dependency sources\n\n"
            "This companion supplies the exact corresponding source-only MSYS2 packages for the six DLLs in the pinned Windows runtime. "
            "`PACKAGE-SOURCE-MAP.json` records official source URLs, exact package versions, archive and recipe hashes, bundled DLL hashes, and runtime license paths. "
            "Each complete source archive includes its PKGBUILD, .SRCINFO, and declared upstream inputs. Runtime license texts are included under `licenses/`.\n\n"
            "The QEMU and project source is supplied separately by `MSM5xxx-QEMU-10.2.1-corresponding-source.tar.xz`. "
            "In Actions, the same corresponding-source download includes `qemu-10.2.1-msm5xxx.tar.xz` and `msm5xxx-project-source.tar.gz` instead. "
            "No firmware, credentials, build logs, or local machine paths are included. The archives provide corresponding source and package recipes; bit-identical binary reproduction is not claimed.\n\n"
            "Verify included files with `sha256sum -c SHA256SUMS`.\n", encoding="utf-8")
        sums = []
        for path in sorted(stage.rglob("*")):
            if path.is_file():
                sums.append(f"{sha256(path)}  {path.relative_to(stage).as_posix()}")
        (stage / "SHA256SUMS").write_text("\n".join(sums) + "\n", encoding="utf-8")
        fd, temporary_archive = tempfile.mkstemp(prefix="windows-sources-", suffix=".tar.xz",
                                                  dir=output.parent)
        os.close(fd)
        try:
            with tarfile.open(temporary_archive, "w:xz", format=tarfile.PAX_FORMAT) as tar:
                for path in sorted(stage.rglob("*")):
                    add_to_tar(tar, path, f"windows-runtime-sources/{path.relative_to(stage).as_posix()}")
                add_to_tar(tar, stage, "windows-runtime-sources")
            # Accept output only after checking every archive member against the manifest.
            with tarfile.open(temporary_archive, "r:xz") as tar:
                members = {m.name: m for m in tar.getmembers()}
                for line in (stage / "SHA256SUMS").read_text().splitlines():
                    digest, name = line.split(maxsplit=1)
                    member = members[f"windows-runtime-sources/{name}"]
                    stream = tar.extractfile(member)
                    if stream is None or hashlib.sha256(stream.read()).hexdigest() != digest:
                        raise RuntimeError(f"source companion archive verification failed: {name}")
            shutil.copytree(stage, output, dirs_exist_ok=True)
            os.replace(temporary_archive, tar_path)
        finally:
            if os.path.exists(temporary_archive):
                os.unlink(temporary_archive)
    print(tar_path)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, json.JSONDecodeError) as exc:
        print(f"package_windows_sources: {exc}", file=sys.stderr)
        raise SystemExit(1)
