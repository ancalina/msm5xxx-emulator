"""Release notices and verified AppImage updates for the native Linux app.

Windows uses Velopack, macOS uses Sparkle. Source checkouts are never replaced.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from .state_io import atomic_write_text, exclusive_path_lock

REPOSITORY = "ancalina/msm5xxx-emulator"
MAX_METADATA_BYTES = 1024 * 1024
MAX_IMAGE_BYTES = 1024 * 1024 * 1024
_VERSION = re.compile(r"v?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?\Z")


class UpdateError(RuntimeError):
    """An update could not be checked, verified or installed."""


def version_key(value: str) -> tuple:
    match = _VERSION.fullmatch(value) if isinstance(value, str) and len(value) <= 128 else None
    if match is None:
        raise UpdateError("Invalid release version")
    identifiers = (match[4] or "").split(".")
    if match[4] and any(not part or (part.isdigit() and len(part) > 1 and part[0] == "0") for part in identifiers):
        raise UpdateError("Invalid prerelease version")
    pre = tuple((0, int(part)) if part.isdigit() else (1, part) for part in identifiers)
    return (*map(int, match.group(1, 2, 3)), not bool(match[4]), pre if match[4] else ())


def _local() -> bool:
    return bool(os.environ.get("MSM5XXX_UPDATE_FEED"))


def _allowed_url(value: str) -> bool:
    url = urlparse(value)
    if url.scheme == "https" and url.hostname in ("github.com", "api.github.com"):
        return True
    if url.scheme == "https" and (url.hostname or "").endswith(".githubusercontent.com"):
        return True
    return _local() and (url.scheme == "file" and not url.netloc or
                         url.scheme == "http" and url.hostname in ("127.0.0.1", "::1"))


def _request(url: str):
    if not isinstance(url, str) or not _allowed_url(url):
        raise UpdateError("Invalid update download URL")
    response = urlopen(Request(url, headers={"Accept": "application/vnd.github+json", "User-Agent": "MSM5xxx-Emulator"}), timeout=20)
    if not _allowed_url(response.geturl()):
        response.close()
        raise UpdateError("Invalid update redirect")
    return response


def check_for_update(current: str) -> dict | None:
    """Read GitHub's latest release, or an explicitly configured local test feed."""
    try:
        feed = os.environ.get("MSM5XXX_UPDATE_FEED")
        url = Path(feed).resolve().as_uri() if feed else f"https://api.github.com/repos/{REPOSITORY}/releases/latest"
        with _request(url) as response:
            data = response.read(MAX_METADATA_BYTES + 1)
        if len(data) > MAX_METADATA_BYTES:
            raise UpdateError("Update metadata is too large")
        release = json.loads(data)
        if not isinstance(release, dict):
            raise UpdateError("Invalid release metadata")
        if release.get("draft") or (release.get("prerelease") and not feed):
            return None
        version = release.get("tag_name")
        if version_key(version) <= version_key(current):
            return None
        page = release.get("html_url", "")
        if not isinstance(page, str) or not page.startswith(f"https://github.com/{REPOSITORY}/releases/"):
            raise UpdateError("Invalid release page")
        assets = release.get("assets", [])
        if not isinstance(assets, list):
            raise UpdateError("Invalid release assets")
        name = f"MSM5xxx-{version.removeprefix('v')}-linux-x86_64.AppImage"
        asset = next((a for a in assets if isinstance(a, dict) and a.get("name") == name), None)
        return {"version": version.removeprefix("v"), "page": page, "asset": asset}
    except (OSError, ValueError, TypeError) as error:
        raise UpdateError(f"Could not check for updates: {error}") from error


def _asset(release: dict) -> tuple[str, str, int]:
    if not isinstance(release, dict):
        raise UpdateError("Invalid update")
    version_key(release.get("version"))
    asset = release.get("asset")
    if not isinstance(asset, dict):
        raise UpdateError("This release has no AppImage")
    url, digest, size = asset.get("browser_download_url"), asset.get("digest"), asset.get("size")
    if (not isinstance(url, str) or not _allowed_url(url) or
            not isinstance(digest, str) or re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is None or
            type(size) is not int or not 0 < size <= MAX_IMAGE_BYTES):
        raise UpdateError("The AppImage has no valid size or SHA-256 digest")
    return url, digest[7:], size


def _image(path: Path) -> bool:
    with path.open("rb") as stream:
        header = stream.read(11)
    return header[:4] == b"\x7fELF" and header[8:11] == b"AI\x02"


def _digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def prepare_update(release: dict, state_root: Path) -> None:
    """Download into user state; a partial or unverified image is never applied."""
    # shortcut: in-app downloads use full AppImages; use libappimageupdate when delta bandwidth is needed.
    url, expected, size = _asset(release)
    updates = state_root / "updates"
    updates.mkdir(parents=True, exist_ok=True)
    target = updates / "pending.AppImage"
    with exclusive_path_lock(target):
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(dir=updates, prefix="download-", delete=False) as output:
                temporary = Path(output.name)
                digest = hashlib.sha256()
                count = 0
                with _request(url) as source:
                    while block := source.read(1024 * 1024):
                        count += len(block)
                        if count > size:
                            raise UpdateError("The update download is larger than expected")
                        output.write(block)
                        digest.update(block)
                output.flush()
                os.fsync(output.fileno())
            if count != size or digest.hexdigest() != expected or not _image(temporary):
                raise UpdateError("The update failed verification")
            os.replace(temporary, target)
            atomic_write_text(updates / "pending.json", json.dumps(release))
        except OSError as error:
            raise UpdateError(f"Could not download the update: {error}") from error
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)


def apply_prepared_update(state_root: Path) -> str:
    """Atomically replace this user's AppImage, keeping the previous image beside it."""
    image_name = os.environ.get("APPIMAGE")
    if not image_name:
        raise UpdateError("Install .deb updates with your package manager")
    image = Path(image_name)
    pending = state_root / "updates" / "pending.AppImage"
    temporary = backup_temp = None
    try:
        image = image.resolve(strict=True)
        info = image.stat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or not _image(image):
            raise UpdateError("The AppImage is not owned by this user")
        metadata = state_root / "updates" / "pending.json"
        if metadata.stat().st_size > MAX_METADATA_BYTES:
            raise UpdateError("Invalid prepared update")
        release = json.loads(metadata.read_text())
        _, expected, size = _asset(release)
        if pending.stat().st_size != size or _digest(pending) != expected or not _image(pending):
            raise UpdateError("The prepared update failed verification")
        backup = image.with_name(image.name + ".old")
        if backup.exists() and (backup.is_symlink() or backup.stat().st_uid != os.getuid() or not _image(backup)):
            raise UpdateError("The backup path contains another file")
        with exclusive_path_lock(image):
            with tempfile.NamedTemporaryFile(dir=image.parent, prefix=".update-", delete=False) as output:
                temporary = Path(output.name)
                with pending.open("rb") as source:
                    shutil.copyfileobj(source, output)
                output.flush()
                os.fsync(output.fileno())
            if _digest(temporary) != expected:
                raise UpdateError("The copied update failed verification")
            temporary.chmod(stat.S_IMODE(info.st_mode) & 0o777)
            with tempfile.NamedTemporaryFile(dir=image.parent, prefix=".backup-", delete=False) as output:
                backup_temp = Path(output.name)
            shutil.copy2(image, backup_temp)
            os.replace(backup_temp, backup)
            os.replace(temporary, image)
        # Wait for the native UI to stop its sessions and release its application ID.
        subprocess.Popen(["/bin/sh", "-c", 'while kill -0 "$1" 2>/dev/null; do sleep 1; done; exec "$2"',
                              "msm5xxx-update", str(os.getppid()), str(image)],
                             start_new_session=True, stdin=subprocess.DEVNULL,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return str(image)
    except (OSError, ValueError, TypeError) as error:
        raise UpdateError(f"Could not apply the update: {error}") from error
    finally:
        for path in (temporary, backup_temp):
            if path is not None:
                path.unlink(missing_ok=True)
