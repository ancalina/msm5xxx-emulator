"""GitHub source-archive update support for the GUI launcher."""
from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import sys
import tempfile
from urllib.request import Request, urlopen
from zipfile import BadZipFile, ZipFile

from .state_io import atomic_write_text, exclusive_path_lock


REPOSITORY = "ancalina/msm5xxx-emulator"
BRANCH = "main"
REVISION_FILE = ".msm5xxx-update-revision"
STATE_FILE = "update.json"
MAX_METADATA_BYTES = 64 * 1024
MAX_ARCHIVE_BYTES = 64 * 1024 * 1024
MAX_EXTRACTED_BYTES = 128 * 1024 * 1024
_SHA = re.compile(r"[0-9a-f]{40}\Z")


class UpdateError(RuntimeError):
    """Raised when an update cannot be checked, verified, or prepared."""


@dataclass(frozen=True)
class UpdateInfo:
    revision: str


def application_root() -> Path:
    """Return the distribution root containing ``gui.py``."""
    return Path(__file__).resolve().parents[2]


def local_revision(root: Path) -> str | None:
    """Read an updater marker written only into downloaded update copies."""
    try:
        revision = (root / REVISION_FILE).read_text(encoding="ascii").strip().lower()
    except OSError:
        return None
    return revision if _SHA.fullmatch(revision) else None


def _state_path(state_root: Path) -> Path:
    return state_root / STATE_FILE


def _seen_revision(state_root: Path) -> str | None:
    try:
        data = json.loads(_state_path(state_root).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    revision = data.get("seen_revision") if isinstance(data, dict) else None
    return revision if isinstance(revision, str) and _SHA.fullmatch(revision) else None


def remember_update(state_root: Path, revision: str) -> None:
    """Avoid prompting again for a commit the user already answered."""
    if not _SHA.fullmatch(revision):
        raise UpdateError("GitHub returned an invalid commit identifier")
    path = _state_path(state_root)
    with exclusive_path_lock(path):
        atomic_write_text(path, json.dumps({"seen_revision": revision}) + "\n")


def _read_url(url: str, limit: int) -> bytes:
    request = Request(url, headers={"Accept": "application/vnd.github+json",
                                    "User-Agent": "msm5xxx-emulator-updater"})
    try:
        with urlopen(request, timeout=8) as response:
            length = response.headers.get("Content-Length")
            if length is not None and int(length) > limit:
                raise UpdateError("GitHub update response is too large")
            data = response.read(limit + 1)
    except (OSError, ValueError) as error:
        raise UpdateError(f"GitHub update request failed: {error}") from error
    if len(data) > limit:
        raise UpdateError("GitHub update response is too large")
    return data


def latest_revision() -> str:
    """Fetch the exact current ``main`` commit from the project API."""
    try:
        data = json.loads(_read_url(
            f"https://api.github.com/repos/{REPOSITORY}/commits/{BRANCH}",
            MAX_METADATA_BYTES,
        ))
    except (TypeError, ValueError) as error:
        raise UpdateError("GitHub update metadata is invalid") from error
    revision = data.get("sha") if isinstance(data, dict) else None
    if not isinstance(revision, str) or not _SHA.fullmatch(revision):
        raise UpdateError("GitHub update metadata has no valid commit identifier")
    return revision


def check_for_update(root: Path, state_root: Path) -> UpdateInfo | None:
    """Return one unseen newer commit, without changing the installation."""
    revision = latest_revision()
    if revision in (local_revision(root), _seen_revision(state_root)):
        return None
    return UpdateInfo(revision)


def _download_archive(revision: str, path: Path) -> None:
    archive = _read_url(
        f"https://github.com/{REPOSITORY}/archive/{revision}.zip",
        MAX_ARCHIVE_BYTES,
    )
    path.write_bytes(archive)


def _extract_update_archive(archive: Path, destination: Path, revision: str) -> Path:
    """Extract one GitHub archive after rejecting traversal and symlink entries."""
    work = Path(tempfile.mkdtemp(prefix=f".{revision[:12]}-", dir=destination))
    try:
        try:
            with ZipFile(archive) as bundle:
                roots: set[str] = set()
                extracted_size = 0
                for member in bundle.infolist():
                    name = PurePosixPath(member.filename)
                    mode = member.external_attr >> 16
                    if (name.is_absolute() or not name.parts or ".." in name.parts
                            or stat.S_ISLNK(mode)):
                        raise UpdateError("GitHub update archive has an unsafe path")
                    extracted_size += member.file_size
                    if extracted_size > MAX_EXTRACTED_BYTES:
                        raise UpdateError("GitHub update archive expands too large")
                    roots.add(name.parts[0])
                if len(roots) != 1:
                    raise UpdateError("GitHub update archive has an invalid root")
                bundle.extractall(work)
        except (BadZipFile, OSError) as error:
            raise UpdateError("GitHub update archive is invalid") from error
        source = work / roots.pop()
        if not ((source / "gui.py").is_file() and (source / "_compat.py").is_file()
                and (source / "src" / "msm5xxx_emulator" / "gui" / "app.py").is_file()):
            raise UpdateError("GitHub update archive is not an emulator distribution")
        (source / REVISION_FILE).write_text(revision + "\n", encoding="ascii")
        return source
    except Exception:
        shutil.rmtree(work, ignore_errors=True)
        raise


def prepare_update(info: UpdateInfo, state_root: Path) -> Path:
    """Download one commit into private state, leaving installed files untouched."""
    revision = info.revision
    if not _SHA.fullmatch(revision):
        raise UpdateError("GitHub returned an invalid commit identifier")
    updates = state_root / "updates"
    target = updates / revision
    with exclusive_path_lock(target):
        if local_revision(target) == revision:
            return target
        if target.exists():
            shutil.rmtree(target)
        updates.mkdir(parents=True, exist_ok=True)
        work = Path(tempfile.mkdtemp(prefix=f".{revision[:12]}-", dir=updates))
        try:
            archive = work / "update.zip"
            _download_archive(revision, archive)
            source = _extract_update_archive(archive, work, revision)
            os.replace(source, target)
        except OSError as error:
            raise UpdateError(f"GitHub update preparation failed: {error}") from error
        finally:
            shutil.rmtree(work, ignore_errors=True)
    return target


def updated_gui_command(root: Path, firmware: Path) -> list[str]:
    """Build a shell-free command for the downloaded GUI copy."""
    gui = root / "gui.py"
    if local_revision(root) is None or not gui.is_file():
        raise UpdateError("prepared update is incomplete")
    return [os.fsdecode(os.path.abspath(sys.executable)), str(gui), str(firmware)]
