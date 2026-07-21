"""GitHub source-archive update support for the GUI launcher."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
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
MANIFEST_FILE = ".msm5xxx-update-manifest.json"
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


@dataclass(frozen=True)
class InstallationStatus:
    modified: tuple[str, ...]

    @property
    def clean(self) -> bool:
        return not self.modified


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


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _manifest(root: Path) -> dict[str, str]:
    try:
        payload = json.loads((root / MANIFEST_FILE).read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise UpdateError("installation has no valid update manifest") from error
    files = payload.get("files") if isinstance(payload, dict) else None
    if not isinstance(files, dict) or not files:
        raise UpdateError("installation update manifest is empty")
    result: dict[str, str] = {}
    for name, digest in files.items():
        path = PurePosixPath(name) if isinstance(name, str) else PurePosixPath("/")
        if (path.is_absolute() or not path.parts or ".." in path.parts
                or not isinstance(digest, str)
                or re.fullmatch(r"[0-9a-f]{64}", digest) is None):
            raise UpdateError("installation update manifest has an unsafe entry")
        result[path.as_posix()] = digest
    return result


def installation_status(root: Path) -> InstallationStatus:
    """Compare only distributed runtime files; user data stays outside manifest."""
    modified = []
    for name, expected in _manifest(root).items():
        path = root / name
        try:
            actual = _file_sha256(path)
        except OSError:
            actual = ""
        if actual != expected:
            modified.append(name)
    return InstallationStatus(tuple(modified))


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
        status = installation_status(source)
        if not status.clean:
            raise UpdateError("GitHub update archive failed file verification")
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


def apply_prepared_update(prepared: Path, target: Path, state_root: Path,
                          revision: str, discard_modified: bool) -> None:
    """Replace manifest-owned files with rollback; preserve every other path."""
    if local_revision(prepared) != revision or not installation_status(prepared).clean:
        raise UpdateError("prepared update is incomplete")
    try:
        current = installation_status(target)
    except UpdateError:
        current = InstallationStatus((MANIFEST_FILE,))
    if not current.clean and not discard_modified:
        raise UpdateError("local source files changed")
    try:
        old_files = _manifest(target)
    except UpdateError:
        old_files = {}
    new_files = _manifest(prepared)
    backup = state_root / "updates" / "backups" / revision
    with exclusive_path_lock(target / MANIFEST_FILE):
        if backup.exists():
            shutil.rmtree(backup)
        backup.mkdir(parents=True)
        touched = sorted(set(old_files) | set(new_files) | {MANIFEST_FILE, REVISION_FILE})
        existing = [name for name in touched if (target / name).is_file()]
        try:
            for name in existing:
                destination = backup / name
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(target / name, destination)
            for name in sorted(new_files):
                destination = target / name
                destination.parent.mkdir(parents=True, exist_ok=True)
                temporary = destination.with_name(f".{destination.name}.update")
                old_mode = destination.stat().st_mode if destination.exists() else None
                shutil.copy2(prepared / name, temporary)
                if old_mode is not None:
                    temporary.chmod(old_mode)
                os.replace(temporary, destination)
            for name in sorted(set(old_files) - set(new_files)):
                (target / name).unlink(missing_ok=True)
            shutil.copy2(prepared / MANIFEST_FILE, target / MANIFEST_FILE)
            atomic_write_text(target / REVISION_FILE, revision + "\n")
        except OSError as error:
            for name in touched:
                saved = backup / name
                destination = target / name
                if saved.is_file():
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(saved, destination)
                elif destination.exists():
                    destination.unlink()
            raise UpdateError(f"update failed and was rolled back: {error}") from error


_APPLY_CODE = """\
import pathlib, subprocess, sys
root, prepared, state, firmware, revision, discard = sys.argv[1:]
sys.path.insert(0, str(pathlib.Path(root) / 'src'))
from msm5xxx_emulator.update import apply_prepared_update
apply_prepared_update(pathlib.Path(prepared), pathlib.Path(root), pathlib.Path(state), revision, discard == '1')
subprocess.Popen([sys.executable, str(pathlib.Path(root) / 'gui.py'), firmware], cwd=root)
"""


def inplace_update_command(prepared: Path, root: Path, state_root: Path,
                           firmware: Path, info: UpdateInfo,
                           discard_modified: bool) -> list[str]:
    """Build shell-free helper command that runs after GUI shutdown."""
    return [
        os.fsdecode(os.path.abspath(sys.executable)), "-c", _APPLY_CODE,
        str(root), str(prepared), str(state_root), str(firmware), info.revision,
        "1" if discard_modified else "0",
    ]
