"""Session, exception, and native-crash logging for emulator entry points."""
from __future__ import annotations

import atexit
from datetime import datetime
import faulthandler
from functools import lru_cache
import hashlib
from importlib import metadata
import json
import logging
import os
from pathlib import Path
import platform
import re
import sys
import threading
import traceback


_LOCK = threading.Lock()
_SESSION_PATH: Path | None = None
_NATIVE_PATH: Path | None = None
_NATIVE_FILE = None


_PATH_KEYS = frozenset({"argv", "cwd", "path", "paths", "session"})
_ABSOLUTE_PATH_TOKEN = re.compile(r"(?<![\w])(?:[A-Za-z]:[\\/]|/)[^\s'\"<>]+")


def _package_version(name: str) -> str:
    try:
        return metadata.version(name)
    except metadata.PackageNotFoundError:
        return "not-installed"


def _source_identity() -> dict[str, str]:
    source = Path(__file__).resolve().parents[1] / "core" / "emulator.py"
    try:
        digest = hashlib.sha256(source.read_bytes()).hexdigest()
    except OSError:
        digest = "unavailable"
    return {"file": "msm5xxx.py", "sha256": digest}


@lru_cache(maxsize=1)
def _runtime_metadata() -> dict[str, object]:
    return {
        "python": platform.python_version(),
        "platform": platform.platform(),
        "packages": {
            "unicorn": _package_version("unicorn"),
            "Pillow": _package_version("Pillow"),
        },
        "source": _source_identity(),
    }


def current_session_log() -> Path | None:
    """Return current session log path, if runtime logging is installed."""
    return _SESSION_PATH


def _safe_text(value: str) -> str:
    """Keep diagnostic strings useful without retaining absolute local paths."""
    def basename(match: re.Match[str]) -> str:
        return Path(match.group().replace("\\", "/")).name

    return _ABSOLUTE_PATH_TOKEN.sub(basename, value)


def _safe_diagnostic(value: object, key: str = "") -> object:
    """Drop path-bearing fields before a diagnostic leaves this process."""
    lowered = key.lower()
    if lowered in _PATH_KEYS or lowered.endswith("_path"):
        return None
    if isinstance(value, Path):
        return value.name
    if isinstance(value, dict):
        return {
            str(item_key): sanitized
            for item_key, item in value.items()
            if (sanitized := _safe_diagnostic(item, str(item_key))) is not None
        }
    if isinstance(value, (list, tuple)):
        return [_safe_diagnostic(item) for item in value]
    if isinstance(value, str):
        return _safe_text(value)
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return _safe_text(str(value))


def _log_root() -> Path:
    configured = os.environ.get("MSM5XXX_LOG_DIR")
    preferred = (Path(configured).expanduser() if configured
                 else Path(__file__).resolve().parents[3] / "logs")
    state = Path(os.environ.get(
        "MSM5XXX_STATE_DIR", Path.home() / ".msm5xxx-emulator"
    )).expanduser() / "logs"
    error: OSError | None = None
    for candidate in dict.fromkeys((preferred, state)):
        probe = candidate / f".write-test-{os.getpid()}-{threading.get_ident()}"
        try:
            candidate.mkdir(parents=True, exist_ok=True)
            descriptor = os.open(probe, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.close(descriptor)
            probe.unlink()
            return candidate
        except OSError as caught:
            error = caught
            try:
                probe.unlink()
            except OSError:
                pass
    assert error is not None
    raise error


def _stamp() -> str:
    return datetime.now().astimezone().strftime("%Y%m%d-%H%M%S-%f")


def _native_fault_logging_enabled() -> bool:
    """Return whether raw native fault traces are safe and requested.

    Unicorn's Windows backend uses recoverable structured exceptions for some
    memory-management paths. CPython's faulthandler writes those first-chance
    events as if they were fatal, even though emulation and the process carry
    on normally. Preserve the useful native tracing default on POSIX, while
    making Windows capture an explicit diagnostic opt-in.
    """
    if sys.platform != "win32":
        return True
    return os.environ.get("MSM5XXX_NATIVE_FAULT_LOG", "").strip().lower() in {
        "1", "true", "yes", "on",
    }


def install_runtime_logging(component: str) -> Path:
    """Install once per process and return current session log path."""
    global _SESSION_PATH, _NATIVE_PATH, _NATIVE_FILE
    with _LOCK:
        if _SESSION_PATH is not None:
            return _SESSION_PATH
        root = _log_root()
        root.mkdir(parents=True, exist_ok=True)
        identity = f"{_stamp()}-{os.getpid()}"
        _SESSION_PATH = root / f"{component}-{identity}.log"
        handler = logging.FileHandler(_SESSION_PATH, encoding="utf-8")
        handler.setFormatter(logging.Formatter(
            "%(asctime)s.%(msecs)03d %(levelname)s %(threadName)s "
            "%(name)s: %(message)s", datefmt="%Y-%m-%dT%H:%M:%S"
        ))
        logging.getLogger().addHandler(handler)
        logging.getLogger().setLevel(logging.INFO)

        if _native_fault_logging_enabled():
            native_prefix = (
                "native-first-chance" if sys.platform == "win32" else "crash-native"
            )
            _NATIVE_PATH = root / f"{native_prefix}-{identity}.log"
            _NATIVE_FILE = _NATIVE_PATH.open("w", encoding="utf-8")
            faulthandler.enable(_NATIVE_FILE, all_threads=True)
        else:
            _NATIVE_PATH = None
            _NATIVE_FILE = None
        sys.excepthook = _unhandled_exception
        threading.excepthook = _unhandled_thread_exception
        atexit.register(_finish_logging)
        logging.getLogger("runtime").info(
            "start component=%s metadata=%s session=%s native_fault_log=%s "
            "session_marker=ancal",
            component, json.dumps(_runtime_metadata(), sort_keys=True),
            _SESSION_PATH.name, _NATIVE_FILE is not None,
        )
        return _SESSION_PATH


def record_exception(context: str, error: BaseException) -> Path | None:
    """Write caught exception to both session log and standalone crash report."""
    safe_context = _safe_text(context)
    logging.getLogger("runtime").error(
        "%s: %s", safe_context, error,
        exc_info=(type(error), error, error.__traceback__)
    )
    try:
        root = _log_root()
        root.mkdir(parents=True, exist_ok=True)
        path = root / f"crash-{_stamp()}-{os.getpid()}.log"
        path.write_text(
            f"context: {safe_context}\n"
            "runtime: " + json.dumps(_runtime_metadata(), sort_keys=True) + "\n\n"
            + "".join(traceback.format_exception(
                type(error), error, error.__traceback__
            )),
            encoding="utf-8",
        )
        return path
    except OSError:
        logging.getLogger("runtime").exception("could not write crash report")
        return None


def record_diagnostic(kind: str, payload: dict[str, object]) -> Path | None:
    """Persist one path-safe diagnostic JSON beside the active session log."""
    safe_kind = re.sub(r"[^a-z0-9_-]+", "-", kind.lower()).strip("-") or "diagnostic"
    try:
        root = _SESSION_PATH.parent if _SESSION_PATH is not None else _log_root()
        root.mkdir(parents=True, exist_ok=True)
        path = root / (
            f"diagnostic-{safe_kind}-{_stamp()}-{os.getpid()}-{threading.get_ident()}.json"
        )
        document = {
            "kind": safe_kind,
            "runtime": _runtime_metadata(),
            "payload": _safe_diagnostic(payload),
        }
        temporary = path.with_suffix(path.suffix + ".tmp")
        temporary.write_text(
            json.dumps(document, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
            encoding="utf-8",
        )
        os.replace(temporary, path)
        logging.getLogger("runtime").info(
            "diagnostic kind=%s file=%s", safe_kind, path.name
        )
        return path
    except OSError:
        logging.getLogger("runtime").exception("could not write diagnostic")
        return None


def _unhandled_exception(error_type: type[BaseException], error: BaseException,
                         trace: object) -> None:
    record_exception("unhandled main-thread exception", error)
    sys.__excepthook__(error_type, error, trace)


def _unhandled_thread_exception(args: threading.ExceptHookArgs) -> None:
    record_exception(f"unhandled thread exception: {args.thread.name}", args.exc_value)
    threading.__excepthook__(args)


def _finish_logging() -> None:
    global _NATIVE_FILE
    logging.getLogger("runtime").info("normal process exit")
    logging.shutdown()
    if _NATIVE_FILE is not None:
        try:
            faulthandler.disable()
            _NATIVE_FILE.close()
            if _NATIVE_PATH is not None and _NATIVE_PATH.stat().st_size == 0:
                _NATIVE_PATH.unlink()
        except OSError:
            pass
        _NATIVE_FILE = None
