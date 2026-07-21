"""Public runtime error types."""
from __future__ import annotations

import re


_QUOTED_ABSOLUTE_PATH_RE = re.compile(
    r"(?P<quote>['\"])(?P<path>(?:[A-Za-z]:[\\/]|/)[^'\"]*)(?P=quote)"
)
_PLAIN_ABSOLUTE_PATH_RE = re.compile(
    r"(?<![\w])(?:[A-Za-z]:[\\/]|/)[^\s'\"<>()\[\]{},;:]+"
)


def _safe_host_error_text(value: object) -> str:
    def basename(path: str) -> str:
        return path.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1] or "."

    text = str(value)
    text = _QUOTED_ABSOLUTE_PATH_RE.sub(
        lambda match: f"{match['quote']}{basename(match['path'])}{match['quote']}",
        text,
    )
    return _PLAIN_ABSOLUTE_PATH_RE.sub(lambda match: basename(match[0]), text)


class HostBackendFault(RuntimeError):
    """Terminal Unicorn host-backend error with a pre-call Python checkpoint."""

    def __init__(self, error: OSError, diagnostic: dict[str, object]) -> None:
        message = _safe_host_error_text(getattr(error, "strerror", None) or str(error))
        self.diagnostic = {
            **diagnostic,
            "host_error": f"{type(error).__name__}: {message}",
        }
        super().__init__(f"Unicorn host backend failure: {message}")
