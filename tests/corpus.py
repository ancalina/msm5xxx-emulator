"""Private firmware corpus and firmware-derived snippets; neither lives in the repository."""
import functools
import json
import os
from pathlib import Path
import unittest

FIRMWARE_ROOT = Path(os.environ.get(
    "MSM5XXX_TEST_FIRMWARE_ROOT", Path(__file__).resolve().parents[2] / "firmwares"
)).expanduser()
SNIPPET_ROOT = Path(os.environ.get(
    "MSM5XXX_TEST_SNIPPET_ROOT", Path(__file__).resolve().parents[2] / "local-tests/snippets"
)).expanduser()


@functools.cache
def _snippets(module: str) -> dict[str, str]:
    path = SNIPPET_ROOT / f"{module}.json"
    try:
        return json.loads(path.read_text())
    except FileNotFoundError:
        raise unittest.SkipTest(f"firmware-derived snippets unavailable: {path.name}") from None


def snippet(module: str, name: str) -> bytes:
    """Return a firmware-derived byte snippet kept outside the repository, or skip the test."""
    return bytes.fromhex(_snippets(module)[name])


def firmware_path(*parts: str) -> Path:
    """Return a path inside the private corpus, or skip the test when it is absent."""
    path = FIRMWARE_ROOT.joinpath(*parts)
    if not path.exists():
        raise unittest.SkipTest(f"private firmware unavailable: {path.name}")
    return path
