"""Firmware model identity detection."""
from __future__ import annotations

from pathlib import Path
import re


MODEL_RE = re.compile(
    rb"(?:"
    rb"(?:SCH|SPH)-[A-Z]\d{3,4}|LG-[A-Z]{1,3}\d{3,4}|SCP-?\d{3,4}|"
    rb"IM-\d{4}|(?:PG|PH|PT)-[A-Z]\d{3,4}[A-Z]?|C-\d{3,4}|"
    rb"CX-\d{3,4}[A-Z]?|KTFT-[A-Z]\d{3,4}"
    rb")(?![A-Z0-9])"
)


def canonical_model(token: bytes | str) -> str:
    if isinstance(token, bytes):
        token = token.decode("ascii")
    value = re.sub(r"[_ ]+", "-", token.upper()).rstrip("/")
    return re.sub(r"^SCP(?=\d)", "SCP-", value)


def embedded_model_scores(image: bytes) -> dict[str, int]:
    """Score coherent product records, not inherited model-name literals."""
    upper = image.upper()
    occurrences: dict[str, list[int]] = {}
    for match in MODEL_RE.finditer(upper):
        candidate = canonical_model(match.group())
        occurrences.setdefault(candidate, []).append(match.start())

    scores: dict[str, int] = {}
    for candidate, offsets in occurrences.items():
        score = 2 if len({offset // 0x1000 for offset in offsets}) >= 2 else 0
        context_score = 0
        company_bound = False
        for offset in offsets:
            near = upper[max(0, offset - 64):offset + 96]
            wide = upper[max(0, offset - 512):offset + 512]
            if b"S/W VER" in near or b"MODEL =" in near:
                context_score = max(context_score, 4)
            if b"COMPATIBLE;" in wide and b"CELLPHONE" in wide:
                context_score = max(context_score, 3)
            if any(marker in near for marker in (
                    b"CORPORATION", b"INCORPORATED", b"CO. LTD", b"ELECTRONICS")):
                company_bound = True
        if company_bound:
            context_score = context_score + 2 if context_score else 6
        score += context_score
        if len(offsets) == 1 and any(marker in upper[
                max(0, offsets[0] - 1024):offsets[0] + 1024
        ] for marker in (b"+CIS707", b"NO CARRIER", b"NO DIALTONE")):
            score -= 4
        scores[candidate] = score
    return scores


def verified_embedded_model(
        image: bytes, scores: dict[str, int] | None = None) -> str | None:
    ranked = sorted(
        (scores if scores is not None else embedded_model_scores(image)).items(),
        key=lambda item: (-item[1], item[0]),
    )
    if not ranked or ranked[0][1] < 6:
        return None
    runner_up = ranked[1][1] if len(ranked) > 1 else -1
    return ranked[0][0] if ranked[0][1] - runner_up >= 3 else None


def detect_model(image: bytes, path: Path,
                 scores: dict[str, int] | None = None) -> str:
    """Prefer a coherent firmware identity record; use filename only as fallback."""
    stem = path.stem.upper()
    normalised_stem = re.sub(r"[_ ]+", "-", stem)
    full_name = re.search(
        r"(?:(?:SCH|SPH|KTFT)-[A-Z]\d{3,4}|LG-[A-Z]{1,3}\d{3,4}|"
        r"SCP-?\d{3,4}|IM-\d{4}|(?:PG|PH|PT)-[A-Z]\d{3,4}[A-Z]?|"
        r"C-\d{3,4}|CX-\d{3,4}[A-Z]?)",
        normalised_stem,
    )
    filename_model = canonical_model(full_name.group(0)) if full_name else None
    scores = scores if scores is not None else embedded_model_scores(image)
    verified = verified_embedded_model(image, scores)
    if verified is not None and filename_model in (None, verified):
        return verified
    if filename_model:
        return filename_model
    embedded = list(scores)
    explicit = re.search(r"(?<![A-Z0-9])(?:SCH[-_ ]?)?([A-Z]\d{3})(?:\b|_)", stem)
    if explicit and (embedded or stem.startswith(("SCH", "E", "V", "X"))):
        token = explicit.group(1)
        if any(item.startswith("SCH-") for item in embedded) or not embedded:
            return f"SCH-{token}"
    return path.stem
