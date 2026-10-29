"""Firmware model identity detection."""
from __future__ import annotations

from pathlib import Path
import re

from .arm import thumb_bl_target, thumb_literal_value
from .chipset import detect_chipset


MODEL_RE = re.compile(
    rb"(?:"
    rb"(?:SCH|SPH)-[A-Z]\d{3,4}|LG-[A-Z]{1,3}\d{3,4}|SCP-?\d{3,4}|"
    rb"IM-\d{4}|(?:PG|PH|PT)-[A-Z]\d{3,4}[A-Z]?|C-\d{3,4}|"
    rb"CX-\d{3,4}[A-Z]?|KTFT-[A-Z]\d{3,4}"
    rb")(?![A-Z0-9])"
)


PRODUCT_TUPLE_RE = re.compile(
    rb"(?<![A-Z0-9])([A-Z][A-Z0-9]{1,7})\x00{1,4}"
    rb"([A-Z]\d{3,4})\x00{1,5}(MSM\d{4})\x00"
)
MOBILE_TYPE_RE = re.compile(
    rb"m_MobileType:\s*([A-Z][A-Z0-9]{1,7})-([A-Z]\d{3,4});"
    rb"([A-Z0-9]+)"
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


def structured_mobiletype_model(
        image: bytes, chipset: str | None = None) -> str | None:
    """Return one product label closed by tuple and labelled MobileType data."""
    tuples = []
    start = 0
    while (position := image.find(b"MSM", start)) >= 0:
        for match in PRODUCT_TUPLE_RE.finditer(
                image, max(0, position - 24), min(len(image), position + 9)):
            if match.start(3) == position:
                tuples.append((match.group(2), match.group(3)))
        start = position + 3
    if len(tuples) != 1:
        return None
    product, tuple_chipset = tuples[0]
    if (chipset or detect_chipset(image, "")) != tuple_chipset.decode("ascii"):
        return None
    matches = []
    start = 0
    while (position := image.find(b"m_MobileType:", start)) >= 0:
        match = MOBILE_TYPE_RE.match(
            image, position, min(len(image), position + 64)
        )
        if match is not None and match.group(2) == product:
            matches.append((match.group(1), match.group(2)))
        start = position + 1
    if len(matches) != 1:
        return None
    brand, mobile_product = matches[0]
    return canonical_model(brand + b"-" + mobile_product)



# shortcut: one complete self-description compiler class; widen only with a peer.
_PRODUCT_CONSTRUCTOR = bytes.fromhex(
    "90b5742000f0cefa2ba101602ca141602ba181600124846104730221071c79733422"
    "ba733221f9733321397430237b740021b974f97436213a757975bb753c77022000f0"
    "affa24a13862098801802349f81d1930f9860471786a230298435900084349000843"
    "0f23db029843490108434b00984389000843490008434b00984349030843c90a0843"
    "07235b0598430901084303235b069843c9000843490008431b019843011c7962"
    "b86a010a0902b962381c90bc08bc1847"
)
_PRODUCT_ALLOCATOR = bytes.fromhex(
    "80b40c4f021c9108386849000b1801219207920f002a00dc0021490059180122d203"
    "8a188a42396001d23860002080bc7047"
)
_AT_PRODUCT_RE = re.compile(
    rb"([A-Za-z][A-Za-z .,&-]{1,63})\x00(" + MODEL_RE.pattern
    + rb") *\x00{1,3}OK\x00CONNECT\x00RING\x00NO CARRIER\x00"
)


def _company_key(value: str) -> tuple[str, ...]:
    return tuple(word for word in re.findall(r"[A-Z0-9]+", value.upper())
                 if word not in {"CO", "LTD", "INC", "CORPORATION", "INCORPORATED"})


def _product_constructor_model(image: bytes) -> tuple[str | None, str]:
    """Bind a full typed self-description producer to an independent AT record."""
    def text(at: int, limit: int = 64) -> str | None:
        if not 0 <= at < len(image):
            return None
        end = image.find(b"\0", at, min(len(image), at + limit + 1))
        if end < 0 or end == at:
            return None
        raw = image[at:end]
        return raw.decode("ascii") if all(32 <= b < 127 for b in raw) else None

    def adr(at: int) -> int | None:
        if not 0 <= at <= len(image) - 2:
            return None
        word = int.from_bytes(image[at:at + 2], "little")
        return ((at + 4) & ~3) + (word & 255) * 4 if word & 0xFF00 == 0xA100 else None

    variable = set(range(4, 8)) | set(range(0x42, 0x46))
    variable |= {8, 9, 12, 13, 16, 17, 0x46, 0x47, 0x4E, 0x4F}
    constructors = []
    start = 0
    while (at := image.find(_PRODUCT_CONSTRUCTOR[:4], start)) >= 0:
        start = at + 1
        if at & 1 or at + len(_PRODUCT_CONSTRUCTOR) > len(image):
            continue
        if any(image[at + i] != byte for i, byte in enumerate(_PRODUCT_CONSTRUCTOR)
               if i not in variable):
            continue
        allocator = thumb_bl_target(image, at + 4)
        if (allocator is None or not 0 <= allocator <= len(image) - 2
                or thumb_bl_target(image, at + 0x42) != allocator
                or allocator + len(_PRODUCT_ALLOCATOR) > len(image)
                or any(image[allocator + i] != byte
                       for i, byte in enumerate(_PRODUCT_ALLOCATOR) if i != 2)
                or image[allocator + 3] != 0x4F
                or thumb_literal_value(image, allocator + 2, 7) is None):
            continue
        model_at, company_at, repeated = (adr(at + offset) for offset in (8, 12, 16))
        locale_at = adr(at + 0x46)
        if (None in (model_at, company_at, repeated, locale_at)
                or company_at != repeated
                or min(model_at, company_at, locale_at) < at + len(_PRODUCT_CONSTRUCTOR)
                or locale_at > len(image) - 2
                or thumb_literal_value(image, at + 0x4E, 1) is None):
            continue
        product, company = text(model_at), text(company_at)
        if (product is None or re.fullmatch(r"[A-Z]{1,3}[0-9]{3,4}[A-Z]?", product) is None
                or company is None or not _company_key(company)):
            continue
        constructors.append((product, _company_key(company), at))
    if not constructors:
        return None, "product-constructor-none"
    if len(constructors) != 1:
        return None, "product-constructor-ambiguous"
    product, company, constructor = constructors[0]
    matches = []
    for match in _AT_PRODUCT_RE.finditer(image):
        model = canonical_model(match.group(2))
        if (not constructor <= match.start() < constructor + len(_PRODUCT_CONSTRUCTOR)
                and _company_key(match.group(1).decode("ascii")) == company):
            matches.append(model)
    if len(matches) != 1:
        return None, "product-constructor-at-ambiguous" if matches else "product-constructor-at-unclosed"
    if matches[0] != company[0] + "-" + product:
        return None, "product-constructor-at-mismatch"
    return matches[0], "provisional-product-constructor-at"



# shortcut: one linked browser self-description compiler class, provisional only.
_BROWSER_BODIES = {
    'producer': (
        'b0b5051c141c2022402189b06846f9f733f900a12c396846f9f7b9f9c5f7f6fa002802d000a13439'
        '01e000a130396846f9f7adf916a16846f9f7a9f9a1f780fb011c6846f9f7a3f912a16846f9f79ff9'
        '6846f9f71ffa6846f9f75df9071cb0f749f9381cb0f7a8f8021c201c0aa1caf7fefc381cb0f700fa'
        '381cb0f70dfa074800f001fe288009b0b0bc08bc01201847'
        , (14, 24, 28, 48, 56, 60, 68, 76, 82, 88, 94, 100, 110, 116, 122, 128)),
    'append': (
        '90b50f1c041c081caff79bfb021c391c201cfff7ddff90bc08bc1847'
        , (8, 18)),
    'span': (
        'b0b5071c0d1c141c111cfff770ff391d03c9221c4018291c32f0b5fdb8680019b860b969814200d2'
        'b861b0bc08bc1847'
        , (10, 24)),
    'init': (
        'b0b5071c0c1c151c242132f0fffd201cb6f76efe38803888b7f730f83888b6f78fff78601c3730c7'
        'b0bc08bc1847'
        , (10, 16, 24, 30)),
    'strlen': (
        '90b4471c810708d001780130002902d1c01b90bc70478107f6d10b4ad40102c88b1a8b432340fad0'
        'c01b0a0601d10338efe70a0a120601d10238eae7090c0906e7d10138e5e70000'
        , ()),
}

_BROWSER_RECORD = re.compile(
    rb"model\x00{1,4}([A-Z][A-Z0-9]{1,7}-[A-Z0-9]{2,12}/[A-Z0-9][A-Z0-9._-]{0,15})"
    rb"\x00{1,4}oem\x00([A-Z][A-Z0-9 .&-]{1,31})\x00psa.version\x00version.software\x00"
)


def _browser_shape(image: bytes, at: int, kind: str, bodies: dict) -> dict[int, int] | None:
    encoded, offsets = bodies[kind]
    body = bytes.fromhex(encoded)
    if at & 1 or not 0 <= at <= len(image) - len(body):
        return None
    variable = {i for offset in offsets for i in range(offset, offset + 4)}
    if any(image[at + i] != value for i, value in enumerate(body) if i not in variable):
        return None
    calls = {}
    for offset in offsets:
        target = thumb_bl_target(image, at + offset)
        if (target is None or not 0 <= target <= len(image) - 4
                or image[target:target + 4] in (b"\0" * 4, b"\xff" * 4)):
            return None
        calls[offset] = target
    return calls


def _browser_literal_product_model(image: bytes) -> tuple[str | None, str]:
    """Return a linked software product label, never a physical model identity."""
    def shape(at: int, kind: str) -> dict[int, int] | None:
        return _browser_shape(image, at, kind, _BROWSER_BODIES)

    products = []
    start = 0
    prefix = bytes.fromhex(_BROWSER_BODIES['producer'][0])[:14]
    while (at := image.find(prefix, start)) >= 0:
        start = at + 1
        calls = shape(at, 'producer')
        if calls is None or at & 3 or at < 0x18 or at + 0xa0 > len(image):
            continue
        version = image[at - 0x18:at - 0xc].split(b'\0', 1)[0]
        if (re.fullmatch(rb'[0-9]+(?:\.[0-9]+){1,3}[a-z]?', version) is None
                or image[at - 0xc:at] != b' WEAK\0\0\0 \0\0\0'):
            continue
        # The same append receiver consumes static fragments and the getter result.
        append = calls[0x18]
        if any(calls[offset] != append for offset in (0x30, 0x38, 0x44, 0x4c)):
            continue
        linked = shape(append, 'append')
        init = shape(calls[0xe], 'init')
        if linked is None or init is None:
            continue
        if (shape(linked[8], 'strlen') is None
                or thumb_literal_value(image, linked[8] + 0x1a, 2) != 0x01010101
                or shape(linked[0x12], 'span') is None):
            continue
        getter = calls[0x3c]
        if getter & 3 or image[getter:getter + 4] != bytes.fromhex('00487047'):
            continue
        model_at = thumb_literal_value(image, getter, 0)
        if model_at is None:
            continue
        records = [match for match in _BROWSER_RECORD.finditer(
            image, max(0, model_at - 9), min(len(image), model_at + 128))
            if match.start(1) == model_at]
        if len(records) != 1:
            continue
        # PC-relative fragments are the literal opening/closing model delimiters.
        if image[at + 0x90:at + 0x98] != b" (\0\0)\0\0\0":
            continue
        # A second independent typed caller retains this getter's returned pointer.
        found = False
        position = 0
        while (position := image.find(bytes.fromhex('1190'), position)) >= 0:
            pc = position - 4
            position += 1
            if (pc >= 0 and not pc & 1
                    and thumb_bl_target(image, pc) == getter
                    and thumb_bl_target(image, pc + 6) == linked[8]
                    and image[pc + 10:pc + 12] == bytes.fromhex('061c')):
                found = True
                break
        if found:
            products.append(records[0].group(1).decode('ascii'))
    if len(products) != 1:
        return None, 'browser-product-ambiguous' if products else 'browser-product-none'
    return products[0], 'provisional-browser-product-constructor'



_BROWSER_ADR_BODIES = {
    'producer': (
        'f0b589b0051c141c20224021684616f087ff1f49684617f05df831f0d7fc002805d000a130396846'
        '17f054f804e000a13439684617f04ef816a1684617f04af8d3f7cafe011c684617f044f812a16846'
        '17f040f8684617f0cbf8684616f0d9ff071c3a1c0da1201c05f056f8381cf5f7c1fa0b4a0ba1201c'
        '05f030f80a4801f08ffd2880012009b0f0bc08bc1847'
        , (14, 22, 26, 40, 52, 60, 64, 72, 80, 86, 92, 104, 110, 120, 126)),
    'append': (
        '90b5041c0f1c381cd9f73af8021c391c201cfff7daff90bc08bc1847'
        , (8, 18)),
    'span': (
        'b0b5071c0d1c141c211c381cfff713ff3a1d06ca8818221c291c42f094f9b8680019b860b869b968'
        '884201d2b868b861b0bc08bc1847'
        , (12, 26)),
    'init': (
        'b0b5071c0c1c151c2421381c43f070fe201cdef741f838803888def775fa3888def7aaf97860fc61'
        '3d62b0bc08bc1847'
        , (12, 18, 26, 32)),
    'strlen': _BROWSER_BODIES['strlen'],
}
_BROWSER_LENGTH_FRAME = bytes.fromhex('f7b595b00020149000240026149f179a002a00d0a4e0')


def _browser_adr_product_model(image: bytes) -> tuple[str | None, str]:
    """Close the separate inline-getter software-description compiler class."""
    def text(at: int | None, limit: int) -> bytes | None:
        if type(at) is not int or not 0 <= at < len(image):
            return None
        end = image.find(b"\0", at, min(len(image), at + limit + 1))
        if end <= at:
            return None
        value = image[at:end]
        return value if all(32 <= byte < 127 for byte in value) else None

    products = []
    start = 0
    prefix = bytes.fromhex(_BROWSER_ADR_BODIES['producer'][0])[:14]
    while (at := image.find(prefix, start)) >= 0:
        start = at + 1
        calls = _browser_shape(image, at, 'producer', _BROWSER_ADR_BODIES)
        if calls is None or at & 3 or at + 0xac > len(image):
            continue
        append = calls[0x16]
        if any(calls[offset] != append for offset in (0x28, 0x34, 0x3c, 0x48, 0x50)):
            continue
        linked = _browser_shape(image, append, 'append', _BROWSER_ADR_BODIES)
        if (linked is None or _browser_shape(image, calls[0xe], 'init', _BROWSER_ADR_BODIES) is None
                or _browser_shape(image, linked[0x12], 'span', _BROWSER_ADR_BODIES) is None
                or _browser_shape(image, linked[8], 'strlen', _BROWSER_ADR_BODIES) is None
                or thumb_literal_value(image, linked[8] + 0x1a, 2) != 0x01010101):
            continue
        getter = calls[0x40]
        if getter & 3 or image[getter:getter + 4] != bytes.fromhex('00a07047'):
            continue
        product = text(getter + 4, 64)
        records = [match for match in _BROWSER_RECORD.finditer(image)
                   if match.group(1) == product]
        if len(records) != 1:
            continue
        version = text(thumb_literal_value(image, at + 0x12, 1), 64)
        build = text(thumb_literal_value(image, at + 0x72, 2), 512)
        if (version is None or re.fullmatch(rb'[0-9]+(?:\.[0-9]+){1,3}(?: \([A-Za-z0-9 -]{1,16}\))?', version) is None
                or build is None or not build.startswith(b'Built on ')
                or thumb_literal_value(image, at + 0x7c, 0) != 0x500c
                or image[at + 0x94:at + 0xa0] != b' (\0\0)\0\0\0v\0\0\0'
                or image[at + 0xa4:at + 0xa8] != b'i\0\0\0'):
            continue
        consumers = []
        position = 0
        while (position := image.find(bytes.fromhex('11901198'), position)) >= 0:
            pc = position - 4
            position += 1
            frame = pc - 0x160
            if (frame >= 0 and not pc & 1
                    and image[frame:frame + len(_BROWSER_LENGTH_FRAME)] == _BROWSER_LENGTH_FRAME
                    and thumb_bl_target(image, pc) == getter
                    and thumb_bl_target(image, pc + 8) == linked[8]
                    and image[pc + 12:pc + 16] == bytes.fromhex('05042d14')):
                consumers.append(pc)
        if len(consumers) == 1:
            products.append(product.decode('ascii'))
    if len(products) != 1:
        return None, 'browser-product-ambiguous' if products else 'browser-product-none'
    return products[0], 'provisional-browser-product-adr-constructor'


def _browser_product_model(image: bytes) -> tuple[str | None, str]:
    candidates = [_browser_literal_product_model(image), _browser_adr_product_model(image)]
    complete = [candidate for candidate in candidates if candidate[0] is not None]
    if len(complete) > 1 or any(reason == 'browser-product-ambiguous' for _, reason in candidates):
        return None, 'browser-product-ambiguous'
    return complete[0] if complete else (None, 'browser-product-none')

def detect_model(image: bytes, path: Path,
                 scores: dict[str, int] | None = None,
                 chipset: str | None = None, *,
                 notes: list[str] | None = None) -> str:
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
    product, reason = _product_constructor_model(image)
    if notes is not None and reason != "product-constructor-none":
        notes.append(reason)
    browser, browser_reason = _browser_product_model(image)
    if notes is not None and browser_reason != "browser-product-none":
        notes.append(browser_reason)
    if browser is not None and (product or verified) not in (None, browser):
        if notes is not None:
            notes.append("browser-product-strong-identity-conflict")
    if product is not None:
        if verified in (None, product):
            return product
        if notes is not None:
            notes.append("product-constructor-heuristic-conflict")
    if verified is not None:
        if filename_model in (None, verified):
            return verified
        if filename_model:
            return filename_model
    structured = structured_mobiletype_model(image, chipset)
    if structured is not None:
        if browser is not None and browser != structured and notes is not None:
            notes.append("browser-product-strong-identity-conflict")
        return structured
    if browser is not None:
        return browser
    if filename_model:
        return filename_model
    embedded = list(scores)
    explicit = re.search(r"(?<![A-Z0-9])(?:SCH[-_ ]?)?([A-Z]\d{3})(?:\b|_)", stem)
    if explicit and (embedded or stem.startswith(("SCH", "E", "V", "X"))):
        token = explicit.group(1)
        if any(item.startswith("SCH-") for item in embedded) or not embedded:
            return f"SCH-{token}"
    return path.stem
