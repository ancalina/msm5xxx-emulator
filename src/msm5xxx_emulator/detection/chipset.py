"""Qualcomm BSP generation detection."""


def detect_chipset(image: bytes, model: str) -> str:
    lowered = image.lower()
    if b"msm6050" in lowered:
        return "MSM6050"
    if (b"clkrgm_5500.c" in lowered or b"boothw_5500.c" in lowered
            or b"dmddown_5500.c" in lowered):
        return "MSM5500"
    if b"mclk_5105.c" in lowered:
        return "MSM5105"
    if b"clkrgm_5100.c" in lowered or b"boothw_510x.c" in lowered:
        return "MSM5100"
    if b"mclk_5000.c" in lowered or b"dec5000.c" in lowered or b"dec5000_.c" in lowered:
        return "MSM5000"
    upper = image.upper()
    has_5500, has_5100 = b"MSM5500" in upper, b"MSM5100" in upper
    if has_5500 and not has_5100:
        return "MSM5500"
    if has_5100 and not has_5500:
        return "MSM5100"
    if model == "SCH-X430" and b"MSM5000" in upper:
        return "MSM5000"
    return "MSM5xxx"


def chipset_confidence(image: bytes, chipset: str) -> str:
    lowered = image.lower()
    markers = {
        "MSM5500": (b"clkrgm_5500.c", b"boothw_5500.c", b"dmddown_5500.c"),
        "MSM5105": (b"mclk_5105.c",),
        "MSM5100": (b"clkrgm_5100.c", b"boothw_510x.c"),
        "MSM5000": (b"mclk_5000.c",),
        "MSM6050": (b"msm6050",),
    }
    if chipset in markers and any(marker in lowered for marker in markers[chipset]):
        return "high"
    return "medium" if chipset != "MSM5xxx" else "unknown"
