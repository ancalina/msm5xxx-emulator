"""Pure settings schema, parsing, and validation helpers."""
from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path

from ..core.config import FirmwareConfig
from ..core.constants import (MAX_NAND_BACKING_SIZE, MAX_NAND_DATA_SIZE,
                              MAX_RAM_SIZE, PAGE)
from ..detection.firmware import MAX_FLASH_SIZE


SETTINGS_SECTIONS = (
    ("기본", (("firmware", "펌웨어"), ("model", "모델"),
            ("chipset", "칩셋"), ("width", "화면 너비"),
            ("height", "화면 높이"), ("board_revision", "Board revision 이름"))),
    ("메모리", (("image_offset", "이미지 오프셋"),
             ("load_address", "로드 주소"), ("flash_size", "Flash 크기"),
             ("ram_base", "RAM 시작 주소"), ("ram_size", "RAM 크기"),
             ("ram_image_offset", "RAM image 오프셋"),
             ("ram_image_size", "RAM image 크기 (0=끔)"),
             ("entry", "진입점 오프셋"))),
    ("화면 버퍼", (("framebuffer_address", "Framebuffer 주소 (빈 값=끔)"),
                 ("framebuffer_stride", "Framebuffer stride bytes"),
                 ("framebuffer_format", "Framebuffer pixel format"),
                 ("framebuffer_flush_address", "Row flush 함수"),
                 ("framebuffer_rect_flush_address", "Rect flush 함수"))),
    ("하드웨어", (("board_revision_register", "Board revision 레지스터"),
               ("board_revision_value", "Board revision 값"),
               ("key_register", "키 레지스터"),
               ("key_active_low", "키 active-low"),
               ("audio_play_address", "Audio play 함수"),
               ("fast_boot_address", "Fast boot 함수"))),
    ("함수", (("delay_address", "Delay 함수"),
            ("busy_delay_address", "Busy delay 함수"),
            ("crc16_address", "CRC16 함수"),
            ("nand_bad_block_address", "NAND bad-block 함수"),
            ("nand_read_address", "NAND read 함수"),
            ("nand_write_address", "NAND write 함수"))),
    ("부팅 HLE", (("rex_idle_address", "REX idle 함수"),
                ("rex_tick_address", "REX tick 함수"),
                ("rex_tick_ms", "REX tick 밀리초"),
                ("board_adc_address", "Board ADC 함수"),
                ("board_adc_value", "Board ADC 값"),
                ("flash_id_address", "Flash ID 함수"),
                ("flash_id_value", "Flash ID 값"),
                ("dmd_download_address", "DMD download 함수"),
                ("primary_flash_probe_address", "NOR probe 함수"))),
    ("EFS NOR", (("secondary_flash_address", "보조 NOR 주소 (0=끔)"),
               ("secondary_flash_size", "보조 NOR 크기"),
               ("secondary_flash_image", "보조 NOR image"),
               ("secondary_flash_state", "보조 NOR state"),
               ("secondary_flash_read_address", "보조 NOR read 함수"),
               ("secondary_flash_write_address", "보조 NOR write 함수"),
               ("legacy_efs_page_read_address", "Legacy EFS page read 함수"))),
    ("저장", (("flash_state", "Flash state"),
            ("nand_enabled", "NAND 사용"), ("nand_image", "NAND raw image"),
            ("nand_data_size", "NAND data 크기"),
            ("nand_page_size", "NAND page 크기"),
            ("nand_spare_size", "NAND spare 크기"),
            ("nand_pages_per_block", "NAND block당 pages"),
            ("nand_bus_width", "NAND bus bytes"))),
)


BOOLEAN_FIELDS = frozenset({"key_active_low", "nand_enabled"})


ADDRESS_FIELDS = (
    "load_address", "key_register", "board_revision_register",
    "board_revision_value", "audio_play_address", "fast_boot_address",
    "delay_address", "busy_delay_address", "crc16_address",
    "rex_idle_address", "rex_tick_address", "board_adc_address",
    "board_adc_value", "flash_id_address", "flash_id_value",
    "dmd_download_address", "primary_flash_probe_address",
    "nand_bad_block_address", "nand_read_address", "nand_write_address",
    "secondary_flash_address", "secondary_flash_read_address",
    "secondary_flash_write_address", "legacy_efs_page_read_address",
    "framebuffer_address", "framebuffer_flush_address",
    "framebuffer_rect_flush_address",
)


def settings_values(firmware: Path, detected: FirmwareConfig,
                    overrides: Mapping[str, object]) -> dict[str, str]:
    def current(name: str) -> object:
        return overrides[name] if name in overrides else getattr(detected, name)

    def shown(name: str, *, hexadecimal: bool = False) -> str:
        value = current(name)
        if value is None:
            return ""
        return hex(int(value)) if hexadecimal else str(value)

    return {
        "firmware": str(firmware),
        "model": shown("model"),
        "chipset": shown("chipset"),
        "width": shown("width"),
        "height": shown("height"),
        "framebuffer_address": shown("framebuffer_address", hexadecimal=True),
        "framebuffer_stride": shown("framebuffer_stride", hexadecimal=True),
        "framebuffer_format": shown("framebuffer_format"),
        "framebuffer_flush_address": shown("framebuffer_flush_address",
                                           hexadecimal=True),
        "framebuffer_rect_flush_address": shown(
            "framebuffer_rect_flush_address", hexadecimal=True),
        "board_revision": shown("board_revision"),
        "image_offset": shown("image_offset", hexadecimal=True),
        "load_address": shown("load_address", hexadecimal=True),
        "flash_size": shown("flash_size", hexadecimal=True),
        "secondary_flash_address": shown("secondary_flash_address", hexadecimal=True),
        "secondary_flash_size": shown("secondary_flash_size", hexadecimal=True),
        "secondary_flash_image": shown("secondary_flash_image"),
        "secondary_flash_state": shown("secondary_flash_state"),
        "secondary_flash_read_address": shown("secondary_flash_read_address",
                                              hexadecimal=True),
        "secondary_flash_write_address": shown("secondary_flash_write_address",
                                               hexadecimal=True),
        "legacy_efs_page_read_address": shown(
            "legacy_efs_page_read_address", hexadecimal=True),
        "ram_base": shown("ram_base", hexadecimal=True),
        "ram_size": shown("ram_size", hexadecimal=True),
        "ram_image_offset": shown("ram_image_offset", hexadecimal=True),
        "ram_image_size": shown("ram_image_size", hexadecimal=True),
        "entry": shown("entry", hexadecimal=True),
        "board_revision_register": shown("board_revision_register", hexadecimal=True),
        "board_revision_value": shown("board_revision_value", hexadecimal=True),
        "key_register": shown("key_register", hexadecimal=True),
        "key_active_low": "true" if current("key_active_low") else "false",
        "audio_play_address": shown("audio_play_address", hexadecimal=True),
        "fast_boot_address": shown("fast_boot_address", hexadecimal=True),
        "delay_address": shown("delay_address", hexadecimal=True),
        "busy_delay_address": shown("busy_delay_address", hexadecimal=True),
        "crc16_address": shown("crc16_address", hexadecimal=True),
        "rex_idle_address": shown("rex_idle_address", hexadecimal=True),
        "rex_tick_address": shown("rex_tick_address", hexadecimal=True),
        "rex_tick_ms": shown("rex_tick_ms"),
        "board_adc_address": shown("board_adc_address", hexadecimal=True),
        "board_adc_value": shown("board_adc_value", hexadecimal=True),
        "flash_id_address": shown("flash_id_address", hexadecimal=True),
        "flash_id_value": shown("flash_id_value", hexadecimal=True),
        "dmd_download_address": shown("dmd_download_address", hexadecimal=True),
        "primary_flash_probe_address": shown("primary_flash_probe_address",
                                             hexadecimal=True),
        "nand_bad_block_address": shown("nand_bad_block_address", hexadecimal=True),
        "nand_read_address": shown("nand_read_address", hexadecimal=True),
        "nand_write_address": shown("nand_write_address", hexadecimal=True),
        "flash_state": shown("flash_state"),
        "nand_enabled": "true" if current("nand_enabled") else "false",
        "nand_image": shown("nand_image"),
        "nand_data_size": shown("nand_data_size", hexadecimal=True),
        "nand_page_size": shown("nand_page_size", hexadecimal=True),
        "nand_spare_size": shown("nand_spare_size", hexadecimal=True),
        "nand_pages_per_block": shown("nand_pages_per_block"),
        "nand_bus_width": shown("nand_bus_width"),
    }


def parse_settings_values(values: Mapping[str, str]) -> dict[str, object]:
    def integer(name: str) -> int:
        return int(values[name], 0)

    def optional_integer(name: str) -> int | None:
        return int(values[name], 0) if values[name] else None

    def boolean(name: str) -> bool:
        text = values[name].lower()
        if text == "true":
            return True
        if text == "false":
            return False
        raise ValueError(f"{name}: true 또는 false만 허용")

    nand_image_text = values["nand_image"]
    secondary_image_text = values["secondary_flash_image"]
    secondary_state_text = values["secondary_flash_state"]
    return {
        "model": values["model"],
        "chipset": values["chipset"],
        "image_offset": integer("image_offset"),
        "load_address": integer("load_address"),
        "flash_size": integer("flash_size"),
        "secondary_flash_address": optional_integer("secondary_flash_address"),
        "secondary_flash_size": integer("secondary_flash_size"),
        "secondary_flash_image": (
            str(Path(secondary_image_text).expanduser().resolve())
            if secondary_image_text else None),
        "secondary_flash_state": (
            str(Path(secondary_state_text).expanduser().resolve())
            if secondary_state_text else ""),
        "secondary_flash_read_address": optional_integer(
            "secondary_flash_read_address"),
        "secondary_flash_write_address": optional_integer(
            "secondary_flash_write_address"),
        "legacy_efs_page_read_address": optional_integer(
            "legacy_efs_page_read_address"),
        "ram_base": integer("ram_base"),
        "ram_size": integer("ram_size"),
        "ram_image_offset": integer("ram_image_offset"),
        "ram_image_size": integer("ram_image_size"),
        "entry": integer("entry"),
        "width": integer("width"),
        "height": integer("height"),
        "framebuffer_address": optional_integer("framebuffer_address"),
        "framebuffer_stride": integer("framebuffer_stride"),
        "framebuffer_format": values["framebuffer_format"],
        "framebuffer_flush_address": optional_integer("framebuffer_flush_address"),
        "framebuffer_rect_flush_address": optional_integer(
            "framebuffer_rect_flush_address"),
        "board_revision": values["board_revision"],
        "board_revision_register": optional_integer("board_revision_register"),
        "board_revision_value": optional_integer("board_revision_value"),
        "key_register": optional_integer("key_register"),
        "key_active_low": boolean("key_active_low"),
        "audio_play_address": optional_integer("audio_play_address"),
        "fast_boot_address": optional_integer("fast_boot_address"),
        "delay_address": optional_integer("delay_address"),
        "busy_delay_address": optional_integer("busy_delay_address"),
        "crc16_address": optional_integer("crc16_address"),
        "rex_idle_address": optional_integer("rex_idle_address"),
        "rex_tick_address": optional_integer("rex_tick_address"),
        "rex_tick_ms": integer("rex_tick_ms"),
        "board_adc_address": optional_integer("board_adc_address"),
        "board_adc_value": integer("board_adc_value"),
        "flash_id_address": optional_integer("flash_id_address"),
        "flash_id_value": optional_integer("flash_id_value"),
        "dmd_download_address": optional_integer("dmd_download_address"),
        "primary_flash_probe_address": optional_integer(
            "primary_flash_probe_address"),
        "nand_bad_block_address": optional_integer("nand_bad_block_address"),
        "nand_read_address": optional_integer("nand_read_address"),
        "nand_write_address": optional_integer("nand_write_address"),
        "flash_state": str(Path(values["flash_state"]).expanduser().resolve()),
        "nand_enabled": boolean("nand_enabled"),
        "nand_image": (str(Path(nand_image_text).expanduser().resolve())
                       if nand_image_text else None),
        "nand_data_size": integer("nand_data_size"),
        "nand_page_size": integer("nand_page_size"),
        "nand_spare_size": integer("nand_spare_size"),
        "nand_pages_per_block": integer("nand_pages_per_block"),
        "nand_bus_width": integer("nand_bus_width"),
    }


def validate_settings_values(
        firmware: Path, effective: FirmwareConfig, overrides: dict[str, object],
        edited: set[str], flash_state_text: str) -> None:
    if not overrides["model"]:
        raise ValueError("모델 이름이 비어 있음")
    if overrides["chipset"] not in (
            "MSM5000", "MSM5100", "MSM5105", "MSM5500", "MSM5xxx"):
        raise ValueError("지원하지 않는 칩셋")
    if not 32 <= overrides["width"] <= 1024 or not 32 <= overrides["height"] <= 1024:
        raise ValueError("화면 크기 범위: 32..1024")
    framebuffer_address = overrides["framebuffer_address"]
    framebuffer_triggers = (
        overrides["framebuffer_flush_address"],
        overrides["framebuffer_rect_flush_address"],
    )
    if framebuffer_address is None:
        if any(value is not None for value in framebuffer_triggers):
            raise ValueError("Framebuffer 주소 없이 flush 함수를 쓸 수 없음")
        if overrides["framebuffer_format"] != "none":
            raise ValueError("Framebuffer를 끌 때 pixel format은 none이어야 함")
    else:
        if overrides["framebuffer_format"] == "none":
            raise ValueError("Framebuffer pixel format을 선택해야 함")
        if overrides["framebuffer_stride"] < overrides["width"] * 2:
            raise ValueError("Framebuffer stride가 한 줄보다 작음")
    file_size = firmware.stat().st_size
    if ("image_offset" in edited
            and not 0 <= overrides["image_offset"] < file_size):
        raise ValueError("이미지 오프셋이 펌웨어 범위를 벗어남")
    available = file_size - overrides["image_offset"]
    if (({"flash_size", "image_offset"} & edited)
            and (overrides["flash_size"] <= 0
                 or overrides["flash_size"] > MAX_FLASH_SIZE
                 or overrides["flash_size"] - available > PAGE)):
        raise ValueError("Flash 크기가 펌웨어 범위를 벗어남")
    if overrides["load_address"] + overrides["flash_size"] > 0x100000000:
        raise ValueError("Flash 매핑이 32-bit 주소 공간을 벗어남")
    if not 0 <= overrides["entry"] < overrides["flash_size"]:
        raise ValueError("진입점 오프셋이 Flash 범위를 벗어남")
    if min(overrides["ram_base"], overrides["ram_size"]) <= 0:
        raise ValueError("RAM 시작 주소와 크기는 양수여야 함")
    if overrides["ram_size"] > MAX_RAM_SIZE:
        raise ValueError("RAM 크기 상한: 128 MiB")
    if overrides["ram_base"] + overrides["ram_size"] > 0x100000000:
        raise ValueError("RAM 범위가 32-bit 주소 공간을 벗어남")
    flash_start = overrides["load_address"]
    flash_end = flash_start + overrides["flash_size"]
    ram_start = overrides["ram_base"]
    ram_end = ram_start + overrides["ram_size"]
    if max(flash_start, ram_start) < min(flash_end, ram_end):
        raise ValueError("주 Flash가 RAM과 겹침")
    if framebuffer_address is not None:
        framebuffer_end = (framebuffer_address
                           + overrides["framebuffer_stride"]
                           * overrides["height"])
        if not ram_start <= framebuffer_address < framebuffer_end <= ram_end:
            raise ValueError("Framebuffer 범위가 RAM을 벗어남")
    if min(overrides["ram_image_offset"], overrides["ram_image_size"]) < 0:
        raise ValueError("RAM image 오프셋과 크기는 음수일 수 없음")
    if (overrides["ram_image_size"]
            and (overrides["ram_image_offset"] + overrides["ram_image_size"]
                 > available)):
        raise ValueError("RAM image 범위가 펌웨어를 벗어남")
    if overrides["ram_image_size"] > overrides["ram_size"]:
        raise ValueError("RAM image 크기가 RAM 크기를 초과함")
    if any(value is not None and not 0 <= value <= 0xFFFFFFFF
           for value in (overrides[name] for name in ADDRESS_FIELDS)):
        raise ValueError("주소와 레지스터 값 범위: 0..0xFFFFFFFF")
    if not 0 <= overrides["rex_tick_ms"] <= 60_000:
        raise ValueError("REX tick 밀리초 범위: 0..60000")
    if not flash_state_text:
        raise ValueError("Flash state 경로가 비어 있음")
    secondary_address = overrides["secondary_flash_address"]
    if overrides["secondary_flash_size"] < 0:
        raise ValueError("보조 NOR 크기는 음수일 수 없음")
    effective_secondary_address = (
        secondary_address if secondary_address is not None
        else effective.secondary_flash_address
    )
    if effective_secondary_address not in (None, 0):
        secondary_address = effective_secondary_address
        secondary_size = overrides["secondary_flash_size"]
        secondary_end = secondary_address + secondary_size
        primary_start = overrides["load_address"]
        primary_end = primary_start + overrides["flash_size"]
        ram_start = overrides["ram_base"]
        ram_end = ram_start + overrides["ram_size"]
        if (not 0 < secondary_size <= MAX_FLASH_SIZE
                or secondary_end > 0x100000000):
            raise ValueError("보조 NOR 주소 또는 크기 범위 오류")
        if max(secondary_address, primary_start) < min(secondary_end, primary_end):
            raise ValueError("보조 NOR가 주 Flash와 겹침")
        if max(secondary_address, ram_start) < min(secondary_end, ram_end):
            raise ValueError("보조 NOR가 RAM과 겹침")
        if not overrides["secondary_flash_state"]:
            raise ValueError("보조 NOR state 경로가 비어 있음")
        if overrides["secondary_flash_image"]:
            image = Path(overrides["secondary_flash_image"])
            if not image.is_file():
                raise ValueError("보조 NOR image 파일 없음")
            if image.stat().st_size > secondary_size:
                raise ValueError("보조 NOR image가 설정 크기보다 큼")
    nand_values = (overrides["nand_data_size"], overrides["nand_page_size"],
                   overrides["nand_spare_size"],
                   overrides["nand_pages_per_block"])
    if min(nand_values) <= 0:
        raise ValueError("NAND 크기와 block geometry는 양수여야 함")
    if overrides["nand_data_size"] > MAX_NAND_DATA_SIZE:
        raise ValueError("NAND data 크기 상한: 128 MiB")
    if not 256 <= overrides["nand_page_size"] <= 0x4000:
        raise ValueError("NAND page 크기 범위: 256..16384")
    if not 1 <= overrides["nand_spare_size"] <= 0x1000:
        raise ValueError("NAND spare 크기 범위: 1..4096")
    if not 1 <= overrides["nand_pages_per_block"] <= 0x1000:
        raise ValueError("NAND block당 pages 범위: 1..4096")
    if overrides["nand_data_size"] % overrides["nand_page_size"]:
        raise ValueError("NAND data 크기는 page 크기의 배수여야 함")
    if overrides["nand_bus_width"] not in (1, 2):
        raise ValueError("NAND bus bytes는 1 또는 2여야 함")
    raw_backing = (overrides["nand_data_size"]
                   // overrides["nand_page_size"]
                   * (overrides["nand_page_size"] + overrides["nand_spare_size"]))
    if raw_backing > MAX_NAND_BACKING_SIZE:
        raise ValueError("NAND raw backing 상한: 256 MiB")
    if (overrides["nand_enabled"] and overrides["nand_image"]
            and not Path(overrides["nand_image"]).is_file()):
        raise ValueError("NAND raw image 파일 없음")
