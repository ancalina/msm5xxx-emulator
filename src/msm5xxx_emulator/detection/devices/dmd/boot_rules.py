"""Closed boot-time instruction evidence owned by this domain."""
from __future__ import annotations
import re
import struct
from msm5xxx_emulator.detection.facts import facts_for
from msm5xxx_emulator.detection.signatures import find_all

DMD_DOWNLOAD_SIGNATURE = bytes.fromhex("f0b5002701250024354901200870")
DMD_DOWNLOAD_510X_SIGNATURE = bytes.fromhex("f0b539480027006801250024002800d060e0")
