"""Small vectorized SoundFont 2 renderer for real-time-ish E170 playback.

It implements the preset/instrument/sample path needed by the bundled GM bank.
Unsupported SF2 modulators fall back to the base generator values.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path

import numpy as np


def _chunks(data: bytes, start: int, end: int):
    pos = start
    while pos + 8 <= end:
        tag = data[pos:pos + 4]
        size = struct.unpack_from("<I", data, pos + 4)[0]
        body = pos + 8
        yield tag, data[body:min(end, body + size)]
        pos = body + size + (size & 1)


def _records(data: bytes, size: int, fmt: str):
    return [struct.unpack_from(fmt, data, pos)
            for pos in range(0, len(data) - size + 1, size)]


def _signed(value: int) -> int:
    return value if value < 0x8000 else value - 0x10000


def _range(value: int) -> tuple[int, int]:
    return value & 0xFF, value >> 8


def _timecents(value: int, default: float) -> float:
    if value <= -12000:
        return 0.0
    try:
        return min(8.0, 2.0 ** (value / 1200.0))
    except OverflowError:
        return default


@dataclass(frozen=True)
class Sample:
    start: int
    end: int
    loop_start: int
    loop_end: int
    rate: int
    root: int
    correction: int


class SoundFont:
    def __init__(self, path: Path):
        data = path.read_bytes()
        if data[:4] != b"RIFF" or data[8:12] != b"sfbk":
            raise ValueError("not an SF2 file")
        pdta: dict[bytes, bytes] = {}
        sample_bytes = b""
        for tag, body in _chunks(data, 12, min(len(data), 8 + struct.unpack_from("<I", data, 4)[0])):
            if tag != b"LIST" or len(body) < 4:
                continue
            for subtag, subbody in _chunks(body, 4, len(body)):
                if body[:4] == b"pdta":
                    pdta[subtag] = subbody
                elif body[:4] == b"sdta" and subtag == b"smpl":
                    sample_bytes = subbody
        self.pcm = np.frombuffer(sample_bytes, dtype="<i2").astype(np.float32) / 32768.0
        phdr = _records(pdta[b"phdr"], 38, "<20sHHHIII")
        pbag = _records(pdta[b"pbag"], 4, "<HH")
        pgen = _records(pdta[b"pgen"], 4, "<HH")
        inst = _records(pdta[b"inst"], 22, "<20sH")
        ibag = _records(pdta[b"ibag"], 4, "<HH")
        igen = _records(pdta[b"igen"], 4, "<HH")
        shdr = _records(pdta[b"shdr"], 46, "<20sIIIIIBbHH")
        self.samples = [Sample(x[1], x[2], x[3], x[4], x[5], x[6], x[7])
                        for x in shdr[:-1]]

        def zones(bags, gens, first: int, last: int):
            out = []
            for bag in range(first, last):
                begin = bags[bag][0]
                end = bags[bag + 1][0] if bag + 1 < len(bags) else len(gens)
                out.append({operator: amount for operator, amount in gens[begin:end]})
            return out

        self.instruments: list[list[dict[int, int]]] = []
        for index in range(len(inst) - 1):
            self.instruments.append(zones(ibag, igen, inst[index][1], inst[index + 1][1]))
        self.presets: dict[tuple[int, int], list[dict[int, int]]] = {}
        for index, record in enumerate(phdr[:-1]):
            self.presets[(record[2], record[1])] = zones(
                pbag, pgen, record[3], phdr[index + 1][3])
        self.cache: dict[tuple[int, int, int, int], dict[int, int] | None] = {}

    @staticmethod
    def _matches(zone: dict[int, int], key: int, velocity: int) -> bool:
        low, high = _range(zone.get(43, 0x7F00))
        vlo, vhi = _range(zone.get(44, 0x7F00))
        return low <= key <= high and vlo <= velocity <= vhi

    @staticmethod
    def _combine(global_zone: dict[int, int], local: dict[int, int]) -> dict[int, int]:
        result = dict(global_zone)
        additive = {0,1,2,3,4,5,6,7,8,9,10,11,12,15,16,17,21,22,23,24,
                    25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,48,
                    50,51,52,56,57}
        for key, value in local.items():
            if key in additive and key in result:
                result[key] = (_signed(result[key]) + _signed(value)) & 0xFFFF
            else:
                result[key] = value
        return result

    def resolve(self, bank: int, program: int, key: int,
                velocity: int) -> dict[int, int] | None:
        cache_key = bank, program, key, velocity // 8
        if cache_key in self.cache:
            return self.cache[cache_key]
        preset = self.presets.get((bank, program)) or self.presets.get((0, program))
        if not preset:
            preset = self.presets.get((0, 0), [])
        preset_global: dict[int, int] = {}
        result = None
        for pzone in preset:
            if 41 not in pzone:
                preset_global = pzone
                continue
            combined_preset = self._combine(preset_global, pzone)
            if not self._matches(combined_preset, key, velocity):
                continue
            instrument_id = combined_preset[41]
            if instrument_id >= len(self.instruments):
                continue
            instrument_global: dict[int, int] = {}
            for izone in self.instruments[instrument_id]:
                if 53 not in izone:
                    instrument_global = izone
                    continue
                combined = self._combine(combined_preset,
                                         self._combine(instrument_global, izone))
                if self._matches(combined, key, velocity):
                    result = combined
                    break
            if result is not None:
                break
        self.cache[cache_key] = result
        return result


def render_notes(sf2: SoundFont, notes, sample_rate: int = 44100,
                 max_seconds: float = 180.0) -> np.ndarray:
    if not notes:
        return np.zeros((1, 2), dtype=np.int16)
    end_seconds = min(max_seconds, max((note.tick + max(1, note.span)) * 0.004
                                       for note in notes) + 2.0)
    mix = np.zeros((max(1, int(end_seconds * sample_rate)), 2), dtype=np.float32)
    drum_map = {0x12:45, 0x1A:41, 0x1F:47, 0x4D:50, 0x54:43, 0x59:48}
    program_map = {(0x7C,0x01,0x22):81, (0x7C,0x01,0x70):30,
                   (0x7C,0x01,0x46):84, (0x7C,0x01,0x21):33,
                   (0x7C,0x01,0x6A):87, (0x7C,0x01,0x62):98}
    for note in notes:
        source_bank = int(note.bank_msb) & 0x7F
        rhythm = source_bank == 0x7D
        key = int(note.note) & 0x7F
        if rhythm:
            key = drum_map.get(key, key)
        program = 0 if rhythm else program_map.get(
            (source_bank, int(note.bank_lsb) & 0x7F, int(note.program) & 0x7F),
            int(note.program) & 0x7F)
        bank = 128 if rhythm else 0
        velocity = max(1, min(127, int(getattr(note, "raw_velocity", note.velocity))))
        zone = sf2.resolve(bank, program, key, velocity)
        if not zone or zone.get(53, 0xFFFF) >= len(sf2.samples):
            continue
        sample = sf2.samples[zone[53]]
        start = sample.start + _signed(zone.get(0, 0)) + _signed(zone.get(4, 0)) * 32768
        end = sample.end + _signed(zone.get(1, 0)) + _signed(zone.get(12, 0)) * 32768
        loop_start = sample.loop_start + _signed(zone.get(2, 0)) + _signed(zone.get(45, 0)) * 32768
        loop_end = sample.loop_end + _signed(zone.get(3, 0)) + _signed(zone.get(50, 0)) * 32768
        start, end = max(0, start), min(len(sf2.pcm), end)
        if end <= start + 1:
            continue
        root = zone.get(58, sample.root)
        root = sample.root if root > 127 else root
        tune = _signed(zone.get(51, 0)) * 100 + _signed(zone.get(52, 0))
        cents = (key - root) * 100 - sample.correction + tune
        step = sample.rate / sample_rate * (2.0 ** (cents / 1200.0))
        duration = max(0.004, int(note.span) * 0.004)
        attack = _timecents(_signed(zone.get(34, 0xD120)), 0.002)
        decay = _timecents(_signed(zone.get(36, 0xD120)), 0.15)
        release = min(1.5, _timecents(_signed(zone.get(38, 0xD120)), 0.2))
        sustain = 10.0 ** (-max(0, _signed(zone.get(37, 0))) / 200.0)
        frames = min(len(mix), int((duration + release) * sample_rate))
        output_start = int(note.tick * 0.004 * sample_rate)
        frames = min(frames, len(mix) - output_start)
        if frames <= 0:
            continue
        positions = np.arange(frames, dtype=np.float64) * step
        looping = (zone.get(54, 0) & 3) in (1, 3) and loop_end > loop_start + 1
        if looping:
            relative_loop = loop_start - start
            loop_size = loop_end - loop_start
            after = positions >= relative_loop
            positions[after] = relative_loop + np.mod(positions[after] - relative_loop,
                                                       loop_size)
        valid = positions < end - start - 1
        if not np.any(valid):
            continue
        frames = int(np.flatnonzero(~valid)[0]) if not np.all(valid) else frames
        positions = positions[:frames]
        indices = positions.astype(np.int64)
        fraction = (positions - indices).astype(np.float32)
        wave = (sf2.pcm[start + indices] * (1.0 - fraction)
                + sf2.pcm[start + indices + 1] * fraction)
        envelope = np.ones(frames, dtype=np.float32) * sustain
        attack_n = min(frames, int(attack * sample_rate))
        if attack_n:
            envelope[:attack_n] = np.linspace(0.0, 1.0, attack_n, endpoint=False)
        decay_n = min(max(0, frames - attack_n), int(decay * sample_rate))
        if decay_n:
            envelope[attack_n:attack_n + decay_n] = np.linspace(
                1.0, sustain, decay_n, endpoint=False)
        release_at = min(frames, int(duration * sample_rate))
        if release_at < frames:
            envelope[release_at:] *= np.linspace(1.0, 0.0, frames - release_at)
        attenuation = max(0, _signed(zone.get(48, 0)))
        gain = (velocity / 127.0) ** 1.6 * 10.0 ** (-attenuation / 200.0)
        gain *= (int(getattr(note, "channel_volume", 127)) / 127.0)
        gain *= (int(getattr(note, "channel_expression", 127)) / 127.0)
        pan = np.clip((int(note.pan) - 64) / 64.0
                      + _signed(zone.get(17, 0)) / 500.0, -1.0, 1.0)
        left = np.sqrt((1.0 - pan) * 0.5)
        right = np.sqrt((1.0 + pan) * 0.5)
        voice = wave * envelope * gain
        stop = output_start + frames
        mix[output_start:stop, 0] += voice * left
        mix[output_start:stop, 1] += voice * right
    peak = float(np.max(np.abs(mix))) if mix.size else 0.0
    if peak > 0.98:
        mix *= 0.98 / peak
    return np.clip(mix * 32767.0, -32768, 32767).astype("<i2")
