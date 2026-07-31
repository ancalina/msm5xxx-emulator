"""SMAF audio-wave decoding and host PCM mixing.

This module complements the clean-room SMAF parser in :mod:`ma7_runtime.smaf`.
It handles the audio-track payloads that are common in Korean feature-phone
firmware: Yamaha 4-bit ADPCM, signed/unsigned 8-bit PCM, and signed 16-bit PCM.
The mixer intentionally stays independent of GUI and Unicorn state so it can
be regression-tested deterministically.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import tempfile
import wave

import numpy as np

from .ma7_runtime.smaf import (
    AudioEvent,
    AudioWaveData,
    TICK_SEC,
    load_mmf_full_with_controls,
    stream_wave_codec,
)
from .sf2_renderer import SoundFont, render_notes

OUTPUT_RATE = 44_100
_YAMAHA_STEP_SCALE = np.asarray((230, 230, 230, 230, 307, 409, 512, 614),
                                dtype=np.int32)


@dataclass(slots=True)
class RenderStats:
    notes: int = 0
    audio_events: int = 0
    audio_waves: int = 0
    decoded_audio_events: int = 0
    missing_audio_waves: int = 0
    unsupported_audio_waves: int = 0
    controls: int = 0
    output_frames: int = 0
    output_rate: int = OUTPUT_RATE
    peak: float = 0.0

    def to_dict(self) -> dict[str, int | float]:
        return {
            "notes": self.notes,
            "audio_events": self.audio_events,
            "audio_waves": self.audio_waves,
            "decoded_audio_events": self.decoded_audio_events,
            "missing_audio_waves": self.missing_audio_waves,
            "unsupported_audio_waves": self.unsupported_audio_waves,
            "controls": self.controls,
            "output_frames": self.output_frames,
            "output_rate": self.output_rate,
            "peak": self.peak,
        }


def _decode_yamaha_nibble(code: int, predictor: int, step: int) -> tuple[int, int]:
    """Decode one Yamaha ADPCM nibble.

    Yamaha's MA-family 4-bit stream codec uses the same predictor/step update
    that appears in Yamaha ADPCM-A implementations: a 127 initial step, an
    odd-multiple delta, and an eight-entry step scale table.
    """
    code &= 0x0F
    delta = ((code & 7) * 2 + 1) * step // 8
    predictor = predictor - delta if code & 8 else predictor + delta
    predictor = max(-32768, min(32767, predictor))
    step = step * int(_YAMAHA_STEP_SCALE[code & 7]) // 256
    step = max(127, min(24576, step))
    return predictor, step


def decode_yamaha_adpcm4(data: bytes, channels: int = 1) -> np.ndarray:
    """Decode Yamaha 4-bit ADPCM into signed 16-bit PCM.

    Mono streams contain two sequential samples per byte (high nibble first).
    Stereo SMAF streams pack one left and one right sample into each byte.
    """
    channels = 2 if int(channels) == 2 else 1
    if not data:
        return np.zeros((0, channels), dtype=np.int16)
    raw = np.frombuffer(data, dtype=np.uint8)
    if channels == 1:
        codes = np.empty(raw.size * 2, dtype=np.uint8)
        codes[0::2] = raw >> 4
        codes[1::2] = raw & 0x0F
        out = np.empty((codes.size, 1), dtype=np.int16)
        predictor = 0
        step = 127
        for index, code in enumerate(codes):
            predictor, step = _decode_yamaha_nibble(int(code), predictor, step)
            out[index, 0] = predictor
        return out

    out = np.empty((raw.size, 2), dtype=np.int16)
    predictors = [0, 0]
    steps = [127, 127]
    for index, value in enumerate(raw):
        for channel, code in enumerate((int(value >> 4), int(value & 0x0F))):
            predictors[channel], steps[channel] = _decode_yamaha_nibble(
                code, predictors[channel], steps[channel])
            out[index, channel] = predictors[channel]
    return out


def _reshape_pcm(values: np.ndarray, channels: int) -> np.ndarray:
    channels = 2 if int(channels) == 2 else 1
    usable = values.size - (values.size % channels)
    if usable <= 0:
        return np.zeros((0, channels), dtype=np.int16)
    return values[:usable].reshape(-1, channels).astype(np.int16, copy=False)


def decode_audio_wave(wave_data: AudioWaveData) -> np.ndarray | None:
    """Decode one parsed SMAF audio wave to ``frames x channels`` int16 PCM."""
    channels = 2 if wave_data.channels == 2 else 1
    codec = stream_wave_codec(wave_data.wave_type) if wave_data.source == "mwa" else ""

    if codec == "adpcm4" or (not codec and wave_data.base_bits == 4):
        return decode_yamaha_adpcm4(wave_data.data, channels)
    if codec == "pcm_s8":
        signed = np.frombuffer(wave_data.data, dtype=np.int8).astype(np.int16) << 8
        return _reshape_pcm(signed, channels)
    if codec == "pcm_u8":
        unsigned = np.frombuffer(wave_data.data, dtype=np.uint8).astype(np.int16)
        return _reshape_pcm((unsigned - 128) << 8, channels)
    if codec == "pcm_s16le":
        count = len(wave_data.data) // 2
        signed = np.frombuffer(wave_data.data[:count * 2], dtype="<i2")
        return _reshape_pcm(signed, channels)

    # Older Awa resources use a two-byte WaveType rather than the compact Mwa
    # type.  Base bit depth is reliable even when the exact PCM signedness flag
    # is vendor-specific.  Prefer signed PCM; this is also what the observed
    # Samsung/LG resources use.
    if wave_data.base_bits == 8:
        signed = np.frombuffer(wave_data.data, dtype=np.int8).astype(np.int16) << 8
        return _reshape_pcm(signed, channels)
    if wave_data.base_bits == 16:
        count = len(wave_data.data) // 2
        signed = np.frombuffer(wave_data.data[:count * 2], dtype=">i2").astype("<i2")
        return _reshape_pcm(signed, channels)
    return None


def _resample_linear(pcm: np.ndarray, source_rate: int,
                     output_rate: int) -> np.ndarray:
    if pcm.size == 0:
        return np.zeros((0, pcm.shape[1] if pcm.ndim == 2 else 1), dtype=np.float32)
    source_rate = max(1, int(source_rate))
    output_rate = max(1, int(output_rate))
    source = pcm.astype(np.float32) / 32768.0
    if source_rate == output_rate:
        return source
    output_frames = max(1, int(round(len(source) * output_rate / source_rate)))
    positions = np.arange(output_frames, dtype=np.float64) * source_rate / output_rate
    positions = np.minimum(positions, max(0, len(source) - 1))
    left = positions.astype(np.int64)
    right = np.minimum(left + 1, len(source) - 1)
    fraction = (positions - left).astype(np.float32)[:, None]
    return source[left] * (1.0 - fraction) + source[right] * fraction


def _audio_event_end(event: AudioEvent, wave_data: AudioWaveData | None) -> float:
    declared = max(1, int(event.span)) * TICK_SEC
    if wave_data is None:
        return event.start_sec + declared
    decoded_frames = (len(wave_data.data) * 2 // max(1, wave_data.channels)
                      if wave_data.base_bits == 4 else 0)
    natural = decoded_frames / max(1, wave_data.sample_rate) if decoded_frames else declared
    return event.start_sec + max(declared, natural)


def mix_smaf(
    notes,
    audio_waves: dict[tuple[int, int], AudioWaveData],
    audio_events: list[AudioEvent],
    *,
    soundfont: SoundFont | None = None,
    output_rate: int = OUTPUT_RATE,
    max_seconds: float = 180.0,
) -> tuple[np.ndarray, RenderStats]:
    """Render melodic and sampled SMAF tracks into stereo int16 PCM."""
    stats = RenderStats(notes=len(notes), audio_events=len(audio_events),
                        audio_waves=len(audio_waves), output_rate=output_rate)
    note_end = max(((int(note.tick) + max(1, int(note.span))) * TICK_SEC + 2.0
                    for note in notes), default=0.0)
    audio_end = max((_audio_event_end(event,
                                      audio_waves.get((event.track, event.wave_id)))
                     for event in audio_events), default=0.0)
    duration = min(max_seconds, max(note_end, audio_end, 1.0 / output_rate))
    total_frames = max(1, int(np.ceil(duration * output_rate)))
    mix = np.zeros((total_frames, 2), dtype=np.float32)

    if soundfont is not None and notes:
        rendered = render_notes(soundfont, notes, sample_rate=output_rate,
                                max_seconds=max_seconds).astype(np.float32) / 32768.0
        count = min(len(mix), len(rendered))
        mix[:count] += rendered[:count]

    decoded_cache: dict[tuple[int, int], np.ndarray | None] = {}
    for event in sorted(audio_events, key=lambda item: (item.tick, item.track, item.wave_id)):
        key = (event.track, event.wave_id)
        wave_data = audio_waves.get(key)
        if wave_data is None:
            stats.missing_audio_waves += 1
            continue
        if key not in decoded_cache:
            decoded_cache[key] = decode_audio_wave(wave_data)
        decoded = decoded_cache[key]
        if decoded is None:
            stats.unsupported_audio_waves += 1
            continue
        resampled = _resample_linear(decoded, wave_data.sample_rate, output_rate)
        if resampled.size == 0:
            continue
        if resampled.shape[1] == 1:
            mono = resampled[:, 0]
            pan = float(np.clip((int(event.pan) - 64) / 64.0, -1.0, 1.0))
            left = np.sqrt((1.0 - pan) * 0.5)
            right = np.sqrt((1.0 + pan) * 0.5)
            stereo = np.column_stack((mono * left, mono * right))
        else:
            stereo = resampled[:, :2].copy()
            # Preserve native stereo while applying the event pan as a balance.
            pan = float(np.clip((int(event.pan) - 64) / 64.0, -1.0, 1.0))
            if pan < 0:
                stereo[:, 1] *= 1.0 + pan
            elif pan > 0:
                stereo[:, 0] *= 1.0 - pan
        gain = (max(0, min(127, int(event.velocity))) / 127.0) ** 1.35
        stereo *= gain

        start = max(0, int(round(event.start_sec * output_rate)))
        if start >= len(mix):
            continue
        # A gate/span shorter than the embedded sample stops the voice.  Apply
        # a tiny click-prevention fade at that boundary; shorter source samples
        # remain one-shot and are not guessed to loop.
        gate_frames = max(1, int(round(event.dur_sec * output_rate)))
        count = min(len(stereo), gate_frames, len(mix) - start)
        if count <= 0:
            continue
        voice = stereo[:count]
        fade = min(count, max(1, int(output_rate * 0.005)))
        if count == gate_frames and fade > 1:
            voice = voice.copy()
            voice[-fade:] *= np.linspace(1.0, 0.0, fade, dtype=np.float32)[:, None]
        mix[start:start + count] += voice
        stats.decoded_audio_events += 1

    peak = float(np.max(np.abs(mix))) if mix.size else 0.0
    if peak > 0.98:
        mix *= 0.98 / peak
        peak = 0.98
    stats.peak = peak
    stats.output_frames = len(mix)
    return np.clip(mix * 32767.0, -32768, 32767).astype("<i2"), stats


def render_mmf_bytes(
    data: bytes,
    *,
    soundfont: SoundFont | None = None,
    output_rate: int = OUTPUT_RATE,
    max_seconds: float = 180.0,
) -> tuple[np.ndarray, dict[str, int | float]]:
    if not data.startswith(b"MMMD"):
        raise ValueError("not an MMF/SMAF stream")
    with tempfile.NamedTemporaryFile(suffix=".mmf", delete=False) as source:
        source.write(data)
        path = Path(source.name)
    try:
        _voices, _waves, notes, audio_waves, audio_events, controls = (
            load_mmf_full_with_controls(path)
        )
    finally:
        path.unlink(missing_ok=True)
    pcm, stats = mix_smaf(notes, audio_waves, audio_events,
                          soundfont=soundfont, output_rate=output_rate,
                          max_seconds=max_seconds)
    stats.controls = len(controls)
    return pcm, stats.to_dict()


def write_wav(path: str | Path, pcm: np.ndarray,
              sample_rate: int = OUTPUT_RATE) -> None:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    array = np.asarray(pcm, dtype="<i2")
    if array.ndim == 1:
        array = array[:, None]
    with wave.open(str(destination), "wb") as output:
        output.setnchannels(array.shape[1])
        output.setsampwidth(2)
        output.setframerate(int(sample_rate))
        output.writeframes(array.tobytes())
