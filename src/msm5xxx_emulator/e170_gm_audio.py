"""Non-blocking E170 SMAF playback.

The parser and decoder operate on the MMF bytes passed by the original E170
firmware.  Melodic MTR tracks are rendered through the bundled GM SoundFont;
Mwa/Awa audio tracks are decoded by :mod:`smaf_audio`, including Yamaha
4-bit ADPCM used by the stock key and UI sounds.
"""
from __future__ import annotations

import os
import logging
import queue
import shutil
import subprocess
import tempfile
import threading
from pathlib import Path

import numpy as np

from .ma7_runtime.smaf import parse_mtsq_handy
from .sf2_renderer import SoundFont, render_notes
from .smaf_audio import OUTPUT_RATE, render_mmf_bytes, write_wav


LOGGER = logging.getLogger("audio")
_MA2_TIMEBASE_CODE = (0x00, 0x01, 0x02, 0x03, 0x10, 0x11, 0x12, 0x13)
_MA2_SNAPSHOT_FIFO_LIMIT = 0x10000


class _Ma2SnapshotDecoder:
    """Parse cumulative MA2 FIFO snapshots without replaying old notes."""

    def __init__(self) -> None:
        self.epoch: int | None = None
        self.emitted: set[tuple[int, int, bytes]] = set()
        self.duplicates = 0

    def decode(self, snapshot: dict[str, object]) -> list[object]:
        epoch = int(snapshot["epoch"])
        if epoch != self.epoch:
            self.epoch = epoch
            self.emitted.clear()
        raw_timebase = int(snapshot["timebase"])
        duration = _MA2_TIMEBASE_CODE[raw_timebase >> 4]
        gate = _MA2_TIMEBASE_CODE[raw_timebase & 0x0F]
        result = []
        for fifo, data in enumerate(snapshot["fifos"]):
            raw = bytes(data)
            for note in parse_mtsq_handy(
                    raw, duration, gate, channel_base=fifo * 4):
                if note.source_order + len(note.raw) > len(raw):
                    continue
                key = fifo, note.source_order, bytes(note.raw)
                if key in self.emitted:
                    self.duplicates += 1
                    continue
                self.emitted.add(key)
                result.append(note)
        return result


class ApproximateSmafPlayer:
    """Asynchronous SMAF-to-PCM player used by the Unicorn thread.

    Audio rendering and process I/O never run on the emulation thread.  A
    newest-item queue matches phone UI behaviour: repeated key sounds replace
    stale queued sounds rather than building an audible backlog.
    """

    def __init__(self) -> None:
        self._sf2_path = Path(__file__).with_name("gm.sf2")
        self._ffplay = shutil.which("ffplay")
        try:
            self._soundfont = SoundFont(self._sf2_path) if self._sf2_path.is_file() else None
        except Exception as exc:
            self._soundfont = None
            self.last_error = f"SoundFont load failed: {type(exc).__name__}: {exc}"
            LOGGER.exception("SoundFont load failed path=%s", self._sf2_path)
        else:
            self.last_error = ""
        self._winsound = None
        if os.name == "nt":
            try:
                import winsound
                self._winsound = winsound
            except ImportError:
                pass

        if self._ffplay:
            self.backend = "SMAF PCM / ffplay"
        elif self._winsound is not None:
            self.backend = "SMAF PCM / Windows waveOut"
        else:
            self.backend = "render-only"
        # Rendering stays enabled even when this host has no playback backend.
        self.enabled = True
        self.muted = False
        self.volume = 0.80
        self.last_stats: dict[str, int | float] = {}
        self.last_submit_error: str | None = None
        self.last_pcm: np.ndarray | None = None
        self.last_mmf: bytes | None = None
        self._queue: queue.Queue[bytes | dict[str, object] | None] = queue.Queue(maxsize=2)
        self._queue_lock = threading.Lock()
        self._ma2_decoder = _Ma2SnapshotDecoder()
        self._process: subprocess.Popen | None = None
        descriptor, wav_path = tempfile.mkstemp(prefix="msm5xxx-audio-", suffix=".wav")
        os.close(descriptor)
        self._wav_path = Path(wav_path)
        self._lock = threading.Lock()
        self._closed = False
        self._thread = threading.Thread(target=self._worker,
                                        name="E170 SMAF audio", daemon=True)
        self._thread.start()
        LOGGER.info("audio initialized backend=%s soundfont=%s",
                    self.backend, self._sf2_path.name if self._soundfont else None)

    def set_volume(self, value: float) -> None:
        self.volume = max(0.0, min(1.0, float(value)))

    def set_muted(self, muted: bool) -> None:
        self.muted = bool(muted)
        if self.muted:
            self.stop()

    def play_mmf(self, data: bytes) -> None:
        LOGGER.info("audio request bytes=%d", len(data))
        if not self.enabled or not data.startswith(b"MMMD"):
            return
        self._replace_request(bytes(data))

    def play_ma2_snapshot(self, snapshot: dict[str, object]) -> bool:
        return self.play_ma2_snapshots((snapshot,))

    def play_ma2_snapshots(
            self, snapshots: tuple[dict[str, object], ...]) -> bool:
        if (not self.enabled or not snapshots
                or not all(self._valid_ma2_snapshot(item)
                           for item in snapshots)):
            self.last_submit_error = "ma2-snapshot-invalid"
            return False
        return self._replace_request({
            "kind": "ma2-fifo-snapshot-batch",
            "snapshots": snapshots,
        })

    @staticmethod
    def _valid_ma2_snapshot(snapshot: dict[str, object]) -> bool:
        if not isinstance(snapshot, dict):
            return False
        if snapshot.get("kind") != "ma2-fifo-snapshot":
            return False
        if any(type(snapshot.get(field)) is not int
               or int(snapshot[field]) < 0
               for field in ("epoch", "sequence")):
            return False
        timebase = snapshot.get("timebase")
        if (type(timebase) is not int or not 0 <= timebase <= 0x77
                or timebase >> 4 > 7 or timebase & 0x0F > 7):
            return False
        fifos = snapshot.get("fifos")
        return (
            isinstance(fifos, (tuple, list))
            and len(fifos) == 4
            and all(
                isinstance(data, (bytes, bytearray, memoryview))
                and len(data) <= _MA2_SNAPSHOT_FIFO_LIMIT
                for data in fifos
            )
        )

    def _replace_request(self, request: bytes | dict[str, object]) -> bool:
        with self._queue_lock:
            if self._closed:
                self.last_submit_error = "audio-player-closed"
                return False
            # Keep only the most recent request.
            while True:
                try:
                    self._queue.get_nowait()
                except queue.Empty:
                    break
            try:
                self._queue.put_nowait(request)
            except queue.Full:
                self.last_submit_error = "audio-queue-full"
                return False
            self.last_submit_error = None
        return True

    def stop(self) -> None:
        with self._lock:
            process = self._process
            self._process = None
        if process is not None and process.poll() is None:
            try:
                process.terminate()
            except OSError:
                pass
        if self._winsound is not None:
            try:
                self._winsound.PlaySound(None, self._winsound.SND_PURGE)
            except RuntimeError:
                pass

    def close(self) -> None:
        """Stop playback and give the renderer a bounded shutdown window."""
        with self._queue_lock:
            if self._closed:
                return
            self._closed = True
            while True:
                try:
                    self._queue.get_nowait()
                except queue.Empty:
                    break
            self._queue.put_nowait(None)
        self.stop()
        if threading.current_thread() is not self._thread:
            self._thread.join(timeout=2.0)
        self.stop()
        try:
            self._wav_path.unlink(missing_ok=True)
        except OSError:
            pass

    def export_last_wav(self, path: str | Path) -> bool:
        pcm = self.last_pcm
        if pcm is None:
            return False
        write_wav(path, pcm, OUTPUT_RATE)
        return True

    def render_now(self, data: bytes) -> tuple[np.ndarray, dict[str, int | float]]:
        return render_mmf_bytes(data, soundfont=self._soundfont,
                                output_rate=OUTPUT_RATE)

    def _play_pcm(self, pcm: np.ndarray) -> None:
        if self._closed or self.muted:
            return
        gain = self.volume
        if gain < 0.999:
            scaled = np.clip(pcm.astype(np.float32) * gain,
                             -32768, 32767).astype("<i2")
        else:
            scaled = pcm
        self.stop()
        if self._ffplay:
            write_wav(self._wav_path, scaled, OUTPUT_RATE)
            with self._lock:
                if self._closed:
                    return
                process = subprocess.Popen(
                    [self._ffplay, "-loglevel", "quiet", "-nodisp", "-autoexit",
                     str(self._wav_path)],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.PIPE,
                )
                self._process = process

            def feed() -> None:
                try:
                    _stdout, stderr = process.communicate()
                except OSError:
                    stderr = b""
                with self._lock:
                    active = self._process is process
                    if active:
                        self._process = None
                if active and process.returncode:
                    detail = stderr.decode(errors="replace").strip().splitlines()
                    self.last_error = f"ffplay exited {process.returncode}: {detail[-1] if detail else 'unknown error'}"
                    LOGGER.error("%s", self.last_error)

            threading.Thread(target=feed, name="E170 audio feed", daemon=True).start()
            return
        if self._winsound is not None:
            write_wav(self._wav_path, scaled, OUTPUT_RATE)
            with self._lock:
                if self._closed:
                    return
                try:
                    self._winsound.PlaySound(
                        str(self._wav_path),
                        self._winsound.SND_FILENAME | self._winsound.SND_ASYNC,
                    )
                except RuntimeError as exc:
                    self.last_error = f"Windows audio: {exc}"
                    LOGGER.error("%s", self.last_error)

    def _worker(self) -> None:
        while True:
            request = self._queue.get()
            if request is None or self._closed:
                return
            try:
                if isinstance(request, bytes):
                    pcm, stats = self.render_now(request)
                    self.last_mmf = request
                else:
                    snapshots = request["snapshots"]
                    note_groups = [
                        self._ma2_decoder.decode(snapshot)
                        for snapshot in snapshots
                    ]
                    notes = [note for group in note_groups for note in group]
                    self.last_stats = {
                        "notes": len(notes),
                        "duplicates": self._ma2_decoder.duplicates,
                        "snapshots": len(snapshots),
                    }
                    if not notes or self._soundfont is None:
                        continue
                    rendered = [
                        render_notes(
                            self._soundfont, group, sample_rate=OUTPUT_RATE,
                            max_seconds=30.0,
                        )
                        for group in note_groups if group
                    ]
                    pcm = (
                        np.concatenate(rendered)
                        if len(rendered) > 1 else rendered[0]
                    )
                    stats = {
                        **self.last_stats,
                        "output_frames": len(pcm),
                        "output_rate": OUTPUT_RATE,
                    }
                if self._closed:
                    return
                self.last_pcm = pcm
                self.last_stats = stats
                self.last_error = ""
                self._play_pcm(pcm)
            except Exception as exc:  # audio must never stop the emulator
                self.last_error = f"{type(exc).__name__}: {exc}"
                LOGGER.exception("audio worker failed")
