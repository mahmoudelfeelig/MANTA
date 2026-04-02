from __future__ import annotations

import os
import threading
import time


class PhaseProgress:
    def __init__(self, title: str, width: int = 28) -> None:
        self.title = title
        self.width = width
        self._last_percent = -1
        self._last_message = "starting"
        self._start = time.monotonic()
        self._done = threading.Event()
        heartbeat_seconds = int(os.getenv("MANTA_PROGRESS_HEARTBEAT_SECONDS", "300") or 300)
        self._heartbeat_seconds = max(300, heartbeat_seconds)
        self._thread = threading.Thread(target=self._heartbeat_loop, daemon=True)
        self._thread.start()

    def _format_elapsed(self) -> str:
        total_seconds = int(max(0.0, time.monotonic() - self._start))
        hours, remainder = divmod(total_seconds, 3600)
        minutes, seconds = divmod(remainder, 60)
        if hours > 0:
            return f"{hours:02d}:{minutes:02d}:{seconds:02d}"
        return f"{minutes:02d}:{seconds:02d}"

    def _emit(self, bounded: float, message: str, *, heartbeat: bool = False) -> None:
        filled = int((bounded / 100.0) * self.width)
        bar = "#" * filled + "." * (self.width - filled)
        suffix = f" (elapsed {self._format_elapsed()})"
        if heartbeat:
            suffix = f" (elapsed {self._format_elapsed()}, still working)"
        print(f"[{bar}] {int(round(bounded)):3d}% {self.title} - {message}{suffix}", flush=True)

    def _heartbeat_loop(self) -> None:
        while not self._done.wait(self._heartbeat_seconds):
            current_percent = 0.0 if self._last_percent < 0 else float(self._last_percent)
            self._emit(current_percent, self._last_message, heartbeat=True)

    def update(self, percent: float, message: str) -> None:
        bounded = max(0.0, min(100.0, percent))
        rounded = int(round(bounded))
        self._last_message = message
        if rounded == self._last_percent:
            return
        self._last_percent = rounded
        self._emit(bounded, message)
        if rounded >= 100:
            self.close()

    def close(self) -> None:
        self._done.set()


class EpochPercentCallback:
    def __init__(self, progress: PhaseProgress, start_percent: float, end_percent: float, epochs: int, label: str) -> None:
        self.progress = progress
        self.start_percent = start_percent
        self.end_percent = end_percent
        self.epochs = max(1, epochs)
        self.label = label

    def on_epoch_end(self, epoch: int) -> None:
        fraction = (epoch + 1) / self.epochs
        percent = self.start_percent + ((self.end_percent - self.start_percent) * fraction)
        self.progress.update(percent, f"{self.label} epoch {epoch + 1}/{self.epochs}")
