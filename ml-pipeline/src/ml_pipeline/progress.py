from __future__ import annotations

import sys


class PhaseProgress:
    def __init__(self, title: str, width: int = 28) -> None:
        self.title = title
        self.width = width
        self._last_percent = -1

    def update(self, percent: float, message: str) -> None:
        bounded = max(0.0, min(100.0, percent))
        rounded = int(round(bounded))
        if rounded == self._last_percent:
            return
        self._last_percent = rounded
        filled = int((bounded / 100.0) * self.width)
        bar = "#" * filled + "." * (self.width - filled)
        print(f"[{bar}] {rounded:3d}% {self.title} - {message}", flush=True)


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
