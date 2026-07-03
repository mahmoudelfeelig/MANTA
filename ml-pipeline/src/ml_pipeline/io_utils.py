from __future__ import annotations

import time
from pathlib import Path

import joblib
import pandas as pd

from .cache_utils import resolve_cache_root


def read_csv_resilient(
    path: str | Path,
    *,
    nrows: int | None = None,
    usecols: list[str] | None = None,
    sep: str = ",",
) -> pd.DataFrame:
    path_obj = Path(path).expanduser().resolve()
    use_frame_cache = nrows is None and usecols is None and sep == ","
    frame_cache_path = None
    if use_frame_cache:
        stat = path_obj.stat()
        cache_root = resolve_cache_root(path_obj)
        cache_name = f"frame-{path_obj.stem}-{stat.st_size}-{stat.st_mtime_ns}.joblib"
        frame_cache_path = cache_root / "frames" / cache_name
        if frame_cache_path.exists():
            print(f"[cache] hit {frame_cache_path.name}", flush=True)
            return joblib.load(frame_cache_path)
    attempts = [
        {"engine": None, "encoding_errors": "strict"},
        {"engine": "python", "encoding_errors": "strict"},
        {"engine": "python", "encoding_errors": "replace"},
    ]
    failures: list[str] = []
    for retry_index in range(2):
        for attempt in attempts:
            kwargs: dict[str, object] = {
                "nrows": nrows,
                "usecols": usecols,
                "sep": sep,
            }
            if sep == "," and attempt["engine"] is None:
                kwargs["low_memory"] = False
            if attempt["engine"] is not None:
                kwargs["engine"] = attempt["engine"]
            if attempt["encoding_errors"] != "strict":
                kwargs["encoding_errors"] = attempt["encoding_errors"]
            try:
                frame = pd.read_csv(path_obj, **kwargs)
                if frame_cache_path is not None:
                    frame_cache_path.parent.mkdir(parents=True, exist_ok=True)
                    print(f"[cache] miss {frame_cache_path.name}", flush=True)
                    joblib.dump(frame, frame_cache_path, compress=3)
                return frame
            except (pd.errors.ParserError, OSError, UnicodeDecodeError, ValueError) as exc:
                failures.append(f"retry={retry_index} engine={attempt['engine'] or 'default'} error={exc}")
        if retry_index == 0:
            time.sleep(0.35)
    raise RuntimeError(f"Could not read CSV {path_obj}: {' | '.join(failures)}")
