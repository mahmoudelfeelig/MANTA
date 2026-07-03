from __future__ import annotations

import argparse
import fnmatch
import json
import sys
import urllib.request
from pathlib import Path


DATASETS = {
    "westermo": {
        "license": "CC BY 4.0",
        "mode": "direct",
        "url": "https://codeload.github.com/westermo/network-traffic-dataset/zip/refs/heads/main",
        "filename": "westermo-network-traffic-dataset.zip",
        "notes": "Public GitHub archive with realistic industrial-network traffic and attack scenarios.",
    },
    "parrot2025_mitmproxy": {
        "license": "See Zenodo record metadata",
        "mode": "zenodo_record",
        "record_id": "16368932",
        "notes": "Zenodo record with mobile/browser-oriented capture material. The public record currently exposes a large ZIP archive, not per-trace CSV files.",
    },
    "android_spyware_mendeley": {
        "license": "CC BY 4.0",
        "mode": "manual",
        "url": "https://data.mendeley.com/datasets/mhvgtywrxf/1",
        "notes": "Manual download required from the public Mendeley Data landing page.",
    },
    "sdncampus_flow_statistics": {
        "license": "CC BY 4.0",
        "mode": "manual",
        "url": "https://data.mendeley.com/datasets/wvp9tksn72/1",
        "notes": "Manual download required from the public Mendeley Data landing page.",
    },
    "android_mischief_rat_traffic": {
        "license": "CC BY 4.0",
        "mode": "manual",
        "url": "https://data.mendeley.com/datasets/xbx2j63xfd/2",
        "notes": "Manual download required. Contains Android RAT network traffic PCAPs plus benign traffic context.",
    },
    "itc_net_blend60_scenario_e": {
        "license": "CC BY 4.0",
        "mode": "manual",
        "url": "https://data.mendeley.com/datasets/gdtnnfyr7s/2",
        "notes": "Manual download required. Benign Android app traffic dataset across 60 applications, useful for privacy leakage, app diversity, and hard benign negatives.",
    },
    "cicandmal2017_android": {
        "license": "Public research dataset; cite the associated CIC paper",
        "mode": "manual",
        "url": "https://www.unb.ca/cic/datasets/andmal2017.html",
        "notes": "Official CIC-AndMal2017 dataset page with Android malware traffic captures and extracted flow features.",
    },
    "android_apt_behavior_dataset": {
        "license": "CC BY 4.0",
        "mode": "manual",
        "url": "https://data.mendeley.com/datasets/bdtn9vj7d7/3",
        "notes": "Manual download required. Device-behavior dataset for multi-stage Android APT activity.",
    },
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Download or list real public datasets for MANTA model training")
    parser.add_argument("--dataset", choices=sorted(DATASETS), help="Dataset to download")
    parser.add_argument("--output-dir", default="downloads", help="Directory for downloaded files")
    parser.add_argument("--match", default="*", help="Optional filename glob for Zenodo downloads")
    parser.add_argument("--list", action="store_true", help="List supported datasets and exit")
    return parser.parse_args()


def list_datasets() -> None:
    for name, meta in DATASETS.items():
        print(f"{name}")
        print(f"  license: {meta['license']}")
        print(f"  mode: {meta['mode']}")
        if "url" in meta:
            print(f"  url: {meta['url']}")
        if "record_id" in meta:
            print(f"  zenodo_record: {meta['record_id']}")
        print(f"  notes: {meta['notes']}")


def _download(url: str, target: Path) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    with urllib.request.urlopen(url) as response, target.open("wb") as handle:
        handle.write(response.read())


def download_direct(dataset: dict, output_dir: Path) -> list[Path]:
    target = output_dir / dataset["filename"]
    _download(dataset["url"], target)
    return [target]


def download_zenodo_record(dataset: dict, output_dir: Path, match: str) -> list[Path]:
    record_id = dataset["record_id"]
    with urllib.request.urlopen(f"https://zenodo.org/api/records/{record_id}") as response:
        payload = json.loads(response.read().decode("utf-8"))
    files = payload.get("files") or []
    downloaded: list[Path] = []
    for item in files:
        key = str(item.get("key") or "").strip()
        if not key or not fnmatch.fnmatch(key, match):
            continue
        url = (
            item.get("links", {}).get("self")
            or item.get("links", {}).get("download")
            or item.get("links", {}).get("content")
        )
        if not url:
            continue
        target = output_dir / key
        _download(str(url), target)
        downloaded.append(target)
    return downloaded


def main() -> None:
    args = parse_args()
    if args.list or not args.dataset:
        list_datasets()
        return

    dataset = DATASETS[args.dataset]
    output_dir = Path(args.output_dir).expanduser().resolve() / args.dataset
    mode = dataset["mode"]

    if mode == "manual":
        print(f"{args.dataset} is intentionally manual-download only.")
        print(f"Open: {dataset['url']}")
        print(f"License: {dataset['license']}")
        print(dataset["notes"])
        return

    if mode == "direct":
        downloaded = download_direct(dataset, output_dir)
    elif mode == "zenodo_record":
        downloaded = download_zenodo_record(dataset, output_dir, args.match)
    else:  # pragma: no cover
        raise ValueError(f"Unsupported dataset mode: {mode}")

    if not downloaded:
        print(f"No files downloaded for {args.dataset}. Try a broader --match pattern.", file=sys.stderr)
        raise SystemExit(1)

    print(f"Downloaded {len(downloaded)} file(s) to {output_dir}")
    for item in downloaded:
        print(item)


if __name__ == "__main__":
    main()
