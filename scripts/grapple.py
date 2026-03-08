#!/usr/bin/env python3
"""
Download the exact Apple installer package set for one selected release.

This script is intentionally single-purpose. It pulls the macOS Ventura 13.7.8
installer package set (product 093-22004) from Apple's software update catalog.
"""

from __future__ import annotations

import argparse
import pathlib
import plistlib
import sys
import urllib.error
import urllib.parse
import urllib.request


PRODUCT_ID = "093-22004"
PRODUCT_NAME = "macOS Ventura 13.7.8"
CATALOG_URL = (
    "https://swscan.apple.com/content/catalogs/others/index-13.merged-1.sucatalog"
)
DEFAULT_OUTPUT_DIR = pathlib.Path("downloads") / PRODUCT_ID
CHUNK_SIZE = 1024 * 1024
PROGRESS_BAR_WIDTH = 32


def fetch_catalog() -> dict:
    with urllib.request.urlopen(CATALOG_URL, timeout=60) as response:
        return plistlib.loads(response.read())


def extract_packages(catalog: dict) -> list[dict]:
    products = catalog.get("Products", {})
    if PRODUCT_ID not in products:
        raise RuntimeError(f"product {PRODUCT_ID} was not found in Apple's catalog")

    packages = products[PRODUCT_ID].get("Packages", [])
    if not packages:
        raise RuntimeError(f"product {PRODUCT_ID} did not contain any packages")

    return packages


def package_name(url: str, fallback_index: int) -> str:
    name = pathlib.PurePosixPath(urllib.parse.urlparse(url).path).name
    return name or f"package-{fallback_index}.pkg"


def download_file(url: str, destination: pathlib.Path, expected_size: int | None) -> None:
    if destination.exists() and expected_size is not None:
        if destination.stat().st_size == expected_size:
            print(f"skip  {destination.name} (already present)")
            return

    destination.parent.mkdir(parents=True, exist_ok=True)

    try:
        with urllib.request.urlopen(url, timeout=60) as response, destination.open("wb") as handle:
            total = expected_size or int(response.headers.get("Content-Length", "0") or "0")
            written = 0

            while True:
                chunk = response.read(CHUNK_SIZE)
                if not chunk:
                    break
                handle.write(chunk)
                written += len(chunk)
                if total > 0:
                    percent = (written / total) * 100
                    filled = min(
                        PROGRESS_BAR_WIDTH,
                        int((written / total) * PROGRESS_BAR_WIDTH),
                    )
                    bar = "#" * filled + "-" * (PROGRESS_BAR_WIDTH - filled)
                    print(
                        f"\r[{bar}] downloading {destination.name}: "
                        f"{written // (1024 * 1024)} / {total // (1024 * 1024)} MiB "
                        f"({percent:5.1f}%)",
                        end="",
                        flush=True,
                    )
                else:
                    print(
                        f"\r[{'#' * PROGRESS_BAR_WIDTH}] downloading {destination.name}: "
                        f"{written // (1024 * 1024)} MiB",
                        end="",
                        flush=True,
                    )
    finally:
        print()

    if expected_size is not None:
        actual_size = destination.stat().st_size
        if actual_size != expected_size:
            raise RuntimeError(
                f"{destination.name} size mismatch: expected {expected_size}, got {actual_size}"
            )


def main() -> int:
    parser = argparse.ArgumentParser(
        description=f"Download {PRODUCT_NAME} ({PRODUCT_ID}) installer packages."
    )
    parser.add_argument(
        "--output-dir",
        type=pathlib.Path,
        default=DEFAULT_OUTPUT_DIR,
        help=f"directory to store the downloaded packages (default: {DEFAULT_OUTPUT_DIR})",
    )
    args = parser.parse_args()

    print(f"Fetching Apple catalog for {PRODUCT_NAME} ({PRODUCT_ID})")
    catalog = fetch_catalog()
    packages = extract_packages(catalog)

    print(f"Writing packages to {args.output_dir}")
    for index, package in enumerate(packages, start=1):
        url = package["URL"]
        size = package.get("Size")
        name = package_name(url, index)
        print(f"[{index}/{len(packages)}] {name}")
        download_file(url, args.output_dir / name, size)

    print("Download complete.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except urllib.error.URLError as error:
        print(f"network error: {error}", file=sys.stderr)
        raise SystemExit(1)
    except RuntimeError as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(1)
