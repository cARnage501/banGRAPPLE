#!/usr/bin/env python3
"""Classify broken symlinks in a rebuild into causal producer/substrate classes.

This is intentionally conservative. It does not invent producers; it separates:
- explicit producer laws we understand
- known substrate/topology expectations
- unresolved bundle-contract obligations
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import plistlib
from collections import Counter, defaultdict

BUNDLE_SUFFIXES = (
    ".framework",
    ".bundle",
    ".axbundle",
    ".qlgenerator",
    ".siriUIBundle",
    ".xpc",
    ".appex",
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Classify broken symlink causes in a rebuild tree")
    parser.add_argument("--rebuild-root", type=pathlib.Path, required=True)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    return parser.parse_args()


def load_contract_paths(root: pathlib.Path) -> set[str]:
    receipts_path = root / "_ban_grapple_contract_receipts.json"
    payload = json.loads(receipts_path.read_text())
    return {
        item["path"]
        for item in payload.get("bundle_executable_contract_missing_producers", [])
    }


def deepest_bundle_root(relative: str) -> str | None:
    parts = pathlib.PurePosixPath(relative).parts
    deepest = None
    for index, part in enumerate(parts):
        if part.endswith(BUNDLE_SUFFIXES):
            deepest = "/".join(parts[: index + 1])
    return deepest


def load_bundle_plist(root: pathlib.Path, bundle_rel: str | None) -> dict | None:
    if not bundle_rel:
        return None
    bundle = pathlib.PurePosixPath(bundle_rel)
    candidates = [
        bundle / "Versions" / "A" / "Resources" / "Info.plist",
        bundle / "Contents" / "Info.plist",
        bundle / "Resources" / "Info.plist",
        bundle / "Info.plist",
    ]
    for candidate in candidates:
        full = root / candidate
        if not full.is_file():
            continue
        try:
            with full.open("rb") as handle:
                value = plistlib.load(handle)
        except Exception:
            continue
        if isinstance(value, dict):
            return value
    return None


def iter_broken_symlinks(root: pathlib.Path):
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        for name in list(dirnames) + list(filenames):
            path = pathlib.Path(dirpath) / name
            try:
                if not path.is_symlink():
                    continue
            except OSError:
                continue
            target = os.readlink(path)
            resolved = (
                pathlib.Path(target)
                if os.path.isabs(target)
                else (path.parent / target).resolve(strict=False)
            )
            if resolved.exists():
                continue
            yield path.relative_to(root).as_posix(), target


def classify(root: pathlib.Path, relative: str, target: str, contract_paths: set[str]) -> str:
    if relative in contract_paths:
        return "bundle_executable_contract_missing_producer"

    bundle = deepest_bundle_root(relative)
    leaf = pathlib.PurePosixPath(relative).name
    info = load_bundle_plist(root, bundle)

    if "Versions/Current/" in target or relative.endswith("/Versions/Current"):
        if info is None and bundle:
            return "bundle_contract_metadata_unavailable"
        if leaf in {"PlugIns", "Frameworks", "XPCServices", "Support"} or leaf.endswith(".dylib"):
            return "bundle_structural_alias_missing_producer"
        if info is not None and info.get("CFBundleExecutable") and info.get("CFBundleExecutable") != leaf:
            return "bundle_declared_name_mismatch"
        if bundle:
            return "bundle_structural_alias_missing_producer"

    if relative.startswith("usr/share/firmware/wifi/"):
        return "firmware_alias_map_missing_producer"

    if relative.startswith("usr/share/locale/"):
        return "locale_alias_map_missing_producer"

    if relative in {"var", "tmp", "etc"}:
        return "private_root_substrate_missing"

    if relative == ".VolumeIcon.icns" or "System/Volumes/Data/" in target:
        return "data_volume_substrate_missing"

    if (
        "System/Cryptexes/" in target
        or "System/Volumes/Preboot/Cryptexes" in target
        or target.startswith("/System/Cryptexes/")
    ):
        return "cryptex_runtime_substrate_missing"

    if target.startswith("/AppleInternal/"):
        return "appleinternal_expected_external"

    if relative.startswith("System/Library/Templates/Data/"):
        return "template_data_or_paired_volume_substrate_missing"

    if target.startswith("/var/") or relative == "usr/share/zoneinfo":
        return "host_or_paired_root_substrate_missing"

    if os.path.isabs(target):
        return "host_root_absolute_expected_external"

    target_parent = (root / pathlib.PurePosixPath(relative)).parent / pathlib.PurePosixPath(target)
    if not target_parent.parent.exists():
        return "cross_tree_parent_chain_missing"

    if relative.startswith("System/Applications/") and leaf == "PkgInfo":
        return "packaging_alias_missing_producer"

    if relative.startswith("usr/lib/") or leaf.endswith(".dylib"):
        return "library_alias_missing_producer"

    if (
        relative.startswith("System/Library/Frameworks/")
        or relative.startswith("System/Library/PrivateFrameworks/")
        or relative.startswith("System/iOSSupport/System/Library/")
    ):
        return "framework_relative_alias_missing_producer"

    return "unclassified"


def main() -> None:
    args = parse_args()
    root = args.rebuild_root
    contract_paths = load_contract_paths(root)
    counts = Counter()
    examples: dict[str, list[dict[str, str]]] = defaultdict(list)

    for relative, target in iter_broken_symlinks(root):
        cause = classify(root, relative, target, contract_paths)
        counts[cause] += 1
        if len(examples[cause]) < 12:
            examples[cause].append({"path": relative, "target": target})

    report = {
        "broken_symlink_count": sum(counts.values()),
        "cause_classes": counts.most_common(),
        "examples": examples,
        "exhaustive": counts.get("unclassified", 0) == 0,
    }
    args.output.write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
