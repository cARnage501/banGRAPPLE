#!/usr/bin/env python3
"""Classify payloadv2 `links.txt` as a reconstruction-semantic layer.

This script joins three currently understood surfaces:
- primary replay metadata (`_yaa_materialized.jsonl`)
- `fixup.manifest` explicit file records
- `links.txt` source/target pairs

The goal is to answer whether `links.txt` looks descriptive or object-producing.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys
from collections import Counter, defaultdict

SCRIPT_DIR = pathlib.Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import payloadv2_probe as probe


PRIMARY_FILE_KIND_BY_OBJECT = {
    "file": "F",
    "directory": "D",
    "link": "L",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build a semantic matrix for payloadv2 links.txt")
    parser.add_argument("--metadata-jsonl", type=pathlib.Path, required=True)
    parser.add_argument("--payloadv2-dir", type=pathlib.Path, required=True)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    return parser.parse_args()


def parse_links_pairs(text: str) -> list[tuple[str, str]]:
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    pairs: list[tuple[str, str]] = []
    index = 0
    while index + 1 < len(lines):
        left = lines[index]
        right = lines[index + 1]
        if left.startswith("=") and right.startswith("+"):
            pairs.append((left[1:], right[1:]))
            index += 2
        else:
            index += 1
    return pairs


def load_primary_paths(path: pathlib.Path) -> dict[str, str]:
    result: dict[str, str] = {}
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            record = json.loads(line)
            rel = record.get("path")
            obj = record.get("object_type")
            if rel and obj:
                result[rel] = PRIMARY_FILE_KIND_BY_OBJECT.get(obj, obj)
    return result


def parse_fixup_index(path: pathlib.Path) -> dict[str, dict]:
    raw = path.read_bytes()
    decoded = probe.decode_pbzx(raw)["decoded_bytes"]
    index: dict[str, dict] = {}
    for rec in probe.parse_yaa_records(decoded, limit=1_000_000):
        rel = rec.get("path")
        if not rel:
            continue
        fields = {field["tag"]: field.get("value") for field in rec.get("fields", []) if "tag" in field}
        hlc = next((fields[tag] for tag in ("HLC4", "HLC2", "HLC1") if tag in fields), None)
        hlo = next((fields[tag] for tag in ("HLO4", "HLO2", "HLO1") if tag in fields), None)
        index[rel] = {
            "type": rec.get("type_code"),
            "data_length": rec.get("data_length"),
            "hlc": hlc,
            "hlo": hlo,
            "field_tags": sorted(fields),
        }
    return index


def shared_tail_components(source: pathlib.PurePosixPath, target: pathlib.PurePosixPath) -> int:
    count = 0
    for left, right in zip(reversed(source.parts), reversed(target.parts)):
        if left != right:
            break
        count += 1
    return count


def nearest_common_ancestor_depth(source: pathlib.PurePosixPath, target: pathlib.PurePosixPath) -> int:
    depth = 0
    for left, right in zip(source.parts, target.parts):
        if left != right:
            break
        depth += 1
    return depth


def classify_path_family(source: str, target: str) -> list[str]:
    src = pathlib.PurePosixPath(source)
    tgt = pathlib.PurePosixPath(target)
    tags: list[str] = []
    if src.name == tgt.name:
        tags.append("same_basename")
    if src.suffix == tgt.suffix:
        tags.append("same_extension")
    if nearest_common_ancestor_depth(src, tgt) >= max(1, min(len(src.parts), len(tgt.parts)) - 3):
        tags.append("local_nearby")
    if shared_tail_components(src, tgt) >= 2:
        tags.append("shared_tail")
    src_s = source
    tgt_s = target
    if "/Resources/" in src_s and "/Resources/" in tgt_s:
        tags.append("resource_parallel")
    if "/_CodeSignature/CodeResources" in src_s and "/_CodeSignature/CodeResources" in tgt_s:
        tags.append("codesign_parallel")
    if ".framework/" in src_s and ".framework/" in tgt_s:
        tags.append("framework_parallel")
    if ".appex/" in src_s and ".appex/" in tgt_s or ".bundle/" in src_s and ".bundle/" in tgt_s:
        tags.append("plugin_parallel")
    if ".lproj/" in src_s and ".lproj/" in tgt_s:
        tags.append("locale_variant")
    if "/XPCServices/" in src_s and "/XPCServices/" in tgt_s:
        tags.append("xpc_parallel")
    if "/Frameworks/" in src_s and "/Frameworks/" in tgt_s:
        tags.append("framework_container_parallel")
    if not tags:
        tags.append("unclassified_shape")
    return tags


def main() -> None:
    args = parse_args()
    primary = load_primary_paths(args.metadata_jsonl)
    fixup = parse_fixup_index(args.payloadv2_dir / "fixup.manifest")
    pairs = parse_links_pairs((args.payloadv2_dir / "links.txt").read_text(errors="replace"))

    summary = {
        "pair_count": len(pairs),
        "pair_presence": Counter(),
        "fixup_type_pairs": Counter(),
        "fixup_payload_relation": Counter(),
        "hlc_relation": Counter(),
        "hlo_relation": Counter(),
        "source_hlo_zero_target_positive": 0,
        "same_hlc_distinct_hlo": 0,
        "source_per_hlc": Counter(),
        "targets_per_hlc": Counter(),
        "family_counts": Counter(),
        "family_hlc_consistency": Counter(),
    }
    source_by_hlc: dict[int, set[str]] = defaultdict(set)
    target_by_hlc: dict[int, set[str]] = defaultdict(set)
    family_examples: dict[str, list[dict]] = defaultdict(list)

    for source, target in pairs:
        primary_source = primary.get(source)
        primary_target = primary.get(target)
        source_fix = fixup.get(source)
        target_fix = fixup.get(target)
        status = (
            f"primary:{bool(primary_source)}->{bool(primary_target)}|"
            f"fixup:{bool(source_fix)}->{bool(target_fix)}"
        )
        summary["pair_presence"][status] += 1
        if not source_fix or not target_fix:
            continue

        source_payload = source_fix["data_length"] is not None
        target_payload = target_fix["data_length"] is not None
        summary["fixup_type_pairs"][f"{source_fix['type']}->{target_fix['type']}"] += 1
        summary["fixup_payload_relation"][f"{source_payload}->{target_payload}"] += 1

        if source_fix["hlc"] == target_fix["hlc"]:
            hlc_rel = "same"
            if source_fix["hlo"] != target_fix["hlo"]:
                summary["same_hlc_distinct_hlo"] += 1
            if source_fix["hlo"] == 0 and isinstance(target_fix["hlo"], int) and target_fix["hlo"] > 0:
                summary["source_hlo_zero_target_positive"] += 1
        elif source_fix["hlc"] is None and target_fix["hlc"] is None:
            hlc_rel = "both_none"
        else:
            hlc_rel = "different"
        summary["hlc_relation"][hlc_rel] += 1

        if source_fix["hlo"] == target_fix["hlo"]:
            hlo_rel = "same"
        elif isinstance(source_fix["hlo"], int) and isinstance(target_fix["hlo"], int) and source_fix["hlo"] < target_fix["hlo"]:
            hlo_rel = "source_less"
        elif isinstance(source_fix["hlo"], int) and isinstance(target_fix["hlo"], int) and source_fix["hlo"] > target_fix["hlo"]:
            hlo_rel = "source_greater"
        else:
            hlo_rel = "different"
        summary["hlo_relation"][hlo_rel] += 1

        if source_fix["hlc"] is not None:
            source_by_hlc[source_fix["hlc"]].add(source)
            target_by_hlc[source_fix["hlc"]].add(target)

        families = classify_path_family(source, target)
        for family in families:
            summary["family_counts"][family] += 1
            consistency = f"{family}|hlc:{hlc_rel}|payload:{source_payload}->{target_payload}"
            summary["family_hlc_consistency"][consistency] += 1
            if len(family_examples[family]) < 3:
                family_examples[family].append(
                    {
                        "source": source,
                        "target": target,
                        "source_hlc": source_fix["hlc"],
                        "source_hlo": source_fix["hlo"],
                        "target_hlc": target_fix["hlc"],
                        "target_hlo": target_fix["hlo"],
                    }
                )

    for hlc, values in source_by_hlc.items():
        summary["source_per_hlc"][str(len(values))] += 1
        summary["targets_per_hlc"][str(len(target_by_hlc[hlc]))] += 1

    result = {
        "summary": {
            key: dict(value) if isinstance(value, Counter) else value
            for key, value in summary.items()
        },
        "top_families": [
            {
                "family": family,
                "count": count,
                "examples": family_examples[family],
            }
            for family, count in summary["family_counts"].most_common(25)
        ],
        "top_family_semantic_signatures": [
            {"signature": sig, "count": count}
            for sig, count in summary["family_hlc_consistency"].most_common(25)
        ],
        "inference": {
            "candidate_law": (
                "Each links.txt pair appears to map one primary content-bearing source path "
                "to one fixup-only target identity inside a shared HLC group, with the source "
                "occupying HLO 0 and targets occupying higher HLO ordinals."
            ),
            "caveat": (
                "This establishes shared-group structure and metadata-only target records, but does "
                "not yet prove whether reconstruction should use copy, hardlink, clone, or another "
                "shared-content mechanism."
            ),
        },
    }

    args.output.write_text(json.dumps(result, indent=2))
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
