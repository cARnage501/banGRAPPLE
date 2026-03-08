#!/usr/bin/env python3
"""
Inventory explicit object nodes and relationship edges across banGRAPPLE's
currently understood source layers.

This does not claim full semantic reconstruction. It answers a narrower
question: which layers currently emit objects, which layers emit edges or
grouping metadata, and where the known framework-leaf gap is still absent.
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import sys
from collections import Counter

SCRIPT_DIR = pathlib.Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import payloadv2_probe as probe


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build an object-graph census across payloadv2 source layers."
    )
    parser.add_argument(
        "--metadata-jsonl",
        type=pathlib.Path,
        required=True,
        help="path to _yaa_materialized.jsonl from a rebuild",
    )
    parser.add_argument(
        "--payloadv2-dir",
        type=pathlib.Path,
        required=True,
        help="path to AssetData/payloadv2",
    )
    parser.add_argument(
        "--closure-cases-json",
        type=pathlib.Path,
        help="optional framework closure case list to trace against graph layers",
    )
    parser.add_argument(
        "--output",
        type=pathlib.Path,
        required=True,
        help="where to write the graph census JSON",
    )
    return parser.parse_args()


def load_metadata_jsonl(path: pathlib.Path) -> dict:
    type_counts = Counter()
    paths = set()
    symlink_edges = []

    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            record = json.loads(line)
            object_type = record.get("object_type") or "<none>"
            type_counts[object_type] += 1
            rel_path = record.get("path")
            if rel_path is not None:
                paths.add(rel_path)
            if object_type == "link" and rel_path and record.get("link_target"):
                symlink_edges.append(
                    {
                        "path": rel_path,
                        "target": record["link_target"],
                    }
                )

    return {
        "explicit_object_count": sum(type_counts.values()),
        "object_type_counts": dict(type_counts),
        "explicit_paths": paths,
        "symlink_edges": symlink_edges,
    }


def parse_links_pairs(text: str) -> list[dict]:
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    pairs = []
    index = 0
    while index + 1 < len(lines):
        left = lines[index]
        right = lines[index + 1]
        if left.startswith("=") and right.startswith("+"):
            pairs.append({"source": left[1:], "target": right[1:]})
            index += 2
        else:
            index += 1
    return pairs


def parse_xattr_blob(blob: bytes) -> dict:
    if len(blob) < 4:
        raise ValueError("xattr blob shorter than name-length prefix")
    name_length = int.from_bytes(blob[:4], "little")
    name_end = 4 + name_length
    if name_end <= len(blob):
        raw_name = blob[4:name_end]
        if raw_name.endswith(b"\0"):
            raw_name = raw_name[:-1]
        return {
            "name": raw_name.decode("utf-8", errors="replace"),
            "value": blob[name_end:],
        }

    # firmlinks_payload uses a variant where the payload begins with a total
    # length field and then stores a NUL-delimited name/value string pair.
    if name_length == len(blob):
        tail = blob[4:]
        parts = tail.split(b"\0")
        if len(parts) >= 2:
            return {
                "name": parts[0].decode("utf-8", errors="replace"),
                "value": parts[1],
            }

    raise ValueError("xattr blob length prefix does not fit payload")


def parse_xattr_payload(blob: bytes) -> list[dict]:
    parsed = []
    cursor = 0
    while cursor + 4 <= len(blob):
        segment_length = int.from_bytes(blob[cursor : cursor + 4], "little")
        if segment_length < 4 or cursor + segment_length > len(blob):
            parsed = []
            break
        body = blob[cursor + 4 : cursor + segment_length]
        if b"\0" not in body:
            parsed = []
            break
        raw_name, value = body.split(b"\0", 1)
        parsed.append(
            {
                "name": raw_name.decode("utf-8", errors="replace"),
                "value": value,
            }
        )
        cursor += segment_length

    if parsed and cursor == len(blob):
        return parsed

    try:
        return [parse_xattr_blob(blob)]
    except ValueError:
        pass
    raise ValueError("xattr payload does not match known formats")


def parse_raw_yaa_with_xattrs(data: bytes) -> list[dict]:
    offset = 0
    records = []
    while offset + 6 <= len(data):
        if data[offset : offset + 4] != b"YAA1":
            break
        declared = int.from_bytes(data[offset + 4 : offset + 6], "little")
        if declared < 6:
            break
        metadata = data[offset + 6 : offset + declared]
        cursor = 0
        record = {
            "offset": offset,
            "type_code": None,
            "path": None,
            "link_target": None,
            "xattrs": [],
        }
        payload_lengths = []
        while cursor < len(metadata):
            tag = metadata[cursor : cursor + 4]
            cursor += 4
            if tag == b"TYP1":
                record["type_code"] = chr(metadata[cursor])
                cursor += 1
            elif tag in {b"PATP", b"LNKP"}:
                length = int.from_bytes(metadata[cursor : cursor + 2], "little")
                cursor += 2
                value = metadata[cursor : cursor + length].decode("utf-8", errors="replace")
                cursor += length
                if tag == b"PATP":
                    record["path"] = value
                else:
                    record["link_target"] = value
            elif tag == b"DATA":
                length = int.from_bytes(metadata[cursor : cursor + 2], "little")
                cursor += 2
                payload_lengths.append(("DATA", length))
            elif tag == b"DATB":
                length = int.from_bytes(metadata[cursor : cursor + 4], "little")
                cursor += 4
                payload_lengths.append(("DATB", length))
            elif tag == b"XATA":
                length = int.from_bytes(metadata[cursor : cursor + 2], "little")
                cursor += 2
                payload_lengths.append(("XATA", length))
            elif tag in {
                b"UID1",
                b"GID1",
                b"FLG1",
                b"AFT1",
                b"AFR1",
                b"HLC1",
                b"HLO1",
            }:
                cursor += 1
            elif tag in {
                b"UID2",
                b"GID2",
                b"FLG2",
                b"MOD2",
                b"AFT2",
                b"AFR2",
                b"HLC2",
                b"HLO2",
            }:
                cursor += 2
            elif tag in {
                b"UID4",
                b"GID4",
                b"FLG4",
                b"FLI4",
                b"AFT4",
                b"AFR4",
                b"HLC4",
                b"HLO4",
            }:
                cursor += 4
            elif tag == b"MTMS":
                cursor += 8
            elif tag == b"MTMT":
                cursor += 12
            else:
                raise ValueError(f"unknown tag {tag!r} at offset {offset}")

        payload_cursor = offset + declared
        for tag_name, length in payload_lengths:
            payload = data[payload_cursor : payload_cursor + length]
            payload_cursor += length
            if tag_name == "XATA":
                record["xattrs"].extend(parse_xattr_payload(payload))

        records.append(record)
        offset = payload_cursor
    return records


def build_fixup_summary(payloadv2_dir: pathlib.Path) -> dict:
    fixup_raw = payloadv2_dir.joinpath("fixup.manifest").read_bytes()
    fixup = probe.decode_pbzx(fixup_raw)["decoded_bytes"]
    records = probe.parse_yaa_records(fixup, limit=1_000_000, start_offset=0)

    type_counts = Counter()
    tag_counts = Counter()
    explicit_paths = set()
    symlink_edges = []
    hlc_hlo_records = 0
    hlc_hlo_combo_counts = Counter()

    for record in records:
        type_code = record.get("type_code") or "<none>"
        type_counts[type_code] += 1
        rel_path = record.get("path")
        if rel_path is not None:
            explicit_paths.add(rel_path)
        if type_code == "L" and rel_path and record.get("link_target"):
            symlink_edges.append({"path": rel_path, "target": record["link_target"]})

        combo = []
        for field in record.get("fields", []):
            tag = field.get("tag")
            if tag:
                tag_counts[tag] += 1
            if tag and (tag.startswith("HLC") or tag.startswith("HLO")):
                combo.append((tag, field.get("value")))
        if combo:
            hlc_hlo_records += 1
            hlc_hlo_combo_counts[tuple(combo)] += 1

    return {
        "explicit_object_count": sum(type_counts.values()),
        "object_type_counts": dict(type_counts),
        "tag_counts": dict(tag_counts),
        "explicit_paths": explicit_paths,
        "symlink_edges": symlink_edges,
        "hlc_hlo_record_count": hlc_hlo_records,
        "hlc_hlo_combo_count": len(hlc_hlo_combo_counts),
        "top_hlc_hlo_combos": [
            {
                "count": count,
                "combo": [{"tag": tag, "value": value} for tag, value in combo],
            }
            for combo, count in hlc_hlo_combo_counts.most_common(20)
        ],
    }


def build_links_summary(payloadv2_dir: pathlib.Path) -> dict:
    links_text = payloadv2_dir.joinpath("links.txt").read_text(errors="replace")
    pairs = parse_links_pairs(links_text)
    source_counts = Counter()
    target_counts = Counter()
    for pair in pairs:
        source_counts[pathlib.PurePosixPath(pair["source"]).suffix or "<none>"] += 1
        target_counts[pathlib.PurePosixPath(pair["target"]).suffix or "<none>"] += 1
    return {
        "pair_count": len(pairs),
        "pairs": pairs,
        "source_suffix_counts": dict(source_counts),
        "target_suffix_counts": dict(target_counts),
    }


def build_firmlink_summary(payloadv2_dir: pathlib.Path) -> dict:
    raw = payloadv2_dir.joinpath("firmlinks_payload").read_bytes()
    records = parse_raw_yaa_with_xattrs(raw)

    type_counts = Counter()
    firmlink_edges = []
    xattr_name_counts = Counter()

    for record in records:
        type_counts[record["type_code"] or "<none>"] += 1
        for xattr in record["xattrs"]:
            xattr_name_counts[xattr["name"]] += 1
            if xattr["name"] == "com.apple.fs.firmlink":
                firmlink_edges.append(
                    {
                        "path": record["path"],
                        "target": xattr["value"].decode("utf-8", errors="replace"),
                    }
                )

    return {
        "explicit_object_count": sum(type_counts.values()),
        "object_type_counts": dict(type_counts),
        "xattr_name_counts": dict(xattr_name_counts),
        "firmlink_edge_count": len(firmlink_edges),
        "firmlink_edges": firmlink_edges,
    }


def build_layer_inventory(payloadv2_dir: pathlib.Path) -> dict:
    def decode_size(name: str) -> dict:
        path = payloadv2_dir / name
        if not path.exists():
            return {"present": False}
        data = path.read_bytes()
        if data.startswith(b"pbzx"):
            decoded = probe.decode_pbzx(data)["decoded_bytes"]
            return {
                "present": True,
                "encoding": "pbzx",
                "size": len(data),
                "decoded_size": len(decoded),
            }
        return {
            "present": True,
            "encoding": "raw",
            "size": len(data),
        }

    return {
        "prepare_payload": decode_size("prepare_payload"),
        "data_payload": decode_size("data_payload"),
        "fixup.manifest": decode_size("fixup.manifest"),
        "links.txt": decode_size("links.txt"),
        "firmlinks_payload": decode_size("firmlinks_payload"),
        "image_patches": sorted(
            str(path.relative_to(payloadv2_dir))
            for path in payloadv2_dir.joinpath("image_patches").glob("*")
        ),
        "basesystem_patches": sorted(
            str(path.relative_to(payloadv2_dir))
            for path in payloadv2_dir.joinpath("basesystem_patches").glob("*")
        ),
    }


def trace_closure_cases(
    closure_cases: list[dict],
    primary_paths: set[str],
    primary_symlink_edges: list[dict],
    fixup_paths: set[str],
    fixup_symlink_edges: list[dict],
    links_pairs: list[dict],
    firmlink_edges: list[dict],
) -> dict:
    primary_link_targets = {edge["target"] for edge in primary_symlink_edges}
    fixup_link_targets = {edge["target"] for edge in fixup_symlink_edges}
    links_sources = {pair["source"] for pair in links_pairs}
    links_targets = {pair["target"] for pair in links_pairs}
    firmlink_targets = {edge["target"] for edge in firmlink_edges}

    counts = Counter(
        {
            "primary_explicit_path": 0,
            "primary_symlink_target_exact": 0,
            "fixup_explicit_path": 0,
            "fixup_symlink_target_exact": 0,
            "links_source_exact": 0,
            "links_target_exact": 0,
            "firmlink_target_exact": 0,
        }
    )
    for case in closure_cases:
        path = case["resolved_target_rel"]
        if path in primary_paths:
            counts["primary_explicit_path"] += 1
        if path in primary_link_targets:
            counts["primary_symlink_target_exact"] += 1
        if path in fixup_paths:
            counts["fixup_explicit_path"] += 1
        if path in fixup_link_targets:
            counts["fixup_symlink_target_exact"] += 1
        if path in links_sources:
            counts["links_source_exact"] += 1
        if path in links_targets:
            counts["links_target_exact"] += 1
        if path in firmlink_targets:
            counts["firmlink_target_exact"] += 1

    return dict(counts)


def main() -> None:
    args = parse_args()

    metadata = load_metadata_jsonl(args.metadata_jsonl)
    fixup = build_fixup_summary(args.payloadv2_dir)
    links = build_links_summary(args.payloadv2_dir)
    firmlinks = build_firmlink_summary(args.payloadv2_dir)
    layer_inventory = build_layer_inventory(args.payloadv2_dir)

    report = {
        "layer_inventory": layer_inventory,
        "node_channels": {
            "primary_yaa_materialized": {
                "explicit_object_count": metadata["explicit_object_count"],
                "object_type_counts": metadata["object_type_counts"],
                "symlink_edge_count": len(metadata["symlink_edges"]),
            },
            "fixup_manifest": {
                "explicit_object_count": fixup["explicit_object_count"],
                "object_type_counts": fixup["object_type_counts"],
                "symlink_edge_count": len(fixup["symlink_edges"]),
                "hlc_hlo_record_count": fixup["hlc_hlo_record_count"],
                "hlc_hlo_combo_count": fixup["hlc_hlo_combo_count"],
                "top_hlc_hlo_combos": fixup["top_hlc_hlo_combos"],
            },
            "firmlinks_payload": {
                "explicit_object_count": firmlinks["explicit_object_count"],
                "object_type_counts": firmlinks["object_type_counts"],
                "xattr_name_counts": firmlinks["xattr_name_counts"],
            },
        },
        "edge_channels": {
            "primary_symlinks": len(metadata["symlink_edges"]),
            "fixup_symlinks": len(fixup["symlink_edges"]),
            "links_txt_pairs": links["pair_count"],
            "firmlink_edges": firmlinks["firmlink_edge_count"],
        },
    }

    if args.closure_cases_json:
        closure_cases = json.loads(args.closure_cases_json.read_text())
        report["framework_closure_trace"] = trace_closure_cases(
            closure_cases=closure_cases,
            primary_paths=metadata["explicit_paths"],
            primary_symlink_edges=metadata["symlink_edges"],
            fixup_paths=fixup["explicit_paths"],
            fixup_symlink_edges=fixup["symlink_edges"],
            links_pairs=links["pairs"],
            firmlink_edges=firmlinks["firmlink_edges"],
        )

    args.output.write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
