#!/usr/bin/env python3
"""Minimal structural probe for RIDIFF10-wrapped image patches.

This does not implement RIDIFF semantics. It only answers:
- does the file carry a fixed RIDIFF wrapper?
- where does the inner pbzx stream begin?
- what does the first decoded pbzx chunk look like?
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys

SCRIPT_DIR = pathlib.Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import payloadv2_probe as probe

RIDIFF_MAGIC = b"RIDIFF10"
KNOWN_NEEDLES = [
    b"YAA1",
    b"koly",
    b"APFS",
    b"HFS",
    b"pbzx",
    b"BXDIFF50",
    b"RIDIFF10",
    b"\xfd7zXZ\x00",
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Probe RIDIFF10-wrapped payloadv2 image patches")
    parser.add_argument("--payloadv2-dir", type=pathlib.Path, required=True)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    parser.add_argument("--head-bytes", type=int, default=2 * 1024 * 1024)
    return parser.parse_args()


def classify_decoded_chunk(decoded: bytes) -> dict:
    return {
        "decoded_len": len(decoded),
        "magic": probe.classify_magic(decoded[:64]),
        "head_hex": decoded[:64].hex(),
        "strings": probe.extract_strings(decoded[: min(len(decoded), 65536)], limit=20),
        "needle_hits": {
            needle.decode("latin1", errors="replace"): decoded.find(needle)
            for needle in KNOWN_NEEDLES
            if decoded.find(needle) != -1
        },
    }


def probe_file(path: pathlib.Path, head_bytes: int) -> dict:
    with path.open("rb") as handle:
        head = handle.read(head_bytes)

    pbzx_offset = head.find(b"pbzx")
    xz_offset = head.find(b"\xfd7zXZ\x00")
    if not head.startswith(RIDIFF_MAGIC):
        raise ValueError(f"{path} does not start with RIDIFF10")
    if pbzx_offset == -1:
        raise ValueError(f"{path} does not expose pbzx in the first {head_bytes} bytes")

    decoded_chunks = []
    decoded_prefix = bytearray()
    pbzx_stream = head[pbzx_offset:]
    for index, chunk in enumerate(probe.iter_pbzx_chunks(pbzx_stream)):
        decoded_chunks.append({"chunk_index": index, **classify_decoded_chunk(chunk)})
        if len(decoded_prefix) < 262144:
            decoded_prefix.extend(chunk[: 262144 - len(decoded_prefix)])
        break

    wrapper_prefix = head[:pbzx_offset]
    return {
        "size": path.stat().st_size,
        "pbzx_offset": pbzx_offset,
        "xz_offset": xz_offset,
        "wrapper_prefix_len": len(wrapper_prefix),
        "wrapper_prefix_hex": wrapper_prefix.hex(),
        "wrapper_u16_from_offset8": [
            int.from_bytes(wrapper_prefix[offset : offset + 2], "little")
            for offset in range(8, len(wrapper_prefix) - ((len(wrapper_prefix) - 8) % 2), 2)
        ],
        "first_decoded_chunk": decoded_chunks[0] if decoded_chunks else None,
        "decoded_prefix_magic": probe.classify_magic(decoded_prefix[:64]),
        "decoded_prefix_strings": probe.extract_strings(decoded_prefix[: min(len(decoded_prefix), 65536)], limit=20),
        "inference": {
            "looks_like_exact_path_control_stream": False,
            "looks_like_filesystem_image_prefix": False,
            "looks_like_opaque_binary_patch_payload": not bool(probe.extract_strings(decoded_prefix[:65536], limit=5)),
        },
    }


def main() -> None:
    args = parse_args()
    image_patches_dir = args.payloadv2_dir / "image_patches"
    report = {}
    for path in sorted(image_patches_dir.iterdir()):
        if path.is_file():
            report[str(path.relative_to(args.payloadv2_dir))] = probe_file(path, args.head_bytes)
    args.output.write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
