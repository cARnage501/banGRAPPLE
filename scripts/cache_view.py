#!/usr/bin/env python3
"""
Inspect a decoded payload cache file with optional YAA record parsing.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import pathlib
import sys


def load_probe_module():
    probe_path = pathlib.Path(__file__).with_name("payloadv2_probe.py")
    spec = importlib.util.spec_from_file_location("payloadv2_probe", probe_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load probe module from {probe_path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def ascii_preview(data: bytes) -> str:
    chars = []
    for byte in data:
        if 32 <= byte <= 126:
            chars.append(chr(byte))
        elif byte in (9, 10, 13):
            chars.append(".")
        else:
            chars.append(".")
    return "".join(chars)


def print_hexdump(data: bytes, base_offset: int) -> None:
    for row_start in range(0, len(data), 16):
        row = data[row_start : row_start + 16]
        hex_bytes = " ".join(f"{byte:02x}" for byte in row)
        ascii_bytes = ascii_preview(row)
        print(f"{base_offset + row_start:012d}  {hex_bytes:<47}  {ascii_bytes}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Inspect a decoded payload cache file.")
    parser.add_argument("cache_path", type=pathlib.Path, help="path to the decoded cache bin")
    parser.add_argument("--offset", type=int, default=0, help="byte offset to inspect")
    parser.add_argument("--bytes", type=int, default=256, help="number of bytes to show")
    parser.add_argument(
        "--strings-min",
        type=int,
        default=8,
        help="minimum printable string length for string extraction",
    )
    parser.add_argument(
        "--parse-yaa-record",
        action="store_true",
        help="attempt to parse one YAA record starting at --offset",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="emit the parsed YAA record as JSON when --parse-yaa-record is used",
    )
    args = parser.parse_args()

    cache = args.cache_path.read_bytes()
    if args.offset < 0 or args.offset > len(cache):
        raise RuntimeError(f"offset {args.offset} is outside cache size {len(cache)}")

    end = min(len(cache), args.offset + max(args.bytes, 0))
    window = cache[args.offset:end]

    probe = load_probe_module()

    print(f"cache: {args.cache_path}")
    print(f"size: {len(cache)} bytes")
    print(f"offset: {args.offset}")
    print(f"window_bytes: {len(window)}")
    print(f"magic: {probe.classify_magic(window[:64]) if window else 'empty'}")
    print(f"sha256_16: {probe.short_sha256(window)}")
    print()
    print("Hexdump")
    print_hexdump(window, args.offset)
    print()
    print("Strings")
    for value in probe.extract_strings(window, minimum=args.strings_min, limit=20):
        print(f"- {value}")

    if args.parse_yaa_record:
        print()
        print("YAA Record")
        records = probe.parse_yaa_records(cache, limit=1, start_offset=args.offset)
        if not records:
            print("no YAA record parsed at this offset")
            return 0
        record = records[0]
        if args.json:
            print(json.dumps(probe.json_safe(record), indent=2, sort_keys=True))
        else:
            print(
                f"offset={record.get('offset')} next={record.get('next_record_offset')} "
                f"type={record.get('type_code')} verdict={record.get('verdict')} "
                f"path={record.get('path')!r}"
            )
            print(f"declared={record.get('declared_length')} parsed={record.get('parsed_length')}")
            if record.get("parse_error"):
                print(f"parse_error={record['parse_error']}")
            if record.get("fields"):
                print("fields:")
                for field in record["fields"]:
                    print(f"  - {json.dumps(probe.json_safe(field), sort_keys=True)}")
            if record.get("external_payloads"):
                print("external_payloads:")
                for payload in record["external_payloads"]:
                    summary = {
                        "tag": payload.get("tag"),
                        "length": payload.get("length"),
                        "payload_offset": payload.get("payload_offset"),
                        "sha256_16": payload.get("sha256_16"),
                        "preview_hex": payload.get("preview_hex"),
                    }
                    print(f"  - {json.dumps(summary, sort_keys=True)}")

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RuntimeError as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(1)
