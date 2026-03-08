#!/usr/bin/env python3
"""
Deterministically inspect Apple's payloadv2 layout and emit an ordered shard map.

This script does not attempt a full reconstruction. It inventories control files,
unwraps pbzx metadata where practical, classifies shard families, and writes a
stable report that can drive later reconstruction work.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import lzma
import math
import pathlib
import re
import shutil
import struct
import subprocess
import sys
from collections import Counter
from dataclasses import dataclass


PBZX_MAGIC = b"pbzx"
XZ_MAGIC = b"\xfd7zXZ\x00"
BXDIFF_MAGIC = b"BXDIFF50"
READ_SAMPLE_BYTES = 1024 * 1024
HEAD_SAMPLE_BYTES = 128
SEMANTICALLY_VALIDATED_TAGS = {"PATP", "LNKP", "DATA", "DATB", "XATA"}
STRUCTURALLY_UNDERSTOOD_TAGS = {
    "TYP1",
    "UID1",
    "UID2",
    "UID4",
    "GID1",
    "GID2",
    "GID4",
    "MOD2",
}
SYNTACTICALLY_PARSED_TAGS = {
    "AFT1",
    "AFT2",
    "AFT4",
    "AFR1",
    "AFR2",
    "AFR4",
    "HLC1",
    "HLC2",
    "HLC4",
    "HLO1",
    "HLO2",
    "HLO4",
    "FLG1",
    "FLG2",
    "FLG4",
    "FLI4",
    "MTMS",
    "MTMT",
}
DEFAULT_REGION_SIZE_BYTES = 64 * 1024 * 1024
KNOWN_TAG_FAMILIES = {
    "TYP",
    "LNK",
    "PAT",
    "UID",
    "GID",
    "MOD",
    "FLG",
    "FLI",
    "AFT",
    "AFR",
    "HLC",
    "HLO",
    "MTM",
    "DAT",
    "XAT",
}


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def classify_magic(data: bytes) -> str:
    if data.startswith(BXDIFF_MAGIC):
        return "bxdiff"
    if data.startswith(PBZX_MAGIC):
        return "pbzx"
    if data.startswith(XZ_MAGIC):
        return "xz"
    if data.startswith(b"<?xml"):
        return "xml"
    if data.startswith(b"bplist00"):
        return "bplist"
    if all(32 <= byte <= 126 or byte in (9, 10, 13) for byte in data[:64] if data):
        return "textish"
    return "binary"


def to_hex(data: bytes, count: int = 32) -> str:
    return data[:count].hex()


def short_sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()[:16]


def json_safe(value):
    if isinstance(value, bytes):
        return {"bytes_len": len(value), "sha256_16": short_sha256(value)}
    if isinstance(value, dict):
        return {key: json_safe(subvalue) for key, subvalue in value.items() if key != "_blob"}
    if isinstance(value, list):
        return [json_safe(item) for item in value]
    return value


def extract_strings(data: bytes, minimum: int = 8, limit: int = 40) -> list[str]:
    text = data.decode("latin1", errors="ignore")
    matches = re.findall(rf"[\x20-\x7e]{{{minimum},}}", text)
    seen: list[str] = []
    for match in matches:
        if match not in seen:
            seen.append(match)
        if len(seen) >= limit:
            break
    return seen


def tag_family(tag: str) -> str:
    if tag.startswith("UID"):
        return "UID"
    if tag.startswith("GID"):
        return "GID"
    if tag.startswith("FLG"):
        return "FLG"
    if tag.startswith("FLI"):
        return "FLI"
    if tag.startswith("AFT"):
        return "AFT"
    if tag.startswith("AFR"):
        return "AFR"
    if tag.startswith("DAT"):
        return "DAT"
    if tag.startswith("XAT"):
        return "XAT"
    if tag.startswith("MTM"):
        return "MTM"
    if tag.startswith("PAT"):
        return "PAT"
    if tag.startswith("TYP"):
        return "TYP"
    if tag.startswith("MOD"):
        return "MOD"
    return tag


def decode_pbzx(data: bytes) -> dict:
    if not data.startswith(PBZX_MAGIC):
        raise ValueError("not a pbzx stream")

    offset = 4
    if len(data) < offset + 8:
        return {
            "initial_flags": None,
            "chunk_count": 0,
            "decoded_bytes": b"",
            "chunks": [],
        }

    initial_flags = struct.unpack(">Q", data[offset : offset + 8])[0]
    offset += 8
    decoded = bytearray()
    chunks = []

    while offset + 16 <= len(data):
        flags = struct.unpack(">Q", data[offset : offset + 8])[0]
        offset += 8
        length = struct.unpack(">Q", data[offset : offset + 8])[0]
        offset += 8
        if offset + length > len(data):
            chunks.append(
                {
                    "flags": flags,
                    "compressed_length": length,
                    "status": "truncated",
                }
            )
            break

        chunk = data[offset : offset + length]
        offset += length

        if chunk.startswith(XZ_MAGIC):
            try:
                unpacked = lzma.decompress(chunk, format=lzma.FORMAT_XZ)
                decoded.extend(unpacked)
                chunks.append(
                    {
                        "flags": flags,
                        "compressed_length": length,
                        "decoded_length": len(unpacked),
                        "encoding": "xz",
                    }
                )
            except lzma.LZMAError as error:
                chunks.append(
                    {
                        "flags": flags,
                        "compressed_length": length,
                        "status": f"xz-error:{error}",
                    }
                )
                break
        else:
            decoded.extend(chunk)
            chunks.append(
                {
                    "flags": flags,
                    "compressed_length": length,
                    "decoded_length": len(chunk),
                    "encoding": "raw",
                }
            )

    return {
        "initial_flags": initial_flags,
        "chunk_count": len(chunks),
        "decoded_bytes": bytes(decoded),
        "chunks": chunks,
    }


def iter_pbzx_chunks(data: bytes):
    if not data.startswith(PBZX_MAGIC):
        raise ValueError("not a pbzx stream")

    offset = 4
    if len(data) < offset + 8:
        return

    offset += 8  # initial flags
    while offset + 16 <= len(data):
        _flags = struct.unpack(">Q", data[offset : offset + 8])[0]
        offset += 8
        length = struct.unpack(">Q", data[offset : offset + 8])[0]
        offset += 8
        if offset + length > len(data):
            break
        chunk = data[offset : offset + length]
        offset += length
        if chunk.startswith(XZ_MAGIC):
            yield lzma.decompress(chunk, format=lzma.FORMAT_XZ)
        else:
            yield chunk


@dataclass
class ZipEntry:
    path: str
    size: int
    packed_size: int | None


class ArtifactSource:
    def list_paths(self, prefix: str) -> list[str]:
        raise NotImplementedError

    def exists(self, relative_path: str) -> bool:
        raise NotImplementedError

    def size(self, relative_path: str) -> int | None:
        raise NotImplementedError

    def read_all(self, relative_path: str) -> bytes:
        raise NotImplementedError

    def read_head(self, relative_path: str, count: int) -> bytes:
        raise NotImplementedError


class DirectorySource(ArtifactSource):
    def __init__(self, asset_root: pathlib.Path):
        self.asset_root = asset_root

    def _path(self, relative_path: str) -> pathlib.Path:
        return self.asset_root / relative_path

    def list_paths(self, prefix: str) -> list[str]:
        root = self._path(prefix)
        if not root.exists():
            return []
        if root.is_file():
            return [prefix]
        paths: list[str] = []
        for path in root.rglob("*"):
            if path.is_file():
                paths.append(path.relative_to(self.asset_root).as_posix())
        return sorted(paths)

    def exists(self, relative_path: str) -> bool:
        return self._path(relative_path).exists()

    def size(self, relative_path: str) -> int | None:
        path = self._path(relative_path)
        return path.stat().st_size if path.exists() else None

    def read_all(self, relative_path: str) -> bytes:
        return self._path(relative_path).read_bytes()

    def read_head(self, relative_path: str, count: int) -> bytes:
        with self._path(relative_path).open("rb") as handle:
            return handle.read(count)


class ZipSource(ArtifactSource):
    def __init__(self, zip_path: pathlib.Path):
        self.zip_path = zip_path
        self.entries = self._load_entries()

    def _load_entries(self) -> dict[str, ZipEntry]:
        command = ["7z", "l", "-slt", str(self.zip_path)]
        output = subprocess.check_output(command, text=True, errors="replace")
        entries: dict[str, ZipEntry] = {}
        current: dict[str, str] = {}
        for line in output.splitlines():
            line = line.strip()
            if not line:
                if "Path" in current and current["Path"].startswith("AssetData/"):
                    rel = current["Path"][len("AssetData/") :]
                    entries[rel] = ZipEntry(
                        path=rel,
                        size=int(current.get("Size", "0") or 0),
                        packed_size=(
                            int(current["Packed Size"])
                            if current.get("Packed Size") not in (None, "")
                            else None
                        ),
                    )
                current = {}
                continue
            if " = " in line:
                key, value = line.split(" = ", 1)
                current[key] = value
        return entries

    def list_paths(self, prefix: str) -> list[str]:
        return sorted(path for path in self.entries if path.startswith(prefix))

    def exists(self, relative_path: str) -> bool:
        return relative_path in self.entries

    def size(self, relative_path: str) -> int | None:
        entry = self.entries.get(relative_path)
        return entry.size if entry else None

    def read_all(self, relative_path: str) -> bytes:
        command = ["7z", "e", "-so", str(self.zip_path), f"AssetData/{relative_path}"]
        return subprocess.check_output(command)

    def read_head(self, relative_path: str, count: int) -> bytes:
        command = ["7z", "e", "-so", str(self.zip_path), f"AssetData/{relative_path}"]
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        assert process.stdout is not None
        try:
            data = process.stdout.read(count)
        finally:
            process.kill()
            process.wait(timeout=5)
        return data


class SequentialDecodedStream:
    def __init__(self, source: ArtifactSource, ordered: list[dict]):
        self.source = source
        self.entries = [entry for entry in ordered if entry["payload_present"]]
        self.entry_index = 0
        self.chunk_iter = iter(())
        self.buffer = bytearray()
        self.position = 0

    def tell(self) -> int:
        return self.position

    def _append_next_chunk(self) -> bool:
        while True:
            try:
                chunk = next(self.chunk_iter)
                if chunk:
                    self.buffer.extend(chunk)
                    return True
            except StopIteration:
                if self.entry_index >= len(self.entries):
                    return False
                entry = self.entries[self.entry_index]
                self.entry_index += 1
                data = self.source.read_all(entry["payload_path"])
                if not data.startswith(PBZX_MAGIC):
                    self.chunk_iter = iter(())
                    continue
                self.chunk_iter = iter_pbzx_chunks(data)

    def _fill(self, count: int) -> None:
        while len(self.buffer) < count:
            if not self._append_next_chunk():
                break

    def peek(self, count: int) -> bytes:
        self._fill(count)
        return bytes(self.buffer[:count])

    def read(self, count: int) -> bytes:
        self._fill(count)
        taken = bytes(self.buffer[:count])
        del self.buffer[: len(taken)]
        self.position += len(taken)
        return taken

    def skip(self, count: int) -> int:
        remaining = count
        skipped = 0

        if self.buffer:
            take = min(len(self.buffer), remaining)
            del self.buffer[:take]
            self.position += take
            skipped += take
            remaining -= take

        while remaining > 0:
            if not self._append_next_chunk():
                break
            take = min(len(self.buffer), remaining)
            del self.buffer[:take]
            self.position += take
            skipped += take
            remaining -= take

        return skipped

    def skip_to(self, absolute_offset: int) -> int:
        if absolute_offset < self.position:
            raise RuntimeError("cannot seek backward in SequentialDecodedStream")
        return self.skip(absolute_offset - self.position)


def resolve_source(path: pathlib.Path) -> ArtifactSource:
    if path.is_file() and path.suffix.lower() == ".zip":
        if shutil.which("7z") is None:
            raise RuntimeError("7z is required when the input is a zip archive")
        return ZipSource(path)

    if path.is_dir():
        if (path / "payloadv2").is_dir():
            return DirectorySource(path)
        if (path / "AssetData").is_dir():
            return DirectorySource(path / "AssetData")
        if path.name == "payloadv2":
            return DirectorySource(path.parent)

    raise RuntimeError(
        "input must be a MobileAsset zip, an AssetData directory, or a directory containing AssetData"
    )


def parse_payload_chunks(text: str) -> list[dict]:
    ordered = []
    for line in text.splitlines():
        line = line.strip()
        if not line or ":" not in line:
            continue
        index_text, size_text = line.split(":", 1)
        ordered.append(
            {
                "index": int(index_text.strip()),
                "target_size": int(size_text.strip()),
            }
        )
    return sorted(ordered, key=lambda item: item["index"])


def parse_links(text: str) -> dict:
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
    return {
        "line_count": len(lines),
        "pair_count": len(pairs),
        "sample_pairs": pairs[:20],
    }


def summarize_pbzx(name: str, data: bytes) -> dict:
    summary = {
        "name": name,
        "size": len(data),
        "magic": classify_magic(data),
        "head_hex": to_hex(data, 48),
    }
    if not data.startswith(PBZX_MAGIC):
        summary["strings_sample"] = extract_strings(data[:4096], limit=10)
        return summary

    decoded = decode_pbzx(data)
    decoded_bytes = decoded.pop("decoded_bytes")
    summary["pbzx"] = decoded
    summary["decoded_size"] = len(decoded_bytes)
    summary["decoded_magic"] = classify_magic(decoded_bytes[:64])
    summary["decoded_head_hex"] = to_hex(decoded_bytes[:48], 48)
    summary["decoded_strings_sample"] = extract_strings(decoded_bytes[:2 * 1024 * 1024], limit=20)
    return summary


def classify_payload(source: ArtifactSource, relative_path: str) -> dict:
    size = source.size(relative_path)
    head = source.read_head(relative_path, max(HEAD_SAMPLE_BYTES, READ_SAMPLE_BYTES))
    sample = head[:READ_SAMPLE_BYTES]
    result = {
        "path": relative_path,
        "size": size,
        "magic": classify_magic(head[:HEAD_SAMPLE_BYTES]),
        "head_hex": to_hex(head, 48),
        "entropy_first_mib": round(shannon_entropy(sample), 5),
    }
    if BXDIFF_MAGIC in head[:64]:
        result["contains_bxdiff"] = True
    if PBZX_MAGIC in head[:128]:
        result["contains_pbzx"] = True
    result["strings_sample"] = extract_strings(sample[:65536], limit=10)
    return result


def decode_payload_summary(source: ArtifactSource, relative_path: str) -> dict:
    data = source.read_all(relative_path)
    summary = {
        "path": relative_path,
        "compressed_size": len(data),
        "magic": classify_magic(data[:HEAD_SAMPLE_BYTES]),
    }
    if not data.startswith(PBZX_MAGIC):
        summary["status"] = "not-pbzx"
        return summary

    decoded = decode_pbzx(data)
    decoded_bytes = decoded.pop("decoded_bytes")
    summary["status"] = "decoded"
    summary["chunk_count"] = decoded["chunk_count"]
    summary["decoded_size"] = len(decoded_bytes)
    summary["decoded_magic"] = classify_magic(decoded_bytes[:HEAD_SAMPLE_BYTES])
    summary["decoded_head_hex"] = to_hex(decoded_bytes, 48)
    summary["decoded_strings_sample"] = extract_strings(
        decoded_bytes[: min(len(decoded_bytes), 2 * 1024 * 1024)],
        limit=20,
    )
    summary["pbzx"] = decoded
    return summary


def inspect_control_files(source: ArtifactSource) -> dict:
    control_files = [
        "payloadv2/fixup.manifest",
        "payloadv2/payload_chunks.txt",
        "payloadv2/links.txt",
        "payloadv2/prepare_payload",
        "payloadv2/data_payload",
    ]
    report = {}
    for relative_path in control_files:
        if not source.exists(relative_path):
            report[relative_path] = {"present": False}
            continue
        data = source.read_all(relative_path)
        report[relative_path] = {"present": True, **summarize_pbzx(relative_path, data)}
    return report


def inspect_related_runtime_artifacts(source: ArtifactSource) -> dict:
    interesting = [
        "Restore/BaseSystem.chunklist",
        "boot/Firmware/BaseSystem.dmg.x86.trustcache",
        "payloadv2/basesystem_patches/x86_64BaseSystem.dmg",
        "payloadv2/basesystem_patches/x86_64BaseSystem.dmg.ecc",
        "payloadv2/basesystem_patches/arm64eBaseSystem.dmg",
    ]
    artifacts = {}
    for relative_path in interesting:
        if not source.exists(relative_path):
            artifacts[relative_path] = {"present": False}
            continue
        artifacts[relative_path] = {
            "present": True,
            **classify_payload(source, relative_path),
        }
    return artifacts


def ordered_payloads(source: ArtifactSource, payload_chunks: list[dict]) -> list[dict]:
    ordered = []
    for entry in payload_chunks:
        index = entry["index"]
        payload_name = f"payloadv2/payload.{index:03d}"
        ecc_name = f"{payload_name}.ecc"
        payload_info = classify_payload(source, payload_name) if source.exists(payload_name) else None
        ecc_size = source.size(ecc_name)
        ordered.append(
            {
                "index": index,
                "payload_path": payload_name,
                "payload_present": source.exists(payload_name),
                "payload_size": source.size(payload_name),
                "target_size": entry["target_size"],
                "ecc_path": ecc_name if source.exists(ecc_name) else None,
                "ecc_size": ecc_size,
                "classification": payload_info,
            }
        )
    return ordered


def enrich_payload_decodes(
    source: ArtifactSource,
    ordered: list[dict],
    decode_payloads: bool,
    limit: int | None,
) -> dict:
    if not decode_payloads:
        return {
            "enabled": False,
            "decoded_count": 0,
            "matching_target_count": 0,
            "mismatching_target_count": 0,
            "entries": [],
        }

    entries = []
    remaining = len(ordered) if limit is None else max(limit, 0)
    for entry in ordered:
        if remaining == 0:
            break
        if not entry["payload_present"]:
            continue
        decoded = decode_payload_summary(source, entry["payload_path"])
        decoded["index"] = entry["index"]
        decoded["target_size"] = entry["target_size"]
        if decoded.get("decoded_size") is not None:
            decoded["matches_target_size"] = decoded["decoded_size"] == entry["target_size"]
            decoded["decoded_minus_target"] = decoded["decoded_size"] - entry["target_size"]
        entries.append(decoded)
        remaining -= 1

    matching = sum(1 for entry in entries if entry.get("matches_target_size") is True)
    mismatching = sum(1 for entry in entries if entry.get("matches_target_size") is False)
    return {
        "enabled": True,
        "decoded_count": len(entries),
        "matching_target_count": matching,
        "mismatching_target_count": mismatching,
        "entries": entries,
    }


def inspect_decoded_stream_prefix(
    source: ArtifactSource,
    ordered: list[dict],
    prefix_bytes: int,
    output_path: pathlib.Path | None,
) -> dict:
    existing = b""
    cache_path = output_path
    cache_hit = False
    cache_extended = False
    if cache_path is not None and cache_path.exists():
        existing = cache_path.read_bytes()
        if len(existing) >= prefix_bytes:
            cache_hit = True

    collected = bytearray(existing[:prefix_bytes])
    shards_used = []
    total_decoded_bytes = 0

    if not cache_hit:
        cached_length = len(existing)
        appended = bytearray()
        for entry in ordered:
            if not entry["payload_present"]:
                continue
            data = source.read_all(entry["payload_path"])
            if not data.startswith(PBZX_MAGIC):
                continue
            shard_decoded = 0
            for chunk in iter_pbzx_chunks(data):
                chunk_start = total_decoded_bytes
                chunk_end = chunk_start + len(chunk)
                shard_decoded += len(chunk)
                total_decoded_bytes = chunk_end

                if len(collected) >= prefix_bytes:
                    continue
                if chunk_end <= cached_length:
                    continue

                start_in_chunk = max(0, cached_length - chunk_start)
                need = prefix_bytes - len(collected)
                take = chunk[start_in_chunk : start_in_chunk + need]
                collected.extend(take)
                appended.extend(take)

            shards_used.append(
                {
                    "index": entry["index"],
                    "payload_path": entry["payload_path"],
                    "decoded_size": shard_decoded,
                }
            )
            if len(collected) >= prefix_bytes:
                break

        if cache_path is not None and appended:
            cache_path.parent.mkdir(parents=True, exist_ok=True)
            with cache_path.open("ab") as handle:
                handle.write(appended)
            cache_extended = True

    prefix = bytes(collected[:prefix_bytes])
    if cache_path is not None and (not cache_path.exists()):
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        cache_path.write_bytes(prefix)

    signatures = {
        "starts_with_bxdiff": prefix.startswith(BXDIFF_MAGIC),
        "starts_with_pbzx": prefix.startswith(PBZX_MAGIC),
        "starts_with_xz": prefix.startswith(XZ_MAGIC),
        "contains_koly": b"koly" in prefix,
        "contains_apfs": b"APFS" in prefix,
        "contains_hfs": b"HFS" in prefix or b"hfs" in prefix,
        "contains_cpio_magic": b"070701" in prefix or b"070702" in prefix,
        "contains_tar_ustar": b"ustar" in prefix,
        "contains_xml": b"<?xml" in prefix,
    }

    return {
        "requested_prefix_bytes": prefix_bytes,
        "captured_prefix_bytes": len(prefix),
        "shards_used": shards_used,
        "total_decoded_bytes_processed": total_decoded_bytes,
        "prefix_magic": classify_magic(prefix[:HEAD_SAMPLE_BYTES]),
        "prefix_head_hex": to_hex(prefix, 96),
        "prefix_strings_sample": extract_strings(prefix[: min(len(prefix), 65536)], limit=30),
        "signatures": signatures,
        "output_path": str(output_path) if output_path is not None else None,
        "cache_hit": cache_hit,
        "cache_extended": cache_extended,
        "cached_prefix_bytes": len(existing),
    }


def read_u16le(data: bytes, offset: int) -> int:
    return struct.unpack_from("<H", data, offset)[0]


def read_u32le(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def read_u64le(data: bytes, offset: int) -> int:
    return struct.unpack_from("<Q", data, offset)[0]


def read_sized_uint_le(data: bytes, offset: int, width: int) -> int:
    if width == 1:
        return data[offset]
    if width == 2:
        return read_u16le(data, offset)
    if width == 4:
        return read_u32le(data, offset)
    raise ValueError(f"unsupported integer width: {width}")


def parse_yaa_records(data: bytes, limit: int, start_offset: int = 0) -> list[dict]:
    records = []
    offset = start_offset

    while offset + 6 <= len(data) and len(records) < limit:
        if data[offset : offset + 4] != b"YAA1":
            break

        declared_length = read_u16le(data, offset + 4)
        if declared_length < 6:
            break

        metadata_end = min(offset + declared_length, len(data))
        cursor = offset + 6
        record = {
            "offset": offset,
            "declared_length": declared_length,
            "fields": [],
        }
        external_payloads = []
        parse_error = None

        while cursor + 4 <= metadata_end:
            tag_bytes = data[cursor : cursor + 4]
            try:
                tag = tag_bytes.decode("ascii")
            except UnicodeDecodeError:
                parse_error = "non_ascii_tag"
                break
            cursor += 4

            if tag == "TYP1":
                if cursor + 1 > metadata_end:
                    parse_error = "truncated_typ1"
                    break
                value = chr(data[cursor])
                cursor += 1
                record["type_code"] = value
                record["fields"].append({"tag": tag, "value": value})
            elif tag in {"UID1", "UID2", "UID4", "GID1", "GID2", "GID4"}:
                width = int(tag[-1])
                if cursor + width > metadata_end:
                    parse_error = f"truncated_{tag.lower()}"
                    break
                value = read_sized_uint_le(data, cursor, width)
                cursor += width
                key = "uid" if tag.startswith("UID") else "gid"
                record[key] = value
                record["fields"].append({"tag": tag, "value": value})
            elif tag == "MOD2":
                if cursor + 2 > metadata_end:
                    parse_error = "truncated_mod2"
                    break
                value = read_u16le(data, cursor)
                cursor += 2
                record["mode"] = value
                record["fields"].append({"tag": tag, "value": value})
            elif tag in {"FLG1"}:
                if cursor + 1 > metadata_end:
                    parse_error = "truncated_flg1"
                    break
                value = data[cursor]
                cursor += 1
                record["flags"] = value
                record["fields"].append({"tag": tag, "value": value})
            elif tag in {"FLG2"}:
                if cursor + 2 > metadata_end:
                    parse_error = "truncated_flg2"
                    break
                value = read_u16le(data, cursor)
                cursor += 2
                record["flags"] = value
                record["fields"].append({"tag": tag, "value": value})
            elif tag in {"FLG4", "FLI4"}:
                if cursor + 4 > metadata_end:
                    parse_error = f"truncated_{tag.lower()}"
                    break
                value = read_u32le(data, cursor)
                cursor += 4
                if tag == "FLI4":
                    record.setdefault("inline_flags", []).append(value)
                else:
                    record["flags"] = value
                record["fields"].append({"tag": tag, "value": value})
            elif tag in {"AFT1", "AFR1", "HLC1", "HLO1"}:
                if cursor + 1 > metadata_end:
                    parse_error = f"truncated_{tag.lower()}"
                    break
                value = data[cursor]
                cursor += 1
                record["fields"].append({"tag": tag, "value": value})
            elif tag in {"AFT2", "AFR2", "HLC2", "HLO2"}:
                if cursor + 2 > metadata_end:
                    parse_error = f"truncated_{tag.lower()}"
                    break
                value = read_u16le(data, cursor)
                cursor += 2
                record["fields"].append({"tag": tag, "value": value})
            elif tag in {"AFT4", "AFR4", "HLC4", "HLO4"}:
                if cursor + 4 > metadata_end:
                    parse_error = f"truncated_{tag.lower()}"
                    break
                value = read_u32le(data, cursor)
                cursor += 4
                record["fields"].append({"tag": tag, "value": value})
            elif tag in {"MTMS", "MTMT"}:
                if cursor + 8 > metadata_end:
                    parse_error = f"truncated_{tag.lower()}"
                    break
                seconds = read_u64le(data, cursor)
                cursor += 8
                field = {"tag": tag, "seconds": seconds}
                if tag == "MTMT":
                    if cursor + 4 > metadata_end:
                        parse_error = "truncated_mtmt_nanos"
                        break
                    nanos = read_u32le(data, cursor)
                    cursor += 4
                    field["nanos"] = nanos
                record["mtime"] = field
                record["fields"].append(field)
            elif tag in {"PATP", "LNKP"}:
                if cursor + 2 > metadata_end:
                    parse_error = f"truncated_{tag.lower()}_length"
                    break
                length = read_u16le(data, cursor)
                cursor += 2
                if cursor + length > metadata_end:
                    parse_error = f"{tag.lower()}_overruns_metadata"
                    break
                payload = data[cursor : cursor + length]
                cursor += length
                field = {"tag": tag, "length": length}
                value = payload.decode("utf-8", errors="replace")
                if tag == "PATP":
                    record["path"] = value
                else:
                    record["link_target"] = value
                field["value"] = value
                record["fields"].append(field)
            elif tag in {"DATA", "DATB", "XATA"}:
                if tag == "DATB":
                    if cursor + 4 > metadata_end:
                        parse_error = "truncated_datb_length"
                        break
                    length = read_u32le(data, cursor)
                    cursor += 4
                else:
                    if cursor + 2 > metadata_end:
                        parse_error = f"truncated_{tag.lower()}_length"
                        break
                    length = read_u16le(data, cursor)
                    cursor += 2
                field = {"tag": tag, "length": length}
                external_payloads.append(field)
                record["fields"].append(field)
            else:
                record["fields"].append(
                    {
                        "tag": tag,
                        "unparsed_offset": cursor,
                        "remaining_hex": to_hex(data[cursor: min(len(data), cursor + 48)], 48),
                    }
                )
                parse_error = f"unknown_tag:{tag}"
                break

        cursor = metadata_end
        external_results = []
        payload_shortfall = False
        for payload in external_payloads:
            length = payload["length"]
            blob = data[cursor : cursor + length]
            if len(blob) < length:
                payload_shortfall = True
            cursor += length
            parsed = {
                "tag": payload["tag"],
                "length": length,
                "preview_hex": to_hex(blob, min(32, len(blob))),
                "sha256_16": short_sha256(blob),
                "payload_offset": cursor - length,
                "_blob": blob,
            }
            if payload["tag"] in {"DATA", "DATB"}:
                record["data_length"] = length
                parsed["strings_sample"] = extract_strings(blob, minimum=4, limit=5)
            elif payload["tag"] == "XATA":
                if len(blob) >= 4:
                    name_length = read_u32le(blob, 0)
                    name = blob[4 : 4 + name_length].rstrip(b"\x00")
                    parsed["name_length"] = name_length
                    parsed["name"] = name.decode("utf-8", errors="replace")
                    value = blob[4 + name_length :]
                    if value:
                        parsed["value_preview_hex"] = to_hex(value, min(32, len(value)))
                        parsed["value_strings"] = extract_strings(value, minimum=4, limit=5)
                record.setdefault("xattrs", []).append(parsed)
            external_results.append(parsed)

        if external_results:
            record["external_payloads"] = external_results
        record["parsed_length"] = cursor - offset
        record["metadata_length"] = metadata_end - offset
        record["next_record_offset"] = cursor
        record["verdict"] = "exact"
        if payload_shortfall:
            record["verdict"] = "payload_shortfall"
        elif parse_error is not None:
            record["verdict"] = "descriptor_mismatch"
            record["parse_error"] = parse_error
        else:
            next_magic = data[cursor : cursor + 4] if cursor + 4 <= len(data) else b""
            if cursor < len(data) and cursor + 4 <= len(data) and next_magic != b"YAA1":
                record["verdict"] = "next_record_desync"
                record["next_magic_hex"] = next_magic.hex()
            elif record["parsed_length"] > record["declared_length"]:
                record["verdict"] = "metadata_overrun"
        records.append(record)
        if cursor <= offset:
            break
        if record["verdict"] in {"descriptor_mismatch", "payload_shortfall", "next_record_desync"}:
            break
        offset = cursor

    return records


def parse_yaa_records_stream(
    source: ArtifactSource,
    ordered: list[dict],
    limit: int,
    start_offset: int = 0,
) -> list[dict]:
    stream = SequentialDecodedStream(source, ordered)
    stream.skip_to(start_offset)
    records = []

    while len(records) < limit:
        offset = stream.tell()
        header = stream.peek(6)
        if len(header) < 6 or header[:4] != b"YAA1":
            break

        declared_length = struct.unpack_from("<H", header, 4)[0]
        if declared_length < 6:
            break

        record = {
            "offset": offset,
            "declared_length": declared_length,
            "fields": [],
        }

        parse_error = None
        external_payloads = []

        stream.read(6)
        metadata_bytes = stream.read(declared_length - 6)
        if len(metadata_bytes) < declared_length - 6:
            record["verdict"] = "descriptor_mismatch"
            record["parse_error"] = "truncated_metadata"
            record["parsed_length"] = stream.tell() - offset
            record["metadata_length"] = 6 + len(metadata_bytes)
            record["next_record_offset"] = stream.tell()
            records.append(record)
            break

        cursor = 0
        metadata_end = len(metadata_bytes)

        while cursor + 4 <= metadata_end:
            tag_bytes = metadata_bytes[cursor : cursor + 4]
            try:
                tag = tag_bytes.decode("ascii")
            except UnicodeDecodeError:
                parse_error = "non_ascii_tag"
                break
            cursor += 4

            if tag == "TYP1":
                if cursor + 1 > metadata_end:
                    parse_error = "truncated_typ1"
                    break
                value = chr(metadata_bytes[cursor])
                cursor += 1
                record["type_code"] = value
                record["fields"].append({"tag": tag, "value": value})
            elif tag in {"UID1", "UID2", "UID4", "GID1", "GID2", "GID4"}:
                width = int(tag[-1])
                if cursor + width > metadata_end:
                    parse_error = f"truncated_{tag.lower()}"
                    break
                value = read_sized_uint_le(metadata_bytes, cursor, width)
                cursor += width
                key = "uid" if tag.startswith("UID") else "gid"
                record[key] = value
                record["fields"].append({"tag": tag, "value": value})
            elif tag == "MOD2":
                if cursor + 2 > metadata_end:
                    parse_error = "truncated_mod2"
                    break
                value = read_u16le(metadata_bytes, cursor)
                cursor += 2
                record["mode"] = value
                record["fields"].append({"tag": tag, "value": value})
            elif tag == "FLG1":
                if cursor + 1 > metadata_end:
                    parse_error = "truncated_flg1"
                    break
                value = metadata_bytes[cursor]
                cursor += 1
                record["flags"] = value
                record["fields"].append({"tag": tag, "value": value})
            elif tag == "FLG2":
                if cursor + 2 > metadata_end:
                    parse_error = "truncated_flg2"
                    break
                value = read_u16le(metadata_bytes, cursor)
                cursor += 2
                record["flags"] = value
                record["fields"].append({"tag": tag, "value": value})
            elif tag in {"FLG4", "FLI4"}:
                if cursor + 4 > metadata_end:
                    parse_error = f"truncated_{tag.lower()}"
                    break
                value = read_u32le(metadata_bytes, cursor)
                cursor += 4
                if tag == "FLI4":
                    record.setdefault("inline_flags", []).append(value)
                else:
                    record["flags"] = value
                record["fields"].append({"tag": tag, "value": value})
            elif tag in {"AFT1", "AFR1", "HLC1", "HLO1"}:
                if cursor + 1 > metadata_end:
                    parse_error = f"truncated_{tag.lower()}"
                    break
                value = metadata_bytes[cursor]
                cursor += 1
                record["fields"].append({"tag": tag, "value": value})
            elif tag in {"AFT2", "AFR2", "HLC2", "HLO2"}:
                if cursor + 2 > metadata_end:
                    parse_error = f"truncated_{tag.lower()}"
                    break
                value = read_u16le(metadata_bytes, cursor)
                cursor += 2
                record["fields"].append({"tag": tag, "value": value})
            elif tag in {"AFT4", "AFR4", "HLC4", "HLO4"}:
                if cursor + 4 > metadata_end:
                    parse_error = f"truncated_{tag.lower()}"
                    break
                value = read_u32le(metadata_bytes, cursor)
                cursor += 4
                record["fields"].append({"tag": tag, "value": value})
            elif tag in {"MTMS", "MTMT"}:
                if cursor + 8 > metadata_end:
                    parse_error = f"truncated_{tag.lower()}"
                    break
                seconds = read_u64le(metadata_bytes, cursor)
                cursor += 8
                field = {"tag": tag, "seconds": seconds}
                if tag == "MTMT":
                    if cursor + 4 > metadata_end:
                        parse_error = "truncated_mtmt_nanos"
                        break
                    nanos = read_u32le(metadata_bytes, cursor)
                    cursor += 4
                    field["nanos"] = nanos
                record["mtime"] = field
                record["fields"].append(field)
            elif tag in {"PATP", "LNKP"}:
                if cursor + 2 > metadata_end:
                    parse_error = f"truncated_{tag.lower()}_length"
                    break
                length = read_u16le(metadata_bytes, cursor)
                cursor += 2
                if cursor + length > metadata_end:
                    parse_error = f"{tag.lower()}_overruns_metadata"
                    break
                payload = metadata_bytes[cursor : cursor + length]
                cursor += length
                value = payload.decode("utf-8", errors="replace")
                if tag == "PATP":
                    record["path"] = value
                else:
                    record["link_target"] = value
                record["fields"].append({"tag": tag, "length": length, "value": value})
            elif tag in {"DATA", "DATB", "XATA"}:
                if tag == "DATB":
                    if cursor + 4 > metadata_end:
                        parse_error = "truncated_datb_length"
                        break
                    length = read_u32le(metadata_bytes, cursor)
                    cursor += 4
                else:
                    if cursor + 2 > metadata_end:
                        parse_error = f"truncated_{tag.lower()}_length"
                        break
                    length = read_u16le(metadata_bytes, cursor)
                    cursor += 2
                field = {"tag": tag, "length": length}
                external_payloads.append(field)
                record["fields"].append(field)
            else:
                record["fields"].append(
                    {
                        "tag": tag,
                        "unparsed_offset": offset + 6 + cursor,
                        "remaining_hex": to_hex(metadata_bytes[cursor : cursor + 48], 48),
                    }
                )
                parse_error = f"unknown_tag:{tag}"
                break

        payload_shortfall = False
        external_results = []
        for payload in external_payloads:
            length = payload["length"]
            payload_offset = stream.tell()
            preview = stream.peek(min(32, length))
            skipped = stream.skip(length)
            if skipped < length:
                payload_shortfall = True
            parsed = {
                "tag": payload["tag"],
                "length": length,
                "preview_hex": to_hex(preview, min(32, len(preview))),
                "payload_offset": payload_offset,
            }
            if payload["tag"] in {"DATA", "DATB"}:
                record["data_length"] = length
                parsed["strings_sample"] = extract_strings(preview, minimum=4, limit=5)
            external_results.append(parsed)

        if external_results:
            record["external_payloads"] = external_results

        record["parsed_length"] = stream.tell() - offset
        record["metadata_length"] = declared_length
        record["next_record_offset"] = stream.tell()
        record["verdict"] = "exact"

        if payload_shortfall:
            record["verdict"] = "payload_shortfall"
        elif parse_error is not None:
            record["verdict"] = "descriptor_mismatch"
            record["parse_error"] = parse_error
        else:
            next_magic = stream.peek(4)
            if next_magic and len(next_magic) == 4 and next_magic != b"YAA1":
                record["verdict"] = "next_record_desync"
                record["next_magic_hex"] = next_magic.hex()
            elif record["parsed_length"] > record["declared_length"]:
                record["verdict"] = "metadata_overrun"

        records.append(record)
        if record["verdict"] in {"descriptor_mismatch", "payload_shortfall", "next_record_desync"}:
            break

    return records


def classify_tag_semantics(tag: str) -> str:
    if tag in SEMANTICALLY_VALIDATED_TAGS:
        return "semantically_validated"
    if tag in STRUCTURALLY_UNDERSTOOD_TAGS:
        return "structurally_understood"
    if tag in SYNTACTICALLY_PARSED_TAGS:
        return "syntactically_parsed"
    return "unknown"


def summarize_yaa_records(
    records: list[dict],
    coverage_bytes: int,
    record_limit: int | None = None,
    start_offset: int = 0,
    region_size_bytes: int = DEFAULT_REGION_SIZE_BYTES,
) -> dict:
    tag_counts = Counter()
    object_kind_counts = Counter()
    payload_bearing = 0
    xattr_bearing = 0
    unknown_tags = Counter()
    verdict_counts = Counter()
    tag_first_seen_offsets = {}
    family_first_seen_offsets = {}
    first_unexpected_tag_family = None
    cumulative_skipped_payload_bytes = 0
    largest_payload_descriptor = None
    region_record_class_frequencies = {}
    first_offset = records[0]["offset"] if records else None
    last_offset = records[-1]["offset"] if records else None
    last_next_offset = records[-1]["next_record_offset"] if records else None
    witnesses = []
    first_breach = None

    for record in records:
        object_kind_counts[record.get("type_code", "?")] += 1
        verdict_counts[record.get("verdict", "unknown")] += 1
        if record.get("external_payloads"):
            payload_bearing += 1
        if record.get("xattrs"):
            xattr_bearing += 1

        region_index = (
            record["offset"] // region_size_bytes if region_size_bytes > 0 else 0
        )
        region_start = region_index * region_size_bytes
        region_end = region_start + region_size_bytes - 1
        region_key = f"{region_start}-{region_end}"
        region_bucket = region_record_class_frequencies.setdefault(
            region_key,
            {
                "record_count": 0,
                "object_kind_counts": {},
                "payload_bearing_records": 0,
                "xattr_bearing_records": 0,
            },
        )
        region_bucket["record_count"] += 1
        kind = record.get("type_code", "?")
        region_bucket["object_kind_counts"][kind] = (
            region_bucket["object_kind_counts"].get(kind, 0) + 1
        )
        if record.get("external_payloads"):
            region_bucket["payload_bearing_records"] += 1
        if record.get("xattrs"):
            region_bucket["xattr_bearing_records"] += 1

        if first_breach is None and record.get("verdict") in {
            "descriptor_mismatch",
            "payload_shortfall",
            "next_record_desync",
        }:
            first_breach = {
                "offset": record.get("offset"),
                "path": record.get("path"),
                "type_code": record.get("type_code"),
                "verdict": record.get("verdict"),
                "parse_error": record.get("parse_error"),
                "next_magic_hex": record.get("next_magic_hex"),
            }

        for field in record.get("fields", []):
            tag = field["tag"]
            tag_counts[tag] += 1
            tag_first_seen_offsets.setdefault(tag, record["offset"])
            family = tag_family(tag)
            family_first_seen_offsets.setdefault(family, record["offset"])
            if (
                first_unexpected_tag_family is None
                and family not in KNOWN_TAG_FAMILIES
            ):
                first_unexpected_tag_family = {
                    "family": family,
                    "tag": tag,
                    "offset": record["offset"],
                    "path": record.get("path"),
                }
            if "unparsed_offset" in field:
                unknown_tags[tag] += 1

        for payload in record.get("external_payloads", []):
            length = payload.get("length", 0) or 0
            cumulative_skipped_payload_bytes += length
            if (
                largest_payload_descriptor is None
                or length > largest_payload_descriptor["length"]
            ):
                largest_payload_descriptor = {
                    "tag": payload.get("tag"),
                    "length": length,
                    "payload_offset": payload.get("payload_offset"),
                    "record_offset": record.get("offset"),
                    "path": record.get("path"),
                    "type_code": record.get("type_code"),
                }

        witnesses.append(
            {
                "offset": record["offset"],
                "next_record_offset": record.get("next_record_offset"),
                "path": record.get("path"),
                "type_code": record.get("type_code"),
                "verdict": record.get("verdict"),
                "metadata_length": record.get("metadata_length"),
                "declared_length": record.get("declared_length"),
                "payload_descriptors": [
                    {
                        "tag": payload["tag"],
                        "payload_offset": payload.get("payload_offset"),
                        "length": payload["length"],
                        "sha256_16": payload.get("sha256_16"),
                        "preview_hex": payload.get("preview_hex"),
                    }
                    for payload in record.get("external_payloads", [])
                ],
                "xattr_names": [xattr.get("name") for xattr in record.get("xattrs", []) if xattr.get("name")],
            }
        )

    semantic_confidence = {}
    for tag, count in sorted(tag_counts.items()):
        semantic_confidence[tag] = {
            "count": count,
            "classification": classify_tag_semantics(tag),
        }

    return {
        "coverage_window_tested_bytes": coverage_bytes,
        "parse_start_offset": start_offset,
        "record_count": len(records),
        "record_limit": record_limit,
        "record_limit_reached": record_limit is not None and len(records) >= record_limit,
        "unknown_tag_count": sum(unknown_tags.values()),
        "unknown_tag_table": dict(sorted(unknown_tags.items())),
        "object_kind_counts": dict(sorted(object_kind_counts.items())),
        "payload_bearing_record_count": payload_bearing,
        "xattr_bearing_record_count": xattr_bearing,
        "cumulative_skipped_payload_bytes": cumulative_skipped_payload_bytes,
        "largest_payload_descriptor": largest_payload_descriptor,
        "first_successful_offset": first_offset,
        "last_successful_offset": last_offset,
        "last_next_record_offset": last_next_offset,
        "verdict_counts": dict(sorted(verdict_counts.items())),
        "first_breach": first_breach,
        "region_size_bytes": region_size_bytes,
        "region_record_class_frequencies": region_record_class_frequencies,
        "tag_frequency_table": dict(sorted(tag_counts.items())),
        "tag_first_seen_offsets": dict(sorted(tag_first_seen_offsets.items())),
        "tag_family_first_seen_offsets": dict(sorted(family_first_seen_offsets.items())),
        "first_unexpected_tag_family": first_unexpected_tag_family,
        "semantic_confidence_by_tag": semantic_confidence,
        "witnesses": witnesses,
    }


def write_witness_exports(summary: dict, jsonl_path: pathlib.Path, tsv_path: pathlib.Path) -> None:
    witnesses = summary.get("witnesses", [])

    with jsonl_path.open("w", encoding="utf-8") as handle:
        for witness in witnesses:
            handle.write(json.dumps(witness, sort_keys=True) + "\n")

    with tsv_path.open("w", encoding="utf-8") as handle:
        handle.write(
            "\t".join(
                [
                    "offset",
                    "next_record_offset",
                    "type_code",
                    "verdict",
                    "path",
                    "declared_length",
                    "metadata_length",
                    "payload_count",
                    "payload_tags",
                    "payload_offsets",
                    "payload_lengths",
                    "payload_hashes",
                    "xattr_names",
                ]
            )
            + "\n"
        )
        for witness in witnesses:
            payloads = witness.get("payload_descriptors", [])
            handle.write(
                "\t".join(
                    [
                        str(witness.get("offset", "")),
                        str(witness.get("next_record_offset", "")),
                        str(witness.get("type_code", "")),
                        str(witness.get("verdict", "")),
                        str(witness.get("path", "")),
                        str(witness.get("declared_length", "")),
                        str(witness.get("metadata_length", "")),
                        str(len(payloads)),
                        ",".join(str(payload.get("tag", "")) for payload in payloads),
                        ",".join(str(payload.get("payload_offset", "")) for payload in payloads),
                        ",".join(str(payload.get("length", "")) for payload in payloads),
                        ",".join(str(payload.get("sha256_16", "")) for payload in payloads),
                        ",".join(str(name) for name in witness.get("xattr_names", [])),
                    ]
                )
                + "\n"
            )


def compact_yaa_summary(summary: dict) -> dict:
    return {
        "coverage_window_tested_bytes": summary.get("coverage_window_tested_bytes"),
        "parse_start_offset": summary.get("parse_start_offset"),
        "record_count": summary.get("record_count"),
        "record_limit": summary.get("record_limit"),
        "record_limit_reached": summary.get("record_limit_reached"),
        "unknown_tag_count": summary.get("unknown_tag_count"),
        "object_kind_counts": summary.get("object_kind_counts"),
        "payload_bearing_record_count": summary.get("payload_bearing_record_count"),
        "xattr_bearing_record_count": summary.get("xattr_bearing_record_count"),
        "cumulative_skipped_payload_bytes": summary.get("cumulative_skipped_payload_bytes"),
        "largest_payload_descriptor": summary.get("largest_payload_descriptor"),
        "first_successful_offset": summary.get("first_successful_offset"),
        "last_successful_offset": summary.get("last_successful_offset"),
        "last_next_record_offset": summary.get("last_next_record_offset"),
        "verdict_counts": summary.get("verdict_counts"),
        "first_breach": summary.get("first_breach"),
        "region_size_bytes": summary.get("region_size_bytes"),
        "region_record_class_frequencies": summary.get("region_record_class_frequencies"),
        "tag_frequency_table": summary.get("tag_frequency_table"),
        "tag_family_first_seen_offsets": summary.get("tag_family_first_seen_offsets"),
        "first_unexpected_tag_family": summary.get("first_unexpected_tag_family"),
        "semantic_confidence_by_tag": summary.get("semantic_confidence_by_tag"),
    }


def load_resume_offset(report_path: pathlib.Path) -> int:
    report = json.loads(report_path.read_text(encoding="utf-8"))

    descriptor_walk = report.get("descriptor_walk")
    if isinstance(descriptor_walk, dict):
        yaa_summary = descriptor_walk.get("yaa_summary")
        if isinstance(yaa_summary, dict):
            offset = yaa_summary.get("last_next_record_offset")
            if isinstance(offset, int):
                return offset

    decoded_stream_prefix = report.get("decoded_stream_prefix")
    if isinstance(decoded_stream_prefix, dict):
        yaa_summary = decoded_stream_prefix.get("yaa_summary")
        if isinstance(yaa_summary, dict):
            offset = yaa_summary.get("last_next_record_offset")
            if isinstance(offset, int):
                return offset

    breach_search = report.get("breach_search")
    if isinstance(breach_search, dict):
        last_summary = breach_search.get("last_summary")
        if isinstance(last_summary, dict):
            offset = last_summary.get("last_next_record_offset")
            if isinstance(offset, int):
                return offset

    raise RuntimeError(
        f"could not find a resumable last_next_record_offset in report: {report_path}"
    )


def find_first_breach(
    source: ArtifactSource,
    ordered: list[dict],
    step_bytes: int,
    max_bytes: int,
    record_limit: int,
    cache_path: pathlib.Path | None = None,
    start_offset: int = 0,
) -> dict:
    if step_bytes <= 0:
        raise RuntimeError("--breach-step-bytes must be greater than zero")
    if max_bytes < step_bytes:
        raise RuntimeError("--breach-max-bytes must be greater than or equal to --breach-step-bytes")
    if record_limit <= 0:
        raise RuntimeError("--breach-records-per-window must be greater than zero")

    history = []
    first_breach = None
    last_summary = None

    window_bytes = step_bytes
    while window_bytes <= max_bytes:
        prefix_info = inspect_decoded_stream_prefix(
            source,
            ordered,
            prefix_bytes=window_bytes,
            output_path=cache_path,
        )
        if cache_path is not None and cache_path.exists():
            with cache_path.open("rb") as handle:
                prefix = handle.read(window_bytes)
        else:
            prefix = b""
        records = parse_yaa_records(prefix, limit=record_limit, start_offset=start_offset)
        summary = summarize_yaa_records(
            records,
            coverage_bytes=len(prefix),
            record_limit=record_limit,
            start_offset=start_offset,
            region_size_bytes=DEFAULT_REGION_SIZE_BYTES,
        )
        compact = compact_yaa_summary(summary)
        compact["cache_hit"] = prefix_info.get("cache_hit")
        compact["cache_extended"] = prefix_info.get("cache_extended")
        history.append(compact)
        last_summary = compact

        if compact.get("first_breach") is not None:
            first_breach = {
                "window_bytes": window_bytes,
                "summary": compact,
            }
            break

        window_bytes += step_bytes

    return {
        "step_bytes": step_bytes,
        "max_bytes": max_bytes,
        "record_limit": record_limit,
        "windows_tested": len(history),
        "history": history,
        "first_breach_window": first_breach,
        "completed_without_breach": first_breach is None,
        "last_summary": last_summary,
    }


def materialize_prefix_tree(records: list[dict], root: pathlib.Path) -> dict:
    root.mkdir(parents=True, exist_ok=True)
    metadata_rows = []
    created_directories = 0
    created_files = 0

    for record in records:
        path = record.get("path")
        if path in (None, ""):
            continue

        target = root / path
        if record.get("type_code") == "D":
            target.mkdir(parents=True, exist_ok=True)
            created_directories += 1
        elif record.get("type_code") == "F":
            target.parent.mkdir(parents=True, exist_ok=True)
            data_payload = next(
                (payload for payload in record.get("external_payloads", []) if payload.get("tag") == "DATA"),
                None,
            )
            if data_payload is not None:
                blob = data_payload.get("_blob", b"")
                if len(blob) != data_payload.get("length", 0):
                    continue
                target.write_bytes(blob)
                created_files += 1

        metadata_rows.append(
            {
                "path": path,
                "type_code": record.get("type_code"),
                "offset": record.get("offset"),
                "next_record_offset": record.get("next_record_offset"),
                "declared_length": record.get("declared_length"),
                "metadata_length": record.get("metadata_length"),
                "xattrs": record.get("xattrs", []),
                "payloads": record.get("external_payloads", []),
            }
        )

    metadata_path = root / "_yaa_prefix_metadata.jsonl"
    with metadata_path.open("w", encoding="utf-8") as handle:
        for row in metadata_rows:
            handle.write(json.dumps(json_safe(row), sort_keys=True) + "\n")

    return {
        "root": str(root),
        "created_directories": created_directories,
        "created_files": created_files,
        "metadata_path": str(metadata_path),
    }


def hypotheses(control_report: dict, payloads: list[dict], runtime_artifacts: dict) -> list[str]:
    notes: list[str] = []
    if payloads:
        notes.append(
            "Shard order is explicit in payload_chunks.txt and runs sequentially from "
            f"{payloads[0]['index']} to {payloads[-1]['index']}."
        )
        notes.append(
            "Every payload.* sample starts as pbzx, so direct byte concatenation of the compressed files is unlikely to produce a bootable image without an unwrap step."
        )

    x86_patch = runtime_artifacts.get("payloadv2/basesystem_patches/x86_64BaseSystem.dmg")
    if x86_patch and x86_patch.get("present"):
        notes.append(
            "The x86_64 BaseSystem candidate starts with BXDIFF50 and also contains pbzx, which identifies it as a patch artifact rather than a directly stageable DMG."
        )

    restore_chunklist = runtime_artifacts.get("Restore/BaseSystem.chunklist")
    trustcache = runtime_artifacts.get("boot/Firmware/BaseSystem.dmg.x86.trustcache")
    if restore_chunklist and restore_chunklist.get("present") and trustcache and trustcache.get("present"):
        notes.append(
            "BaseSystem integrity metadata exists outside payloadv2, which supports a reconstruction model of canonical image + patch layer + trust metadata."
        )

    fixup = control_report.get("payloadv2/fixup.manifest", {})
    if fixup.get("present") and fixup.get("decoded_size"):
        notes.append(
            "fixup.manifest expands from pbzx into a large binary metadata stream, so it likely drives content mapping rather than serving as a plain-text manifest."
        )

    links = control_report.get("payloadv2/links.txt", {})
    if links.get("present"):
        notes.append(
            "links.txt is plain text and appears to encode source/target path pairs, which suggests the reconstructed image is built as a filesystem tree rather than a simple monolithic blob."
        )

    return notes


def print_summary(report: dict) -> None:
    print("payloadv2 analysis")
    print()
    print("Control files")
    for name, info in report["control_files"].items():
        status = "present" if info.get("present") else "missing"
        print(f"- {name}: {status}")
        if not info.get("present"):
            continue
        extra = info.get("magic")
        if info.get("decoded_size") is not None:
            extra += f", decoded={info['decoded_size']} bytes"
        print(f"  type: {extra}")

    print()
    print("Ordered payload shards")
    for payload in report["ordered_payloads"][:8]:
        print(
            f"- {payload['payload_path']}: target={payload['target_size']} actual={payload['payload_size']} ecc={payload['ecc_size']}"
        )
    if len(report["ordered_payloads"]) > 8:
        print(f"- ... {len(report['ordered_payloads']) - 8} more shards")

    payload_decode = report.get("payload_decode", {})
    if payload_decode.get("enabled"):
        print()
        print("Decoded payload summaries")
        print(
            "- decoded entries: "
            f"{payload_decode['decoded_count']} "
            f"(matches target: {payload_decode['matching_target_count']}, "
            f"mismatches: {payload_decode['mismatching_target_count']})"
        )
        for entry in payload_decode["entries"][:8]:
            print(
                f"  - {entry['path']}: decoded={entry.get('decoded_size')} "
                f"target={entry['target_size']} "
                f"match={entry.get('matches_target_size')}"
            )
        if len(payload_decode["entries"]) > 8:
            print(f"  - ... {len(payload_decode['entries']) - 8} more decoded entries")

    print()
    print("Runtime artifacts")
    for name, info in report["runtime_artifacts"].items():
        status = "present" if info.get("present") else "missing"
        line = f"- {name}: {status}"
        if info.get("present"):
            line += f", magic={info.get('magic')}, size={info.get('size')}"
        print(line)

    print()
    print("Hypotheses")
    for note in report["hypotheses"]:
        print(f"- {note}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Inventory Apple's payloadv2 shard layout and emit an ordered reconstruction report."
    )
    parser.add_argument(
        "input_path",
        type=pathlib.Path,
        help="path to a MobileAsset zip, an AssetData directory, or a directory containing AssetData",
    )
    parser.add_argument(
        "--json-out",
        type=pathlib.Path,
        default=pathlib.Path("payloadv2-report.json"),
        help="where to write the machine-readable report (default: payloadv2-report.json)",
    )
    parser.add_argument(
        "--ordered-out",
        type=pathlib.Path,
        default=pathlib.Path("payloadv2-ordered.txt"),
        help="where to write the ordered shard table (default: payloadv2-ordered.txt)",
    )
    parser.add_argument(
        "--decode-payloads",
        action="store_true",
        help="unwrap payload.* pbzx streams and compare decoded sizes to payload_chunks.txt",
    )
    parser.add_argument(
        "--decode-limit",
        type=int,
        default=None,
        help="limit how many payload.* files to decode when --decode-payloads is enabled",
    )
    parser.add_argument(
        "--decoded-prefix-bytes",
        type=int,
        default=0,
        help="capture the first N bytes of the ordered pbzx-decoded payload stream",
    )
    parser.add_argument(
        "--decoded-prefix-out",
        type=pathlib.Path,
        default=pathlib.Path("payloadv2-decoded-prefix.bin"),
        help="where to write the decoded stream prefix when --decoded-prefix-bytes is used",
    )
    parser.add_argument(
        "--parse-yaa-records",
        type=int,
        default=0,
        help="parse the first N YAA records from the decoded stream prefix",
    )
    parser.add_argument(
        "--parse-start-offset",
        type=int,
        default=0,
        help="resume YAA parsing from this byte offset inside the cached decoded prefix",
    )
    parser.add_argument(
        "--resume-from-report",
        type=pathlib.Path,
        default=None,
        help="load parse-start-offset from a prior JSON report's last_next_record_offset",
    )
    parser.add_argument(
        "--witness-jsonl-out",
        type=pathlib.Path,
        default=pathlib.Path("payloadv2-witnesses.jsonl"),
        help="where to write per-record witnesses as JSONL when YAA parsing is enabled",
    )
    parser.add_argument(
        "--witness-tsv-out",
        type=pathlib.Path,
        default=pathlib.Path("payloadv2-witnesses.tsv"),
        help="where to write per-record witnesses as TSV when YAA parsing is enabled",
    )
    parser.add_argument(
        "--materialize-prefix-root",
        type=pathlib.Path,
        default=None,
        help="optionally reconstruct parsed prefix records into a filesystem tree at this path",
    )
    parser.add_argument(
        "--descriptor-walk-records",
        type=int,
        default=0,
        help="walk YAA records directly from the decoded source stream without caching payload blobs",
    )
    parser.add_argument(
        "--find-first-breach",
        action="store_true",
        help="iteratively expand the decoded prefix window until the first real parser breach is found",
    )
    parser.add_argument(
        "--breach-step-bytes",
        type=int,
        default=32 * 1024 * 1024,
        help="window size increment for --find-first-breach (default: 32 MiB)",
    )
    parser.add_argument(
        "--breach-max-bytes",
        type=int,
        default=256 * 1024 * 1024,
        help="maximum decoded prefix window for --find-first-breach (default: 256 MiB)",
    )
    parser.add_argument(
        "--breach-records-per-window",
        type=int,
        default=50000,
        help="maximum YAA records to parse in each frontier-search window (default: 50000)",
    )
    parser.add_argument(
        "--breach-cache-prefix",
        type=pathlib.Path,
        default=None,
        help="cache file for decoded prefix bytes reused across frontier-search windows",
    )
    parser.add_argument(
        "--region-size-bytes",
        type=int,
        default=DEFAULT_REGION_SIZE_BYTES,
        help="byte width for region-level structural frequency summaries (default: 64 MiB)",
    )
    args = parser.parse_args()

    if args.resume_from_report is not None:
        args.parse_start_offset = load_resume_offset(args.resume_from_report)

    source = resolve_source(args.input_path)
    control = inspect_control_files(source)

    payload_chunks_text = source.read_all("payloadv2/payload_chunks.txt").decode("utf-8", errors="replace")
    payload_chunks = parse_payload_chunks(payload_chunks_text)
    ordered = ordered_payloads(source, payload_chunks)
    payload_decode = enrich_payload_decodes(
        source,
        ordered,
        decode_payloads=args.decode_payloads,
        limit=args.decode_limit,
    )
    decoded_stream_prefix = None
    descriptor_walk = None
    if args.decoded_prefix_bytes > 0:
        decoded_stream_prefix = inspect_decoded_stream_prefix(
            source,
            ordered,
            prefix_bytes=args.decoded_prefix_bytes,
            output_path=args.decoded_prefix_out,
        )
        if args.parse_yaa_records > 0:
            prefix_bytes = args.decoded_prefix_out.read_bytes()
            decoded_stream_prefix["yaa_records"] = parse_yaa_records(
                prefix_bytes,
                limit=args.parse_yaa_records,
                start_offset=args.parse_start_offset,
            )
            decoded_stream_prefix["yaa_summary"] = summarize_yaa_records(
                decoded_stream_prefix["yaa_records"],
                coverage_bytes=len(prefix_bytes),
                record_limit=args.parse_yaa_records,
                start_offset=args.parse_start_offset,
                region_size_bytes=args.region_size_bytes,
            )
            write_witness_exports(
                decoded_stream_prefix["yaa_summary"],
                args.witness_jsonl_out,
                args.witness_tsv_out,
            )
            decoded_stream_prefix["witness_outputs"] = {
                "jsonl": str(args.witness_jsonl_out),
                "tsv": str(args.witness_tsv_out),
            }
            if args.materialize_prefix_root is not None:
                decoded_stream_prefix["materialized_prefix_tree"] = materialize_prefix_tree(
                    decoded_stream_prefix["yaa_records"],
                    args.materialize_prefix_root,
                )
    if args.descriptor_walk_records > 0:
        descriptor_records = parse_yaa_records_stream(
            source,
            ordered,
            limit=args.descriptor_walk_records,
            start_offset=args.parse_start_offset,
        )
        descriptor_walk = {
            "yaa_records": descriptor_records,
            "yaa_summary": summarize_yaa_records(
                descriptor_records,
                coverage_bytes=0,
                record_limit=args.descriptor_walk_records,
                start_offset=args.parse_start_offset,
                region_size_bytes=args.region_size_bytes,
            ),
        }
        write_witness_exports(
            descriptor_walk["yaa_summary"],
            args.witness_jsonl_out,
            args.witness_tsv_out,
        )
        descriptor_walk["witness_outputs"] = {
            "jsonl": str(args.witness_jsonl_out),
            "tsv": str(args.witness_tsv_out),
        }
    breach_search = None
    if args.find_first_breach:
        breach_search = find_first_breach(
            source,
            ordered,
            step_bytes=args.breach_step_bytes,
            max_bytes=args.breach_max_bytes,
            record_limit=args.breach_records_per_window,
            cache_path=args.breach_cache_prefix,
            start_offset=args.parse_start_offset,
        )

    links_text = source.read_all("payloadv2/links.txt").decode("utf-8", errors="replace")
    control["payloadv2/links.txt"]["link_summary"] = parse_links(links_text)

    runtime = inspect_related_runtime_artifacts(source)

    report = {
        "input_path": str(args.input_path),
        "control_files": control,
        "ordered_payloads": ordered,
        "payload_decode": payload_decode,
        "decoded_stream_prefix": decoded_stream_prefix,
        "descriptor_walk": descriptor_walk,
        "breach_search": breach_search,
        "runtime_artifacts": runtime,
        "hypotheses": hypotheses(control, ordered, runtime),
    }

    args.json_out.write_text(json.dumps(json_safe(report), indent=2))
    with args.ordered_out.open("w", encoding="utf-8") as handle:
        for entry in ordered:
            handle.write(
                f"{entry['index']:02d}\t{entry['payload_path']}\t"
                f"target={entry['target_size']}\tactual={entry['payload_size']}\t"
                f"ecc={entry['ecc_size']}\n"
            )

    print_summary(report)
    if decoded_stream_prefix is not None:
        print()
        print("Decoded stream prefix")
        print(
            f"- captured {decoded_stream_prefix['captured_prefix_bytes']} bytes "
            f"from {len(decoded_stream_prefix['shards_used'])} shard(s)"
        )
        print(f"- prefix magic: {decoded_stream_prefix['prefix_magic']}")
        for key, value in decoded_stream_prefix["signatures"].items():
            print(f"  - {key}: {value}")
        print(f"- wrote prefix to {decoded_stream_prefix['output_path']}")
        print(
            f"- cache status: hit={decoded_stream_prefix['cache_hit']} "
            f"extended={decoded_stream_prefix['cache_extended']} "
            f"cached_prefix_bytes={decoded_stream_prefix['cached_prefix_bytes']}"
        )
        yaa_records = decoded_stream_prefix.get("yaa_records", [])
        if yaa_records:
            print("- parsed YAA records:")
            for record in yaa_records:
                kind = record.get("type_code", "?")
                path = record.get("path", "")
                print(
                    f"  - offset={record['offset']} "
                    f"type={kind} path={path!r} "
                    f"parsed={record['parsed_length']} declared={record['declared_length']}"
                )
        yaa_summary = decoded_stream_prefix.get("yaa_summary")
        if yaa_summary:
            print("- parser state:")
            print(
                f"  - coverage window: {yaa_summary['coverage_window_tested_bytes']} bytes"
            )
            print(f"  - parse start offset: {yaa_summary['parse_start_offset']}")
            print(f"  - record count: {yaa_summary['record_count']}")
            print(f"  - record limit reached: {yaa_summary['record_limit_reached']}")
            print(f"  - unknown tag count: {yaa_summary['unknown_tag_count']}")
            print(
                "  - object kinds: "
                + ", ".join(f"{k}={v}" for k, v in yaa_summary["object_kind_counts"].items())
            )
            print(
                "  - verdicts: "
                + ", ".join(f"{k}={v}" for k, v in yaa_summary["verdict_counts"].items())
            )
            print(
                f"  - payload-bearing records: {yaa_summary['payload_bearing_record_count']}"
            )
            print(
                f"  - xattr-bearing records: {yaa_summary['xattr_bearing_record_count']}"
            )
            print(
                f"  - cumulative skipped payload bytes: "
                f"{yaa_summary['cumulative_skipped_payload_bytes']}"
            )
            largest = yaa_summary.get("largest_payload_descriptor")
            if largest:
                print(
                    "  - largest payload descriptor: "
                    f"{largest['length']} bytes at offset={largest['record_offset']} "
                    f"path={largest.get('path')!r}"
                )
            print(
                f"  - first/last offsets: {yaa_summary['first_successful_offset']} -> "
                f"{yaa_summary['last_next_record_offset']}"
            )
            unexpected_family = yaa_summary.get("first_unexpected_tag_family")
            if unexpected_family:
                print(
                    "  - first unexpected tag family: "
                    f"{unexpected_family['family']} via {unexpected_family['tag']} "
                    f"at offset={unexpected_family['offset']}"
                )
            first_breach = yaa_summary.get("first_breach")
            if first_breach:
                print(
                    f"  - first breach: offset={first_breach['offset']} "
                    f"verdict={first_breach['verdict']} path={first_breach.get('path')!r}"
                )
            else:
                print("  - first breach: none in tested coverage window")
        witness_outputs = decoded_stream_prefix.get("witness_outputs")
        if witness_outputs:
            print(
                f"  - wrote witnesses: {witness_outputs['jsonl']}, {witness_outputs['tsv']}"
            )
        materialized = decoded_stream_prefix.get("materialized_prefix_tree")
        if materialized:
            print("- materialized prefix tree:")
            print(f"  - root: {materialized['root']}")
            print(f"  - created directories: {materialized['created_directories']}")
            print(f"  - created files: {materialized['created_files']}")
            print(f"  - metadata: {materialized['metadata_path']}")
    if descriptor_walk is not None:
        print()
        print("Descriptor walk")
        yaa_summary = descriptor_walk["yaa_summary"]
        print(f"- parse start offset: {yaa_summary['parse_start_offset']}")
        print(f"- record count: {yaa_summary['record_count']}")
        print(f"- record limit reached: {yaa_summary['record_limit_reached']}")
        print(f"- unknown tag count: {yaa_summary['unknown_tag_count']}")
        print(
            "  - object kinds: "
            + ", ".join(f"{k}={v}" for k, v in yaa_summary["object_kind_counts"].items())
        )
        print(
            "  - verdicts: "
            + ", ".join(f"{k}={v}" for k, v in yaa_summary["verdict_counts"].items())
        )
        print(
            f"  - cumulative skipped payload bytes: "
            f"{yaa_summary['cumulative_skipped_payload_bytes']}"
        )
        largest = yaa_summary.get("largest_payload_descriptor")
        if largest:
            print(
                "  - largest payload descriptor: "
                f"{largest['length']} bytes at offset={largest['record_offset']} "
                f"path={largest.get('path')!r}"
            )
        print(
            f"  - first/last offsets: {yaa_summary['first_successful_offset']} -> "
            f"{yaa_summary['last_next_record_offset']}"
        )
        unexpected_family = yaa_summary.get("first_unexpected_tag_family")
        if unexpected_family:
            print(
                "  - first unexpected tag family: "
                f"{unexpected_family['family']} via {unexpected_family['tag']} "
                f"at offset={unexpected_family['offset']}"
            )
        first_breach = yaa_summary.get("first_breach")
        if first_breach:
            print(
                f"  - first breach: offset={first_breach['offset']} "
                f"verdict={first_breach['verdict']} path={first_breach.get('path')!r}"
            )
        else:
            print("  - first breach: none in walked records")
        witness_outputs = descriptor_walk.get("witness_outputs")
        if witness_outputs:
            print(
                f"  - wrote witnesses: {witness_outputs['jsonl']}, {witness_outputs['tsv']}"
            )
    if breach_search is not None:
        print()
        print("Breach search")
        print(f"- windows tested: {breach_search['windows_tested']}")
        print(
            f"- step/max bytes: {breach_search['step_bytes']} / {breach_search['max_bytes']}"
        )
        print(f"- record limit per window: {breach_search['record_limit']}")
        for window in breach_search["history"]:
            print(
                "  - window="
                f"{window['coverage_window_tested_bytes']} "
                f"start={window['parse_start_offset']} "
                f"records={window['record_count']} "
                f"limit_reached={window['record_limit_reached']} "
                f"cache_hit={window['cache_hit']} "
                f"cache_extended={window['cache_extended']} "
                "verdicts="
                + ",".join(f"{k}={v}" for k, v in window["verdict_counts"].items())
            )
        first_breach_window = breach_search.get("first_breach_window")
        if first_breach_window is None:
            print("- first breach: none up to tested maximum")
        else:
            first_breach = first_breach_window["summary"]["first_breach"]
            print(
                f"- first breach window: {first_breach_window['window_bytes']} bytes"
            )
            print(
                f"  offset={first_breach['offset']} "
                f"verdict={first_breach['verdict']} "
                f"path={first_breach.get('path')!r}"
            )
    print()
    print(f"wrote {args.json_out}")
    print(f"wrote {args.ordered_out}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except subprocess.CalledProcessError as error:
        print(f"command failed: {error}", file=sys.stderr)
        raise SystemExit(1)
    except RuntimeError as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(1)
