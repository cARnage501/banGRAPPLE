#!/usr/bin/env python3
"""
Small repo-local task runner for one-off workflow commands.

This exists to avoid brittle heredoc commands in chat. Add focused subcommands
here as needed, then invoke them as a single shell command.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import subprocess
import sys


REPO_ROOT = pathlib.Path(__file__).resolve().parent
PAYLOADV2_PROBE = REPO_ROOT / "scripts" / "payloadv2_probe.py"
DEFAULT_ZIP_PATH = (
    "/tmp/ssroot/Shared Support/com_apple_MobileAsset_MacSoftwareUpdate/"
    "97a386b5182904411d3cf455febfcf86757eb2cd.zip"
)


def continue_descriptor_walk(args: argparse.Namespace) -> int:
    prev = pathlib.Path(args.resume_from_report)

    for index in range(args.start_index, args.end_index + 1):
        out = pathlib.Path(f"/tmp/payloadv2-descriptor-map-{index:02d}.json")
        txt = pathlib.Path(f"/tmp/payloadv2-descriptor-map-{index:02d}.txt")
        log = pathlib.Path(f"/tmp/payloadv2-descriptor-map-{index:02d}.log")

        cmd = [
            "python3",
            str(PAYLOADV2_PROBE),
            args.zip_path,
            "--descriptor-walk-records",
            str(args.records_per_pass),
            "--resume-from-report",
            str(prev),
            "--json-out",
            str(out),
            "--ordered-out",
            str(txt),
        ]

        with log.open("w", encoding="utf-8") as handle:
            subprocess.run(
                cmd,
                cwd=REPO_ROOT,
                stdout=handle,
                stderr=subprocess.STDOUT,
                check=True,
            )

        report = json.loads(out.read_text(encoding="utf-8"))
        summary = report["descriptor_walk"]["yaa_summary"]

        print(f"pass={index}")
        print(f"  start={summary['parse_start_offset']}")
        print(f"  records={summary['record_count']}")
        print(f"  limit_reached={summary['record_limit_reached']}")
        print(f"  last_next={summary['last_next_record_offset']}")
        print(f"  skipped_bytes={summary['cumulative_skipped_payload_bytes']}")
        print(f"  largest={summary['largest_payload_descriptor']}")
        print(f"  first_breach={summary['first_breach']}")
        print(f"  first_unexpected_tag_family={summary['first_unexpected_tag_family']}")
        print()

        prev = out

        if summary["first_breach"] is not None:
            break
        if not summary["record_limit_reached"]:
            break

    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Repo-local helper commands.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    walk = subparsers.add_parser(
        "continue-descriptor-walk",
        help="continue the payloadv2 descriptor walk from a prior report",
    )
    walk.add_argument(
        "--zip-path",
        default=DEFAULT_ZIP_PATH,
        help="path to the MobileAsset zip",
    )
    walk.add_argument(
        "--resume-from-report",
        default="/tmp/payloadv2-descriptor-map-28.json",
        help="prior descriptor-walk JSON report",
    )
    walk.add_argument(
        "--start-index",
        type=int,
        default=29,
        help="first output pass index to write",
    )
    walk.add_argument(
        "--end-index",
        type=int,
        default=40,
        help="last output pass index to write",
    )
    walk.add_argument(
        "--records-per-pass",
        type=int,
        default=1500,
        help="descriptor-walk record limit for each pass",
    )
    walk.set_defaults(func=continue_descriptor_walk)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except subprocess.CalledProcessError as error:
        print(f"command failed: {error}", file=sys.stderr)
        raise SystemExit(1)
    except RuntimeError as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(1)
