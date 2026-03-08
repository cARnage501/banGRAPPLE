# Architecture Overview

`banGRAPPLE` is a Rust CLI for constructing macOS installer media and, later, full bootable macOS external disks from Linux. The repository is organized so the user interface stays separate from orchestration, and orchestration stays separate from system-facing modules.

For the reverse-engineering details behind Ventura-era `payloadv2`, YAA records, and streamed filesystem reconstruction, see [payloadv2-yaa.md](/home/tc/concepts/banGRAPPLE/docs/payloadv2-yaa.md).

## Dependency Flow

```text
main
  -> tui
  -> pipeline
  -> catalog + downloader + bootloader + disk + installer + image
```

This keeps the UI thin, centralizes workflow coordination, and makes the system modules easier to test independently.

## Module Map

- `src/main.rs`: command entry point and top-level argument handling
- `src/assets.rs`: canonical resolution of payload-root, `AssetData`, and `payloadv2` roots
- `src/catalog.rs`: release discovery interface, currently backed by curated placeholders
- `src/downloader.rs`: installer download planning, cache paths, and future retry/checksum behavior
- `src/bootloader.rs`: bootloader source resolution, pinned OpenCore policy, and EFI validation
- `src/basesystem.rs`: read-only inspection of the separate BaseSystem patch, chunklist, and trust metadata path
- `src/substrate.rs`: joined BaseSystem/runtime substrate inspection across stageable runtime, patch-backed BaseSystem, cryptex image patches, and optional manifest evidence
- `src/disk.rs`: Linux block-device inspection, transport inference, and safety verdicts
- `src/installer.rs`: BaseSystem and recovery layout planning for installer media
- `src/image.rs`: golden-image metadata, distribution hints, and full-system deployment planning
- `src/pipeline.rs`: mode-aware orchestration, stage ordering, and execution plans
- `src/tui.rs`: terminal rendering for releases, disks, and dry-run output
- `src/yaa.rs`: early Rust-side reader for Ventura-era YAA record parsing and payload descriptor mapping

## Execution Modes

`banGRAPPLE` should support two modes.

1. Installer media
- query Apple catalogs
- download installer payloads
- extract BaseSystem runtime
- partition the target disk
- populate EFI and recovery assets

2. Full system deployment
- resolve a versioned golden image
- partition the target disk
- write the image to disk
- expand the APFS container
- refresh boot metadata and first-boot state

The second mode should begin with image-based deployment. A synthetic offline macOS installation path can remain a later research track.

## Execution Phases

Each mode should be split into two phases.

1. Read-only planning
- discover releases
- inspect local disks
- resolve either package artifacts or a system image
- render the intended execution stages

2. Privileged execution
- partition the selected target
- write EFI, recovery, or full-system assets
- sync and verify outputs

This split keeps risky behavior behind a deliberate boundary and supports dry-run validation before any disk write happens.

## Distribution and Updates

Image distribution is the decision that will define how usable Phase 2 becomes. The recommended approach is a managed manifest format that separates image discovery from the binary itself.

Recommended properties:
- versioned manifest per macOS release
- checksum and provenance metadata for each image
- cache root under `~/.cache/ban-grapple/images/`
- the ability to invalidate and rebuild images as Apple updates ship

This model lets `banGRAPPLE` stay current without rebuilding the binary just to rotate URLs or checksums.

## Safety Model

Disk selection is deny-first. Internal devices are blocked, clearly external USB targets of sufficient size are allowed, and ambiguous transports stay in review-only status until their detection logic is proven reliable. This rule should remain stricter than the eventual UX until destructive paths are tested thoroughly.

## Near-Term Milestones

1. Implement live Apple catalog fetch and parse logic.
2. Add real package metadata and managed image manifest resolution.
3. Add privileged executors for partitioning, formatting, and deployment.
4. Introduce an interactive terminal selector and progress view.
5. Add integration tests around disk filtering, plan generation, and failure handling.


## Bootloader Resolution

Installer media is modeled as a hybrid bootloader policy. The preferred Phase 1 default is a user-supplied EFI tree, but the resolver also supports a pinned OpenCore download path.

Supported sources:
- `UserPath(PathBuf)`
- `OpenCoreRelease(String)`

The OpenCore path is pinned to an explicit release and verified against a configured SHA256 before extraction.
