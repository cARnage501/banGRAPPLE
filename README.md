# banGRAPPLE

Create a bootable macOS installer or a full external macOS system from Linux.

No Mac required.

`banGRAPPLE` is a Linux-native utility that automates the workflow commonly used by Hackintosh builders and Mac lab admins: fetch Apple installer payloads, reconstruct the recovery runtime, prepare an external disk, and eventually deploy either installer media or a bootable macOS system image.

## User Flow

```text
ban-grapple

select mode
select macOS version
select disk
confirm erase
build
```

The current scaffold is intentionally read-only. It plans workflows, resolves bootloader sources, and inspects disks safely, but it does not yet execute the full installer-media write path or full-system deployment.

Release discovery is cached under `~/.cache/ban-grapple/catalog/` and refreshes automatically once every 24 hours. Installer package metadata caches under `~/.cache/ban-grapple/installers/`, and resolved image manifests cache under `~/.cache/ban-grapple/images/`. Use `cargo run -- refresh-releases` to bypass the release cache manually, or add `--refresh-artifacts` to the plan commands to bypass artifact metadata caches.

## Modes

`banGRAPPLE` is designed around two execution modes.

1. Create installer disk
- build EFI and recovery media that boots into the macOS installer environment

2. Create full macOS installation
- deploy a golden image to an external disk so macOS can boot directly without showing the installer UI

Phase 2 should start with golden-image deployment, not synthetic offline installation. That keeps the first full-system implementation deterministic, fast, and maintainable.

## Architecture

The intended dependency flow is:

```text
main
  -> tui
  -> pipeline
  -> catalog + downloader + bootloader + disk + installer + image
```

Current modules:
- `src/catalog.rs`: live Apple release discovery and catalog caching
- `src/downloader.rs`: installer artifact planning and metadata caching
- `src/bootloader.rs`: user EFI validation and pinned OpenCore download with SHA256 verification
- `src/disk.rs`: Linux block-device inspection and safety classification
- `src/installer.rs`: installer-media runtime layout and target asset planning
- `src/image.rs`: full-system image distribution and deployment planning
- `src/pipeline.rs`: mode-aware execution orchestration and stage ordering
- `src/tui.rs`: terminal rendering helpers

## Distribution Strategy

The key architectural decision for Phase 2 is how full-system images are distributed and updated. The current scaffold assumes a managed manifest model:

- versioned image metadata lives under a predictable manifest path
- image blobs are cached under `~/.cache/ban-grapple/images/`
- the manifest controls image URLs, checksums, and rebuild provenance

This keeps updates explicit and allows image refreshes without hardcoding URLs into the binary. The current full-system resolver now follows `index -> channel -> image descriptor -> manifest`.

## Safety Constraints

`banGRAPPLE` is deny-first by design.

- Internal disks are blocked by default.
- Only clearly external targets should be auto-approved.
- Destructive actions should require an explicit erase confirmation.
- T2-equipped Intel Macs still depend on Apple firmware policy for external boot.

## Quick Start

```bash
cargo run -- list-releases
cargo run -- refresh-releases
cargo run -- list-disks
cargo run -- plan-installer --efi ./EFI /dev/sdX
cargo run -- plan-installer --fetch-opencore /dev/sdX
cargo run -- plan-installer --fetch-opencore --refresh-artifacts /dev/sdX
cargo run -- plan-system /dev/sdX
cargo run -- plan-system --channel stable /dev/sdX
cargo run -- plan-system --refresh-artifacts --channel stable /dev/sdX
cargo test
```

## Roadmap

1. Replace curated release data with live Apple catalog discovery.
2. Add package download, image manifest resolution, retry, and checksum verification.
3. Add privileged partitioning and deployment executors behind explicit confirmation.
4. Add an interactive terminal flow with mode, release, disk, and progress selection.
5. Implement golden-image deployment before attempting synthetic APFS installation.

## Phase 1 Bootloader Policy

Installer media planning supports two EFI modes:

- `--efi PATH`: use a user-supplied EFI tree
- `--fetch-opencore`: download the pinned OpenCore `0.9.9` release and verify SHA256 before extraction

The repository does not fetch `latest`. OpenCore downloads are pinned and checksum-verified.
