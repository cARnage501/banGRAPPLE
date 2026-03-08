# Repository Guidelines

## Project Structure & Module Organization
`banGRAPPLE` is a Rust CLI for building macOS installer media and, later, full bootable external macOS systems from Linux. Keep runtime code in `src/`, design notes in `docs/`, and helper scripts in `scripts/` only when Rust is clearly the wrong tool.

Current module layout:
- `src/main.rs`: CLI entry point and command routing
- `src/catalog.rs`: release discovery and Apple catalog parsing interface
- `src/downloader.rs`: installer download planning, cache handling, and future retry logic
- `src/bootloader.rs`: EFI source resolution and pinned OpenCore handling
- `src/disk.rs`: disk discovery, transport detection, and safety checks
- `src/installer.rs`: installer-media runtime layout and deployment planning
- `src/image.rs`: full-system image distribution and deployment planning
- `src/pipeline.rs`: mode-aware orchestration and ordered execution stages
- `src/tui.rs`: terminal rendering helpers
- `docs/architecture.md`: system design and milestones

## Build, Test, and Development Commands
Use Cargo from the repository root.

- `cargo run -- list-releases`: show the current release set
- `cargo run -- list-disks`: inspect local block devices without writing anything
- `cargo run -- plan-installer --efi ./EFI /dev/sdX`: build a dry installer-media plan with a local EFI tree
- `cargo run -- plan-installer --fetch-opencore /dev/sdX`: build a dry installer-media plan with pinned OpenCore
- `cargo run -- plan-installer --fetch-opencore --refresh-artifacts /dev/sdX`: force-refresh installer artifacts and the bootloader archive
- `cargo run -- plan-system /dev/sdX`: build a dry full-system deployment plan
- `cargo run -- plan-system --refresh-artifacts /dev/sdX`: force-refresh resolved image metadata
- `cargo test`: run unit tests
- `cargo fmt`: format the codebase
- `cargo clippy --all-targets --all-features`: lint for correctness and style issues

## Coding Style & Naming Conventions
Follow standard Rust style: 4-space indentation, `snake_case` for functions and modules, `UpperCamelCase` for types, and small focused files. Prefer explicit types and return `Result` for operations that may touch disks, the network, or external processes.

Keep read-only planning logic separate from destructive execution. If a function can erase, partition, format, or write a disk, its name and call path must make that obvious.

## Testing Guidelines
Place unit tests next to the module they cover. Add integration tests under `tests/` once downloader, partitioning, or deployment code becomes executable.

Every safety rule needs a regression test, especially logic that decides whether a disk is internal, external, blocked, or review-only. Add the same level of coverage for image selection, manifest resolution, and full-system mode planning.

## Commit & Pull Request Guidelines
Use short imperative commit subjects such as `Add full-system planning mode` or `Tighten disk safety checks`. Keep pull requests focused and include:

- a summary of the behavior or safety change
- commands used for verification
- notes on any destructive paths intentionally left untested
- terminal captures for interactive UX changes when relevant

## Safety Notes
Never merge code that writes to disks by default, weakens internal-disk protections, or bypasses explicit erase confirmation without a clear review trail in the pull request.
