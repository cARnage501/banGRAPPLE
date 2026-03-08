use std::env;
use std::fs::File;
use std::io::BufReader;
use std::io::{self, Write};
use std::path::Path;
use std::process;

use ban_grapple::audit::audit_rebuild;
use ban_grapple::basesystem::inspect_base_system_evidence;
use ban_grapple::bootloader::{
    BootloaderSource, default_bootloader_source, parse_bootloader_source, resolve_bootloader,
};
use ban_grapple::catalog::{InstallerRelease, fetch_releases, refresh_releases};
use ban_grapple::disk::{DiskDevice, SafetyVerdict, discover_disks};
use ban_grapple::dmg::discover_runtime_assets;
use ban_grapple::image::ImageChannel;
use ban_grapple::manifest::inspect_runtime_manifest;
use ban_grapple::pipeline::{
    WorkflowMode, build_installer_with_options, deploy_system_with_options,
};
use ban_grapple::rebuild::rebuild_image;
use ban_grapple::tui::{render_disks, render_plan, render_releases};
use ban_grapple::xar::{extract_named_member, inspect_archive};
use ban_grapple::yaa::YaaStreamReader;

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {error}");
        process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let args: Vec<String> = env::args().collect();
    match args.get(1).map(String::as_str) {
        None => interactive_plan(),
        Some("list-releases") => {
            let releases = fetch_releases().map_err(|err| err.to_string())?;
            println!("{}", render_releases(&releases));
            Ok(())
        }
        Some("refresh-releases") => {
            let releases = refresh_releases().map_err(|err| err.to_string())?;
            println!("{}", render_releases(&releases));
            Ok(())
        }
        Some("list-disks") => {
            let disks = discover_disks().map_err(|err| err.to_string())?;
            println!("{}", render_disks(&disks));
            Ok(())
        }
        Some("inspect-runtime-manifest") => inspect_runtime_manifest_command(&args),
        Some("discover-runtime") => discover_runtime(&args),
        Some("inspect-basesystem") => inspect_basesystem(&args),
        Some("inspect-xar") => inspect_xar(&args),
        Some("inspect-yaa") => inspect_yaa(&args),
        Some("inspect-yaa-regions") => inspect_yaa_regions(&args),
        Some("materialize-yaa-prefix") => materialize_yaa_prefix(&args),
        Some("rebuild-image") => rebuild_image_command(&args),
        Some("audit-rebuild") => audit_rebuild_command(&args),
        Some("extract-sharedsupport") => extract_sharedsupport(&args),
        Some("plan") | Some("plan-installer") => plan_installer(&args),
        Some("plan-system") => plan_system(&args),
        _ => {
            print_help();
            Ok(())
        }
    }
}

fn plan_installer(args: &[String]) -> Result<(), String> {
    let releases = fetch_releases().map_err(|err| err.to_string())?;
    let release = resolve_release_arg(args, &releases)?;
    let disk = find_disk(plan_disk_arg(args))?;
    let refresh_artifacts = has_flag(args, "--refresh-artifacts");
    let bootloader_source = parse_bootloader_source(args)?;
    let bootloader = resolve_bootloader(&bootloader_source, refresh_artifacts)?;
    let plan = build_installer_with_options(release, disk, refresh_artifacts, bootloader)?;
    println!("{}", render_plan(&plan));
    Ok(())
}

fn inspect_xar(args: &[String]) -> Result<(), String> {
    let pkg_path = args.get(2).ok_or_else(|| {
        "usage: ban-grapple inspect-xar /path/to/InstallAssistant.pkg".to_string()
    })?;
    let archive = inspect_archive(Path::new(pkg_path)).map_err(|err| err.to_string())?;
    println!("Archive: {}", pkg_path);
    println!("Heap start: {}", archive.heap_start);
    for member in archive.members {
        println!(
            "{}\toffset={}\tabs={}\tlength={}\tencoding={}",
            member.name,
            member.offset,
            member.absolute_offset,
            member.length,
            member.encoding_style.as_deref().unwrap_or("none")
        );
    }
    Ok(())
}

fn inspect_yaa(args: &[String]) -> Result<(), String> {
    let path = args.get(2).ok_or_else(|| {
        "usage: ban-grapple inspect-yaa /path/to/decoded-yaa.bin [--start-offset N] [--records N]"
            .to_string()
    })?;
    let start_offset = parse_u64_flag(args, "--start-offset")?.unwrap_or(0);
    let records = parse_usize_flag(args, "--records")?.unwrap_or(1000);

    let file = File::open(path).map_err(|err| err.to_string())?;
    let mut reader = YaaStreamReader::new(BufReader::new(file));
    reader
        .seek_to(start_offset)
        .map_err(|err| err.to_string())?;
    let summary = reader.summarize(records).map_err(|err| err.to_string())?;

    println!("YAA stream: {}", path);
    println!("Start offset: {}", summary.start_offset);
    println!("Records parsed: {}", summary.record_count);
    println!(
        "Last next record offset: {}",
        summary.last_next_record_offset
    );
    println!("Skipped payload bytes: {}", summary.skipped_payload_bytes);
    println!(
        "Object counts: directories={} files={} links={} others={}",
        summary.object_counts.directories,
        summary.object_counts.files,
        summary.object_counts.links,
        summary.object_counts.others
    );

    if let Some(payload) = summary.largest_payload {
        println!("Largest payload:");
        println!(
            "  path: {}",
            payload.path.unwrap_or_else(|| "<unknown>".to_string())
        );
        println!(
            "  tag: {:?}\n  length: {}\n  record offset: {}\n  payload offset: {}",
            payload.tag, payload.length, payload.record_offset, payload.payload_offset
        );
    }

    if !summary.tag_counts.is_empty() {
        println!("Tag counts:");
        for (tag, count) in summary.tag_counts {
            println!("  {tag}: {count}");
        }
    }

    Ok(())
}

fn inspect_yaa_regions(args: &[String]) -> Result<(), String> {
    let path = args.get(2).ok_or_else(|| {
        "usage: ban-grapple inspect-yaa-regions /path/to/decoded-yaa.bin [--start-offset N] [--records-per-region N] [--regions N]"
            .to_string()
    })?;
    let start_offset = parse_u64_flag(args, "--start-offset")?.unwrap_or(0);
    let records_per_region = parse_usize_flag(args, "--records-per-region")?.unwrap_or(1000);
    let regions = parse_usize_flag(args, "--regions")?.unwrap_or(4);

    let file = File::open(path).map_err(|err| err.to_string())?;
    let mut reader = YaaStreamReader::new(BufReader::new(file));
    reader
        .seek_to(start_offset)
        .map_err(|err| err.to_string())?;
    let region_summaries = reader
        .summarize_regions(records_per_region, regions)
        .map_err(|err| err.to_string())?;

    println!("YAA stream: {}", path);
    println!("Start offset: {}", start_offset);
    for region in region_summaries {
        println!("Region {}:", region.region_index);
        println!("  records: {}", region.summary.record_count);
        println!(
            "  offsets: {} -> {}",
            region.summary.start_offset, region.summary.last_next_record_offset
        );
        println!(
            "  objects: directories={} files={} links={} others={}",
            region.summary.object_counts.directories,
            region.summary.object_counts.files,
            region.summary.object_counts.links,
            region.summary.object_counts.others
        );
        println!(
            "  skipped payload bytes: {}",
            region.summary.skipped_payload_bytes
        );
        if let Some(payload) = region.summary.largest_payload {
            println!(
                "  largest payload: {} ({:?}, {} bytes)",
                payload.path.unwrap_or_else(|| "<unknown>".to_string()),
                payload.tag,
                payload.length
            );
        }
    }

    Ok(())
}

fn materialize_yaa_prefix(args: &[String]) -> Result<(), String> {
    let path = args.get(2).ok_or_else(|| {
        "usage: ban-grapple materialize-yaa-prefix /path/to/decoded-yaa.bin /path/to/output-root [--start-offset N] [--records N]"
            .to_string()
    })?;
    let output_root = args.get(3).ok_or_else(|| {
        "usage: ban-grapple materialize-yaa-prefix /path/to/decoded-yaa.bin /path/to/output-root [--start-offset N] [--records N]"
            .to_string()
    })?;
    let start_offset = parse_u64_flag(args, "--start-offset")?.unwrap_or(0);
    let records = parse_usize_flag(args, "--records")?.unwrap_or(1000);

    let file = File::open(path).map_err(|err| err.to_string())?;
    let mut reader = YaaStreamReader::new(BufReader::new(file));
    reader
        .seek_to(start_offset)
        .map_err(|err| err.to_string())?;
    let result = reader
        .materialize_prefix(Path::new(output_root), records)
        .map_err(|err| err.to_string())?;

    println!("YAA stream: {}", path);
    println!("Output root: {}", result.output_root.display());
    println!("Records written: {}", result.records_written);
    println!("Directories created: {}", result.directories_created);
    println!("Files created: {}", result.files_created);
    println!(
        "Last next record offset: {}",
        result.last_next_record_offset
    );
    println!("Metadata: {}", result.metadata_path.display());
    Ok(())
}

fn rebuild_image_command(args: &[String]) -> Result<(), String> {
    let source_root = args.get(2).ok_or_else(|| {
        "usage: ban-grapple rebuild-image /path/to/AssetData-or-payloadv2 /path/to/output-root"
            .to_string()
    })?;
    let output_root = args.get(3).ok_or_else(|| {
        "usage: ban-grapple rebuild-image /path/to/AssetData-or-payloadv2 /path/to/output-root"
            .to_string()
    })?;

    let result = rebuild_image(Path::new(source_root), Path::new(output_root))
        .map_err(|err| err.to_string())?;
    println!("Payload root: {}", result.payload_root.display());
    println!(
        "Decoded YAA stream: {}",
        result.decoded_stream_path.display()
    );
    println!("Decoded shards: {}", result.decoded_shards.len());
    for shard in result.decoded_shards {
        println!(
            "  payload.{:03}: decoded {} bytes from {} bytes (target {})",
            shard.index, shard.decoded_size, shard.compressed_size, shard.target_size
        );
    }
    println!("Output root: {}", result.materialized.output_root.display());
    println!("Records written: {}", result.materialized.records_written);
    println!(
        "Directories created: {}",
        result.materialized.directories_created
    );
    println!("Files created: {}", result.materialized.files_created);
    println!("Links created: {}", result.materialized.links_created);
    println!(
        "Mode updates applied: {}",
        result.materialized.mode_updates_applied
    );
    println!(
        "Timestamp updates applied: {}",
        result.materialized.timestamp_updates_applied
    );
    println!(
        "Ownership updates applied: {}",
        result.materialized.ownership_updates_applied
    );
    println!(
        "Ownership update failures: {}",
        result.materialized.ownership_update_failures
    );
    println!(
        "Xattr sidecars written: {}",
        result.materialized.xattr_sidecars_written
    );
    println!("Metadata: {}", result.materialized.metadata_path.display());
    Ok(())
}

fn audit_rebuild_command(args: &[String]) -> Result<(), String> {
    let root = args
        .get(2)
        .ok_or_else(|| "usage: ban-grapple audit-rebuild /path/to/rebuilt-tree".to_string())?;

    let report = audit_rebuild(Path::new(root)).map_err(|err| err.to_string())?;
    println!("Rebuilt tree: {}", report.root.display());
    println!("Replay metadata: {}", report.metadata_path.display());
    println!("Audit report: {}", report.report_path.display());
    println!(
        "Actual tree: directories={} files={} symlinks={} others={} bytes={} broken_symlinks={}",
        report.actual.directories,
        report.actual.files,
        report.actual.symlinks,
        report.actual.other,
        report.actual.total_bytes,
        report.actual.broken_symlinks
    );
    println!(
        "Replay coverage: records={} directories={} files={} links={} others={}",
        report.replay.records,
        report.replay.directories,
        report.replay.files,
        report.replay.links,
        report.replay.other
    );
    println!(
        "Metadata coverage: modes={} uids={} gids={} xattr_records={} xattr_sidecars={}/{}",
        report.replay.records_with_mode,
        report.replay.records_with_uid,
        report.replay.records_with_gid,
        report.replay.records_with_xattr_payloads,
        report.replay.xattr_sidecars_present,
        report.replay.xattr_sidecars_referenced
    );
    println!(
        "Path coverage: replay_paths={} actual_paths={} missing_from_tree={} extra_in_tree={} mode_mismatches={}",
        report.coverage.replay_paths,
        report.coverage.actual_paths,
        report.coverage.missing_from_tree,
        report.coverage.extra_in_tree,
        report.coverage.mode_mismatches
    );

    if !report.samples.missing_from_tree.is_empty() {
        println!("Sample missing paths:");
        for path in &report.samples.missing_from_tree {
            println!("  {path}");
        }
    }
    if !report.samples.extra_in_tree.is_empty() {
        println!("Sample extra paths:");
        for path in &report.samples.extra_in_tree {
            println!("  {path}");
        }
    }
    if !report.samples.mode_mismatches.is_empty() {
        println!("Sample mode mismatches:");
        for sample in &report.samples.mode_mismatches {
            println!(
                "  {} expected {:o} actual {:o}",
                sample.path, sample.expected, sample.actual
            );
        }
    }
    if !report.samples.broken_symlinks.is_empty() {
        println!("Sample broken symlinks:");
        for path in &report.samples.broken_symlinks {
            println!("  {path}");
        }
    }
    if !report.samples.xattr_sidecars_missing.is_empty() {
        println!("Sample missing xattr sidecars:");
        for path in &report.samples.xattr_sidecars_missing {
            println!("  {path}");
        }
    }

    Ok(())
}

fn inspect_basesystem(args: &[String]) -> Result<(), String> {
    let root = args
        .get(2)
        .ok_or_else(|| "usage: ban-grapple inspect-basesystem /path/to/AssetData".to_string())?;
    let report = inspect_base_system_evidence(Path::new(root)).map_err(|err| err.to_string())?;
    println!("Asset root: {}", report.asset_root.display());
    print_basesystem_artifact("x86 patch", &report.x86_patch);
    print_basesystem_artifact("x86 patch ecc", &report.x86_patch_ecc);
    print_basesystem_artifact("arm64 patch", &report.arm64_patch);
    print_basesystem_artifact("restore chunklist", &report.restore_chunklist);
    print_basesystem_artifact("x86 trustcache", &report.x86_trustcache);
    Ok(())
}

fn discover_runtime(args: &[String]) -> Result<(), String> {
    let root = args
        .get(2)
        .ok_or_else(|| "usage: ban-grapple discover-runtime /path/to/AssetData".to_string())?;
    let report = discover_runtime_assets(Path::new(root)).map_err(|err| err.to_string())?;
    println!("Asset root: {}", root);

    match report.base_system_pair {
        Some(pair) => {
            println!("BaseSystem runtime:");
            println!("  dmg: {}", pair.dmg.display());
            println!("  chunklist: {}", pair.chunklist.display());
            println!("  dmg size: {} bytes", pair.dmg_size_bytes);
        }
        None => println!("BaseSystem runtime: not found"),
    }

    if !report.suramdisk_pairs.is_empty() {
        println!("SURamDisk candidates:");
        for pair in report.suramdisk_pairs {
            println!("  name: {}", pair.basename);
            println!("    dmg: {}", pair.dmg.display());
            if let Some(chunklist) = pair.chunklist {
                println!("    chunklist: {}", chunklist.display());
            }
            println!("    dmg size: {} bytes", pair.dmg_size_bytes);
        }
    }

    Ok(())
}

fn inspect_runtime_manifest_command(args: &[String]) -> Result<(), String> {
    let metadata_root = args.get(2).ok_or_else(|| {
        "usage: ban-grapple inspect-runtime-manifest /path/to/metadata-or-directory /path/to/AssetData"
            .to_string()
    })?;
    let asset_root = args.get(3).ok_or_else(|| {
        "usage: ban-grapple inspect-runtime-manifest /path/to/metadata-or-directory /path/to/AssetData"
            .to_string()
    })?;

    let report = inspect_runtime_manifest(Path::new(metadata_root), Path::new(asset_root))
        .map_err(|err| err.to_string())?;

    println!("Metadata source: {}", report.metadata_source.display());
    if let Some(build) = report.build.as_deref() {
        println!("Build: {build}");
    }
    if let Some(version) = report.os_version.as_deref() {
        println!("OS version: {version}");
    }

    for identity in report.identities {
        println!();
        println!("Variant: {}", identity.variant);
        if let Some(device_class) = identity.device_class.as_deref() {
            println!("  device class: {device_class}");
        }
        if !identity.variant_contents.is_empty() {
            println!("  variant contents:");
            for (key, value) in identity.variant_contents {
                println!("    {key} -> {value}");
            }
        }
        if !identity.resolved_paths.is_empty() {
            println!("  resolved manifest paths:");
            for path in identity.resolved_paths {
                println!(
                    "    {} -> {} [{}]",
                    path.manifest_key,
                    path.path.display(),
                    if path.exists { "present" } else { "missing" }
                );
                if let Some(additional) = path.additional_path {
                    let status = if path.additional_exists == Some(true) {
                        "present"
                    } else {
                        "missing"
                    };
                    println!("      additional -> {} [{}]", additional.display(), status);
                }
            }
        }
    }

    Ok(())
}

fn extract_sharedsupport(args: &[String]) -> Result<(), String> {
    let pkg_path = args.get(2).ok_or_else(|| {
        "usage: ban-grapple extract-sharedsupport /path/to/InstallAssistant.pkg /path/to/SharedSupport.dmg"
            .to_string()
    })?;
    let out_path = args.get(3).ok_or_else(|| {
        "usage: ban-grapple extract-sharedsupport /path/to/InstallAssistant.pkg /path/to/SharedSupport.dmg"
            .to_string()
    })?;
    let member = extract_named_member(
        Path::new(pkg_path),
        "SharedSupport.dmg",
        Path::new(out_path),
    )
    .map_err(|err| err.to_string())?;
    println!(
        "Extracted {} from {} to {} ({} bytes)",
        member.name, pkg_path, out_path, member.length
    );
    Ok(())
}

fn plan_system(args: &[String]) -> Result<(), String> {
    let releases = fetch_releases().map_err(|err| err.to_string())?;
    let release = resolve_release_arg(args, &releases)?;
    let disk = find_disk(plan_disk_arg(args))?;
    let refresh_artifacts = has_flag(args, "--refresh-artifacts");
    let channel = parse_channel(args)?;
    let plan = deploy_system_with_options(release, disk, refresh_artifacts, channel)?;
    println!("{}", render_plan(&plan));
    Ok(())
}

fn interactive_plan() -> Result<(), String> {
    let releases = fetch_releases().map_err(|err| err.to_string())?;
    let disks = discover_disks().map_err(|err| err.to_string())?;

    let mode = prompt_mode()?;
    let release = prompt_release(&releases)?;
    let disk = prompt_disk(&disks)?;
    confirm_planning(&disk, mode)?;

    match mode {
        WorkflowMode::InstallerMedia => {
            let bootloader_source = prompt_bootloader_source()?;
            let bootloader = resolve_bootloader(&bootloader_source, false)?;
            let plan = build_installer_with_options(release, disk, false, bootloader)?;
            println!("{}", render_plan(&plan));
        }
        WorkflowMode::FullSystem => {
            let channel = prompt_image_channel()?;
            let plan = deploy_system_with_options(release, disk, false, channel)?;
            println!("{}", render_plan(&plan));
        }
    }

    Ok(())
}

fn first_release(releases: &[InstallerRelease]) -> Result<InstallerRelease, String> {
    releases
        .iter()
        .next()
        .cloned()
        .ok_or_else(|| "no installer releases found in Apple catalog".to_string())
}

fn plan_disk_arg(args: &[String]) -> Option<String> {
    positional_args(args, &["--efi", "--release", "--channel"])
        .into_iter()
        .next()
}

fn has_flag(args: &[String], flag: &str) -> bool {
    args.iter().any(|arg| arg == flag)
}

fn positional_args(args: &[String], value_flags: &[&str]) -> Vec<String> {
    let mut out = Vec::new();
    let mut iter = args.iter().skip(2);
    while let Some(arg) = iter.next() {
        if value_flags.iter().any(|flag| arg == flag) {
            let _ = iter.next();
            continue;
        }
        if arg.starts_with("--") {
            continue;
        }
        out.push(arg.clone());
    }
    out
}

fn parse_channel(args: &[String]) -> Result<ImageChannel, String> {
    let mut iter = args.iter().skip(2);
    while let Some(arg) = iter.next() {
        if arg == "--channel" {
            let value = iter
                .next()
                .ok_or_else(|| "usage: --channel <stable|beta|lab>".to_string())?;
            return value.parse();
        }
    }
    Ok(ImageChannel::Stable)
}

fn parse_release_query(args: &[String]) -> Result<Option<String>, String> {
    let mut iter = args.iter().skip(2);
    while let Some(arg) = iter.next() {
        if arg == "--release" {
            let value = iter.next().ok_or_else(|| {
                "usage: --release <index|product-id|version|build|name>".to_string()
            })?;
            return Ok(Some(value.clone()));
        }
    }
    Ok(None)
}

fn resolve_release_arg(
    args: &[String],
    releases: &[InstallerRelease],
) -> Result<InstallerRelease, String> {
    if let Some(query) = parse_release_query(args)? {
        return select_release(releases, &query);
    }
    first_release(releases)
}

fn select_release(releases: &[InstallerRelease], query: &str) -> Result<InstallerRelease, String> {
    if releases.is_empty() {
        return Err("no installer releases found in Apple catalog".to_string());
    }

    if let Ok(index) = query.parse::<usize>() {
        if let Some(release) = releases.get(index.saturating_sub(1)) {
            return Ok(release.clone());
        }
        return Err(format!(
            "release selection '{}' is out of range; choose 1-{}",
            query,
            releases.len()
        ));
    }

    let needle = query.trim().to_ascii_lowercase();
    let mut matches: Vec<InstallerRelease> = releases
        .iter()
        .filter(|release| release_matches(release, &needle))
        .cloned()
        .collect();

    if matches.len() == 1 {
        return Ok(matches.remove(0));
    }
    if matches.is_empty() {
        return Err(format!(
            "no release matched '{}'; use `list-releases` to inspect available versions",
            query
        ));
    }

    Err(format!(
        "release selector '{}' is ambiguous; refine it with product id, build, or exact version",
        query
    ))
}

fn release_matches(release: &InstallerRelease, needle: &str) -> bool {
    let name = release.name.to_ascii_lowercase();
    let product_id = release.product_id.to_ascii_lowercase();
    let version = release.version.to_ascii_lowercase();
    let build = release.build.to_ascii_lowercase();

    product_id == needle
        || version == needle
        || build == needle
        || name == needle
        || name.contains(needle)
}

fn parse_u64_flag(args: &[String], flag: &str) -> Result<Option<u64>, String> {
    let mut iter = args.iter().skip(2);
    while let Some(arg) = iter.next() {
        if arg == flag {
            let value = iter
                .next()
                .ok_or_else(|| format!("usage: {flag} <value>"))?;
            let parsed = value
                .parse::<u64>()
                .map_err(|_| format!("invalid integer for {flag}: {value}"))?;
            return Ok(Some(parsed));
        }
    }
    Ok(None)
}

fn parse_usize_flag(args: &[String], flag: &str) -> Result<Option<usize>, String> {
    let mut iter = args.iter().skip(2);
    while let Some(arg) = iter.next() {
        if arg == flag {
            let value = iter
                .next()
                .ok_or_else(|| format!("usage: {flag} <value>"))?;
            let parsed = value
                .parse::<usize>()
                .map_err(|_| format!("invalid integer for {flag}: {value}"))?;
            return Ok(Some(parsed));
        }
    }
    Ok(None)
}

fn print_basesystem_artifact(label: &str, artifact: &ban_grapple::basesystem::BaseSystemArtifact) {
    println!("{label}:");
    println!("  path: {}", artifact.path.display());
    println!("  exists: {}", artifact.exists);
    if let Some(size) = artifact.size_bytes {
        println!("  size: {} bytes", size);
    }
    println!("  starts_with_bxdiff: {}", artifact.starts_with_bxdiff);
}

fn find_disk(path: Option<String>) -> Result<ban_grapple::disk::DiskDevice, String> {
    let path = path.ok_or_else(|| {
        "usage: ban-grapple plan-installer [--release SELECTOR] [--efi PATH | --fetch-opencore] [--refresh-artifacts] /dev/sdX"
            .to_string()
    })?;
    discover_disks()
        .map_err(|err| err.to_string())?
        .into_iter()
        .find(|candidate| candidate.path == path)
        .ok_or_else(|| format!("disk '{path}' not found in safe discovery list"))
}

fn prompt_mode() -> Result<WorkflowMode, String> {
    println!("Select mode");
    println!("1. Create installer disk");
    println!("2. Create full macOS installation");
    loop {
        match prompt("Mode [1-2]: ")?.as_str() {
            "1" => return Ok(WorkflowMode::InstallerMedia),
            "2" => return Ok(WorkflowMode::FullSystem),
            _ => println!("Enter 1 or 2."),
        }
    }
}

fn prompt_release(releases: &[InstallerRelease]) -> Result<InstallerRelease, String> {
    println!();
    print!("{}", render_releases(releases));
    loop {
        let choice = prompt("Release [number, version, build, product id, or name]: ")?;
        match select_release(releases, &choice) {
            Ok(release) => return Ok(release),
            Err(err) => println!("{err}"),
        }
    }
}

fn prompt_disk(disks: &[DiskDevice]) -> Result<DiskDevice, String> {
    println!();
    print!("{}", render_disks(disks));
    if !disks
        .iter()
        .any(|disk| matches!(disk.safety_verdict(), SafetyVerdict::Allowed))
    {
        return Err("no auto-approved external disks are currently available".to_string());
    }
    loop {
        let choice = prompt("Disk [number or /dev path]: ")?;
        let disk = if let Ok(index) = choice.parse::<usize>() {
            disks.get(index.saturating_sub(1)).cloned()
        } else {
            disks.iter().find(|disk| disk.path == choice).cloned()
        };

        let Some(disk) = disk else {
            println!("Select one of the listed disks.");
            continue;
        };

        match disk.safety_verdict() {
            SafetyVerdict::Allowed => return Ok(disk),
            SafetyVerdict::Review(reason) | SafetyVerdict::Blocked(reason) => {
                println!("{} is not selectable: {}", disk.path, reason);
            }
        }
    }
}

fn confirm_planning(disk: &DiskDevice, mode: WorkflowMode) -> Result<(), String> {
    println!();
    println!("About to build a {} plan for {}.", mode.label(), disk.path);
    println!("This is still read-only and will not write to the disk.");
    loop {
        let answer = prompt("Continue? [y/N]: ")?;
        match answer.to_ascii_lowercase().as_str() {
            "y" | "yes" => return Ok(()),
            "" | "n" | "no" => return Err("planning cancelled".to_string()),
            _ => println!("Enter y or n."),
        }
    }
}

fn prompt_bootloader_source() -> Result<BootloaderSource, String> {
    println!();
    println!("Select EFI source");
    println!("1. Fetch pinned OpenCore ({})", default_bootloader_source());
    println!("2. Use local EFI tree");
    loop {
        match prompt("EFI source [1-2]: ")?.as_str() {
            "1" => return Ok(default_bootloader_source()),
            "2" => {
                let path = prompt("EFI path: ")?;
                if path.trim().is_empty() {
                    println!("Enter a path to an EFI tree.");
                    continue;
                }
                return Ok(BootloaderSource::UserPath(path.into()));
            }
            _ => println!("Enter 1 or 2."),
        }
    }
}

fn prompt_image_channel() -> Result<ImageChannel, String> {
    println!();
    println!("Select image channel");
    println!("1. stable");
    println!("2. beta");
    println!("3. lab");
    loop {
        match prompt("Channel [1-3]: ")?.as_str() {
            "1" => return Ok(ImageChannel::Stable),
            "2" => return Ok(ImageChannel::Beta),
            "3" => return Ok(ImageChannel::Lab),
            _ => println!("Enter 1, 2, or 3."),
        }
    }
}

fn prompt(message: &str) -> Result<String, String> {
    print!("{message}");
    io::stdout().flush().map_err(|err| err.to_string())?;
    let mut line = String::new();
    io::stdin()
        .read_line(&mut line)
        .map_err(|err| err.to_string())?;
    Ok(line.trim().to_string())
}

fn print_help() {
    println!(
        "ban-grapple\n\nWith no command, start an interactive read-only planning flow.\n\nCommands:\n  list-releases                                                     Show macOS releases, refreshing automatically every 24 hours\n  refresh-releases                                                  Force a live catalog refresh and replace the cache\n  list-disks                                                        Inspect local block devices safely\n  inspect-runtime-manifest /path/to/metadata-or-directory /path/to/AssetData\n                                                                   Decode PreflightBuildManifest and report resolved runtime paths\n  discover-runtime /path/to/AssetData                              Discover BaseSystem or SURamDisk runtime pairs in extracted assets\n  inspect-basesystem /path/to/AssetData                            Report the separate BaseSystem patch and trust artifacts\n  inspect-xar /path/to/InstallAssistant.pkg                         List XAR members with resolved absolute offsets\n  inspect-yaa /path/to/decoded-yaa.bin [--start-offset N] [--records N]\n                                                                   Summarize a decoded YAA stream without materializing file payloads\n  inspect-yaa-regions /path/to/decoded-yaa.bin [--start-offset N] [--records-per-region N] [--regions N]\n                                                                   Summarize consecutive regions of a decoded YAA stream\n  materialize-yaa-prefix /path/to/decoded-yaa.bin /path/to/output-root [--start-offset N] [--records N]\n                                                                   Reconstruct a small decoded YAA prefix into a filesystem tree\n  rebuild-image /path/to/AssetData-or-payloadv2 /path/to/output-root\n                                                                   Decode ordered payloadv2 shards and reconstruct the full filesystem tree\n  audit-rebuild /path/to/rebuilt-tree\n                                                                   Audit replay coverage, modes, symlinks, and xattr sidecar coverage\n  extract-sharedsupport /path/to/InstallAssistant.pkg /path/to/SharedSupport.dmg\n                                                                   Extract the SharedSupport.dmg member read-only from InstallAssistant.pkg\n  plan-installer [--release SELECTOR] [--efi PATH | --fetch-opencore] [--refresh-artifacts] /dev/sdX\n                                                                   Build a dry installer-media plan with a resolved EFI source\n  plan-system [--release SELECTOR] [--channel stable|beta|lab] [--refresh-artifacts] /dev/sdX\n                                                                   Build a dry full-system deployment plan"
    );
}

#[cfg(test)]
mod tests {
    use ban_grapple::catalog::InstallerRelease;

    use super::{parse_release_query, plan_disk_arg, select_release};

    fn sample_releases() -> Vec<InstallerRelease> {
        vec![
            InstallerRelease {
                product_id: "001-00001".to_string(),
                name: "macOS Sonoma".to_string(),
                version: "14.4".to_string(),
                build: "23E214".to_string(),
                catalog_url: "https://example.test/catalog".to_string(),
                server_metadata_url: None,
                distribution_url: None,
                post_date: None,
                packages: Vec::new(),
            },
            InstallerRelease {
                product_id: "001-00002".to_string(),
                name: "macOS Sequoia".to_string(),
                version: "15.0".to_string(),
                build: "24A335".to_string(),
                catalog_url: "https://example.test/catalog".to_string(),
                server_metadata_url: None,
                distribution_url: None,
                post_date: None,
                packages: Vec::new(),
            },
        ]
    }

    #[test]
    fn plan_disk_arg_skips_efi_value() {
        let args = vec![
            "ban-grapple".to_string(),
            "plan-installer".to_string(),
            "--efi".to_string(),
            "./EFI".to_string(),
            "/dev/sdb".to_string(),
        ];

        assert_eq!(plan_disk_arg(&args).as_deref(), Some("/dev/sdb"));
    }

    #[test]
    fn plan_disk_arg_skips_channel_and_release_values() {
        let args = vec![
            "ban-grapple".to_string(),
            "plan-system".to_string(),
            "--release".to_string(),
            "15.0".to_string(),
            "--channel".to_string(),
            "stable".to_string(),
            "/dev/sdc".to_string(),
        ];

        assert_eq!(plan_disk_arg(&args).as_deref(), Some("/dev/sdc"));
    }

    #[test]
    fn parse_release_query_reads_value() {
        let args = vec![
            "ban-grapple".to_string(),
            "plan-installer".to_string(),
            "--release".to_string(),
            "23E214".to_string(),
            "/dev/sdb".to_string(),
        ];

        assert_eq!(
            parse_release_query(&args).unwrap().as_deref(),
            Some("23E214")
        );
    }

    #[test]
    fn select_release_matches_exact_version() {
        let release = select_release(&sample_releases(), "15.0").expect("release should match");
        assert_eq!(release.name, "macOS Sequoia");
    }

    #[test]
    fn select_release_matches_product_id() {
        let release =
            select_release(&sample_releases(), "001-00001").expect("release should match");
        assert_eq!(release.build, "23E214");
    }

    #[test]
    fn select_release_rejects_ambiguous_name() {
        let err = select_release(&sample_releases(), "macos").expect_err("selector should fail");
        assert!(err.contains("ambiguous"));
    }
}
