use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader};
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

use plist::Value as PlistValue;
use serde::{Deserialize, Serialize};

const SAMPLE_LIMIT: usize = 25;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RebuildAuditReport {
    pub root: PathBuf,
    pub metadata_path: PathBuf,
    pub report_path: PathBuf,
    pub contract_receipts_path: PathBuf,
    pub broken_symlink_receipts_path: PathBuf,
    pub actual: ActualTreeSummary,
    pub replay: ReplaySummary,
    pub coverage: CoverageSummary,
    pub broken_symlink_causes: BrokenSymlinkCauseSummary,
    pub samples: AuditSamples,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Default)]
pub struct ActualTreeSummary {
    pub directories: u64,
    pub files: u64,
    pub symlinks: u64,
    pub other: u64,
    pub total_bytes: u64,
    pub broken_symlinks: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Default)]
pub struct ReplaySummary {
    pub records: u64,
    pub directories: u64,
    pub files: u64,
    pub links: u64,
    pub other: u64,
    pub records_with_mode: u64,
    pub records_with_uid: u64,
    pub records_with_gid: u64,
    pub records_with_xattr_payloads: u64,
    pub xattr_sidecars_referenced: u64,
    pub xattr_sidecars_present: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Default)]
pub struct CoverageSummary {
    pub replay_paths: u64,
    pub actual_paths: u64,
    pub missing_from_tree: u64,
    pub extra_in_tree: u64,
    pub mode_mismatches: u64,
    pub mode_host_artifacts: u64,
    pub bundle_executable_contract_missing_producers: u64,
    pub residual_broken_symlinks: u64,
    pub inaccessible_paths: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Default)]
pub struct BrokenSymlinkCauseSummary {
    pub exhaustive: bool,
    pub counts: Vec<BrokenSymlinkCauseCount>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BrokenSymlinkCauseCount {
    pub cause: BrokenSymlinkCause,
    pub count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Default)]
pub struct AuditSamples {
    pub missing_from_tree: Vec<String>,
    pub extra_in_tree: Vec<String>,
    pub mode_mismatches: Vec<ModeMismatchSample>,
    pub mode_host_artifacts: Vec<ModeMismatchSample>,
    pub broken_symlinks: Vec<String>,
    pub broken_symlink_receipts: Vec<BrokenSymlinkReceipt>,
    pub bundle_executable_contract_missing_producers: Vec<BundleExecutableContractSample>,
    pub inaccessible_paths: Vec<String>,
    pub xattr_sidecars_missing: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ModeMismatchSample {
    pub path: String,
    pub expected: u32,
    pub actual: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BundleExecutableContractSample {
    pub path: String,
    pub bundle: String,
    pub declared_executable: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Default)]
pub struct ContractReceiptsReport {
    pub bundle_executable_contract_missing_producers: Vec<BundleExecutableContractSample>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Default)]
pub struct BrokenSymlinkReceiptsReport {
    pub receipts: Vec<BrokenSymlinkReceipt>,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum BrokenSymlinkCause {
    BundleExecutableContractMissingProducer,
    FirmwareAliasMapMissingProducer,
    LocaleAliasMapMissingProducer,
    HostRootAbsoluteExpectedExternal,
    CryptexRuntimeSubstrateMissing,
    BundleStructuralAliasMissingProducer,
    CrossTreeParentChainMissing,
    FrameworkRelativeAliasMissingProducer,
    BundleContractMetadataUnavailable,
    LibraryAliasMissingProducer,
    TemplateDataOrPairedVolumeSubstrateMissing,
    BundleDeclaredNameMismatch,
    PrivateRootSubstrateMissing,
    AppleinternalExpectedExternal,
    DataVolumeSubstrateMissing,
    PackagingAliasMissingProducer,
    HostOrPairedRootSubstrateMissing,
    Unknown,
}

impl BrokenSymlinkCause {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BundleExecutableContractMissingProducer => {
                "bundle_executable_contract_missing_producer"
            }
            Self::FirmwareAliasMapMissingProducer => "firmware_alias_map_missing_producer",
            Self::LocaleAliasMapMissingProducer => "locale_alias_map_missing_producer",
            Self::HostRootAbsoluteExpectedExternal => "host_root_absolute_expected_external",
            Self::CryptexRuntimeSubstrateMissing => "cryptex_runtime_substrate_missing",
            Self::BundleStructuralAliasMissingProducer => {
                "bundle_structural_alias_missing_producer"
            }
            Self::CrossTreeParentChainMissing => "cross_tree_parent_chain_missing",
            Self::FrameworkRelativeAliasMissingProducer => {
                "framework_relative_alias_missing_producer"
            }
            Self::BundleContractMetadataUnavailable => "bundle_contract_metadata_unavailable",
            Self::LibraryAliasMissingProducer => "library_alias_missing_producer",
            Self::TemplateDataOrPairedVolumeSubstrateMissing => {
                "template_data_or_paired_volume_substrate_missing"
            }
            Self::BundleDeclaredNameMismatch => "bundle_declared_name_mismatch",
            Self::PrivateRootSubstrateMissing => "private_root_substrate_missing",
            Self::AppleinternalExpectedExternal => "appleinternal_expected_external",
            Self::DataVolumeSubstrateMissing => "data_volume_substrate_missing",
            Self::PackagingAliasMissingProducer => "packaging_alias_missing_producer",
            Self::HostOrPairedRootSubstrateMissing => {
                "host_or_paired_root_substrate_missing"
            }
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BrokenSymlinkReceipt {
    pub path: String,
    pub target: String,
    pub cause: BrokenSymlinkCause,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bundle: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub declared_executable: Option<String>,
}

#[derive(Debug)]
pub enum AuditError {
    Io(io::Error),
    MissingMetadata(PathBuf),
    InvalidRoot(PathBuf),
    Json(serde_json::Error),
    Plist(plist::Error),
}

impl fmt::Display for AuditError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => write!(f, "{err}"),
            Self::MissingMetadata(path) => write!(
                f,
                "rebuild metadata '{}' was not found; expected a completed rebuild output root",
                path.display()
            ),
            Self::InvalidRoot(path) => write!(
                f,
                "expected '{}' to be a rebuilt tree root containing _yaa_materialized.jsonl",
                path.display()
            ),
            Self::Json(err) => write!(f, "{err}"),
            Self::Plist(err) => write!(f, "{err}"),
        }
    }
}

impl From<io::Error> for AuditError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<serde_json::Error> for AuditError {
    fn from(value: serde_json::Error) -> Self {
        Self::Json(value)
    }
}

impl From<plist::Error> for AuditError {
    fn from(value: plist::Error) -> Self {
        Self::Plist(value)
    }
}

#[derive(Debug, Deserialize)]
struct ReplayRecord {
    path: Option<String>,
    object_type: Option<String>,
    mode: Option<u16>,
    uid: Option<u32>,
    gid: Option<u32>,
    payloads: Vec<ReplayPayload>,
}

#[derive(Debug, Deserialize)]
struct ReplayPayload {
    tag: String,
    sidecar_path: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct BundleContractInfo {
    declared_executable: Option<String>,
    has_info_plist: bool,
}

pub fn audit_rebuild(root: &Path) -> Result<RebuildAuditReport, AuditError> {
    let metadata_path = root.join("_yaa_materialized.jsonl");
    if !root.is_dir() {
        return Err(AuditError::InvalidRoot(root.to_path_buf()));
    }
    if !metadata_path.is_file() {
        return Err(AuditError::MissingMetadata(metadata_path));
    }

    let mut replay = ReplaySummary::default();
    let mut replay_paths = BTreeSet::new();
    let mut expected_modes = BTreeMap::new();
    let mut samples = AuditSamples::default();

    let metadata = File::open(&metadata_path)?;
    for line in BufReader::new(metadata).lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let record: ReplayRecord = serde_json::from_str(&line)?;
        replay.records += 1;
        match record.object_type.as_deref() {
            Some("directory") => replay.directories += 1,
            Some("file") => replay.files += 1,
            Some("link") => replay.links += 1,
            _ => replay.other += 1,
        }
        if record.mode.is_some() {
            replay.records_with_mode += 1;
        }
        if record.uid.is_some() {
            replay.records_with_uid += 1;
        }
        if record.gid.is_some() {
            replay.records_with_gid += 1;
        }

        let mut record_has_xattr = false;
        for payload in &record.payloads {
            if payload.tag == "XATA" {
                record_has_xattr = true;
                if let Some(sidecar_path) = payload.sidecar_path.as_deref() {
                    replay.xattr_sidecars_referenced += 1;
                    if Path::new(sidecar_path).is_file() {
                        replay.xattr_sidecars_present += 1;
                    } else if samples.xattr_sidecars_missing.len() < SAMPLE_LIMIT {
                        samples
                            .xattr_sidecars_missing
                            .push(sidecar_path.to_string());
                    }
                }
            }
        }
        if record_has_xattr {
            replay.records_with_xattr_payloads += 1;
        }

        if let Some(path) = record.path.as_deref().and_then(normalized_relative_path) {
            let display = path.display().to_string();
            replay_paths.insert(display.clone());
            if let Some(mode) = record.mode {
                expected_modes.insert(display, u32::from(mode));
            }
        }
    }

    let mut actual = ActualTreeSummary::default();
    let mut actual_paths = BTreeSet::new();
    let mut inaccessible_paths = 0u64;
    let mut bundle_contract_cache = BTreeMap::new();
    let mut bundle_executable_contract_missing_producers = 0u64;
    let mut contract_receipts = Vec::new();
    let mut broken_symlink_cause_counts = BTreeMap::new();
    let mut broken_symlink_receipts = Vec::new();
    walk_actual_tree(
        root,
        root,
        &expected_modes,
        &mut actual,
        &mut actual_paths,
        &mut inaccessible_paths,
        &mut bundle_contract_cache,
        &mut bundle_executable_contract_missing_producers,
        &mut contract_receipts,
        &mut broken_symlink_cause_counts,
        &mut broken_symlink_receipts,
        &mut samples,
    )?;

    for path in replay_paths.difference(&actual_paths) {
        if samples.missing_from_tree.len() < SAMPLE_LIMIT {
            samples.missing_from_tree.push(path.clone());
        }
    }
    for path in actual_paths.difference(&replay_paths) {
        if samples.extra_in_tree.len() < SAMPLE_LIMIT {
            samples.extra_in_tree.push(path.clone());
        }
    }

    let mut mode_mismatches = 0u64;
    let mut mode_host_artifacts = 0u64;
    for (path, expected) in &expected_modes {
        let full = root.join(path);
        match fs::symlink_metadata(&full) {
            Ok(metadata) => {
                let actual_mode = metadata.mode() & 0o7777;
                if actual_mode != *expected {
                    if is_linux_host_mode_artifact(metadata.file_type(), *expected, actual_mode) {
                        mode_host_artifacts += 1;
                    } else {
                        mode_mismatches += 1;
                    }
                }
            }
            Err(err) if err.kind() == io::ErrorKind::PermissionDenied => {
                inaccessible_paths += 1;
                if samples.inaccessible_paths.len() < SAMPLE_LIMIT {
                    samples.inaccessible_paths.push(path.clone());
                }
            }
            Err(err) if err.kind() == io::ErrorKind::NotFound => {}
            Err(err) => return Err(AuditError::Io(err)),
        }
    }

    let coverage = CoverageSummary {
        replay_paths: replay_paths.len() as u64,
        actual_paths: actual_paths.len() as u64,
        missing_from_tree: replay_paths.difference(&actual_paths).count() as u64,
        extra_in_tree: actual_paths.difference(&replay_paths).count() as u64,
        mode_mismatches,
        mode_host_artifacts,
        bundle_executable_contract_missing_producers,
        residual_broken_symlinks: actual
            .broken_symlinks
            .saturating_sub(bundle_executable_contract_missing_producers),
        inaccessible_paths,
    };

    let report_path = root.join("_ban_grapple_audit.json");
    let contract_receipts_path = root.join("_ban_grapple_contract_receipts.json");
    let broken_symlink_receipts_path = root.join("_ban_grapple_broken_symlink_receipts.json");
    sort_contract_receipts(&mut contract_receipts);
    sort_broken_symlink_receipts(&mut broken_symlink_receipts);
    sort_audit_samples(&mut samples);
    let contract_report = ContractReceiptsReport {
        bundle_executable_contract_missing_producers: contract_receipts,
    };
    let contract_bytes = serde_json::to_vec_pretty(&contract_report)?;
    fs::write(&contract_receipts_path, contract_bytes)?;
    let broken_symlink_report = BrokenSymlinkReceiptsReport {
        receipts: broken_symlink_receipts,
    };
    let broken_symlink_bytes = serde_json::to_vec_pretty(&broken_symlink_report)?;
    fs::write(&broken_symlink_receipts_path, broken_symlink_bytes)?;
    let mut broken_symlink_cause_counts_vec: Vec<_> = broken_symlink_cause_counts
        .into_iter()
        .map(|(cause, count)| BrokenSymlinkCauseCount { cause, count })
        .collect();
    broken_symlink_cause_counts_vec.sort_by(|left, right| {
        right
            .count
            .cmp(&left.count)
            .then_with(|| left.cause.cmp(&right.cause))
    });

    let report = RebuildAuditReport {
        root: root.to_path_buf(),
        metadata_path,
        report_path: report_path.clone(),
        contract_receipts_path,
        broken_symlink_receipts_path,
        actual,
        replay,
        coverage,
        broken_symlink_causes: BrokenSymlinkCauseSummary {
            exhaustive: !broken_symlink_cause_counts_vec
                .iter()
                .any(|entry| entry.cause == BrokenSymlinkCause::Unknown),
            counts: broken_symlink_cause_counts_vec,
        },
        samples,
    };
    let bytes = serde_json::to_vec_pretty(&report)?;
    fs::write(&report_path, bytes)?;
    Ok(report)
}

fn normalized_relative_path(path: &str) -> Option<PathBuf> {
    if path.is_empty() {
        return None;
    }
    let candidate = PathBuf::from(path);
    if candidate.is_absolute() {
        return None;
    }
    if candidate
        .components()
        .any(|component| matches!(component, Component::ParentDir))
    {
        return None;
    }
    if let Some(Component::Normal(name)) = candidate.components().next()
        && matches!(
            name.to_str(),
            Some(".file" | ".nofollow" | ".resolve" | ".vol")
        )
    {
        return None;
    }
    Some(candidate)
}

fn is_internal_artifact(relative: &str) -> bool {
    relative == "_yaa_materialized.jsonl"
        || relative == "_payloadv2_decoded.yaa"
        || relative == "_ban_grapple_audit.json"
        || relative == "_ban_grapple_contract_receipts.json"
        || relative == "_ban_grapple_broken_symlink_receipts.json"
        || relative == "_yaa_xattrs"
        || relative.starts_with("_yaa_xattrs/")
}

fn is_linux_host_mode_artifact(
    file_type: fs::FileType,
    expected_mode: u32,
    actual_mode: u32,
) -> bool {
    if file_type.is_symlink() && actual_mode == 0o777 {
        return true;
    }

    if file_type.is_dir() && actual_mode == normalize_directory_mode_for_linux(expected_mode) {
        return actual_mode != expected_mode;
    }

    false
}

fn normalize_directory_mode_for_linux(mode: u32) -> u32 {
    let owner_has_read_or_write = mode & 0o600 != 0;
    let owner_has_traverse = mode & 0o100 != 0;

    if owner_has_read_or_write && !owner_has_traverse {
        mode | 0o100
    } else {
        mode
    }
}

fn walk_actual_tree(
    root: &Path,
    current: &Path,
    expected_modes: &BTreeMap<String, u32>,
    actual: &mut ActualTreeSummary,
    actual_paths: &mut BTreeSet<String>,
    inaccessible_paths: &mut u64,
    bundle_contract_cache: &mut BTreeMap<String, BundleContractInfo>,
    bundle_executable_contract_missing_producers: &mut u64,
    contract_receipts: &mut Vec<BundleExecutableContractSample>,
    broken_symlink_cause_counts: &mut BTreeMap<BrokenSymlinkCause, u64>,
    broken_symlink_receipts: &mut Vec<BrokenSymlinkReceipt>,
    samples: &mut AuditSamples,
) -> Result<(), AuditError> {
    let read_dir = match fs::read_dir(current) {
        Ok(entries) => entries,
        Err(err) if err.kind() == io::ErrorKind::PermissionDenied => {
            *inaccessible_paths += 1;
            record_inaccessible_sample(root, current, samples);
            return Ok(());
        }
        Err(err) => return Err(AuditError::Io(err)),
    };

    let mut entries = Vec::new();
    for entry in read_dir {
        let entry = match entry {
            Ok(entry) => entry,
            Err(err) if err.kind() == io::ErrorKind::PermissionDenied => {
                *inaccessible_paths += 1;
                record_inaccessible_sample(root, current, samples);
                continue;
            }
            Err(err) => return Err(AuditError::Io(err)),
        };
        entries.push(entry);
    }
    entries.sort_by(|left, right| left.path().cmp(&right.path()));

    for entry in entries {
        let path = entry.path();
        let relative = path
            .strip_prefix(root)
            .map_err(io::Error::other)?
            .to_string_lossy()
            .to_string();
        if is_internal_artifact(&relative) {
            continue;
        }

        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(err) if err.kind() == io::ErrorKind::PermissionDenied => {
                *inaccessible_paths += 1;
                record_inaccessible_sample(root, &path, samples);
                continue;
            }
            Err(err) => return Err(AuditError::Io(err)),
        };

        actual_paths.insert(relative.clone());
        let file_type = metadata.file_type();
        if file_type.is_dir() {
            actual.directories += 1;
        } else if file_type.is_file() {
            actual.files += 1;
            actual.total_bytes = actual.total_bytes.saturating_add(metadata.len());
        } else if file_type.is_symlink() {
            actual.symlinks += 1;
            match fs::read_link(&path) {
                Ok(target) => {
                    let resolved = if target.is_absolute() {
                        target.clone()
                    } else {
                        path.parent().unwrap_or(root).join(&target)
                    };
                    if !resolved.exists() {
                        actual.broken_symlinks += 1;
                        let receipt = classify_broken_symlink_cause(
                            root,
                            &path,
                            &target,
                            bundle_contract_cache,
                        )?;
                        *broken_symlink_cause_counts.entry(receipt.cause).or_insert(0) += 1;
                        broken_symlink_receipts.push(receipt.clone());
                        if samples.broken_symlink_receipts.len() < SAMPLE_LIMIT {
                            samples.broken_symlink_receipts.push(receipt.clone());
                        }
                        if receipt.cause
                            == BrokenSymlinkCause::BundleExecutableContractMissingProducer
                        {
                            *bundle_executable_contract_missing_producers += 1;
                            let sample = BundleExecutableContractSample {
                                path: receipt.path.clone(),
                                bundle: receipt
                                    .bundle
                                    .clone()
                                    .unwrap_or_else(|| "<unknown>".to_string()),
                                declared_executable: receipt
                                    .declared_executable
                                    .clone()
                                    .unwrap_or_else(|| "<unknown>".to_string()),
                            };
                            contract_receipts.push(sample.clone());
                            if samples.bundle_executable_contract_missing_producers.len()
                                < SAMPLE_LIMIT
                            {
                                samples
                                    .bundle_executable_contract_missing_producers
                                    .push(sample);
                            }
                        } else if samples.broken_symlinks.len() < SAMPLE_LIMIT {
                            samples.broken_symlinks.push(relative.clone());
                        }
                    }
                }
                Err(err) if err.kind() == io::ErrorKind::PermissionDenied => {
                    *inaccessible_paths += 1;
                    record_inaccessible_sample(root, &path, samples);
                }
                Err(err) => return Err(AuditError::Io(err)),
            }
        } else {
            actual.other += 1;
        }

        if let Some(expected) = expected_modes.get(&relative) {
            let actual_mode = metadata.mode() & 0o7777;
            if actual_mode == *expected {
                // exact match, nothing to record
            } else if is_linux_host_mode_artifact(file_type, *expected, actual_mode) {
                if samples.mode_host_artifacts.len() < SAMPLE_LIMIT {
                    samples.mode_host_artifacts.push(ModeMismatchSample {
                        path: relative.clone(),
                        expected: *expected,
                        actual: actual_mode,
                    });
                }
            } else if samples.mode_mismatches.len() < SAMPLE_LIMIT {
                samples.mode_mismatches.push(ModeMismatchSample {
                    path: relative.clone(),
                    expected: *expected,
                    actual: actual_mode,
                });
            }
        }

        if file_type.is_dir() {
            walk_actual_tree(
                root,
                &path,
                expected_modes,
                actual,
                actual_paths,
                inaccessible_paths,
                bundle_contract_cache,
                bundle_executable_contract_missing_producers,
                contract_receipts,
                broken_symlink_cause_counts,
                broken_symlink_receipts,
                samples,
            )?;
        }
    }

    Ok(())
}

fn classify_broken_symlink_cause(
    root: &Path,
    path: &Path,
    link_target: &Path,
    cache: &mut BTreeMap<String, BundleContractInfo>,
) -> Result<BrokenSymlinkReceipt, AuditError> {
    let relative = match path.strip_prefix(root) {
        Ok(relative) => relative,
        Err(_) => {
            return Ok(BrokenSymlinkReceipt {
                path: path.display().to_string(),
                target: link_target.display().to_string(),
                cause: BrokenSymlinkCause::Unknown,
                bundle: None,
                declared_executable: None,
            });
        }
    };
    let relative_display = relative.display().to_string();
    let target_display = link_target.display().to_string();
    let leaf_name = match relative.file_name().and_then(|name| name.to_str()) {
        Some(name) => name,
        None => {
            return Ok(BrokenSymlinkReceipt {
                path: relative_display,
                target: target_display,
                cause: BrokenSymlinkCause::Unknown,
                bundle: None,
                declared_executable: None,
            });
        }
    };
    let bundle = deepest_bundle_root(relative);
    let bundle_key = bundle
        .as_ref()
        .map(|bundle| bundle.to_string_lossy().to_string());
    let bundle_info = if let Some(bundle) = bundle.as_ref() {
        let key = bundle.to_string_lossy().to_string();
        match cache.get(&key) {
            Some(value) => value.clone(),
            None => {
                let parsed = load_bundle_contract_info(root, bundle)?;
                cache.insert(key, parsed.clone());
                parsed
            }
        }
    } else {
        BundleContractInfo::default()
    };

    let cause = classify_broken_symlink_cause_kind(
        root,
        &relative_display,
        &target_display,
        leaf_name,
        bundle.as_deref(),
        &bundle_info,
    );

    Ok(BrokenSymlinkReceipt {
        path: relative_display,
        target: target_display,
        cause,
        bundle: bundle_key,
        declared_executable: bundle_info.declared_executable,
    })
}

fn deepest_bundle_root(relative: &Path) -> Option<PathBuf> {
    const BUNDLE_SUFFIXES: &[&str] = &[
        ".framework",
        ".bundle",
        ".axbundle",
        ".qlgenerator",
        ".siriUIBundle",
        ".xpc",
        ".appex",
    ];

    let mut current = PathBuf::new();
    let mut deepest = None;
    for component in relative.components() {
        let Component::Normal(name) = component else {
            continue;
        };
        current.push(name);
        let name = name.to_string_lossy();
        if BUNDLE_SUFFIXES.iter().any(|suffix| name.ends_with(suffix)) {
            deepest = Some(current.clone());
        }
    }
    deepest
}

fn load_bundle_contract_info(
    root: &Path,
    bundle: &Path,
) -> Result<BundleContractInfo, AuditError> {
    let candidates = [
        bundle.join("Versions/A/Resources/Info.plist"),
        bundle.join("Contents/Info.plist"),
        bundle.join("Resources/Info.plist"),
        bundle.join("Info.plist"),
    ];

    for candidate in candidates {
        let full = root.join(&candidate);
        if !full.is_file() {
            continue;
        }
        let plist = PlistValue::from_file(&full)?;
        let Some(dict) = plist.as_dictionary() else {
            continue;
        };
        let executable = dict
            .get("CFBundleExecutable")
            .and_then(PlistValue::as_string)
            .map(|value| value.to_string());
        return Ok(BundleContractInfo {
            declared_executable: executable,
            has_info_plist: true,
        });
    }

    Ok(BundleContractInfo::default())
}

fn classify_broken_symlink_cause_kind(
    root: &Path,
    relative: &str,
    target: &str,
    leaf_name: &str,
    bundle: Option<&Path>,
    bundle_info: &BundleContractInfo,
) -> BrokenSymlinkCause {
    if target.contains("Versions/Current/") || relative.ends_with("/Versions/Current") {
        if bundle.is_some()
            && bundle_info.has_info_plist
            && bundle_info
                .declared_executable
                .as_deref()
                .is_some_and(|declared| declared == leaf_name)
        {
            return BrokenSymlinkCause::BundleExecutableContractMissingProducer;
        }
        if bundle.is_some() && !bundle_info.has_info_plist {
            return BrokenSymlinkCause::BundleContractMetadataUnavailable;
        }
        if matches!(
            leaf_name,
            "PlugIns" | "Frameworks" | "XPCServices" | "Support"
        ) || leaf_name.ends_with(".dylib")
        {
            return BrokenSymlinkCause::BundleStructuralAliasMissingProducer;
        }
        if bundle_info
            .declared_executable
            .as_deref()
            .is_some_and(|declared| declared != leaf_name)
        {
            return BrokenSymlinkCause::BundleDeclaredNameMismatch;
        }
        if bundle.is_some() {
            return BrokenSymlinkCause::BundleStructuralAliasMissingProducer;
        }
    }

    if relative.starts_with("usr/share/firmware/wifi/") {
        return BrokenSymlinkCause::FirmwareAliasMapMissingProducer;
    }

    if relative.starts_with("usr/share/locale/") {
        return BrokenSymlinkCause::LocaleAliasMapMissingProducer;
    }

    if matches!(relative, "var" | "tmp" | "etc") {
        return BrokenSymlinkCause::PrivateRootSubstrateMissing;
    }

    if relative == ".VolumeIcon.icns" || target.contains("System/Volumes/Data/") {
        return BrokenSymlinkCause::DataVolumeSubstrateMissing;
    }

    if target.contains("System/Cryptexes/")
        || target.contains("System/Volumes/Preboot/Cryptexes")
        || target.starts_with("/System/Cryptexes/")
    {
        return BrokenSymlinkCause::CryptexRuntimeSubstrateMissing;
    }

    if target.starts_with("/AppleInternal/") {
        return BrokenSymlinkCause::AppleinternalExpectedExternal;
    }

    if relative.starts_with("System/Library/Templates/Data/") {
        return BrokenSymlinkCause::TemplateDataOrPairedVolumeSubstrateMissing;
    }

    if target.starts_with("/var/") || relative == "usr/share/zoneinfo" {
        return BrokenSymlinkCause::HostOrPairedRootSubstrateMissing;
    }

    if Path::new(target).is_absolute() {
        return BrokenSymlinkCause::HostRootAbsoluteExpectedExternal;
    }

    let target_parent = root.join(relative).parent().unwrap_or(root).join(target);
    if !target_parent.parent().is_some_and(Path::exists) {
        return BrokenSymlinkCause::CrossTreeParentChainMissing;
    }

    if relative.starts_with("System/Applications/") && leaf_name == "PkgInfo" {
        return BrokenSymlinkCause::PackagingAliasMissingProducer;
    }

    if relative.starts_with("usr/lib/") || leaf_name.ends_with(".dylib") {
        return BrokenSymlinkCause::LibraryAliasMissingProducer;
    }

    if relative.starts_with("System/Library/Frameworks/")
        || relative.starts_with("System/Library/PrivateFrameworks/")
        || relative.starts_with("System/iOSSupport/System/Library/")
    {
        return BrokenSymlinkCause::FrameworkRelativeAliasMissingProducer;
    }

    BrokenSymlinkCause::Unknown
}

fn record_inaccessible_sample(root: &Path, path: &Path, samples: &mut AuditSamples) {
    if samples.inaccessible_paths.len() >= SAMPLE_LIMIT {
        return;
    }
    let relative = path
        .strip_prefix(root)
        .unwrap_or(path)
        .display()
        .to_string();
    samples.inaccessible_paths.push(relative);
}

fn sort_contract_receipts(receipts: &mut [BundleExecutableContractSample]) {
    receipts.sort_by(|left, right| {
        left.path
            .cmp(&right.path)
            .then_with(|| left.bundle.cmp(&right.bundle))
            .then_with(|| left.declared_executable.cmp(&right.declared_executable))
    });
}

fn sort_broken_symlink_receipts(receipts: &mut [BrokenSymlinkReceipt]) {
    receipts.sort_by(|left, right| {
        left.path
            .cmp(&right.path)
            .then_with(|| left.target.cmp(&right.target))
            .then_with(|| left.cause.cmp(&right.cause))
            .then_with(|| left.bundle.cmp(&right.bundle))
            .then_with(|| left.declared_executable.cmp(&right.declared_executable))
    });
}

fn sort_mode_mismatch_samples(samples: &mut [ModeMismatchSample]) {
    samples.sort_by(|left, right| {
        left.path
            .cmp(&right.path)
            .then_with(|| left.expected.cmp(&right.expected))
            .then_with(|| left.actual.cmp(&right.actual))
    });
}

fn sort_audit_samples(samples: &mut AuditSamples) {
    samples.missing_from_tree.sort();
    samples.extra_in_tree.sort();
    sort_mode_mismatch_samples(&mut samples.mode_mismatches);
    sort_mode_mismatch_samples(&mut samples.mode_host_artifacts);
    samples.broken_symlinks.sort();
    sort_broken_symlink_receipts(&mut samples.broken_symlink_receipts);
    sort_contract_receipts(&mut samples.bundle_executable_contract_missing_producers);
    samples.inaccessible_paths.sort();
    samples.xattr_sidecars_missing.sort();
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::fs;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::{BrokenSymlinkCause, audit_rebuild, classify_broken_symlink_cause};

    fn temp_dir(label: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time should advance")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("ban-grapple-{label}-{unique}"));
        fs::create_dir_all(&path).expect("temp dir should be created");
        path
    }

    fn write_info_plist(path: &Path, executable: &str) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("plist parent dirs");
        }
        fs::write(
            path,
            format!(
                r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleExecutable</key>
    <string>{}</string>
</dict>
</plist>
"#,
                executable
            ),
        )
        .expect("info plist");
    }

    fn create_broken_symlink(root: &Path, relative: &str, target: &str) -> PathBuf {
        let path = root.join(relative);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("symlink parent dirs");
        }
        symlink(target, &path).expect("broken symlink");
        path
    }

    #[test]
    fn audit_rebuild_reports_expected_counts() {
        let root = temp_dir("audit");
        fs::create_dir_all(root.join("System/Applications")).expect("dirs");
        fs::write(root.join("System/Applications/Test.app"), b"app").expect("file");
        symlink("private/var", root.join("var")).expect("symlink");
        fs::create_dir_all(root.join("private")).expect("private dir");
        fs::create_dir_all(root.join("_yaa_xattrs")).expect("xattrs");
        fs::set_permissions(root.join("System"), fs::Permissions::from_mode(0o755))
            .expect("system permissions");
        fs::set_permissions(
            root.join("System/Applications"),
            fs::Permissions::from_mode(0o755),
        )
        .expect("applications permissions");
        fs::write(root.join("_yaa_xattrs/0000000000000001-00.bin"), b"xattr").expect("xattr file");
        fs::write(
            root.join("_yaa_materialized.jsonl"),
            concat!(
                r#"{"path":"System","object_type":"directory","mode":493,"uid":0,"gid":0,"payloads":[]}"#,
                "\n",
                r#"{"path":"System/Applications","object_type":"directory","mode":493,"uid":0,"gid":0,"payloads":[]}"#,
                "\n",
                r#"{"path":"System/Applications/Test.app","object_type":"file","mode":420,"uid":0,"gid":0,"payloads":[]}"#,
                "\n",
                r#"{"path":"var","object_type":"link","mode":511,"uid":0,"gid":0,"payloads":[{"tag":"XATA","sidecar_path":"__ROOT__/_yaa_xattrs/0000000000000001-00.bin"}]}"#,
                "\n"
            )
            .replace("__ROOT__", &root.display().to_string()),
        )
        .expect("metadata");

        fs::set_permissions(
            root.join("System/Applications/Test.app"),
            fs::Permissions::from_mode(0o600),
        )
        .expect("permissions");

        let report = audit_rebuild(&root).expect("audit should succeed");
        assert_eq!(report.actual.directories, 3);
        assert_eq!(report.actual.files, 1);
        assert_eq!(report.actual.symlinks, 1);
        assert_eq!(report.replay.records, 4);
        assert_eq!(report.replay.records_with_xattr_payloads, 1);
        assert_eq!(report.replay.xattr_sidecars_present, 1);
        assert_eq!(report.coverage.missing_from_tree, 0);
        assert_eq!(report.coverage.mode_mismatches, 1);
        assert_eq!(report.coverage.mode_host_artifacts, 0);
        assert!(
            report
                .samples
                .mode_mismatches
                .iter()
                .any(|sample| sample.path == "System/Applications/Test.app")
        );
        assert!(report.report_path.is_file());

        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn audit_rebuild_classifies_linux_symlink_mode_noise_as_host_artifact() {
        let root = temp_dir("audit-symlink-host");
        fs::create_dir_all(root.join("_yaa_xattrs")).expect("xattrs");
        symlink("private/var", root.join("var")).expect("symlink");
        fs::create_dir_all(root.join("private")).expect("private dir");
        fs::write(
            root.join("_yaa_materialized.jsonl"),
            r#"{"path":"var","object_type":"link","mode":493,"uid":0,"gid":0,"payloads":[]}"#,
        )
        .expect("metadata");

        let report = audit_rebuild(&root).expect("audit should succeed");
        assert_eq!(report.coverage.mode_mismatches, 0);
        assert_eq!(report.coverage.mode_host_artifacts, 1);
        assert_eq!(report.samples.mode_host_artifacts.len(), 1);
        assert_eq!(report.samples.mode_host_artifacts[0].path, "var");

        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn audit_rebuild_classifies_directory_traversal_normalization_as_host_artifact() {
        let root = temp_dir("audit-dir-host");
        fs::create_dir_all(root.join("System/secure")).expect("dirs");
        fs::write(
            root.join("_yaa_materialized.jsonl"),
            concat!(
                r#"{"path":"System","object_type":"directory","mode":493,"uid":0,"gid":0,"payloads":[]}"#,
                "\n",
                r#"{"path":"System/secure","object_type":"directory","mode":384,"uid":0,"gid":0,"payloads":[]}"#,
                "\n"
            ),
        )
        .expect("metadata");
        fs::set_permissions(root.join("System"), fs::Permissions::from_mode(0o755))
            .expect("system permissions");
        fs::set_permissions(root.join("System/secure"), fs::Permissions::from_mode(0o700))
            .expect("secure permissions");

        let report = audit_rebuild(&root).expect("audit should succeed");
        assert_eq!(report.coverage.mode_mismatches, 0);
        assert_eq!(report.coverage.mode_host_artifacts, 1);
        assert_eq!(report.samples.mode_host_artifacts.len(), 1);
        assert_eq!(report.samples.mode_host_artifacts[0].path, "System/secure");

        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn audit_rebuild_classifies_bundle_executable_contract_gap() {
        let root = temp_dir("audit-bundle-contract");
        fs::create_dir_all(root.join("System/Library/Frameworks/Test.framework/Versions/A/Resources"))
            .expect("framework dirs");
        symlink(
            "A",
            root.join("System/Library/Frameworks/Test.framework/Versions/Current"),
        )
        .expect("current symlink");
        symlink(
            "Versions/Current/Test",
            root.join("System/Library/Frameworks/Test.framework/Test"),
        )
        .expect("framework leaf symlink");
        fs::write(
            root.join("System/Library/Frameworks/Test.framework/Versions/A/Resources/Info.plist"),
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleExecutable</key>
    <string>Test</string>
</dict>
</plist>
"#,
        )
        .expect("info plist");
        fs::write(
            root.join("_yaa_materialized.jsonl"),
            concat!(
                r#"{"path":"System","object_type":"directory","mode":493,"uid":0,"gid":0,"payloads":[]}"#,
                "\n",
                r#"{"path":"System/Library","object_type":"directory","mode":493,"uid":0,"gid":0,"payloads":[]}"#,
                "\n",
                r#"{"path":"System/Library/Frameworks","object_type":"directory","mode":493,"uid":0,"gid":0,"payloads":[]}"#,
                "\n",
                r#"{"path":"System/Library/Frameworks/Test.framework","object_type":"directory","mode":493,"uid":0,"gid":0,"payloads":[]}"#,
                "\n",
                r#"{"path":"System/Library/Frameworks/Test.framework/Versions","object_type":"directory","mode":493,"uid":0,"gid":0,"payloads":[]}"#,
                "\n",
                r#"{"path":"System/Library/Frameworks/Test.framework/Versions/A","object_type":"directory","mode":493,"uid":0,"gid":0,"payloads":[]}"#,
                "\n",
                r#"{"path":"System/Library/Frameworks/Test.framework/Versions/A/Resources","object_type":"directory","mode":493,"uid":0,"gid":0,"payloads":[]}"#,
                "\n",
                r#"{"path":"System/Library/Frameworks/Test.framework/Versions/A/Resources/Info.plist","object_type":"file","mode":420,"uid":0,"gid":0,"payloads":[]}"#,
                "\n",
                r#"{"path":"System/Library/Frameworks/Test.framework/Versions/Current","object_type":"link","mode":511,"uid":0,"gid":0,"payloads":[]}"#,
                "\n",
                r#"{"path":"System/Library/Frameworks/Test.framework/Test","object_type":"link","mode":511,"uid":0,"gid":0,"payloads":[]}"#,
                "\n"
            ),
        )
        .expect("metadata");

        let report = audit_rebuild(&root).expect("audit should succeed");
        assert_eq!(report.actual.broken_symlinks, 1);
        assert_eq!(
            report.coverage.bundle_executable_contract_missing_producers,
            1
        );
        assert!(report.broken_symlink_causes.exhaustive);
        assert_eq!(report.broken_symlink_causes.counts[0].cause, BrokenSymlinkCause::BundleExecutableContractMissingProducer);
        assert_eq!(report.broken_symlink_causes.counts[0].count, 1);
        assert!(report.samples.broken_symlinks.is_empty());
        assert_eq!(report.samples.broken_symlink_receipts.len(), 1);
        assert_eq!(
            report.samples.bundle_executable_contract_missing_producers.len(),
            1
        );
        assert_eq!(
            report.samples.bundle_executable_contract_missing_producers[0].path,
            "System/Library/Frameworks/Test.framework/Test"
        );
        assert_eq!(
            report.samples.bundle_executable_contract_missing_producers[0]
                .declared_executable,
            "Test"
        );

        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn broken_symlink_classifier_acceptance_buckets() {
        struct Case {
            label: &'static str,
            relative: &'static str,
            target: &'static str,
            expected: BrokenSymlinkCause,
            setup: fn(&Path),
        }

        fn no_setup(_: &Path) {}

        fn setup_bundle_contract(root: &Path) {
            write_info_plist(
                &root.join("System/Library/Frameworks/Test.framework/Versions/A/Resources/Info.plist"),
                "Test",
            );
        }

        fn setup_bundle_structural(root: &Path) {
            write_info_plist(
                &root.join("System/Library/PrivateFrameworks/FinderKit.framework/Versions/A/Resources/Info.plist"),
                "FinderKit",
            );
        }

        fn setup_bundle_no_info(root: &Path) {
            fs::create_dir_all(root.join("System/Library/Frameworks/DriverKit.framework"))
                .expect("bundle dirs");
        }

        fn setup_bundle_mismatch(root: &Path) {
            write_info_plist(
                &root.join("System/Library/PrivateFrameworks/StoreServices.framework/Versions/A/Resources/Info.plist"),
                "iTunesStore",
            );
        }

        fn setup_framework_relative(root: &Path) {
            fs::create_dir_all(root.join("System/Library/Frameworks")).expect("framework dir");
            fs::create_dir_all(root.join("System/Library/PrivateFrameworks"))
                .expect("private framework dir");
        }

        let cases = [
            Case {
                label: "bundle_executable_contract_missing_producer",
                relative: "System/Library/Frameworks/Test.framework/Test",
                target: "Versions/Current/Test",
                expected: BrokenSymlinkCause::BundleExecutableContractMissingProducer,
                setup: setup_bundle_contract,
            },
            Case {
                label: "firmware_alias_map_missing_producer",
                relative: "usr/share/firmware/wifi/C-4377__s-B3/P-formosa-X3_M-SPPR_V-m__m-4.5.txt",
                target: "P-formosa_M-SPPR_V-m__m-4.5.txt",
                expected: BrokenSymlinkCause::FirmwareAliasMapMissingProducer,
                setup: no_setup,
            },
            Case {
                label: "locale_alias_map_missing_producer",
                relative: "usr/share/locale/da_DK.ISO8859-15/LC_NUMERIC",
                target: "../da_DK.ISO8859-1/LC_NUMERIC",
                expected: BrokenSymlinkCause::LocaleAliasMapMissingProducer,
                setup: no_setup,
            },
            Case {
                label: "host_root_absolute_expected_external",
                relative: "System/Library/CoreServices/DefaultDesktop.heic",
                target: "/System/Library/Desktop Pictures/Ventura Graphic.heic",
                expected: BrokenSymlinkCause::HostRootAbsoluteExpectedExternal,
                setup: no_setup,
            },
            Case {
                label: "cryptex_runtime_substrate_missing",
                relative: "System/Cryptexes/App",
                target: "../../System/Volumes/Preboot/Cryptexes/App",
                expected: BrokenSymlinkCause::CryptexRuntimeSubstrateMissing,
                setup: no_setup,
            },
            Case {
                label: "bundle_structural_alias_missing_producer",
                relative: "System/Library/PrivateFrameworks/FinderKit.framework/XPCServices",
                target: "Versions/Current/XPCServices",
                expected: BrokenSymlinkCause::BundleStructuralAliasMissingProducer,
                setup: setup_bundle_structural,
            },
            Case {
                label: "cross_tree_parent_chain_missing",
                relative: "usr/X11",
                target: "../private/var/select/X11",
                expected: BrokenSymlinkCause::CrossTreeParentChainMissing,
                setup: no_setup,
            },
            Case {
                label: "framework_relative_alias_missing_producer",
                relative: "System/Library/PrivateFrameworks/AuthenticationServices.framework",
                target: "../Frameworks/AuthenticationServices.framework",
                expected: BrokenSymlinkCause::FrameworkRelativeAliasMissingProducer,
                setup: setup_framework_relative,
            },
            Case {
                label: "bundle_contract_metadata_unavailable",
                relative: "System/Library/Frameworks/DriverKit.framework/DriverKit",
                target: "Versions/Current/DriverKit",
                expected: BrokenSymlinkCause::BundleContractMetadataUnavailable,
                setup: setup_bundle_no_info,
            },
            Case {
                label: "library_alias_missing_producer",
                relative: "usr/lib/libpcre2-8.dylib",
                target: "libpcre2-8.0.dylib",
                expected: BrokenSymlinkCause::LibraryAliasMissingProducer,
                setup: no_setup,
            },
            Case {
                label: "template_data_or_paired_volume_substrate_missing",
                relative: "System/Library/Templates/Data/private/etc/localtime",
                target: "/var/db/timezone/zoneinfo/US/Pacific",
                expected: BrokenSymlinkCause::TemplateDataOrPairedVolumeSubstrateMissing,
                setup: no_setup,
            },
            Case {
                label: "bundle_declared_name_mismatch",
                relative: "System/Library/PrivateFrameworks/StoreServices.framework/StoreServices",
                target: "Versions/Current/StoreServices",
                expected: BrokenSymlinkCause::BundleDeclaredNameMismatch,
                setup: setup_bundle_mismatch,
            },
            Case {
                label: "private_root_substrate_missing",
                relative: "var",
                target: "private/var",
                expected: BrokenSymlinkCause::PrivateRootSubstrateMissing,
                setup: no_setup,
            },
            Case {
                label: "appleinternal_expected_external",
                relative:
                    "System/Library/Templates/Data/System/Library/CoreServices/CoreTypes.bundle/Contents/Library/_.bundle",
                target: "/AppleInternal/CoreServices/CoreTypes/AppleInternalTypes.bundle",
                expected: BrokenSymlinkCause::AppleinternalExpectedExternal,
                setup: no_setup,
            },
            Case {
                label: "data_volume_substrate_missing",
                relative: ".VolumeIcon.icns",
                target: "System/Volumes/Data/.VolumeIcon.icns",
                expected: BrokenSymlinkCause::DataVolumeSubstrateMissing,
                setup: no_setup,
            },
            Case {
                label: "packaging_alias_missing_producer",
                relative:
                    "System/Applications/Utilities/VoiceOver Utility.app/Contents/OtherBinaries/VoiceOverUtilityCacheBuilder.app/Contents/PkgInfo",
                target: "../../../PkgInfo",
                expected: BrokenSymlinkCause::PackagingAliasMissingProducer,
                setup: no_setup,
            },
            Case {
                label: "host_or_paired_root_substrate_missing",
                relative: "usr/share/zoneinfo",
                target: "/var/db/timezone/zoneinfo",
                expected: BrokenSymlinkCause::HostOrPairedRootSubstrateMissing,
                setup: no_setup,
            },
        ];

        for case in cases {
            let root = temp_dir(case.label);
            (case.setup)(&root);
            let symlink_path = create_broken_symlink(&root, case.relative, case.target);
            let receipt = classify_broken_symlink_cause(
                &root,
                &symlink_path,
                Path::new(case.target),
                &mut BTreeMap::new(),
            )
            .expect("classification should succeed");
            assert_eq!(receipt.cause, case.expected, "case {}", case.label);
            fs::remove_dir_all(root).expect("cleanup");
        }
    }

    #[test]
    fn audit_rebuild_emits_deterministic_receipts() {
        let root = temp_dir("audit-deterministic-receipts");
        fs::create_dir_all(root.join("System/Library/Frameworks/Test.framework/Versions/A/Resources"))
            .expect("framework dirs");
        fs::create_dir_all(root.join("usr/share/locale")).expect("locale dir");
        fs::create_dir_all(root.join("usr/share/locale/en_DK")).expect("locale leaf dir");
        fs::create_dir_all(root.join("usr/share/firmware/wifi")).expect("firmware dir");

        write_info_plist(
            &root.join("System/Library/Frameworks/Test.framework/Versions/A/Resources/Info.plist"),
            "Test",
        );
        symlink(
            "A",
            root.join("System/Library/Frameworks/Test.framework/Versions/Current"),
        )
        .expect("current symlink");
        symlink(
            "Versions/Current/Test",
            root.join("System/Library/Frameworks/Test.framework/Test"),
        )
        .expect("framework symlink");
        symlink(
            "../da/LC_TIME",
            root.join("usr/share/locale/en_DK/LC_TIME"),
        )
        .expect("locale symlink");
        symlink(
            "P-main.txt",
            root.join("usr/share/firmware/wifi/P-alias.txt"),
        )
        .expect("firmware symlink");

        fs::write(
            root.join("_yaa_materialized.jsonl"),
            concat!(
                r#"{"path":"System","object_type":"directory","mode":493,"uid":0,"gid":0,"payloads":[]}"#,
                "\n",
                r#"{"path":"System/Library","object_type":"directory","mode":493,"uid":0,"gid":0,"payloads":[]}"#,
                "\n",
                r#"{"path":"System/Library/Frameworks","object_type":"directory","mode":493,"uid":0,"gid":0,"payloads":[]}"#,
                "\n",
                r#"{"path":"System/Library/Frameworks/Test.framework","object_type":"directory","mode":493,"uid":0,"gid":0,"payloads":[]}"#,
                "\n",
                r#"{"path":"System/Library/Frameworks/Test.framework/Versions","object_type":"directory","mode":493,"uid":0,"gid":0,"payloads":[]}"#,
                "\n",
                r#"{"path":"System/Library/Frameworks/Test.framework/Versions/A","object_type":"directory","mode":493,"uid":0,"gid":0,"payloads":[]}"#,
                "\n",
                r#"{"path":"System/Library/Frameworks/Test.framework/Versions/A/Resources","object_type":"directory","mode":493,"uid":0,"gid":0,"payloads":[]}"#,
                "\n",
                r#"{"path":"System/Library/Frameworks/Test.framework/Versions/A/Resources/Info.plist","object_type":"file","mode":420,"uid":0,"gid":0,"payloads":[]}"#,
                "\n",
                r#"{"path":"System/Library/Frameworks/Test.framework/Versions/Current","object_type":"link","mode":511,"uid":0,"gid":0,"payloads":[]}"#,
                "\n",
                r#"{"path":"System/Library/Frameworks/Test.framework/Test","object_type":"link","mode":511,"uid":0,"gid":0,"payloads":[]}"#,
                "\n",
                r#"{"path":"usr","object_type":"directory","mode":493,"uid":0,"gid":0,"payloads":[]}"#,
                "\n",
                r#"{"path":"usr/share","object_type":"directory","mode":493,"uid":0,"gid":0,"payloads":[]}"#,
                "\n",
                r#"{"path":"usr/share/locale","object_type":"directory","mode":493,"uid":0,"gid":0,"payloads":[]}"#,
                "\n",
                r#"{"path":"usr/share/locale/en_DK/LC_TIME","object_type":"link","mode":511,"uid":0,"gid":0,"payloads":[]}"#,
                "\n",
                r#"{"path":"usr/share/firmware","object_type":"directory","mode":493,"uid":0,"gid":0,"payloads":[]}"#,
                "\n",
                r#"{"path":"usr/share/firmware/wifi","object_type":"directory","mode":493,"uid":0,"gid":0,"payloads":[]}"#,
                "\n",
                r#"{"path":"usr/share/firmware/wifi/P-alias.txt","object_type":"link","mode":511,"uid":0,"gid":0,"payloads":[]}"#,
                "\n"
            ),
        )
        .expect("metadata");

        let first = audit_rebuild(&root).expect("first audit should succeed");
        let first_report = fs::read(&first.report_path).expect("first report bytes");
        let first_contracts =
            fs::read(&first.contract_receipts_path).expect("first contract receipt bytes");
        let first_broken = fs::read(&first.broken_symlink_receipts_path)
            .expect("first broken symlink receipt bytes");

        let second = audit_rebuild(&root).expect("second audit should succeed");
        let second_report = fs::read(&second.report_path).expect("second report bytes");
        let second_contracts =
            fs::read(&second.contract_receipts_path).expect("second contract receipt bytes");
        let second_broken = fs::read(&second.broken_symlink_receipts_path)
            .expect("second broken symlink receipt bytes");

        assert_eq!(first_report, second_report);
        assert_eq!(first_contracts, second_contracts);
        assert_eq!(first_broken, second_broken);

        fs::remove_dir_all(root).expect("cleanup");
    }
}
