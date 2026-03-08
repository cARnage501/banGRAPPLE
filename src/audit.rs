use std::collections::{BTreeMap, HashSet};
use std::fmt;
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader};
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};

const SAMPLE_LIMIT: usize = 25;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RebuildAuditReport {
    pub root: PathBuf,
    pub metadata_path: PathBuf,
    pub report_path: PathBuf,
    pub actual: ActualTreeSummary,
    pub replay: ReplaySummary,
    pub coverage: CoverageSummary,
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
    pub inaccessible_paths: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Default)]
pub struct AuditSamples {
    pub missing_from_tree: Vec<String>,
    pub extra_in_tree: Vec<String>,
    pub mode_mismatches: Vec<ModeMismatchSample>,
    pub broken_symlinks: Vec<String>,
    pub inaccessible_paths: Vec<String>,
    pub xattr_sidecars_missing: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ModeMismatchSample {
    pub path: String,
    pub expected: u32,
    pub actual: u32,
}

#[derive(Debug)]
pub enum AuditError {
    Io(io::Error),
    MissingMetadata(PathBuf),
    InvalidRoot(PathBuf),
    Json(serde_json::Error),
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

pub fn audit_rebuild(root: &Path) -> Result<RebuildAuditReport, AuditError> {
    let metadata_path = root.join("_yaa_materialized.jsonl");
    if !root.is_dir() {
        return Err(AuditError::InvalidRoot(root.to_path_buf()));
    }
    if !metadata_path.is_file() {
        return Err(AuditError::MissingMetadata(metadata_path));
    }

    let mut replay = ReplaySummary::default();
    let mut replay_paths = HashSet::new();
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
    let mut actual_paths = HashSet::new();
    let mut inaccessible_paths = 0u64;
    walk_actual_tree(
        root,
        root,
        &expected_modes,
        &mut actual,
        &mut actual_paths,
        &mut inaccessible_paths,
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
    for (path, expected) in &expected_modes {
        let full = root.join(path);
        match fs::symlink_metadata(&full) {
            Ok(metadata) => {
                let actual_mode = metadata.mode() & 0o7777;
                if actual_mode != *expected {
                    mode_mismatches += 1;
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
        inaccessible_paths,
    };

    let report_path = root.join("_ban_grapple_audit.json");
    let report = RebuildAuditReport {
        root: root.to_path_buf(),
        metadata_path,
        report_path: report_path.clone(),
        actual,
        replay,
        coverage,
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
        || relative == "_yaa_xattrs"
        || relative.starts_with("_yaa_xattrs/")
}

fn walk_actual_tree(
    root: &Path,
    current: &Path,
    expected_modes: &BTreeMap<String, u32>,
    actual: &mut ActualTreeSummary,
    actual_paths: &mut HashSet<String>,
    inaccessible_paths: &mut u64,
    samples: &mut AuditSamples,
) -> Result<(), AuditError> {
    let entries = match fs::read_dir(current) {
        Ok(entries) => entries,
        Err(err) if err.kind() == io::ErrorKind::PermissionDenied => {
            *inaccessible_paths += 1;
            record_inaccessible_sample(root, current, samples);
            return Ok(());
        }
        Err(err) => return Err(AuditError::Io(err)),
    };

    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(err) if err.kind() == io::ErrorKind::PermissionDenied => {
                *inaccessible_paths += 1;
                record_inaccessible_sample(root, current, samples);
                continue;
            }
            Err(err) => return Err(AuditError::Io(err)),
        };
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
                        target
                    } else {
                        path.parent().unwrap_or(root).join(&target)
                    };
                    if !resolved.exists() {
                        actual.broken_symlinks += 1;
                        if samples.broken_symlinks.len() < SAMPLE_LIMIT {
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
            if actual_mode != *expected && samples.mode_mismatches.len() < SAMPLE_LIMIT {
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
                samples,
            )?;
        }
    }

    Ok(())
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

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::audit_rebuild;

    fn temp_dir(label: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time should advance")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("ban-grapple-{label}-{unique}"));
        fs::create_dir_all(&path).expect("temp dir should be created");
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
}
