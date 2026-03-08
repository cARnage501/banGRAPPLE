use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::audit::{RebuildAuditReport, audit_rebuild};
use crate::patch::{PatchApplicationLaw, decode_patch_layer};
use crate::substrate::{RuntimeSubstrateKind, inspect_runtime_substrate};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComposeOptions {
    pub asset_root: Option<PathBuf>,
    pub metadata_root: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComposedImageArtifact {
    pub output_root: PathBuf,
    pub manifest_path: PathBuf,
    pub manifest: ComposedImageArtifactManifest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ComposedImageArtifactManifest {
    pub schema_version: u32,
    pub artifact_kind: String,
    pub bootability: String,
    pub source_rebuild_root: String,
    pub source_metadata_path: String,
    pub source_metadata_sha256: String,
    pub audit_summary: ComposedAuditSummary,
    pub substrate: Option<ComposedSubstrateSummary>,
    pub bundled_files: Vec<ComposedBundledFile>,
    pub blockers: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ComposedAuditSummary {
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ComposedSubstrateSummary {
    pub input_root: String,
    pub asset_root: String,
    pub payloadv2_root: String,
    pub kind: String,
    pub stageable_base_system_present: bool,
    pub basesystem_x86_patch_present: bool,
    pub basesystem_arm64_patch_present: bool,
    pub cryptex_image_patch_count: usize,
    pub suramdisk_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ComposedBundledFile {
    pub role: String,
    pub relative_path: String,
    pub sha256: String,
}

#[derive(Debug)]
pub enum ComposeError {
    Io(io::Error),
    Audit(crate::audit::AuditError),
    Substrate(crate::substrate::RuntimeSubstrateError),
    Patch(crate::patch::PatchError),
    Json(serde_json::Error),
}

impl fmt::Display for ComposeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => write!(f, "{err}"),
            Self::Audit(err) => write!(f, "{err}"),
            Self::Substrate(err) => write!(f, "{err}"),
            Self::Patch(err) => write!(f, "{err}"),
            Self::Json(err) => write!(f, "{err}"),
        }
    }
}

impl From<io::Error> for ComposeError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<crate::audit::AuditError> for ComposeError {
    fn from(value: crate::audit::AuditError) -> Self {
        Self::Audit(value)
    }
}

impl From<crate::substrate::RuntimeSubstrateError> for ComposeError {
    fn from(value: crate::substrate::RuntimeSubstrateError) -> Self {
        Self::Substrate(value)
    }
}

impl From<crate::patch::PatchError> for ComposeError {
    fn from(value: crate::patch::PatchError) -> Self {
        Self::Patch(value)
    }
}

impl From<serde_json::Error> for ComposeError {
    fn from(value: serde_json::Error) -> Self {
        Self::Json(value)
    }
}

pub fn compose_image_artifact(
    rebuilt_root: &Path,
    output_root: &Path,
    options: &ComposeOptions,
) -> Result<ComposedImageArtifact, ComposeError> {
    fs::create_dir_all(output_root)?;

    let audit = audit_rebuild(rebuilt_root)?;
    let substrate = options
        .asset_root
        .as_deref()
        .map(|asset_root| inspect_runtime_substrate(asset_root, options.metadata_root.as_deref()))
        .transpose()?;

    let mut bundled_files = vec![
        bundle_file(
            &audit.report_path,
            output_root,
            "audit_report",
            "audit.json",
        )?,
        bundle_file(
            &audit.contract_receipts_path,
            output_root,
            "contract_receipts",
            "contract_receipts.json",
        )?,
        bundle_file(
            &audit.broken_symlink_receipts_path,
            output_root,
            "broken_symlink_receipts",
            "broken_symlink_receipts.json",
        )?,
    ];

    let mut materialized_basesystem_images = 0usize;
    if let Some(report) = substrate.as_ref() {
        if report.base_system_evidence.x86_patch.exists
            && report.base_system_evidence.x86_patch.starts_with_bxdiff
        {
            bundled_files.push(materialize_patch_image(
                &report.base_system_evidence.x86_patch.path,
                output_root,
                "materialized_basesystem_x86_64",
                "runtime_substrate/BaseSystem.x86_64.dmg",
            )?);
            materialized_basesystem_images += 1;
        }
        if report.base_system_evidence.arm64_patch.exists
            && report.base_system_evidence.arm64_patch.starts_with_bxdiff
        {
            bundled_files.push(materialize_patch_image(
                &report.base_system_evidence.arm64_patch.path,
                output_root,
                "materialized_basesystem_arm64e",
                "runtime_substrate/BaseSystem.arm64e.dmg",
            )?);
            materialized_basesystem_images += 1;
        }
        for patch in &report.image_patches {
            if patch.starts_with_ridiff {
                bundled_files.push(bundle_decoded_patch_program(
                    &patch.path,
                    output_root,
                    &format!("decoded_cryptex_program_{}", patch.name),
                    &format!("runtime_substrate/{}.ridiff.bin", patch.name),
                    PatchApplicationLaw::OrderedExtentProgram,
                )?);
            }
        }
    }

    let source_metadata_sha256 = file_sha256_hex(&audit.metadata_path)?;
    let substrate_summary = substrate.as_ref().map(|report| ComposedSubstrateSummary {
        input_root: report.input_root.display().to_string(),
        asset_root: report.asset_root.display().to_string(),
        payloadv2_root: report.payloadv2_root.display().to_string(),
        kind: report.substrate_kind.label().to_string(),
        stageable_base_system_present: report.runtime_assets.base_system_pair.is_some(),
        basesystem_x86_patch_present: report.base_system_evidence.x86_patch.exists,
        basesystem_arm64_patch_present: report.base_system_evidence.arm64_patch.exists,
        cryptex_image_patch_count: report.image_patches.len(),
        suramdisk_count: report.runtime_assets.suramdisk_pairs.len(),
    });

    let blockers =
        composition_blockers(&audit, substrate_summary.as_ref(), materialized_basesystem_images);
    let manifest = ComposedImageArtifactManifest {
        schema_version: 1,
        artifact_kind: "conservative-image-artifact-bundle".to_string(),
        bootability: "not-bootable".to_string(),
        source_rebuild_root: rebuilt_root.display().to_string(),
        source_metadata_path: audit.metadata_path.display().to_string(),
        source_metadata_sha256,
        audit_summary: ComposedAuditSummary {
            replay_paths: audit.coverage.replay_paths,
            actual_paths: audit.coverage.actual_paths,
            missing_from_tree: audit.coverage.missing_from_tree,
            extra_in_tree: audit.coverage.extra_in_tree,
            mode_mismatches: audit.coverage.mode_mismatches,
            mode_host_artifacts: audit.coverage.mode_host_artifacts,
            bundle_executable_contract_missing_producers: audit
                .coverage
                .bundle_executable_contract_missing_producers,
            residual_broken_symlinks: audit.coverage.residual_broken_symlinks,
            inaccessible_paths: audit.coverage.inaccessible_paths,
        },
        substrate: substrate_summary,
        bundled_files,
        blockers,
    };

    let manifest_path = output_root.join("artifact.json");
    fs::write(&manifest_path, serde_json::to_vec_pretty(&manifest)?)?;

    Ok(ComposedImageArtifact {
        output_root: output_root.to_path_buf(),
        manifest_path,
        manifest,
    })
}

fn bundle_file(
    source: &Path,
    output_root: &Path,
    role: &str,
    relative_name: &str,
) -> Result<ComposedBundledFile, ComposeError> {
    let destination = output_root.join(relative_name);
    fs::copy(source, &destination)?;
    Ok(ComposedBundledFile {
        role: role.to_string(),
        relative_path: relative_name.to_string(),
        sha256: file_sha256_hex(&destination)?,
    })
}

fn materialize_patch_image(
    source_patch: &Path,
    output_root: &Path,
    role: &str,
    relative_name: &str,
) -> Result<ComposedBundledFile, ComposeError> {
    let destination = output_root.join(relative_name);
    let decoded = decode_patch_layer(source_patch, &destination)?;
    if decoded.application_law != PatchApplicationLaw::WrappedDiskImage {
        return Err(ComposeError::Io(io::Error::other(format!(
            "patch '{}' did not decode to a stageable disk image",
            source_patch.display()
        ))));
    }
    Ok(ComposedBundledFile {
        role: role.to_string(),
        relative_path: relative_name.to_string(),
        sha256: file_sha256_hex(&destination)?,
    })
}

fn bundle_decoded_patch_program(
    source_patch: &Path,
    output_root: &Path,
    role: &str,
    relative_name: &str,
    expected_law: PatchApplicationLaw,
) -> Result<ComposedBundledFile, ComposeError> {
    let destination = output_root.join(relative_name);
    let decoded = decode_patch_layer(source_patch, &destination)?;
    if decoded.application_law != expected_law {
        return Err(ComposeError::Io(io::Error::other(format!(
            "patch '{}' decoded with unexpected law '{}'",
            source_patch.display(),
            decoded.application_law.label()
        ))));
    }
    Ok(ComposedBundledFile {
        role: role.to_string(),
        relative_path: relative_name.to_string(),
        sha256: file_sha256_hex(&destination)?,
    })
}

fn file_sha256_hex(path: &Path) -> Result<String, io::Error> {
    let bytes = fs::read(path)?;
    let digest = Sha256::digest(bytes);
    Ok(format!("{digest:x}"))
}

fn composition_blockers(
    audit: &RebuildAuditReport,
    substrate: Option<&ComposedSubstrateSummary>,
    materialized_basesystem_images: usize,
) -> Vec<String> {
    let mut blockers = vec!["bootable Apple image synthesis is not implemented yet".to_string()];

    if audit.coverage.bundle_executable_contract_missing_producers > 0 {
        blockers.push(format!(
            "{} bundle executable contract obligations remain unresolved",
            audit.coverage.bundle_executable_contract_missing_producers
        ));
    }
    if audit.coverage.residual_broken_symlinks > 0 {
        blockers.push(format!(
            "{} residual broken symlink obligations remain unresolved",
            audit.coverage.residual_broken_symlinks
        ));
    }
    if audit.coverage.missing_from_tree > 0 || audit.coverage.extra_in_tree > 0 {
        blockers.push(format!(
            "path coverage mismatch remains (missing={} extra={})",
            audit.coverage.missing_from_tree, audit.coverage.extra_in_tree
        ));
    }
    if audit.coverage.mode_mismatches > 0 {
        blockers.push(format!(
            "{} actionable mode mismatches remain",
            audit.coverage.mode_mismatches
        ));
    }
    match substrate {
        Some(summary) if summary.kind == RuntimeSubstrateKind::PatchBackedBaseSystem.label() => {
            if materialized_basesystem_images == 0
                && (summary.basesystem_x86_patch_present || summary.basesystem_arm64_patch_present)
            {
                blockers.push("BXDIFF50 BaseSystem patch application is not implemented yet".to_string());
            }
            if summary.cryptex_image_patch_count > 0 {
                blockers
                    .push("RIDIFF10 cryptex image patch application is not implemented yet".to_string());
                blockers.push(
                    "runtime substrate still depends on unapplied RIDIFF10 cryptex law".to_string(),
                );
            }
            if materialized_basesystem_images == 0 && summary.cryptex_image_patch_count == 0 {
                blockers.push(
                    "runtime substrate is patch-backed, so composition still depends on unapplied patch law"
                        .to_string(),
                );
            }
        }
        Some(summary) => {
            if summary.cryptex_image_patch_count > 0 {
                blockers
                    .push("RIDIFF10 cryptex image patch application is not implemented yet".to_string());
            }
        }
        None => blockers.push("runtime substrate was not inspected for this artifact".to_string()),
    }

    blockers.sort();
    blockers.dedup();
    blockers
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::symlink;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use xz2::write::XzEncoder;

    use super::{ComposeOptions, compose_image_artifact};

    fn unique_dir(label: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("ban-grapple-compose-{label}-{nanos}"))
    }

    fn write_minimal_rebuild(root: &PathBuf) {
        fs::create_dir_all(root.join("System")).unwrap();
        fs::create_dir_all(root.join("_yaa_xattrs")).unwrap();
        fs::write(root.join("System/file"), b"hello").unwrap();
        symlink("missing-target", root.join("System/broken")).unwrap();
        fs::write(
            root.join("_yaa_materialized.jsonl"),
            concat!(
                r#"{"path":"System","object_type":"directory","mode":493,"uid":0,"gid":0,"payloads":[]}"#,
                "\n",
                r#"{"path":"System/file","object_type":"file","mode":420,"uid":0,"gid":0,"payloads":[]}"#,
                "\n",
                r#"{"path":"System/broken","object_type":"link","mode":511,"uid":0,"gid":0,"payloads":[]}"#,
                "\n"
            ),
        )
        .unwrap();
    }

    fn wrap_pbzx(decoded: &[u8]) -> Vec<u8> {
        use std::io::Write;

        let mut encoder = XzEncoder::new(Vec::new(), 6);
        encoder.write_all(decoded).unwrap();
        let compressed = encoder.finish().unwrap();

        let mut wrapped = Vec::new();
        wrapped.extend_from_slice(b"pbzx");
        wrapped.extend_from_slice(&0x0010_0000_u64.to_be_bytes());
        wrapped.extend_from_slice(&0x0010_0000_u64.to_be_bytes());
        wrapped.extend_from_slice(&(compressed.len() as u64).to_be_bytes());
        wrapped.extend_from_slice(&compressed);
        wrapped
    }

    fn wrap_bxdiff(decoded: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0u8; 60];
        bytes[..8].copy_from_slice(b"BXDIFF50");
        bytes.extend_from_slice(&wrap_pbzx(decoded));
        bytes
    }

    fn synthetic_udif_image() -> Vec<u8> {
        let mut bytes = vec![0u8; 4096];
        bytes[512..520].copy_from_slice(b"EFI PART");
        let koly_offset = bytes.len() - 512;
        bytes[koly_offset..koly_offset + 4].copy_from_slice(b"koly");
        bytes
    }

    #[test]
    fn composes_conservative_artifact_bundle() {
        let root = unique_dir("bundle");
        let rebuild_root = root.join("rebuild");
        let output_root = root.join("artifact");
        write_minimal_rebuild(&rebuild_root);

        let artifact = compose_image_artifact(
            &rebuild_root,
            &output_root,
            &ComposeOptions {
                asset_root: None,
                metadata_root: None,
            },
        )
        .unwrap();

        assert_eq!(artifact.manifest.schema_version, 1);
        assert_eq!(artifact.manifest.artifact_kind, "conservative-image-artifact-bundle");
        assert_eq!(artifact.manifest.bootability, "not-bootable");
        assert!(artifact.manifest_path.is_file());
        assert_eq!(artifact.manifest.bundled_files.len(), 3);
        assert!(
            artifact
                .manifest
                .blockers
                .iter()
                .any(|line| line.contains("bootable Apple image synthesis"))
        );

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn composes_materialized_basesystem_images_from_bxdiff_patches() {
        let root = unique_dir("bxdiff-substrate");
        let rebuild_root = root.join("rebuild");
        let asset_root = root.join("payload-root/AssetData");
        let output_root = root.join("artifact");
        write_minimal_rebuild(&rebuild_root);
        fs::create_dir_all(asset_root.join("payloadv2/basesystem_patches")).unwrap();
        fs::write(
            asset_root.join("payloadv2/basesystem_patches/x86_64BaseSystem.dmg"),
            wrap_bxdiff(&synthetic_udif_image()),
        )
        .unwrap();
        fs::write(
            asset_root.join("payloadv2/basesystem_patches/arm64eBaseSystem.dmg"),
            wrap_bxdiff(&synthetic_udif_image()),
        )
        .unwrap();

        let artifact = compose_image_artifact(
            &rebuild_root,
            &output_root,
            &ComposeOptions {
                asset_root: Some(root.join("payload-root")),
                metadata_root: None,
            },
        )
        .unwrap();

        assert!(
            artifact
                .manifest
                .bundled_files
                .iter()
                .any(|file| file.role == "materialized_basesystem_x86_64")
        );
        assert!(
            artifact
                .manifest
                .bundled_files
                .iter()
                .any(|file| file.role == "materialized_basesystem_arm64e")
        );
        assert!(
            !artifact
                .manifest
                .blockers
                .iter()
                .any(|line| line.contains("BXDIFF50 BaseSystem patch application"))
        );

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn composes_decoded_cryptex_programs_from_ridiff_patches() {
        let root = unique_dir("ridiff-substrate");
        let rebuild_root = root.join("rebuild");
        let asset_root = root.join("payload-root/AssetData");
        let output_root = root.join("artifact");
        write_minimal_rebuild(&rebuild_root);
        fs::create_dir_all(asset_root.join("payloadv2/image_patches")).unwrap();
        fs::write(
            asset_root.join("payloadv2/image_patches/cryptex-app"),
            {
                let mut bytes = vec![0u8; 62];
                bytes[..8].copy_from_slice(b"RIDIFF10");
                bytes.extend_from_slice(&wrap_pbzx(&{
                    let mut payload = vec![0u8; 0xb0 + 16];
                    payload[..32].copy_from_slice(&[0x22; 32]);
                    payload[0x20..0x28].copy_from_slice(&0x0012_0000_u64.to_le_bytes());
                    payload[0x28..0x30].copy_from_slice(&24u64.to_le_bytes());
                    payload[0x30..0x38].copy_from_slice(&5u64.to_le_bytes());
                    payload[0x38..0x40].copy_from_slice(&3u64.to_le_bytes());
                    let extents = [
                        (0x1000_u64, 0x2000_u64),
                        (0x4000, 0x1000),
                        (0x8000, 0x3000),
                        (0x9000, 0x1000),
                        (0x10000, 0x1000),
                    ];
                    for (index, (offset, length)) in extents.into_iter().enumerate() {
                        let base = 0x40 + index * 16;
                        payload[base..base + 8].copy_from_slice(&offset.to_le_bytes());
                        payload[base + 8..base + 16].copy_from_slice(&length.to_le_bytes());
                    }
                    payload
                }));
                bytes
            },
        )
        .unwrap();

        let artifact = compose_image_artifact(
            &rebuild_root,
            &output_root,
            &ComposeOptions {
                asset_root: Some(root.join("payload-root")),
                metadata_root: None,
            },
        )
        .unwrap();

        assert!(
            artifact
                .manifest
                .bundled_files
                .iter()
                .any(|file| file.role == "decoded_cryptex_program_cryptex-app")
        );
        assert!(
            artifact
                .manifest
                .blockers
                .iter()
                .any(|line| line.contains("RIDIFF10 cryptex image patch application"))
        );

        fs::remove_dir_all(root).unwrap();
    }
}
