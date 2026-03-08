use crate::bootloader::ResolvedBootloader;
use crate::catalog::InstallerRelease;
use crate::disk::{DiskDevice, SafetyVerdict};
use crate::downloader::{ArtifactRequest, ResolvedArtifacts, resolve_artifacts_with_policy};
use crate::image::{
    ImageChannel, SystemDeploymentPlan, build_system_deployment_plan,
    build_system_image_plan_with_channel,
};
use crate::installer::{InstallerLayout, build_installer_layout};
use crate::substrate::{RuntimeSubstrateKind, inspect_runtime_substrate};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkflowMode {
    InstallerMedia,
    FullSystem,
}

impl WorkflowMode {
    pub fn label(&self) -> &'static str {
        match self {
            Self::InstallerMedia => "installer disk",
            Self::FullSystem => "full macOS installation",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    QueryCatalog,
    DiscoverInstaller,
    ResolveArtifacts,
    DownloadPackages,
    ExtractRuntime,
    InspectDisks,
    PartitionDisk,
    PopulateEfi,
    DeployRuntime,
    AcquireSystemImage,
    WriteSystemImage,
    ExpandContainer,
    RefreshBootMetadata,
    Finalize,
}

impl Stage {
    pub fn label(&self) -> &'static str {
        match self {
            Self::QueryCatalog => "Query Apple catalog",
            Self::DiscoverInstaller => "Resolve installer packages",
            Self::ResolveArtifacts => "Resolve workflow artifacts",
            Self::DownloadPackages => "Download Apple payloads",
            Self::ExtractRuntime => "Extract BaseSystem runtime",
            Self::InspectDisks => "Inspect candidate disks",
            Self::PartitionDisk => "Create GPT and partitions",
            Self::PopulateEfi => "Populate EFI boot environment",
            Self::DeployRuntime => "Copy BaseSystem and recovery assets",
            Self::AcquireSystemImage => "Acquire versioned macOS system image",
            Self::WriteSystemImage => "Write golden image to target disk",
            Self::ExpandContainer => "Expand APFS container to target size",
            Self::RefreshBootMetadata => "Refresh boot metadata and first-boot state",
            Self::Finalize => "Sync and finalize target disk",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArtifactPlan {
    InstallerPackages(crate::downloader::DownloadPlan),
    ManagedImage(Box<crate::downloader::ResolvedImage>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeploymentPlan {
    InstallerMedia(InstallerLayout),
    FullSystem(SystemDeploymentPlan),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeSubstratePlan {
    pub required: bool,
    pub obligations: Vec<&'static str>,
    pub inspected_root: Option<PathBuf>,
    pub metadata_root: Option<PathBuf>,
    pub inspected_kind: Option<RuntimeSubstrateKind>,
    pub stageable_base_system_present: bool,
    pub basesystem_x86_patch_present: bool,
    pub basesystem_arm64_patch_present: bool,
    pub cryptex_image_patch_count: usize,
    pub suramdisk_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionPlan {
    pub mode: WorkflowMode,
    pub release: InstallerRelease,
    pub disk: DiskDevice,
    pub artifacts: ArtifactPlan,
    pub deployment: DeploymentPlan,
    pub substrate: RuntimeSubstratePlan,
    pub stages: Vec<Stage>,
}

pub fn build_installer(
    release: InstallerRelease,
    disk: DiskDevice,
    bootloader: ResolvedBootloader,
) -> Result<ExecutionPlan, String> {
    build_installer_with_options(release, disk, false, bootloader)
}

pub fn build_installer_with_options(
    release: InstallerRelease,
    disk: DiskDevice,
    refresh_artifacts: bool,
    bootloader: ResolvedBootloader,
) -> Result<ExecutionPlan, String> {
    build_installer_with_substrate_options(
        release,
        disk,
        refresh_artifacts,
        bootloader,
        None,
        None,
    )
}

pub fn build_installer_with_substrate_options(
    release: InstallerRelease,
    disk: DiskDevice,
    refresh_artifacts: bool,
    bootloader: ResolvedBootloader,
    asset_root: Option<&Path>,
    metadata_root: Option<&Path>,
) -> Result<ExecutionPlan, String> {
    validate_disk(&disk)?;

    let artifacts = match resolve_artifacts_with_policy(
        ArtifactRequest::InstallerPackages(release.clone()),
        refresh_artifacts,
    )? {
        ResolvedArtifacts::InstallerPackages(plan) => ArtifactPlan::InstallerPackages(plan),
        ResolvedArtifacts::ManagedImage(_) => {
            return Err("artifact resolver returned managed image for installer mode".to_string());
        }
    };

    Ok(ExecutionPlan {
        mode: WorkflowMode::InstallerMedia,
        artifacts,
        deployment: DeploymentPlan::InstallerMedia(build_installer_layout(
            &release,
            &disk,
            &bootloader,
        )),
        substrate: build_runtime_substrate_plan(
            WorkflowMode::InstallerMedia,
            asset_root,
            metadata_root,
        )?,
        release,
        disk,
        stages: vec![
            Stage::QueryCatalog,
            Stage::DiscoverInstaller,
            Stage::ResolveArtifacts,
            Stage::DownloadPackages,
            Stage::ExtractRuntime,
            Stage::InspectDisks,
            Stage::PartitionDisk,
            Stage::PopulateEfi,
            Stage::DeployRuntime,
            Stage::Finalize,
        ],
    })
}

pub fn deploy_system(release: InstallerRelease, disk: DiskDevice) -> Result<ExecutionPlan, String> {
    deploy_system_with_options(release, disk, false, ImageChannel::Stable)
}

pub fn deploy_system_with_options(
    release: InstallerRelease,
    disk: DiskDevice,
    refresh_artifacts: bool,
    channel: ImageChannel,
) -> Result<ExecutionPlan, String> {
    deploy_system_with_substrate_options(release, disk, refresh_artifacts, channel, None, None)
}

pub fn deploy_system_with_substrate_options(
    release: InstallerRelease,
    disk: DiskDevice,
    refresh_artifacts: bool,
    channel: ImageChannel,
    asset_root: Option<&Path>,
    metadata_root: Option<&Path>,
) -> Result<ExecutionPlan, String> {
    validate_disk(&disk)?;

    let image_plan = build_system_image_plan_with_channel(&release, channel);
    let artifacts = match resolve_artifacts_with_policy(
        ArtifactRequest::ManagedImage(image_plan),
        refresh_artifacts,
    )? {
        ResolvedArtifacts::ManagedImage(plan) => ArtifactPlan::ManagedImage(plan),
        ResolvedArtifacts::InstallerPackages(_) => {
            return Err(
                "artifact resolver returned installer packages for system mode".to_string(),
            );
        }
    };

    Ok(ExecutionPlan {
        mode: WorkflowMode::FullSystem,
        artifacts,
        deployment: DeploymentPlan::FullSystem(build_system_deployment_plan(&release, &disk)),
        substrate: build_runtime_substrate_plan(WorkflowMode::FullSystem, asset_root, metadata_root)?,
        release,
        disk,
        stages: vec![
            Stage::QueryCatalog,
            Stage::DiscoverInstaller,
            Stage::ResolveArtifacts,
            Stage::AcquireSystemImage,
            Stage::InspectDisks,
            Stage::PartitionDisk,
            Stage::WriteSystemImage,
            Stage::ExpandContainer,
            Stage::RefreshBootMetadata,
            Stage::Finalize,
        ],
    })
}

fn validate_disk(disk: &DiskDevice) -> Result<(), String> {
    match disk.safety_verdict() {
        SafetyVerdict::Allowed => Ok(()),
        SafetyVerdict::Review(reason) => Err(format!(
            "manual review required before using '{}': {reason}",
            disk.path
        )),
        SafetyVerdict::Blocked(reason) => Err(format!("refusing to use '{}': {reason}", disk.path)),
    }
}

fn build_runtime_substrate_plan(
    mode: WorkflowMode,
    asset_root: Option<&Path>,
    metadata_root: Option<&Path>,
) -> Result<RuntimeSubstratePlan, String> {
    let obligations = match mode {
        WorkflowMode::InstallerMedia => vec![
            "BaseSystem substrate must be available as a stageable runtime or patch-backed synthesis path",
            "recovery runtime assets must be joined deliberately before deployment",
            "cryptex/runtime patch layers may be required to satisfy installer substrate fidelity",
        ],
        WorkflowMode::FullSystem => vec![
            "cryptex image patch composition must be accounted for in the final image law",
            "BaseSystem/runtime substrate must be preserved for recovery and preboot topology",
            "paired-volume and runtime substrate expectations must remain explicit during deployment",
        ],
    };

    let Some(asset_root) = asset_root else {
        return Ok(RuntimeSubstratePlan {
            required: true,
            obligations,
            inspected_root: None,
            metadata_root: metadata_root.map(Path::to_path_buf),
            inspected_kind: None,
            stageable_base_system_present: false,
            basesystem_x86_patch_present: false,
            basesystem_arm64_patch_present: false,
            cryptex_image_patch_count: 0,
            suramdisk_count: 0,
        });
    };

    let report = inspect_runtime_substrate(asset_root, metadata_root).map_err(|err| {
        format!(
            "failed to inspect runtime substrate at '{}': {err}",
            asset_root.display()
        )
    })?;

    Ok(RuntimeSubstratePlan {
        required: true,
        obligations,
        inspected_root: Some(report.input_root),
        metadata_root: metadata_root.map(Path::to_path_buf),
        inspected_kind: Some(report.substrate_kind),
        stageable_base_system_present: report.runtime_assets.base_system_pair.is_some(),
        basesystem_x86_patch_present: report.base_system_evidence.x86_patch.exists,
        basesystem_arm64_patch_present: report.base_system_evidence.arm64_patch.exists,
        cryptex_image_patch_count: report.image_patches.len(),
        suramdisk_count: report.runtime_assets.suramdisk_pairs.len(),
    })
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use crate::bootloader::{BootloaderSource, ResolvedBootloader};
    use crate::catalog::InstallerRelease;
    use crate::disk::{DiskDevice, Transport};
    use crate::downloader::ResolvedImage;
    use crate::image::{ImageChannel, build_system_image_plan_with_channel};
    use crate::substrate::RuntimeSubstrateKind;
    use std::path::Path;

    use super::{
        ArtifactPlan, DeploymentPlan, Stage, WorkflowMode, build_installer,
        build_installer_with_substrate_options, deploy_system_with_options,
    };

    fn sample_release() -> InstallerRelease {
        InstallerRelease {
            product_id: "001-00001".to_string(),
            name: "macOS Sonoma".to_string(),
            version: "14.4".to_string(),
            build: "23E214".to_string(),
            catalog_url: "https://example.test/catalog".to_string(),
            server_metadata_url: Some("https://example.test/ServerMetadata.plist".to_string()),
            distribution_url: Some("https://example.test/English.dist".to_string()),
            post_date: Some("2024-03-07T18:00:00Z".to_string()),
            packages: Vec::new(),
        }
    }

    fn sample_disk() -> DiskDevice {
        DiskDevice {
            name: "sdb".to_string(),
            path: "/dev/sdb".to_string(),
            model: "USB SSD".to_string(),
            transport: Transport::Usb,
            removable: false,
            size_gib: 256,
            likely_internal: false,
        }
    }

    fn sample_bootloader() -> ResolvedBootloader {
        ResolvedBootloader {
            source: BootloaderSource::UserPath(PathBuf::from("/tmp/EFI")),
            efi_dir: PathBuf::from("/tmp/EFI"),
            cache_dir: PathBuf::from("/tmp/EFI"),
            archive_path: None,
        }
    }

    #[test]
    fn installer_plan_contains_finalize_stage() {
        let plan = build_installer(sample_release(), sample_disk(), sample_bootloader())
            .expect("plan should build");
        assert_eq!(plan.mode, WorkflowMode::InstallerMedia);
        assert_eq!(plan.stages.last(), Some(&Stage::Finalize));
        assert!(matches!(plan.artifacts, ArtifactPlan::InstallerPackages(_)));
        assert!(matches!(plan.deployment, DeploymentPlan::InstallerMedia(_)));
        assert!(plan.substrate.required);
        assert!(plan.substrate.inspected_kind.is_none());
    }

    #[test]
    fn full_system_plan_uses_managed_image() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time works")
            .as_nanos();
        let temp_dir = std::env::temp_dir().join(format!("ban-grapple-pipeline-{unique}"));
        fs::create_dir_all(&temp_dir).expect("temp dir created");

        let release = sample_release();
        let mut image_plan = build_system_image_plan_with_channel(&release, ImageChannel::Stable);
        image_plan.index_path = temp_dir.join("index.json");
        image_plan.resolved_index_cache_path = temp_dir.join("index.cache.json");
        image_plan.manifest_path = temp_dir.join("manifest.json");
        image_plan.resolved_manifest_cache_path = temp_dir.join("manifest.cache.json");
        fs::write(
            &image_plan.index_path,
            include_str!("../tests/fixtures/sample_image_index.json"),
        )
        .expect("index written");
        fs::write(
            &image_plan.manifest_path,
            include_str!("../tests/fixtures/sample_image_manifest.json"),
        )
        .expect("manifest written");

        let resolved =
            crate::downloader::resolve_system_image(&image_plan).expect("image resolves");
        let plan = super::ExecutionPlan {
            mode: WorkflowMode::FullSystem,
            release: release.clone(),
            disk: sample_disk(),
            artifacts: ArtifactPlan::ManagedImage(Box::new(ResolvedImage {
                channel: resolved.channel,
                descriptor: resolved.descriptor,
                manifest: resolved.manifest,
                cache_dir: resolved.cache_dir,
                image_path: resolved.image_path,
            })),
            deployment: DeploymentPlan::FullSystem(crate::image::build_system_deployment_plan(
                &release,
                &sample_disk(),
            )),
            substrate: super::build_runtime_substrate_plan(
                WorkflowMode::FullSystem,
                None,
                None,
            )
            .expect("substrate plan"),
            stages: vec![
                Stage::QueryCatalog,
                Stage::DiscoverInstaller,
                Stage::ResolveArtifacts,
                Stage::AcquireSystemImage,
                Stage::InspectDisks,
                Stage::PartitionDisk,
                Stage::WriteSystemImage,
                Stage::ExpandContainer,
                Stage::RefreshBootMetadata,
                Stage::Finalize,
            ],
        };

        assert_eq!(plan.mode, WorkflowMode::FullSystem);
        assert!(plan.stages.contains(&Stage::WriteSystemImage));
        assert!(matches!(plan.artifacts, ArtifactPlan::ManagedImage(_)));
        assert!(matches!(plan.deployment, DeploymentPlan::FullSystem(_)));
        assert!(plan.substrate.required);

        fs::remove_dir_all(temp_dir).expect("temp dir removed");
    }

    #[test]
    fn full_system_options_accept_channel() {
        let release = sample_release();
        let disk = sample_disk();
        let result = deploy_system_with_options(release, disk, false, ImageChannel::Beta);
        assert!(result.is_err());
    }

    #[test]
    fn installer_plan_can_attach_patch_backed_substrate_evidence() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time works")
            .as_nanos();
        let temp_dir = std::env::temp_dir().join(format!("ban-grapple-pipeline-substrate-{unique}"));
        let asset_root = temp_dir.join("payload-root/AssetData");
        fs::create_dir_all(asset_root.join("payloadv2/basesystem_patches")).expect("patch dir");
        fs::create_dir_all(asset_root.join("payloadv2/image_patches")).expect("image patch dir");
        fs::write(
            asset_root.join("payloadv2/basesystem_patches/x86_64BaseSystem.dmg"),
            b"BXDIFF50patch",
        )
        .expect("x86 patch");
        fs::write(
            asset_root.join("payloadv2/image_patches/cryptex-app"),
            b"RIDIFF10patch",
        )
        .expect("cryptex patch");

        let plan = build_installer_with_substrate_options(
            sample_release(),
            sample_disk(),
            false,
            sample_bootloader(),
            Some(temp_dir.join("payload-root").as_path()),
            None,
        )
        .expect("plan should build");

        assert_eq!(
            plan.substrate.inspected_kind,
            Some(RuntimeSubstrateKind::PatchBackedBaseSystem)
        );
        assert!(plan.substrate.basesystem_x86_patch_present);
        assert_eq!(plan.substrate.cryptex_image_patch_count, 1);

        fs::remove_dir_all(temp_dir).expect("temp dir removed");
    }

    #[test]
    fn full_system_plan_can_attach_stageable_substrate_evidence() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time works")
            .as_nanos();
        let temp_dir = std::env::temp_dir().join(format!("ban-grapple-pipeline-stageable-{unique}"));
        let asset_root = temp_dir.join("AssetData");
        fs::create_dir_all(asset_root.join("boot")).expect("boot dir");
        fs::write(asset_root.join("boot/BaseSystem.dmg"), vec![0u8; 16]).expect("dmg");
        fs::write(asset_root.join("boot/BaseSystem.chunklist"), b"chunk").expect("chunklist");
        let plan = super::ExecutionPlan {
            mode: WorkflowMode::FullSystem,
            release: sample_release(),
            disk: sample_disk(),
            artifacts: ArtifactPlan::ManagedImage(Box::new(ResolvedImage {
                channel: ImageChannel::Stable,
                descriptor: crate::image::ImageDescriptor {
                    release: crate::image::manifest_release_from_installer(&sample_release()),
                    manifest_path: "manifest.json".to_string(),
                    image_name: Some("sample.img.zst".to_string()),
                    published_at: None,
                },
                manifest: crate::image::parse_manifest_str(
                    include_str!("../tests/fixtures/sample_image_manifest.json"),
                )
                .expect("manifest parses"),
                cache_dir: temp_dir.join("cache"),
                image_path: temp_dir.join("sample.img.zst"),
            })),
            deployment: DeploymentPlan::FullSystem(crate::image::build_system_deployment_plan(
                &sample_release(),
                &sample_disk(),
            )),
            substrate: super::build_runtime_substrate_plan(
                WorkflowMode::FullSystem,
                Some(Path::new(&asset_root)),
                None,
            )
            .expect("substrate plan"),
            stages: vec![Stage::AcquireSystemImage, Stage::WriteSystemImage, Stage::Finalize],
        };

        assert_eq!(
            plan.substrate.inspected_kind,
            Some(RuntimeSubstrateKind::StageableBaseSystem)
        );
        assert!(plan.substrate.stageable_base_system_present);

        fs::remove_dir_all(temp_dir).expect("temp dir removed");
    }
}
