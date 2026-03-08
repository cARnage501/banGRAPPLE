use crate::bootloader::ResolvedBootloader;
use crate::catalog::InstallerRelease;
use crate::disk::{DiskDevice, SafetyVerdict};
use crate::downloader::{ArtifactRequest, ResolvedArtifacts, resolve_artifacts_with_policy};
use crate::image::{
    ImageChannel, SystemDeploymentPlan, build_system_deployment_plan,
    build_system_image_plan_with_channel,
};
use crate::installer::{InstallerLayout, build_installer_layout};

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
pub struct ExecutionPlan {
    pub mode: WorkflowMode,
    pub release: InstallerRelease,
    pub disk: DiskDevice,
    pub artifacts: ArtifactPlan,
    pub deployment: DeploymentPlan,
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

    use super::{
        ArtifactPlan, DeploymentPlan, Stage, WorkflowMode, build_installer,
        deploy_system_with_options,
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

        fs::remove_dir_all(temp_dir).expect("temp dir removed");
    }

    #[test]
    fn full_system_options_accept_channel() {
        let release = sample_release();
        let disk = sample_disk();
        let result = deploy_system_with_options(release, disk, false, ImageChannel::Beta);
        assert!(result.is_err());
    }
}
