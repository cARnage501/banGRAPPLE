use crate::catalog::InstallerRelease;
use crate::disk::{DiskDevice, SafetyVerdict};
use crate::pipeline::{ArtifactPlan, DeploymentPlan, ExecutionPlan};

pub fn render_releases(releases: &[InstallerRelease]) -> String {
    let mut out = String::from("Available macOS versions\n------------------------\n");
    for (index, release) in releases.iter().enumerate() {
        out.push_str(&format!(
            "{}. {} {} ({}) [{}]\n",
            index + 1,
            release.name,
            release.version,
            release.build,
            release.product_id
        ));
    }
    out
}

pub fn render_disks(disks: &[DiskDevice]) -> String {
    let mut out = String::from("Available disks\n---------------\n");
    for (index, disk) in disks.iter().enumerate() {
        let status = match disk.safety_verdict() {
            SafetyVerdict::Allowed => "allowed".to_string(),
            SafetyVerdict::Review(reason) => format!("review: {reason}"),
            SafetyVerdict::Blocked(reason) => format!("blocked: {reason}"),
        };
        out.push_str(&format!(
            "{}. {} {} GiB {} [{}]\n",
            index + 1,
            disk.path,
            disk.size_gib,
            disk.model,
            status
        ));
    }
    out
}

pub fn render_plan(plan: &ExecutionPlan) -> String {
    let mut out = format!(
        "Execution plan for {} {} on {}\nMode: {}\n----------------------------------------\n",
        plan.release.name,
        plan.release.version,
        plan.disk.path,
        plan.mode.label()
    );
    for (index, stage) in plan.stages.iter().enumerate() {
        out.push_str(&format!("{}. {}\n", index + 1, stage.label()));
    }

    out.push_str("\nArtifacts\n---------\n");
    match &plan.artifacts {
        ArtifactPlan::InstallerPackages(download) => {
            out.push_str(&format!("cache: {}\n", download.cache_dir.display()));
            for item in &download.items {
                out.push_str(&format!("- {}\n", item.name));
            }
        }
        ArtifactPlan::ManagedImage(image) => {
            out.push_str(&format!("cache: {}\n", image.cache_dir.display()));
            out.push_str(&format!("image: {}\n", image.image_path.display()));
            out.push_str(&format!(
                "checksum: {}:{}\n",
                image.manifest.distribution.checksum.algorithm,
                image.manifest.distribution.checksum.value
            ));
        }
    }

    out.push_str("\nDeployment\n----------\n");
    match &plan.deployment {
        DeploymentPlan::InstallerMedia(installer) => {
            out.push_str(&format!(
                "recovery dir: {}\n",
                installer.recovery_directory.display()
            ));
            out.push_str(&format!("bootloader: {}\n", installer.bootloader_source));
            out.push_str(&format!(
                "bootloader EFI: {}\n",
                installer.bootloader_efi_dir.display()
            ));
            for asset in &installer.required_assets {
                out.push_str(&format!("- {}\n", asset));
            }
        }
        DeploymentPlan::FullSystem(system) => {
            out.push_str(&format!(
                "APFS container: {}\n",
                system.apfs_container_label
            ));
            out.push_str("expected volumes:\n");
            for volume in &system.expected_volumes {
                out.push_str(&format!("- {}\n", volume));
            }
        }
    }

    out
}
