use std::path::PathBuf;

use crate::bootloader::ResolvedBootloader;
use crate::catalog::InstallerRelease;
use crate::disk::DiskDevice;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallerLayout {
    pub target_disk: String,
    pub efi_partition_label: String,
    pub installer_partition_label: String,
    pub recovery_directory: PathBuf,
    pub required_assets: Vec<&'static str>,
    pub boot_files: Vec<&'static str>,
    pub release_name: String,
    pub bootloader_source: String,
    pub bootloader_efi_dir: PathBuf,
}

pub fn build_installer_layout(
    release: &InstallerRelease,
    disk: &DiskDevice,
    bootloader: &ResolvedBootloader,
) -> InstallerLayout {
    InstallerLayout {
        target_disk: disk.path.clone(),
        efi_partition_label: "EFI".to_string(),
        installer_partition_label: "Install macOS".to_string(),
        recovery_directory: PathBuf::from("com.apple.recovery.boot"),
        required_assets: vec!["BaseSystem.dmg", "BaseSystem.chunklist"],
        boot_files: vec!["EFI/BOOT/BOOTx64.efi", "EFI/OC/OpenCore.efi"],
        release_name: format!("{} {}", release.name, release.version),
        bootloader_source: bootloader.source.to_string(),
        bootloader_efi_dir: bootloader.efi_dir.clone(),
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use crate::bootloader::{BootloaderSource, ResolvedBootloader};
    use crate::catalog::InstallerRelease;
    use crate::disk::{DiskDevice, Transport};

    use super::build_installer_layout;

    #[test]
    fn layout_requires_recovery_assets() {
        let release = InstallerRelease {
            product_id: "001-00002".to_string(),
            name: "macOS Ventura".to_string(),
            version: "13.6".to_string(),
            build: "22G630".to_string(),
            catalog_url: "https://example.test/catalog".to_string(),
            server_metadata_url: None,
            distribution_url: None,
            post_date: None,
            packages: Vec::new(),
        };
        let disk = DiskDevice {
            name: "sdb".to_string(),
            path: "/dev/sdb".to_string(),
            model: "USB SSD".to_string(),
            transport: Transport::Usb,
            removable: false,
            size_gib: 512,
            likely_internal: false,
        };
        let bootloader = ResolvedBootloader {
            source: BootloaderSource::UserPath(PathBuf::from("/tmp/EFI")),
            efi_dir: PathBuf::from("/tmp/EFI"),
            cache_dir: PathBuf::from("/tmp/EFI"),
            archive_path: None,
        };

        let layout = build_installer_layout(&release, &disk, &bootloader);
        assert!(layout.required_assets.contains(&"BaseSystem.dmg"));
        assert!(layout.boot_files.contains(&"EFI/BOOT/BOOTx64.efi"));
        assert_eq!(layout.bootloader_source, "user EFI tree (/tmp/EFI)");
    }
}
