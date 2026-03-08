use std::fmt;
use std::fs;
use std::io;
use std::path::Path;

const MIN_INSTALLER_SIZE_GIB: u64 = 16;
const SYS_BLOCK: &str = "/sys/block";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    Usb,
    Nvme,
    Ata,
    Scsi,
    Mmc,
    Virtual,
    Unknown,
}

impl fmt::Display for Transport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::Usb => "usb",
            Self::Nvme => "nvme",
            Self::Ata => "ata",
            Self::Scsi => "scsi",
            Self::Mmc => "mmc",
            Self::Virtual => "virtual",
            Self::Unknown => "unknown",
        };
        write!(f, "{label}")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiskDevice {
    pub name: String,
    pub path: String,
    pub model: String,
    pub transport: Transport,
    pub removable: bool,
    pub size_gib: u64,
    pub likely_internal: bool,
}

impl DiskDevice {
    pub fn safety_verdict(&self) -> SafetyVerdict {
        if self.likely_internal {
            return SafetyVerdict::Blocked("device appears to be internal".to_string());
        }

        if self.size_gib < MIN_INSTALLER_SIZE_GIB {
            return SafetyVerdict::Blocked(format!(
                "device is smaller than {MIN_INSTALLER_SIZE_GIB} GiB"
            ));
        }

        match self.transport {
            Transport::Usb => SafetyVerdict::Allowed,
            Transport::Nvme if self.removable => SafetyVerdict::Allowed,
            _ => SafetyVerdict::Review(format!(
                "transport '{}' is not yet considered safe automatically",
                self.transport
            )),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SafetyVerdict {
    Allowed,
    Review(String),
    Blocked(String),
}

pub fn discover_disks() -> io::Result<Vec<DiskDevice>> {
    let mut devices = Vec::new();

    for entry in fs::read_dir(SYS_BLOCK)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().to_string();
        if !is_supported_block_device(&name) {
            continue;
        }

        let sys_path = entry.path();
        let symlink = fs::canonicalize(&sys_path).unwrap_or(sys_path.clone());
        let symlink_text = symlink.display().to_string();
        let transport = infer_transport(&name, &symlink_text);
        let removable = read_trimmed(sys_path.join("removable"))
            .map(|value| value == "1")
            .unwrap_or(false);
        let size_gib = read_size_gib(sys_path.join("size")).unwrap_or(0);
        let model = read_trimmed(sys_path.join("device/model"))
            .or_else(|_| read_trimmed(sys_path.join("device/name")))
            .unwrap_or_else(|_| "Unknown".to_string());
        let likely_internal = is_likely_internal(&transport, removable, &symlink_text);

        devices.push(DiskDevice {
            path: format!("/dev/{name}"),
            name,
            model,
            transport,
            removable,
            size_gib,
            likely_internal,
        });
    }

    devices.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(devices)
}

fn is_supported_block_device(name: &str) -> bool {
    name.starts_with("sd") || name.starts_with("nvme") || name.starts_with("mmcblk")
}

fn infer_transport(name: &str, symlink_text: &str) -> Transport {
    if symlink_text.contains("/usb") {
        return Transport::Usb;
    }
    if name.starts_with("nvme") {
        return Transport::Nvme;
    }
    if name.starts_with("mmcblk") {
        return Transport::Mmc;
    }
    if symlink_text.contains("/virtio") || symlink_text.contains("/virtual/") {
        return Transport::Virtual;
    }
    if symlink_text.contains("/ata") {
        return Transport::Ata;
    }
    if name.starts_with("sd") {
        return Transport::Scsi;
    }
    Transport::Unknown
}

fn is_likely_internal(transport: &Transport, removable: bool, symlink_text: &str) -> bool {
    if symlink_text.contains("/usb") {
        return false;
    }
    matches!(
        transport,
        Transport::Ata | Transport::Mmc | Transport::Virtual
    ) || (!removable && matches!(transport, Transport::Nvme | Transport::Scsi))
}

fn read_trimmed(path: impl AsRef<Path>) -> io::Result<String> {
    let raw = fs::read_to_string(path)?;
    Ok(raw.trim().to_string())
}

fn read_size_gib(path: impl AsRef<Path>) -> io::Result<u64> {
    let sectors: u64 = read_trimmed(path)?.parse().unwrap_or(0);
    Ok((sectors * 512) / 1024 / 1024 / 1024)
}

#[cfg(test)]
mod tests {
    use super::{DiskDevice, SafetyVerdict, Transport};

    #[test]
    fn blocks_internal_nvme_drive() {
        let disk = DiskDevice {
            name: "nvme0n1".to_string(),
            path: "/dev/nvme0n1".to_string(),
            model: "Internal SSD".to_string(),
            transport: Transport::Nvme,
            removable: false,
            size_gib: 512,
            likely_internal: true,
        };

        assert_eq!(
            disk.safety_verdict(),
            SafetyVerdict::Blocked("device appears to be internal".to_string())
        );
    }

    #[test]
    fn allows_large_usb_target() {
        let disk = DiskDevice {
            name: "sdb".to_string(),
            path: "/dev/sdb".to_string(),
            model: "Samsung T7".to_string(),
            transport: Transport::Usb,
            removable: false,
            size_gib: 512,
            likely_internal: false,
        };

        assert_eq!(disk.safety_verdict(), SafetyVerdict::Allowed);
    }
}
