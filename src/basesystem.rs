use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

const BXDIFF_MAGIC: &[u8; 8] = b"BXDIFF50";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BaseSystemArtifact {
    pub path: PathBuf,
    pub exists: bool,
    pub size_bytes: Option<u64>,
    pub starts_with_bxdiff: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BaseSystemEvidenceReport {
    pub asset_root: PathBuf,
    pub x86_patch: BaseSystemArtifact,
    pub x86_patch_ecc: BaseSystemArtifact,
    pub arm64_patch: BaseSystemArtifact,
    pub restore_chunklist: BaseSystemArtifact,
    pub x86_trustcache: BaseSystemArtifact,
}

#[derive(Debug)]
pub enum BaseSystemEvidenceError {
    Io(io::Error),
}

impl std::fmt::Display for BaseSystemEvidenceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(err) => write!(f, "{err}"),
        }
    }
}

impl From<io::Error> for BaseSystemEvidenceError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

pub fn inspect_base_system_evidence(
    asset_root: &Path,
) -> Result<BaseSystemEvidenceReport, BaseSystemEvidenceError> {
    Ok(BaseSystemEvidenceReport {
        asset_root: asset_root.to_path_buf(),
        x86_patch: inspect_artifact(
            asset_root,
            "payloadv2/basesystem_patches/x86_64BaseSystem.dmg",
        )?,
        x86_patch_ecc: inspect_artifact(
            asset_root,
            "payloadv2/basesystem_patches/x86_64BaseSystem.dmg.ecc",
        )?,
        arm64_patch: inspect_artifact(
            asset_root,
            "payloadv2/basesystem_patches/arm64eBaseSystem.dmg",
        )?,
        restore_chunklist: inspect_artifact(asset_root, "Restore/BaseSystem.chunklist")?,
        x86_trustcache: inspect_artifact(
            asset_root,
            "boot/Firmware/BaseSystem.dmg.x86.trustcache",
        )?,
    })
}

fn inspect_artifact(
    asset_root: &Path,
    relative_path: &str,
) -> Result<BaseSystemArtifact, BaseSystemEvidenceError> {
    let path = asset_root.join(relative_path);
    let metadata = fs::metadata(&path).ok();
    let exists = metadata.is_some();
    let size_bytes = metadata.map(|meta| meta.len());
    let starts_with_bxdiff = if exists {
        starts_with_magic(&path, BXDIFF_MAGIC)?
    } else {
        false
    };

    Ok(BaseSystemArtifact {
        path,
        exists,
        size_bytes,
        starts_with_bxdiff,
    })
}

fn starts_with_magic(path: &Path, magic: &[u8]) -> Result<bool, io::Error> {
    let mut file = fs::File::open(path)?;
    let mut prefix = vec![0u8; magic.len()];
    let bytes_read = file.read(&mut prefix)?;
    Ok(bytes_read == magic.len() && prefix == magic)
}

#[cfg(test)]
mod tests {
    use super::inspect_base_system_evidence;

    #[test]
    fn reports_patch_and_support_artifacts() {
        let unique = format!(
            "basesystem-evidence-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let root = std::env::temp_dir().join(unique);
        std::fs::create_dir_all(root.join("payloadv2/basesystem_patches")).unwrap();
        std::fs::create_dir_all(root.join("Restore")).unwrap();
        std::fs::create_dir_all(root.join("boot/Firmware")).unwrap();

        std::fs::write(
            root.join("payloadv2/basesystem_patches/x86_64BaseSystem.dmg"),
            b"BXDIFF50patch",
        )
        .unwrap();
        std::fs::write(
            root.join("payloadv2/basesystem_patches/x86_64BaseSystem.dmg.ecc"),
            b"ecc",
        )
        .unwrap();
        std::fs::write(
            root.join("payloadv2/basesystem_patches/arm64eBaseSystem.dmg"),
            b"BXDIFF50arm",
        )
        .unwrap();
        std::fs::write(root.join("Restore/BaseSystem.chunklist"), b"chunk").unwrap();
        std::fs::write(
            root.join("boot/Firmware/BaseSystem.dmg.x86.trustcache"),
            b"trust",
        )
        .unwrap();

        let report = inspect_base_system_evidence(&root).unwrap();
        assert!(report.x86_patch.exists);
        assert!(report.x86_patch.starts_with_bxdiff);
        assert!(report.arm64_patch.starts_with_bxdiff);
        assert!(report.restore_chunklist.exists);
        assert!(report.x86_trustcache.exists);

        let _ = std::fs::remove_dir_all(root);
    }
}
