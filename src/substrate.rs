use std::fmt;
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use crate::assets::{ResolvedAssetRoots, resolve_asset_roots};
use crate::basesystem::{
    BaseSystemEvidenceError, BaseSystemEvidenceReport, inspect_base_system_evidence,
};
use crate::dmg::{RuntimeDiscoveryError, RuntimeDiscoveryReport, discover_runtime_assets};
use crate::manifest::{ManifestError, RuntimeManifestReport, inspect_runtime_manifest};

const RIDIFF_MAGIC: &[u8; 8] = b"RIDIFF10";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimePatchArtifact {
    pub name: String,
    pub path: PathBuf,
    pub exists: bool,
    pub size_bytes: Option<u64>,
    pub starts_with_ridiff: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeSubstrateKind {
    StageableBaseSystem,
    PatchBackedBaseSystem,
    Missing,
}

impl RuntimeSubstrateKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::StageableBaseSystem => "stageable-basesystem",
            Self::PatchBackedBaseSystem => "patch-backed-basesystem",
            Self::Missing => "missing",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeSubstrateReport {
    pub input_root: PathBuf,
    pub asset_root: PathBuf,
    pub payloadv2_root: PathBuf,
    pub runtime_assets: RuntimeDiscoveryReport,
    pub base_system_evidence: BaseSystemEvidenceReport,
    pub image_patches: Vec<RuntimePatchArtifact>,
    pub manifest: Option<RuntimeManifestReport>,
    pub substrate_kind: RuntimeSubstrateKind,
}

#[derive(Debug)]
pub enum RuntimeSubstrateError {
    RuntimeDiscovery(RuntimeDiscoveryError),
    BaseSystem(BaseSystemEvidenceError),
    Manifest(ManifestError),
    Io(io::Error),
}

impl fmt::Display for RuntimeSubstrateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RuntimeDiscovery(err) => write!(f, "{err}"),
            Self::BaseSystem(err) => write!(f, "{err}"),
            Self::Manifest(err) => write!(f, "{err}"),
            Self::Io(err) => write!(f, "{err}"),
        }
    }
}

impl From<RuntimeDiscoveryError> for RuntimeSubstrateError {
    fn from(value: RuntimeDiscoveryError) -> Self {
        Self::RuntimeDiscovery(value)
    }
}

impl From<BaseSystemEvidenceError> for RuntimeSubstrateError {
    fn from(value: BaseSystemEvidenceError) -> Self {
        Self::BaseSystem(value)
    }
}

impl From<ManifestError> for RuntimeSubstrateError {
    fn from(value: ManifestError) -> Self {
        Self::Manifest(value)
    }
}

impl From<io::Error> for RuntimeSubstrateError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

pub fn inspect_runtime_substrate(
    root: &Path,
    metadata_root: Option<&Path>,
) -> Result<RuntimeSubstrateReport, RuntimeSubstrateError> {
    let resolved = resolve_asset_roots(root);
    let runtime_assets = discover_runtime_assets(&resolved.asset_root)?;
    let base_system_evidence = inspect_base_system_evidence(&resolved.asset_root)?;
    let image_patches = inspect_image_patches(&resolved)?;
    let manifest = metadata_root
        .map(|metadata| inspect_runtime_manifest(metadata, &resolved.asset_root))
        .transpose()?;

    let substrate_kind = if runtime_assets.base_system_pair.is_some() {
        RuntimeSubstrateKind::StageableBaseSystem
    } else if base_system_evidence.x86_patch.exists
        || base_system_evidence.arm64_patch.exists
        || !image_patches.is_empty()
    {
        RuntimeSubstrateKind::PatchBackedBaseSystem
    } else {
        RuntimeSubstrateKind::Missing
    };

    Ok(RuntimeSubstrateReport {
        input_root: resolved.input_root,
        asset_root: resolved.asset_root,
        payloadv2_root: resolved.payloadv2_root,
        runtime_assets,
        base_system_evidence,
        image_patches,
        manifest,
        substrate_kind,
    })
}

fn inspect_image_patches(
    roots: &ResolvedAssetRoots,
) -> Result<Vec<RuntimePatchArtifact>, RuntimeSubstrateError> {
    let patch_dir = roots.asset_root.join("payloadv2/image_patches");
    let mut patches = Vec::new();
    if !patch_dir.is_dir() {
        return Ok(patches);
    }

    for entry in fs::read_dir(&patch_dir)? {
        let entry = entry?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let metadata = fs::metadata(&path)?;
        patches.push(RuntimePatchArtifact {
            name: entry.file_name().to_string_lossy().to_string(),
            path,
            exists: true,
            size_bytes: Some(metadata.len()),
            starts_with_ridiff: starts_with_magic(&patch_dir.join(entry.file_name()), RIDIFF_MAGIC)?,
        });
    }

    patches.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(patches)
}

fn starts_with_magic(path: &Path, magic: &[u8]) -> Result<bool, io::Error> {
    let mut file = fs::File::open(path)?;
    let mut prefix = vec![0u8; magic.len()];
    let bytes_read = file.read(&mut prefix)?;
    Ok(bytes_read == magic.len() && prefix == magic)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::{RuntimeSubstrateKind, inspect_runtime_substrate};

    fn unique_dir(label: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("ban-grapple-substrate-{label}-{nanos}"))
    }

    #[test]
    fn integrates_patch_backed_substrate_from_nested_assetdata_root() {
        let root = unique_dir("patch-backed");
        let asset_root = root.join("payload-root/AssetData");
        fs::create_dir_all(asset_root.join("payloadv2/basesystem_patches")).unwrap();
        fs::create_dir_all(asset_root.join("payloadv2/image_patches")).unwrap();
        fs::write(
            asset_root.join("payloadv2/basesystem_patches/x86_64BaseSystem.dmg"),
            b"BXDIFF50patch",
        )
        .unwrap();
        fs::write(
            asset_root.join("payloadv2/image_patches/cryptex-system-x86_64"),
            b"RIDIFF10payload",
        )
        .unwrap();

        let report = inspect_runtime_substrate(&root.join("payload-root"), None).unwrap();
        assert_eq!(report.asset_root, asset_root);
        assert_eq!(report.substrate_kind, RuntimeSubstrateKind::PatchBackedBaseSystem);
        assert!(report.runtime_assets.base_system_pair.is_none());
        assert!(report.base_system_evidence.x86_patch.exists);
        assert_eq!(report.image_patches.len(), 1);
        assert!(report.image_patches[0].starts_with_ridiff);

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn prefers_stageable_basesystem_when_runtime_pair_exists() {
        let root = unique_dir("stageable");
        let asset_root = root.join("AssetData");
        fs::create_dir_all(asset_root.join("boot")).unwrap();
        fs::create_dir_all(asset_root.join("payloadv2/image_patches")).unwrap();
        fs::write(asset_root.join("boot/BaseSystem.dmg"), vec![0u8; 16]).unwrap();
        fs::write(asset_root.join("boot/BaseSystem.chunklist"), b"chunk").unwrap();
        fs::write(
            asset_root.join("payloadv2/image_patches/cryptex-app"),
            b"RIDIFF10payload",
        )
        .unwrap();

        let report = inspect_runtime_substrate(&asset_root, None).unwrap();
        assert_eq!(report.substrate_kind, RuntimeSubstrateKind::StageableBaseSystem);
        assert!(report.runtime_assets.base_system_pair.is_some());
        assert_eq!(report.image_patches.len(), 1);

        fs::remove_dir_all(root).unwrap();
    }
}
