use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use crate::assets::resolve_asset_roots;
use walkdir::WalkDir;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BaseSystemPair {
    pub dmg: PathBuf,
    pub chunklist: PathBuf,
    pub dmg_size_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RamDiskPair {
    pub basename: String,
    pub dmg: PathBuf,
    pub chunklist: Option<PathBuf>,
    pub dmg_size_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeDiscoveryReport {
    pub base_system_pair: Option<BaseSystemPair>,
    pub suramdisk_pairs: Vec<RamDiskPair>,
}

#[derive(Debug)]
pub enum RuntimeDiscoveryError {
    Io(std::io::Error),
    Walk(walkdir::Error),
}

impl fmt::Display for RuntimeDiscoveryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => write!(f, "runtime discovery IO failed: {err}"),
            Self::Walk(err) => write!(f, "runtime discovery walk failed: {err}"),
        }
    }
}

impl From<std::io::Error> for RuntimeDiscoveryError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<walkdir::Error> for RuntimeDiscoveryError {
    fn from(value: walkdir::Error) -> Self {
        Self::Walk(value)
    }
}

pub fn discover_runtime_assets(
    root: &Path,
) -> Result<RuntimeDiscoveryReport, RuntimeDiscoveryError> {
    let resolved = resolve_asset_roots(root);
    let mut base_system_dmgs = Vec::new();
    let mut base_system_chunklists = Vec::new();
    let mut suramdisk_dmgs = Vec::new();
    let mut suramdisk_chunklists = Vec::new();

    for entry in WalkDir::new(&resolved.asset_root) {
        let entry = entry?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }

        let Some(name) = path.file_name().and_then(|value| value.to_str()) else {
            continue;
        };

        if name.starts_with("BaseSystem") && name.ends_with(".dmg") {
            base_system_dmgs.push(path.to_path_buf());
        } else if name.starts_with("BaseSystem") && name.ends_with(".chunklist") {
            base_system_chunklists.push(path.to_path_buf());
        } else if name.ends_with("SURamDisk.dmg") {
            suramdisk_dmgs.push(path.to_path_buf());
        } else if name.ends_with("SURamDisk.chunklist") {
            suramdisk_chunklists.push(path.to_path_buf());
        }
    }

    Ok(RuntimeDiscoveryReport {
        base_system_pair: select_base_system_pair(&base_system_dmgs, &base_system_chunklists)?,
        suramdisk_pairs: collect_ramdisk_pairs(&suramdisk_dmgs, &suramdisk_chunklists)?,
    })
}

fn select_base_system_pair(
    dmgs: &[PathBuf],
    chunklists: &[PathBuf],
) -> Result<Option<BaseSystemPair>, RuntimeDiscoveryError> {
    let mut best_pair = None;
    let mut best_size = 0;

    for dmg in dmgs {
        let Some(stem) = dmg.file_stem().and_then(|value| value.to_str()) else {
            continue;
        };

        for chunklist in chunklists {
            let Some(chunk_stem) = chunklist.file_stem().and_then(|value| value.to_str()) else {
                continue;
            };

            if stem != chunk_stem {
                continue;
            }

            let size = fs::metadata(dmg)?.len();
            if size > best_size {
                best_size = size;
                best_pair = Some(BaseSystemPair {
                    dmg: dmg.clone(),
                    chunklist: chunklist.clone(),
                    dmg_size_bytes: size,
                });
            }
        }
    }

    Ok(best_pair)
}

fn collect_ramdisk_pairs(
    dmgs: &[PathBuf],
    chunklists: &[PathBuf],
) -> Result<Vec<RamDiskPair>, RuntimeDiscoveryError> {
    let mut chunk_map = BTreeMap::new();
    for chunklist in chunklists {
        if let Some(stem) = chunklist.file_stem().and_then(|value| value.to_str()) {
            chunk_map.insert(stem.to_string(), chunklist.clone());
        }
    }

    let mut pairs = Vec::new();
    for dmg in dmgs {
        let Some(stem) = dmg.file_stem().and_then(|value| value.to_str()) else {
            continue;
        };

        pairs.push(RamDiskPair {
            basename: stem.to_string(),
            dmg: dmg.clone(),
            chunklist: chunk_map.get(stem).cloned(),
            dmg_size_bytes: fs::metadata(dmg)?.len(),
        });
    }

    pairs.sort_by(|left, right| right.dmg_size_bytes.cmp(&left.dmg_size_bytes));
    Ok(pairs)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::discover_runtime_assets;

    fn unique_path(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("ban-grapple-{name}-{nanos}"))
    }

    #[test]
    fn prefers_largest_matching_base_system_pair() {
        let root = unique_path("runtime-base");
        fs::create_dir_all(root.join("AssetData/boot")).unwrap();
        fs::write(root.join("AssetData/boot/BaseSystem.dmg"), vec![0u8; 16]).unwrap();
        fs::write(root.join("AssetData/boot/BaseSystem.chunklist"), b"chunk").unwrap();
        fs::write(
            root.join("AssetData/boot/BaseSystem.x86.dmg"),
            vec![0u8; 32],
        )
        .unwrap();
        fs::write(
            root.join("AssetData/boot/BaseSystem.x86.chunklist"),
            b"chunk",
        )
        .unwrap();

        let report = discover_runtime_assets(&root).unwrap();
        let pair = report.base_system_pair.expect("pair should exist");
        assert!(pair.dmg.ends_with("BaseSystem.x86.dmg"));
        assert!(pair.chunklist.ends_with("BaseSystem.x86.chunklist"));

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn collects_suramdisk_pairs_even_without_base_system() {
        let root = unique_path("runtime-ramdisk");
        fs::create_dir_all(root.join("AssetData/usr/standalone/update/ramdisk")).unwrap();
        fs::write(
            root.join("AssetData/usr/standalone/update/ramdisk/x86_64SURamDisk.dmg"),
            vec![0u8; 64],
        )
        .unwrap();
        fs::write(
            root.join("AssetData/usr/standalone/update/ramdisk/x86_64SURamDisk.chunklist"),
            b"chunk",
        )
        .unwrap();

        let report = discover_runtime_assets(&root).unwrap();
        assert!(report.base_system_pair.is_none());
        assert_eq!(report.suramdisk_pairs.len(), 1);
        assert_eq!(report.suramdisk_pairs[0].basename, "x86_64SURamDisk");

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn discovers_stageable_runtime_under_nested_assetdata_root() {
        let root = unique_path("runtime-nested");
        fs::create_dir_all(root.join("payload-root/AssetData/boot")).unwrap();
        fs::write(
            root.join("payload-root/AssetData/boot/BaseSystem.dmg"),
            vec![0u8; 16],
        )
        .unwrap();
        fs::write(
            root.join("payload-root/AssetData/boot/BaseSystem.chunklist"),
            b"chunk",
        )
        .unwrap();

        let report = discover_runtime_assets(&root.join("payload-root")).unwrap();
        assert!(report.base_system_pair.is_some());

        fs::remove_dir_all(root).unwrap();
    }
}
