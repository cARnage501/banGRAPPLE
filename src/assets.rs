use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedAssetRoots {
    pub input_root: PathBuf,
    pub asset_root: PathBuf,
    pub payloadv2_root: PathBuf,
}

pub fn resolve_asset_roots(root: &Path) -> ResolvedAssetRoots {
    let input_root = root.to_path_buf();

    if is_payloadv2_root(root) {
        let asset_root = root
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| root.to_path_buf());
        return ResolvedAssetRoots {
            input_root,
            asset_root,
            payloadv2_root: root.to_path_buf(),
        };
    }

    let nested_asset_root = root.join("AssetData");
    if is_asset_root(&nested_asset_root) {
        return ResolvedAssetRoots {
            input_root,
            asset_root: nested_asset_root.clone(),
            payloadv2_root: nested_asset_root.join("payloadv2"),
        };
    }

    if is_asset_root(root) {
        return ResolvedAssetRoots {
            input_root,
            asset_root: root.to_path_buf(),
            payloadv2_root: root.join("payloadv2"),
        };
    }

    ResolvedAssetRoots {
        input_root,
        asset_root: root.to_path_buf(),
        payloadv2_root: root.join("payloadv2"),
    }
}

fn is_asset_root(root: &Path) -> bool {
    root.join("payloadv2").is_dir()
}

fn is_payloadv2_root(root: &Path) -> bool {
    root.file_name().and_then(|value| value.to_str()) == Some("payloadv2")
        && root.join("payload_chunks.txt").is_file()
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::resolve_asset_roots;

    fn unique_dir(label: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("ban-grapple-assets-{label}-{nanos}"))
    }

    #[test]
    fn resolves_nested_assetdata_root() {
        let root = unique_dir("nested");
        fs::create_dir_all(root.join("payload-root/AssetData/payloadv2")).unwrap();

        let resolved = resolve_asset_roots(&root.join("payload-root"));
        assert_eq!(resolved.asset_root, root.join("payload-root/AssetData"));
        assert_eq!(
            resolved.payloadv2_root,
            root.join("payload-root/AssetData/payloadv2")
        );

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn resolves_payloadv2_root_directly() {
        let root = unique_dir("payloadv2");
        fs::create_dir_all(root.join("AssetData/payloadv2")).unwrap();
        fs::write(root.join("AssetData/payloadv2/payload_chunks.txt"), b"payload.000").unwrap();

        let resolved = resolve_asset_roots(&root.join("AssetData/payloadv2"));
        assert_eq!(resolved.asset_root, root.join("AssetData"));
        assert_eq!(resolved.payloadv2_root, root.join("AssetData/payloadv2"));

        fs::remove_dir_all(root).unwrap();
    }
}
