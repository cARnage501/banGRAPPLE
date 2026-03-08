use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use plist::Value;
use serde_json::Value as JsonValue;
use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::io::Cursor;
use std::io::Read;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;
use xz2::read::XzDecoder;

use crate::assets::resolve_asset_roots;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedManifestPath {
    pub manifest_key: String,
    pub path: PathBuf,
    pub exists: bool,
    pub additional_path: Option<PathBuf>,
    pub additional_exists: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuildIdentityReport {
    pub variant: String,
    pub device_class: Option<String>,
    pub variant_contents: BTreeMap<String, String>,
    pub resolved_paths: Vec<ResolvedManifestPath>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeManifestReport {
    pub metadata_source: PathBuf,
    pub build: Option<String>,
    pub os_version: Option<String>,
    pub identities: Vec<BuildIdentityReport>,
}

#[derive(Debug)]
pub enum ManifestError {
    Io(std::io::Error),
    Json(serde_json::Error),
    Base64(base64::DecodeError),
    Xz(std::io::Error),
    Plist(plist::Error),
    Walk(walkdir::Error),
    ManifestNotFound,
    InvalidMetadata(&'static str),
}

impl fmt::Display for ManifestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => write!(f, "manifest IO failed: {err}"),
            Self::Json(err) => write!(f, "manifest JSON failed: {err}"),
            Self::Base64(err) => write!(f, "manifest base64 decode failed: {err}"),
            Self::Xz(err) => write!(f, "manifest xz decode failed: {err}"),
            Self::Plist(err) => write!(f, "manifest plist parse failed: {err}"),
            Self::Walk(err) => write!(f, "manifest search failed: {err}"),
            Self::ManifestNotFound => write!(f, "no PreflightBuildManifest metadata found"),
            Self::InvalidMetadata(message) => write!(f, "invalid metadata: {message}"),
        }
    }
}

impl From<std::io::Error> for ManifestError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<serde_json::Error> for ManifestError {
    fn from(value: serde_json::Error) -> Self {
        Self::Json(value)
    }
}

impl From<base64::DecodeError> for ManifestError {
    fn from(value: base64::DecodeError) -> Self {
        Self::Base64(value)
    }
}

impl From<plist::Error> for ManifestError {
    fn from(value: plist::Error) -> Self {
        Self::Plist(value)
    }
}

impl From<walkdir::Error> for ManifestError {
    fn from(value: walkdir::Error) -> Self {
        Self::Walk(value)
    }
}

pub fn inspect_runtime_manifest(
    metadata_root: &Path,
    asset_root: &Path,
) -> Result<RuntimeManifestReport, ManifestError> {
    let metadata_path = find_preflight_metadata(metadata_root)?;
    inspect_runtime_manifest_file(metadata_path.as_path(), asset_root)
}

pub fn inspect_runtime_manifest_file(
    metadata_path: &Path,
    asset_root: &Path,
) -> Result<RuntimeManifestReport, ManifestError> {
    let resolved_roots = resolve_asset_roots(asset_root);
    let metadata: JsonValue = serde_json::from_slice(&fs::read(metadata_path)?)?;
    let object = metadata
        .as_object()
        .ok_or(ManifestError::InvalidMetadata("expected JSON object"))?;

    let build = object
        .get("Build")
        .and_then(JsonValue::as_str)
        .map(str::to_string);
    let os_version = object
        .get("OSVersion")
        .and_then(JsonValue::as_str)
        .map(str::to_string);

    let encoded = object
        .get("PreflightBuildManifest")
        .and_then(JsonValue::as_str)
        .ok_or(ManifestError::InvalidMetadata(
            "missing PreflightBuildManifest string",
        ))?;
    let compressed = STANDARD.decode(encoded)?;
    let mut decoder = XzDecoder::new(compressed.as_slice());
    let mut decoded = Vec::new();
    decoder
        .read_to_end(&mut decoded)
        .map_err(ManifestError::Xz)?;
    let plist = Value::from_reader_xml(Cursor::new(decoded.as_slice()))
        .or_else(|_| Value::from_reader(Cursor::new(decoded.as_slice())))?;

    let identities = plist
        .as_dictionary()
        .and_then(|dict| dict.get("BuildIdentities"))
        .and_then(Value::as_array)
        .ok_or(ManifestError::InvalidMetadata(
            "missing BuildIdentities array",
        ))?;

    let mut reports = Vec::new();

    for identity in identities {
        let Some(dict) = identity.as_dictionary() else {
            continue;
        };
        let info = dict.get("Info").and_then(Value::as_dictionary).ok_or(
            ManifestError::InvalidMetadata("BuildIdentity missing Info dictionary"),
        )?;
        let variant = info
            .get("Variant")
            .and_then(Value::as_string)
            .unwrap_or("unknown")
            .to_string();
        let device_class = info
            .get("DeviceClass")
            .and_then(Value::as_string)
            .map(str::to_string);
        let variant_contents = info
            .get("VariantContents")
            .and_then(Value::as_dictionary)
            .map(|contents| {
                contents
                    .iter()
                    .filter_map(|(key, value)| {
                        value
                            .as_string()
                            .map(|text| (key.clone(), text.to_string()))
                    })
                    .collect::<BTreeMap<_, _>>()
            })
            .unwrap_or_default();

        let resolved_paths = dict
            .get("Manifest")
            .and_then(Value::as_dictionary)
            .map(|manifest| resolve_manifest_paths(manifest, &resolved_roots.asset_root))
            .unwrap_or_default();

        reports.push(BuildIdentityReport {
            variant,
            device_class,
            variant_contents,
            resolved_paths,
        });
    }

    Ok(RuntimeManifestReport {
        metadata_source: metadata_path.to_path_buf(),
        build,
        os_version,
        identities: reports,
    })
}

fn resolve_manifest_paths(
    manifest: &plist::Dictionary,
    asset_root: &Path,
) -> Vec<ResolvedManifestPath> {
    let interesting_keys = [
        "Cryptex1,AppOS",
        "Cryptex1,SystemOS",
        "x86,BaseSystemTrustCache",
        "x86,RestoreTrustCache",
        "x86,SystemVolume",
        "x86,SystemVolumeCanonicalMetadata",
        "x86,EfiBoot",
        "x86,EfiBootBase",
        "x86,MacKernelCache",
    ];

    let mut resolved = Vec::new();

    for key in interesting_keys {
        let Some(entry) = manifest.get(key).and_then(Value::as_dictionary) else {
            continue;
        };
        let Some(info) = entry.get("Info").and_then(Value::as_dictionary) else {
            continue;
        };
        let Some(path) = info.get("Path").and_then(Value::as_string) else {
            continue;
        };

        let resolved_path = asset_root.join(path);
        let additional_path = info
            .get("AdditionalManifestPath")
            .and_then(Value::as_string)
            .map(|value| asset_root.join(value));

        resolved.push(ResolvedManifestPath {
            manifest_key: key.to_string(),
            exists: resolved_path.exists(),
            path: resolved_path,
            additional_exists: additional_path.as_ref().map(|candidate| candidate.exists()),
            additional_path,
        });
    }

    resolved
}

fn find_preflight_metadata(root: &Path) -> Result<PathBuf, ManifestError> {
    if root.is_file() {
        return Ok(root.to_path_buf());
    }

    for entry in WalkDir::new(root) {
        let entry = entry?;
        let path = entry.path();
        if !path.is_file() || path.extension().and_then(|value| value.to_str()) != Some("json") {
            continue;
        }

        let contents = fs::read_to_string(path)?;
        if contents.contains("\"PreflightBuildManifest\"") {
            return Ok(path.to_path_buf());
        }
    }

    Err(ManifestError::ManifestNotFound)
}

#[cfg(test)]
mod tests {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;
    use std::fs;
    use std::io::Write;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};
    use xz2::write::XzEncoder;

    use super::inspect_runtime_manifest_file;

    fn unique_dir(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("ban-grapple-{name}-{nanos}"))
    }

    #[test]
    fn parses_embedded_preflight_build_manifest() {
        let root = unique_dir("manifest");
        let asset_root = root.join("AssetData");
        fs::create_dir_all(asset_root.join("Firmware")).unwrap();
        fs::write(asset_root.join("043-30550-024.dmg"), b"app").unwrap();
        fs::write(asset_root.join("043-30482-024.dmg"), b"sys").unwrap();
        fs::write(
            asset_root.join("Firmware/BaseSystem.dmg.x86.trustcache"),
            b"trust",
        )
        .unwrap();

        let plist = br#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>BuildIdentities</key>
  <array>
    <dict>
      <key>Info</key>
      <dict>
        <key>Variant</key>
        <string>RecoveryBoot</string>
        <key>DeviceClass</key>
        <string>x86legacyap</string>
        <key>VariantContents</key>
        <dict>
          <key>BaseSystem</key>
          <string>RecoveryBoot</string>
        </dict>
      </dict>
      <key>Manifest</key>
      <dict>
        <key>Cryptex1,AppOS</key>
        <dict>
          <key>Info</key>
          <dict>
            <key>Path</key>
            <string>043-30550-024.dmg</string>
          </dict>
        </dict>
        <key>Cryptex1,SystemOS</key>
        <dict>
          <key>Info</key>
          <dict>
            <key>Path</key>
            <string>043-30482-024.dmg</string>
          </dict>
        </dict>
        <key>x86,BaseSystemTrustCache</key>
        <dict>
          <key>Info</key>
          <dict>
            <key>Path</key>
            <string>Firmware/BaseSystem.dmg.x86.trustcache</string>
          </dict>
        </dict>
      </dict>
    </dict>
  </array>
</dict>
</plist>"#;

        let mut encoder = XzEncoder::new(Vec::new(), 6);
        encoder.write_all(plist).unwrap();
        let compressed = encoder.finish().unwrap();
        let json = serde_json::json!({
            "Build": "22H730",
            "OSVersion": "13.7.8",
            "PreflightBuildManifest": STANDARD.encode(compressed),
        });

        let metadata_path = root.join("asset.json");
        fs::write(&metadata_path, serde_json::to_vec(&json).unwrap()).unwrap();

        let report = inspect_runtime_manifest_file(&metadata_path, &asset_root).unwrap();
        assert_eq!(report.build.as_deref(), Some("22H730"));
        assert_eq!(report.identities.len(), 1);
        assert_eq!(report.identities[0].variant, "RecoveryBoot");
        assert!(
            report.identities[0]
                .resolved_paths
                .iter()
                .any(|path| path.manifest_key == "Cryptex1,AppOS" && path.exists)
        );

        fs::remove_dir_all(root).unwrap();
    }
}
