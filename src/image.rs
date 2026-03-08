use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::cache::{DAILY_CACHE_TTL, cache_root, current_epoch_secs, is_cache_fresh};
use crate::catalog::InstallerRelease;
use crate::disk::DiskDevice;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageChannel {
    Stable,
    Beta,
    Lab,
}

impl ImageChannel {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Stable => "stable",
            Self::Beta => "beta",
            Self::Lab => "lab",
        }
    }
}

impl fmt::Display for ImageChannel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl FromStr for ImageChannel {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "stable" => Ok(Self::Stable),
            "beta" => Ok(Self::Beta),
            "lab" => Ok(Self::Lab),
            other => Err(format!("unsupported image channel '{other}'")),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImageDistribution {
    ManagedManifest,
}

impl ImageDistribution {
    pub fn label(&self) -> &'static str {
        match self {
            Self::ManagedManifest => "managed manifest",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImageManifest {
    pub schema_version: u32,
    pub release: ManifestRelease,
    pub distribution: ManifestDistribution,
    pub provenance: ManifestProvenance,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestRelease {
    pub name: String,
    pub version: String,
    pub build: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestDistribution {
    pub image_url: String,
    pub checksum: ManifestChecksum,
    pub format: String,
    pub size_bytes: u64,
    pub created_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestChecksum {
    pub algorithm: String,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestProvenance {
    pub builder: String,
    pub source: String,
    pub notes: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImageManifestIndex {
    pub schema_version: u32,
    pub channels: Vec<ManifestChannel>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestChannel {
    pub name: String,
    pub images: Vec<ImageDescriptor>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImageDescriptor {
    pub release: ManifestRelease,
    pub manifest_path: String,
    pub image_name: Option<String>,
    pub published_at: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedImageDescriptor {
    pub channel: ImageChannel,
    pub descriptor: ImageDescriptor,
    pub manifest: ImageManifest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemImagePlan {
    pub release: ManifestRelease,
    pub cache_dir: PathBuf,
    pub image_name: String,
    pub distribution: ImageDistribution,
    pub channel: ImageChannel,
    pub index_path: PathBuf,
    pub resolved_index_cache_path: PathBuf,
    pub manifest_path: PathBuf,
    pub resolved_manifest_cache_path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemDeploymentPlan {
    pub target_disk: String,
    pub efi_partition_label: String,
    pub apfs_container_label: String,
    pub expected_volumes: Vec<&'static str>,
    pub post_deploy_steps: Vec<&'static str>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CachedImageManifest {
    fetched_at_epoch_secs: u64,
    manifest: ImageManifest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CachedImageManifestIndex {
    fetched_at_epoch_secs: u64,
    index: ImageManifestIndex,
}

pub fn build_system_image_plan(release: &InstallerRelease) -> SystemImagePlan {
    build_system_image_plan_with_channel(release, ImageChannel::Stable)
}

pub fn build_system_image_plan_with_channel(
    release: &InstallerRelease,
    channel: ImageChannel,
) -> SystemImagePlan {
    let image_dir = image_cache_dir(release);
    SystemImagePlan {
        release: manifest_release_from_installer(release),
        cache_dir: image_dir.clone(),
        image_name: format!("{}.img.zst", release_slug(release)),
        distribution: ImageDistribution::ManagedManifest,
        channel,
        index_path: cache_root().join("images").join("index.json"),
        resolved_index_cache_path: cache_root().join("images").join("index.cache.json"),
        manifest_path: image_dir.join("manifest.json"),
        resolved_manifest_cache_path: image_dir.join("manifest.cache.json"),
    }
}

pub fn image_cache_dir(release: &InstallerRelease) -> PathBuf {
    cache_root().join("images").join(release_slug(release))
}

pub fn manifest_release_from_installer(release: &InstallerRelease) -> ManifestRelease {
    ManifestRelease {
        name: release.name.clone(),
        version: release.version.clone(),
        build: release.build.clone(),
    }
}

pub fn read_manifest(path: &Path) -> Result<ImageManifest, String> {
    let raw = std::fs::read_to_string(path)
        .map_err(|err| format!("failed to read image manifest '{}': {err}", path.display()))?;
    parse_manifest_str(&raw)
}

pub fn read_manifest_index(path: &Path) -> Result<ImageManifestIndex, String> {
    let raw = fs::read_to_string(path).map_err(|err| {
        format!(
            "failed to read image manifest index '{}': {err}",
            path.display()
        )
    })?;
    parse_manifest_index_str(&raw)
}

pub fn resolve_image_descriptor(
    plan: &SystemImagePlan,
    force_refresh: bool,
) -> Result<ResolvedImageDescriptor, String> {
    let index = resolve_image_index(plan, force_refresh)?;
    let descriptor = select_image_descriptor(&index, plan.channel, &plan.release)?;
    let manifest_source = resolve_descriptor_manifest_path(plan, &descriptor);
    let manifest = resolve_image_manifest_with_cache(
        &manifest_source,
        &plan.resolved_manifest_cache_path,
        force_refresh,
    )?;

    if manifest.release != descriptor.release {
        return Err(format!(
            "resolved image manifest '{}' does not match descriptor pin {} {} ({})",
            manifest_source.display(),
            descriptor.release.name,
            descriptor.release.version,
            descriptor.release.build
        ));
    }

    Ok(ResolvedImageDescriptor {
        channel: plan.channel,
        descriptor,
        manifest,
    })
}

pub fn parse_manifest_str(raw: &str) -> Result<ImageManifest, String> {
    let manifest: ImageManifest = serde_json::from_str(raw)
        .map_err(|err| format!("failed to parse image manifest: {err}"))?;
    validate_manifest(&manifest)?;
    Ok(manifest)
}

pub fn parse_manifest_index_str(raw: &str) -> Result<ImageManifestIndex, String> {
    let index: ImageManifestIndex = serde_json::from_str(raw)
        .map_err(|err| format!("failed to parse image manifest index: {err}"))?;
    validate_manifest_index(&index)?;
    Ok(index)
}

pub fn validate_manifest(manifest: &ImageManifest) -> Result<(), String> {
    if manifest.schema_version != 1 {
        return Err(format!(
            "unsupported image manifest schema version {}",
            manifest.schema_version
        ));
    }
    if manifest.release.version.trim().is_empty() {
        return Err("image manifest release version is required".to_string());
    }
    if manifest.distribution.image_url.trim().is_empty() {
        return Err("image manifest image_url is required".to_string());
    }
    if manifest.distribution.checksum.algorithm.trim().is_empty()
        || manifest.distribution.checksum.value.trim().is_empty()
    {
        return Err("image manifest checksum is required".to_string());
    }
    Ok(())
}

pub fn validate_manifest_index(index: &ImageManifestIndex) -> Result<(), String> {
    if index.schema_version != 1 {
        return Err(format!(
            "unsupported image manifest index schema version {}",
            index.schema_version
        ));
    }
    if index.channels.is_empty() {
        return Err("image manifest index must contain at least one channel".to_string());
    }
    for channel in &index.channels {
        if channel.name.trim().is_empty() {
            return Err("image manifest channel name is required".to_string());
        }
        for descriptor in &channel.images {
            if descriptor.release.version.trim().is_empty() {
                return Err("image descriptor release version is required".to_string());
            }
            if descriptor.manifest_path.trim().is_empty() {
                return Err("image descriptor manifest_path is required".to_string());
            }
        }
    }
    Ok(())
}

pub fn build_system_deployment_plan(
    _release: &InstallerRelease,
    disk: &DiskDevice,
) -> SystemDeploymentPlan {
    SystemDeploymentPlan {
        target_disk: disk.path.clone(),
        efi_partition_label: "EFI".to_string(),
        apfs_container_label: "macOS".to_string(),
        expected_volumes: vec![
            "Preboot",
            "Recovery",
            "VM",
            "Macintosh HD",
            "Macintosh HD - Data",
        ],
        post_deploy_steps: vec![
            "expand APFS container to fill the target disk",
            "refresh Preboot entries on first macOS boot",
            "allow Setup Assistant to generate machine-specific state",
        ],
    }
}

fn resolve_image_index(
    plan: &SystemImagePlan,
    force_refresh: bool,
) -> Result<ImageManifestIndex, String> {
    resolve_image_index_with_cache(
        &plan.index_path,
        &plan.resolved_index_cache_path,
        force_refresh,
    )
}

fn resolve_image_index_with_cache(
    source_path: &Path,
    cache_path: &Path,
    force_refresh: bool,
) -> Result<ImageManifestIndex, String> {
    let cached = load_cached_image_index(cache_path)?;

    if !force_refresh
        && let Some(entry) = cached.as_ref()
        && is_cache_fresh(entry.fetched_at_epoch_secs, DAILY_CACHE_TTL)
    {
        return Ok(entry.index.clone());
    }

    match read_manifest_index(source_path) {
        Ok(index) => {
            let _ = store_cached_image_index(cache_path, &index);
            Ok(index)
        }
        Err(err) if !force_refresh => cached.map(|entry| entry.index).ok_or(err),
        Err(err) => Err(err),
    }
}

fn select_image_descriptor(
    index: &ImageManifestIndex,
    channel: ImageChannel,
    release_pin: &ManifestRelease,
) -> Result<ImageDescriptor, String> {
    let channel_name = channel.as_str();
    let channel_entry = index
        .channels
        .iter()
        .find(|candidate| candidate.name == channel_name)
        .ok_or_else(|| {
            format!("image channel '{channel_name}' was not found in the manifest index")
        })?;

    channel_entry
        .images
        .iter()
        .find(|descriptor| descriptor.release == *release_pin)
        .cloned()
        .ok_or_else(|| {
            format!(
                "no image descriptor found in channel '{}' for {} {} ({})",
                channel_name, release_pin.name, release_pin.version, release_pin.build
            )
        })
}

fn resolve_descriptor_manifest_path(
    plan: &SystemImagePlan,
    descriptor: &ImageDescriptor,
) -> PathBuf {
    let candidate = PathBuf::from(&descriptor.manifest_path);
    if candidate.is_absolute() {
        candidate
    } else {
        plan.index_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join(candidate)
    }
}

fn resolve_image_manifest_with_cache(
    source_path: &Path,
    cache_path: &Path,
    force_refresh: bool,
) -> Result<ImageManifest, String> {
    let cached = load_cached_image_manifest(cache_path)?;

    if !force_refresh
        && let Some(entry) = cached.as_ref()
        && is_cache_fresh(entry.fetched_at_epoch_secs, DAILY_CACHE_TTL)
    {
        return Ok(entry.manifest.clone());
    }

    match read_manifest(source_path) {
        Ok(manifest) => {
            let _ = store_cached_image_manifest(cache_path, &manifest);
            Ok(manifest)
        }
        Err(err) if !force_refresh => cached.map(|entry| entry.manifest).ok_or(err),
        Err(err) => Err(err),
    }
}

fn load_cached_image_index(path: &Path) -> Result<Option<CachedImageManifestIndex>, String> {
    match fs::read_to_string(path) {
        Ok(raw) => serde_json::from_str(&raw)
            .map(Some)
            .map_err(|err| format!("failed to parse resolved image index cache: {err}")),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(format!(
            "failed to read resolved image index cache '{}': {err}",
            path.display()
        )),
    }
}

fn store_cached_image_index(path: &Path, index: &ImageManifestIndex) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|err| {
            format!(
                "failed to create resolved image index cache directory '{}': {err}",
                parent.display()
            )
        })?;
    }

    let payload = CachedImageManifestIndex {
        fetched_at_epoch_secs: current_epoch_secs().ok_or_else(|| {
            "failed to read current system time for image index cache".to_string()
        })?,
        index: index.clone(),
    };
    fs::write(
        path,
        serde_json::to_vec_pretty(&payload)
            .map_err(|err| format!("failed to serialize resolved image index cache: {err}"))?,
    )
    .map_err(|err| {
        format!(
            "failed to write resolved image index cache '{}': {err}",
            path.display()
        )
    })
}

fn load_cached_image_manifest(path: &Path) -> Result<Option<CachedImageManifest>, String> {
    match fs::read_to_string(path) {
        Ok(raw) => serde_json::from_str(&raw)
            .map(Some)
            .map_err(|err| format!("failed to parse resolved image manifest cache: {err}")),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(format!(
            "failed to read resolved image manifest cache '{}': {err}",
            path.display()
        )),
    }
}

fn store_cached_image_manifest(path: &Path, manifest: &ImageManifest) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|err| {
            format!(
                "failed to create resolved image manifest cache directory '{}': {err}",
                parent.display()
            )
        })?;
    }

    let payload = CachedImageManifest {
        fetched_at_epoch_secs: current_epoch_secs().ok_or_else(|| {
            "failed to read current system time for image manifest cache".to_string()
        })?,
        manifest: manifest.clone(),
    };
    fs::write(
        path,
        serde_json::to_vec_pretty(&payload)
            .map_err(|err| format!("failed to serialize resolved image manifest cache: {err}"))?,
    )
    .map_err(|err| {
        format!(
            "failed to write resolved image manifest cache '{}': {err}",
            path.display()
        )
    })
}

fn release_slug(release: &InstallerRelease) -> String {
    format!(
        "{}-{}-{}",
        release.name.to_ascii_lowercase().replace(' ', "-"),
        release.version,
        release.build.to_ascii_lowercase()
    )
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use crate::catalog::InstallerRelease;
    use crate::disk::{DiskDevice, Transport};

    use super::{
        CachedImageManifest, CachedImageManifestIndex, ImageChannel, ImageDistribution,
        build_system_deployment_plan, build_system_image_plan,
        build_system_image_plan_with_channel, parse_manifest_index_str, parse_manifest_str,
        resolve_image_descriptor, resolve_image_manifest_with_cache,
    };

    #[test]
    fn full_install_uses_versioned_image_cache() {
        let release = InstallerRelease {
            product_id: "001-00001".to_string(),
            name: "macOS Sonoma".to_string(),
            version: "14.4".to_string(),
            build: "23E214".to_string(),
            catalog_url: "https://example.test/catalog".to_string(),
            server_metadata_url: None,
            distribution_url: None,
            post_date: None,
            packages: Vec::new(),
        };

        let plan = build_system_image_plan(&release);
        let rendered = plan.cache_dir.display().to_string();

        assert!(rendered.contains("ban-grapple/images"));
        assert!(rendered.contains("macos-sonoma-14.4-23e214"));
        assert_eq!(plan.distribution, ImageDistribution::ManagedManifest);
        assert_eq!(plan.channel, ImageChannel::Stable);
    }

    #[test]
    fn full_install_expects_apfs_volume_set() {
        let release = InstallerRelease {
            product_id: "001-00001".to_string(),
            name: "macOS Sonoma".to_string(),
            version: "14.4".to_string(),
            build: "23E214".to_string(),
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

        let plan = build_system_deployment_plan(&release, &disk);
        assert!(plan.expected_volumes.contains(&"Macintosh HD"));
    }

    #[test]
    fn parses_manifest_fixture() {
        let raw = include_str!("../tests/fixtures/sample_image_manifest.json");
        let manifest = parse_manifest_str(raw).expect("manifest parses");
        assert_eq!(manifest.schema_version, 1);
        assert_eq!(manifest.release.version, "14.4");
        assert_eq!(manifest.distribution.checksum.algorithm, "sha256");
    }

    #[test]
    fn parses_manifest_index_fixture() {
        let raw = include_str!("../tests/fixtures/sample_image_index.json");
        let index = parse_manifest_index_str(raw).expect("index parses");
        assert_eq!(index.schema_version, 1);
        assert_eq!(index.channels.len(), 3);
        assert_eq!(index.channels[0].name, "stable");
    }

    #[test]
    fn resolves_descriptor_from_channel_index() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time works")
            .as_nanos();
        let temp_dir = std::env::temp_dir().join(format!("ban-grapple-image-index-{unique}"));
        fs::create_dir_all(&temp_dir).expect("temp dir created");

        let release = InstallerRelease {
            product_id: "001-00001".to_string(),
            name: "macOS Sonoma".to_string(),
            version: "14.4".to_string(),
            build: "23E214".to_string(),
            catalog_url: "https://example.test/catalog".to_string(),
            server_metadata_url: None,
            distribution_url: None,
            post_date: None,
            packages: Vec::new(),
        };
        let mut plan = build_system_image_plan_with_channel(&release, ImageChannel::Stable);
        plan.index_path = temp_dir.join("index.json");
        plan.resolved_index_cache_path = temp_dir.join("index.cache.json");
        plan.manifest_path = temp_dir.join("manifest.json");
        plan.resolved_manifest_cache_path = temp_dir.join("manifest.cache.json");

        fs::write(
            &plan.index_path,
            include_str!("../tests/fixtures/sample_image_index.json"),
        )
        .expect("index written");
        fs::write(
            &plan.manifest_path,
            include_str!("../tests/fixtures/sample_image_manifest.json"),
        )
        .expect("manifest written");

        let resolved = resolve_image_descriptor(&plan, false).expect("descriptor resolves");
        assert_eq!(resolved.channel, ImageChannel::Stable);
        assert_eq!(resolved.descriptor.release.version, "14.4");
        assert_eq!(resolved.manifest.release.build, "23E214");

        fs::remove_dir_all(temp_dir).expect("temp dir removed");
    }

    #[test]
    fn uses_fresh_resolved_manifest_cache() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time works")
            .as_nanos();
        let temp_dir = std::env::temp_dir().join(format!("ban-grapple-image-{unique}"));
        let source_path = temp_dir.join("manifest.json");
        let cache_path = temp_dir.join("manifest.cache.json");
        fs::create_dir_all(&temp_dir).expect("temp dir created");

        let cached_manifest =
            parse_manifest_str(include_str!("../tests/fixtures/sample_image_manifest.json"))
                .expect("manifest parses");
        let cached_entry = CachedImageManifest {
            fetched_at_epoch_secs: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("time works")
                .as_secs(),
            manifest: cached_manifest,
        };
        fs::write(
            &cache_path,
            serde_json::to_vec_pretty(&cached_entry).expect("cache serializes"),
        )
        .expect("cache written");
        fs::write(&source_path, "not json").expect("source written");

        let manifest = resolve_image_manifest_with_cache(&source_path, &cache_path, false)
            .expect("cache resolves");
        assert_eq!(manifest.release.version, "14.4");

        fs::remove_dir_all(temp_dir).expect("temp dir removed");
    }

    #[test]
    fn refresh_reloads_manifest_from_source() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time works")
            .as_nanos();
        let temp_dir = std::env::temp_dir().join(format!("ban-grapple-image-refresh-{unique}"));
        let source_path = temp_dir.join("manifest.json");
        let cache_path = temp_dir.join("manifest.cache.json");
        fs::create_dir_all(&temp_dir).expect("temp dir created");

        let stale_entry = CachedImageManifest {
            fetched_at_epoch_secs: SystemTime::now()
                .checked_sub(Duration::from_secs(3 * 24 * 60 * 60))
                .expect("time math works")
                .duration_since(UNIX_EPOCH)
                .expect("time works")
                .as_secs(),
            manifest: parse_manifest_str(include_str!(
                "../tests/fixtures/sample_image_manifest.json"
            ))
            .expect("manifest parses"),
        };
        fs::write(
            &cache_path,
            serde_json::to_vec_pretty(&stale_entry).expect("cache serializes"),
        )
        .expect("cache written");

        let updated = include_str!("../tests/fixtures/sample_image_manifest.json")
            .replace("23E214", "23F999")
            .replace("14.4", "14.5");
        fs::write(&source_path, updated).expect("source written");

        let manifest = resolve_image_manifest_with_cache(&source_path, &cache_path, true)
            .expect("refresh resolves");
        assert_eq!(manifest.release.version, "14.5");
        assert_eq!(manifest.release.build, "23F999");

        fs::remove_dir_all(temp_dir).expect("temp dir removed");
    }

    #[test]
    fn uses_fresh_resolved_index_cache() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time works")
            .as_nanos();
        let temp_dir = std::env::temp_dir().join(format!("ban-grapple-index-cache-{unique}"));
        let source_path = temp_dir.join("index.json");
        let cache_path = temp_dir.join("index.cache.json");
        fs::create_dir_all(&temp_dir).expect("temp dir created");

        let cached_index =
            parse_manifest_index_str(include_str!("../tests/fixtures/sample_image_index.json"))
                .expect("index parses");
        let cached_entry = CachedImageManifestIndex {
            fetched_at_epoch_secs: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("time works")
                .as_secs(),
            index: cached_index,
        };
        fs::write(
            &cache_path,
            serde_json::to_vec_pretty(&cached_entry).expect("cache serializes"),
        )
        .expect("cache written");
        fs::write(&source_path, "not json").expect("source written");

        let index = super::resolve_image_index_with_cache(&source_path, &cache_path, false)
            .expect("cache resolves");
        assert_eq!(index.channels[0].name, "stable");

        fs::remove_dir_all(temp_dir).expect("temp dir removed");
    }
}
