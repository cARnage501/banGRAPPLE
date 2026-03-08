use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::cache::{DAILY_CACHE_TTL, cache_root, current_epoch_secs, is_cache_fresh};
use crate::catalog::{InstallerPackage, InstallerRelease};
use crate::image::{
    ImageChannel, ImageDescriptor, ImageManifest, SystemImagePlan, resolve_image_descriptor,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DownloadItem {
    pub name: String,
    pub source_url: String,
    #[serde(default)]
    pub size_bytes: Option<u64>,
    #[serde(default)]
    pub integrity_data_url: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DownloadPlan {
    pub cache_dir: PathBuf,
    pub items: Vec<DownloadItem>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaterializedPackage {
    pub name: String,
    pub local_path: PathBuf,
    pub source_url: String,
    pub size_bytes: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArtifactRequest {
    InstallerPackages(InstallerRelease),
    ManagedImage(SystemImagePlan),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolvedArtifacts {
    InstallerPackages(DownloadPlan),
    ManagedImage(Box<ResolvedImage>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedImage {
    pub channel: ImageChannel,
    pub descriptor: ImageDescriptor,
    pub manifest: ImageManifest,
    pub cache_dir: PathBuf,
    pub image_path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CachedDownloadPlan {
    fetched_at_epoch_secs: u64,
    plan: DownloadPlan,
}

pub fn resolve_artifacts(request: ArtifactRequest) -> Result<ResolvedArtifacts, String> {
    resolve_artifacts_with_policy(request, false)
}

pub fn resolve_artifacts_with_policy(
    request: ArtifactRequest,
    force_refresh: bool,
) -> Result<ResolvedArtifacts, String> {
    match request {
        ArtifactRequest::InstallerPackages(release) => {
            resolve_installer_packages(&release, force_refresh)
                .map(ResolvedArtifacts::InstallerPackages)
        }
        ArtifactRequest::ManagedImage(plan) => {
            resolve_system_image_with_policy(&plan, force_refresh)
                .map(|image| ResolvedArtifacts::ManagedImage(Box::new(image)))
        }
    }
}

pub fn build_download_plan(release: &InstallerRelease) -> DownloadPlan {
    let cache_dir = installer_cache_dir(release);

    DownloadPlan {
        cache_dir,
        items: release
            .packages
            .iter()
            .map(download_item_from_package)
            .collect(),
    }
}

pub fn materialize_installer_packages(
    plan: &DownloadPlan,
    force_refresh: bool,
) -> Result<Vec<MaterializedPackage>, String> {
    fs::create_dir_all(&plan.cache_dir).map_err(|err| {
        format!(
            "failed to create installer package cache '{}': {err}",
            plan.cache_dir.display()
        )
    })?;

    let client = reqwest::blocking::Client::builder()
        .build()
        .map_err(|err| format!("failed to create installer download client: {err}"))?;

    let mut materialized = Vec::with_capacity(plan.items.len());
    for item in &plan.items {
        let local_path = plan.cache_dir.join(&item.name);
        if !force_refresh && local_path.exists() && local_file_matches(item, &local_path)? {
            materialized.push(MaterializedPackage {
                name: item.name.clone(),
                local_path,
                source_url: item.source_url.clone(),
                size_bytes: item.size_bytes,
            });
            continue;
        }

        let response = client
            .get(&item.source_url)
            .send()
            .and_then(|resp| resp.error_for_status())
            .map_err(|err| {
                format!(
                    "failed to download installer package '{}': {err}",
                    item.source_url
                )
            })?;
        let bytes = response.bytes().map_err(|err| {
            format!(
                "failed to read installer package response '{}': {err}",
                item.source_url
            )
        })?;
        if let Some(expected) = item.size_bytes
            && u64::try_from(bytes.len()).ok() != Some(expected)
        {
            return Err(format!(
                "downloaded installer package '{}' has size {}, expected {}",
                item.name,
                bytes.len(),
                expected
            ));
        }
        fs::write(&local_path, &bytes).map_err(|err| {
            format!(
                "failed to write installer package '{}': {err}",
                local_path.display()
            )
        })?;
        materialized.push(MaterializedPackage {
            name: item.name.clone(),
            local_path,
            source_url: item.source_url.clone(),
            size_bytes: item.size_bytes,
        });
    }

    Ok(materialized)
}

pub fn installer_cache_dir(release: &InstallerRelease) -> PathBuf {
    cache_root().join("installers").join(release_slug(release))
}

pub fn resolve_system_image(plan: &SystemImagePlan) -> Result<ResolvedImage, String> {
    resolve_system_image_with_policy(plan, false)
}

pub fn resolve_system_image_with_policy(
    plan: &SystemImagePlan,
    force_refresh: bool,
) -> Result<ResolvedImage, String> {
    let resolved = resolve_image_descriptor(plan, force_refresh)?;
    let image_name = resolved
        .descriptor
        .image_name
        .clone()
        .unwrap_or_else(|| plan.image_name.clone());

    Ok(ResolvedImage {
        channel: resolved.channel,
        descriptor: resolved.descriptor,
        manifest: resolved.manifest,
        image_path: plan.cache_dir.join(image_name),
        cache_dir: plan.cache_dir.clone(),
    })
}

fn download_item_from_package(package: &InstallerPackage) -> DownloadItem {
    DownloadItem {
        name: package.name.clone(),
        source_url: package.url.clone(),
        size_bytes: package.size_bytes,
        integrity_data_url: package.integrity_data_url.clone(),
    }
}

fn resolve_installer_packages(
    release: &InstallerRelease,
    force_refresh: bool,
) -> Result<DownloadPlan, String> {
    let cache_path = installer_metadata_cache_path(release);
    resolve_installer_packages_with_cache_path(release, &cache_path, force_refresh)
}

fn resolve_installer_packages_with_cache_path(
    release: &InstallerRelease,
    cache_path: &Path,
    force_refresh: bool,
) -> Result<DownloadPlan, String> {
    if !force_refresh
        && let Some(cached) = load_cached_download_plan(cache_path)?
        && is_cache_fresh(cached.fetched_at_epoch_secs, DAILY_CACHE_TTL)
    {
        return Ok(cached.plan);
    }

    let plan = build_download_plan(release);
    let _ = store_cached_download_plan(cache_path, &plan);
    Ok(plan)
}

fn installer_metadata_cache_path(release: &InstallerRelease) -> PathBuf {
    installer_cache_dir(release).join("packages.json")
}

fn local_file_matches(item: &DownloadItem, path: &Path) -> Result<bool, String> {
    if let Some(expected) = item.size_bytes {
        let metadata = fs::metadata(path).map_err(|err| {
            format!(
                "failed to read installer package metadata '{}': {err}",
                path.display()
            )
        })?;
        return Ok(metadata.len() == expected);
    }
    Ok(true)
}

fn load_cached_download_plan(path: &Path) -> Result<Option<CachedDownloadPlan>, String> {
    match fs::read_to_string(path) {
        Ok(raw) => serde_json::from_str(&raw)
            .map(Some)
            .map_err(|err| format!("failed to parse installer metadata cache: {err}")),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(format!(
            "failed to read installer metadata cache '{}': {err}",
            path.display()
        )),
    }
}

fn store_cached_download_plan(path: &Path, plan: &DownloadPlan) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|err| {
            format!(
                "failed to create installer metadata cache directory '{}': {err}",
                parent.display()
            )
        })?;
    }

    let payload = CachedDownloadPlan {
        fetched_at_epoch_secs: current_epoch_secs()
            .ok_or_else(|| "failed to read current system time for installer cache".to_string())?,
        plan: plan.clone(),
    };
    fs::write(
        path,
        serde_json::to_vec_pretty(&payload)
            .map_err(|err| format!("failed to serialize installer metadata cache: {err}"))?,
    )
    .map_err(|err| {
        format!(
            "failed to write installer metadata cache '{}': {err}",
            path.display()
        )
    })
}

fn release_slug(release: &InstallerRelease) -> String {
    format!(
        "{}-{}-{}",
        slugify(&release.name),
        release.version,
        release.build.to_ascii_lowercase()
    )
}

fn slugify(value: &str) -> String {
    value.to_ascii_lowercase().replace(' ', "-")
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use super::{
        ArtifactRequest, CachedDownloadPlan, DownloadItem, DownloadPlan, ResolvedArtifacts,
        build_download_plan, materialize_installer_packages, resolve_artifacts,
        resolve_installer_packages_with_cache_path,
    };
    use crate::catalog::{InstallerPackage, InstallerRelease};
    use crate::image::{ImageChannel, build_system_image_plan_with_channel};

    fn sample_release() -> InstallerRelease {
        InstallerRelease {
            product_id: "001-00001".to_string(),
            name: "macOS Sonoma".to_string(),
            version: "14.4".to_string(),
            build: "23E214".to_string(),
            catalog_url: "https://example.test/catalog".to_string(),
            server_metadata_url: None,
            distribution_url: None,
            post_date: None,
            packages: vec![
                InstallerPackage {
                    name: "InstallAssistant.pkg".to_string(),
                    url: "https://example.test/001-00001/InstallAssistant.pkg".to_string(),
                    size_bytes: Some(123456),
                    integrity_data_url: Some(
                        "https://example.test/001-00001/InstallAssistant.pkg.integrity".to_string(),
                    ),
                },
                InstallerPackage {
                    name: "BaseSystem.dmg".to_string(),
                    url: "https://example.test/001-00001/BaseSystem.dmg".to_string(),
                    size_bytes: Some(654321),
                    integrity_data_url: None,
                },
            ],
        }
    }

    #[test]
    fn builds_cache_root_under_ban_grapple_namespace() {
        let plan = build_download_plan(&sample_release());
        let rendered = plan.cache_dir.display().to_string();

        assert!(rendered.contains("ban-grapple/installers"));
        assert_eq!(plan.items.len(), 2);
        assert_eq!(plan.items[0].size_bytes, Some(123456));
        assert!(plan.items[0].integrity_data_url.is_some());
    }

    #[test]
    fn resolves_installer_package_artifacts() {
        let resolved = resolve_artifacts(ArtifactRequest::InstallerPackages(sample_release()))
            .expect("installer artifacts resolve");

        match resolved {
            ResolvedArtifacts::InstallerPackages(plan) => {
                assert_eq!(plan.items[0].name, "InstallAssistant.pkg");
                assert_eq!(plan.items[1].name, "BaseSystem.dmg");
            }
            other => panic!("unexpected artifact resolution: {other:?}"),
        }
    }

    #[test]
    fn materialize_skips_existing_matching_packages() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time works")
            .as_nanos();
        let temp_dir = std::env::temp_dir().join(format!("ban-grapple-materialize-{unique}"));
        fs::create_dir_all(&temp_dir).expect("temp dir created");

        let local_path = temp_dir.join("BaseSystem.dmg");
        fs::write(&local_path, vec![0_u8; 4]).expect("local file written");

        let plan = DownloadPlan {
            cache_dir: temp_dir.clone(),
            items: vec![DownloadItem {
                name: "BaseSystem.dmg".to_string(),
                source_url: "https://example.test/BaseSystem.dmg".to_string(),
                size_bytes: Some(4),
                integrity_data_url: None,
            }],
        };
        let materialized =
            materialize_installer_packages(&plan, false).expect("materialization succeeds");
        assert_eq!(materialized.len(), 1);
        assert_eq!(materialized[0].local_path, local_path);

        fs::remove_dir_all(temp_dir).expect("temp dir removed");
    }

    #[test]
    fn resolves_managed_image_from_manifest_index() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time works")
            .as_nanos();
        let temp_dir = std::env::temp_dir().join(format!("ban-grapple-test-{unique}"));
        fs::create_dir_all(&temp_dir).expect("temp dir created");

        let mut plan =
            build_system_image_plan_with_channel(&sample_release(), ImageChannel::Stable);
        plan.cache_dir = temp_dir.clone();
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

        let resolved =
            resolve_artifacts(ArtifactRequest::ManagedImage(plan)).expect("managed image resolves");

        match resolved {
            ResolvedArtifacts::ManagedImage(image) => {
                assert_eq!(image.channel, ImageChannel::Stable);
                assert_eq!(image.manifest.release.build, "23E214");
                assert_eq!(image.descriptor.release.version, "14.4");
                assert!(
                    image
                        .image_path
                        .ends_with("macos-sonoma-14.4-23e214.img.zst")
                );
            }
            other => panic!("unexpected artifact resolution: {other:?}"),
        }

        fs::remove_dir_all(temp_dir).expect("temp dir removed");
    }

    #[test]
    fn uses_fresh_installer_metadata_cache() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time works")
            .as_nanos();
        let temp_dir = std::env::temp_dir().join(format!("ban-grapple-installer-{unique}"));
        let cache_path = temp_dir.join("packages.json");
        fs::create_dir_all(&temp_dir).expect("temp dir created");

        let cached_plan = CachedDownloadPlan {
            fetched_at_epoch_secs: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("time works")
                .as_secs(),
            plan: super::DownloadPlan {
                cache_dir: temp_dir.clone(),
                items: vec![super::DownloadItem {
                    name: "Cached.pkg".to_string(),
                    source_url: "https://cache.test/Cached.pkg".to_string(),
                    size_bytes: Some(10),
                    integrity_data_url: None,
                }],
            },
        };
        fs::write(
            &cache_path,
            serde_json::to_vec_pretty(&cached_plan).expect("cache serializes"),
        )
        .expect("cache written");

        let resolved =
            resolve_installer_packages_with_cache_path(&sample_release(), &cache_path, false)
                .expect("installer cache resolves");
        assert_eq!(resolved.items[0].name, "Cached.pkg");

        fs::remove_dir_all(temp_dir).expect("temp dir removed");
    }

    #[test]
    fn refresh_rebuilds_installer_metadata_cache() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time works")
            .as_nanos();
        let temp_dir = std::env::temp_dir().join(format!("ban-grapple-installer-refresh-{unique}"));
        let cache_path = temp_dir.join("packages.json");
        fs::create_dir_all(&temp_dir).expect("temp dir created");

        let stale_plan = CachedDownloadPlan {
            fetched_at_epoch_secs: SystemTime::now()
                .checked_sub(Duration::from_secs(3 * 24 * 60 * 60))
                .expect("time math works")
                .duration_since(UNIX_EPOCH)
                .expect("time works")
                .as_secs(),
            plan: super::DownloadPlan {
                cache_dir: temp_dir.clone(),
                items: vec![super::DownloadItem {
                    name: "Stale.pkg".to_string(),
                    source_url: "https://cache.test/Stale.pkg".to_string(),
                    size_bytes: Some(10),
                    integrity_data_url: None,
                }],
            },
        };
        fs::write(
            &cache_path,
            serde_json::to_vec_pretty(&stale_plan).expect("cache serializes"),
        )
        .expect("cache written");

        let resolved =
            resolve_installer_packages_with_cache_path(&sample_release(), &cache_path, true)
                .expect("refresh resolves");
        assert_eq!(resolved.items[0].name, "InstallAssistant.pkg");

        fs::remove_dir_all(temp_dir).expect("temp dir removed");
    }
}
