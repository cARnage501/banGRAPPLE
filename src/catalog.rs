use plist::Value;
use serde::{Deserialize, Serialize};
use std::cmp::Reverse;
use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::cache::cache_root;

const DEFAULT_CATALOG_URLS: &[&str] = &[
    "https://swscan.apple.com/content/catalogs/others/index-15.merged-1.sucatalog",
    "https://swscan.apple.com/content/catalogs/others/index-14.merged-1.sucatalog",
    "https://swscan.apple.com/content/catalogs/others/index-13.merged-1.sucatalog",
    "https://swscan.apple.com/content/catalogs/others/index-12.merged-1.sucatalog",
];
const CACHE_TTL: Duration = Duration::from_secs(24 * 60 * 60);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstallerPackage {
    pub name: String,
    pub url: String,
    pub size_bytes: Option<u64>,
    pub integrity_data_url: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstallerRelease {
    pub product_id: String,
    pub name: String,
    pub version: String,
    pub build: String,
    pub catalog_url: String,
    pub server_metadata_url: Option<String>,
    pub distribution_url: Option<String>,
    pub post_date: Option<String>,
    #[serde(default)]
    pub packages: Vec<InstallerPackage>,
}

#[derive(Debug)]
pub enum CatalogError {
    Http(reqwest::Error),
    Parse(plist::Error),
    Io(std::io::Error),
    Json(serde_json::Error),
    InvalidCatalog(&'static str),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DistributionMetadata {
    title: Option<String>,
    version: Option<String>,
    build: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CachedReleases {
    fetched_at_epoch_secs: u64,
    releases: Vec<InstallerRelease>,
}

impl fmt::Display for CatalogError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Http(err) => write!(f, "catalog request failed: {err}"),
            Self::Parse(err) => write!(f, "catalog parse failed: {err}"),
            Self::Io(err) => write!(f, "catalog cache IO failed: {err}"),
            Self::Json(err) => write!(f, "catalog cache JSON failed: {err}"),
            Self::InvalidCatalog(message) => write!(f, "invalid catalog: {message}"),
        }
    }
}

impl From<reqwest::Error> for CatalogError {
    fn from(value: reqwest::Error) -> Self {
        Self::Http(value)
    }
}

impl From<plist::Error> for CatalogError {
    fn from(value: plist::Error) -> Self {
        Self::Parse(value)
    }
}

impl From<std::io::Error> for CatalogError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<serde_json::Error> for CatalogError {
    fn from(value: serde_json::Error) -> Self {
        Self::Json(value)
    }
}

pub fn default_catalog_urls() -> &'static [&'static str] {
    DEFAULT_CATALOG_URLS
}

pub fn fetch_releases() -> Result<Vec<InstallerRelease>, CatalogError> {
    fetch_releases_with_policy(false)
}

pub fn refresh_releases() -> Result<Vec<InstallerRelease>, CatalogError> {
    fetch_releases_with_policy(true)
}

fn fetch_releases_with_policy(force_refresh: bool) -> Result<Vec<InstallerRelease>, CatalogError> {
    let cache_path = releases_cache_path();
    fetch_releases_with_cache(cache_path.as_path(), force_refresh, fetch_live_releases)
}

fn fetch_releases_with_cache<F>(
    cache_path: &Path,
    force_refresh: bool,
    mut loader: F,
) -> Result<Vec<InstallerRelease>, CatalogError>
where
    F: FnMut() -> Result<Vec<InstallerRelease>, CatalogError>,
{
    let cached = load_cached_releases(cache_path)?;

    if !force_refresh
        && let Some(cache) = cached.as_ref()
        && is_cache_fresh(cache)
    {
        return Ok(cache.releases.clone());
    }

    match loader() {
        Ok(releases) => {
            store_cached_releases(cache_path, &releases)?;
            Ok(releases)
        }
        Err(err) if !force_refresh => cached.map(|cache| cache.releases).ok_or(err),
        Err(err) => Err(err),
    }
}

fn fetch_live_releases() -> Result<Vec<InstallerRelease>, CatalogError> {
    let mut merged = BTreeMap::new();

    for catalog_url in DEFAULT_CATALOG_URLS {
        for release in fetch_releases_from_url(catalog_url)? {
            merged.entry(release.product_id.clone()).or_insert(release);
        }
    }

    Ok(sort_releases(merged.into_values().collect()))
}

pub fn fetch_releases_from_url(catalog_url: &str) -> Result<Vec<InstallerRelease>, CatalogError> {
    let response = reqwest::blocking::get(catalog_url)?.error_for_status()?;
    let bytes = response.bytes()?;
    let mut releases = parse_catalog_bytes(&bytes, catalog_url)?;

    for release in &mut releases {
        if let Some(distribution_url) = &release.distribution_url
            && let Ok(metadata) = fetch_distribution_metadata(distribution_url)
        {
            if let Some(title) = metadata.title {
                release.name = title;
            }
            if let Some(version) = metadata.version {
                release.version = version;
            }
            if let Some(build) = metadata.build {
                release.build = build;
            }
        }
    }

    Ok(releases)
}

pub fn parse_catalog_bytes(
    catalog_bytes: &[u8],
    catalog_url: &str,
) -> Result<Vec<InstallerRelease>, CatalogError> {
    let catalog = Value::from_reader_xml(catalog_bytes)?;
    parse_catalog_value(&catalog, catalog_url)
}

fn parse_catalog_value(
    catalog: &Value,
    catalog_url: &str,
) -> Result<Vec<InstallerRelease>, CatalogError> {
    let products = catalog
        .as_dictionary()
        .and_then(|dict| dict.get("Products"))
        .and_then(Value::as_dictionary)
        .ok_or(CatalogError::InvalidCatalog("missing Products dictionary"))?;

    let mut releases = Vec::new();

    for (product_id, product_value) in products {
        let Some(product) = product_value.as_dictionary() else {
            continue;
        };

        if !has_install_assistant_marker(product) {
            continue;
        }

        let release = InstallerRelease {
            product_id: product_id.clone(),
            name: infer_release_name(product),
            version: infer_version(product),
            build: infer_build(product),
            catalog_url: catalog_url.to_string(),
            server_metadata_url: get_string(product, "ServerMetadataURL"),
            distribution_url: product
                .get("Distributions")
                .and_then(Value::as_dictionary)
                .and_then(|dist| {
                    dist.get("English")
                        .and_then(Value::as_string)
                        .or_else(|| dist.values().find_map(Value::as_string))
                })
                .map(str::to_string),
            post_date: product.get("PostDate").map(date_to_string),
            packages: parse_packages(product),
        };

        releases.push(release);
    }

    Ok(sort_releases(releases))
}

fn parse_packages(product: &plist::Dictionary) -> Vec<InstallerPackage> {
    product
        .get("Packages")
        .and_then(Value::as_array)
        .map(|packages| {
            packages
                .iter()
                .filter_map(|pkg| {
                    let dict = pkg.as_dictionary()?;
                    let url = dict.get("URL")?.as_string()?.to_string();
                    Some(InstallerPackage {
                        name: file_name_from_url(&url),
                        url,
                        size_bytes: dict.get("Size").and_then(integer_to_u64),
                        integrity_data_url: dict
                            .get("IntegrityDataURL")
                            .and_then(Value::as_string)
                            .map(str::to_string),
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

fn integer_to_u64(value: &Value) -> Option<u64> {
    match value {
        Value::Integer(number) => {
            let signed = number.as_signed()?;
            u64::try_from(signed).ok()
        }
        _ => None,
    }
}

fn file_name_from_url(url: &str) -> String {
    url.rsplit('/').next().unwrap_or(url).to_string()
}

fn sort_releases(mut releases: Vec<InstallerRelease>) -> Vec<InstallerRelease> {
    releases.sort_by_key(|release| {
        (
            Reverse(version_key(&release.version)),
            Reverse(release.post_date.clone().unwrap_or_default()),
        )
    });
    releases
}

fn fetch_distribution_metadata(url: &str) -> Result<DistributionMetadata, CatalogError> {
    let response = reqwest::blocking::get(url)?.error_for_status()?;
    let text = response.text()?;
    Ok(parse_distribution_metadata(&text))
}

fn has_install_assistant_marker(product: &plist::Dictionary) -> bool {
    let package_match = product
        .get("Packages")
        .and_then(Value::as_array)
        .map(|packages| {
            packages.iter().any(|pkg| {
                pkg.as_dictionary()
                    .and_then(|dict| dict.get("URL"))
                    .and_then(Value::as_string)
                    .map(|url| url.contains("InstallAssistant") || url.contains("BaseSystem"))
                    .unwrap_or(false)
            })
        })
        .unwrap_or(false);

    let metadata_match = product
        .get("ExtendedMetaInfo")
        .and_then(Value::as_dictionary)
        .and_then(|meta| meta.get("InstallAssistantPackageIdentifiers"))
        .is_some();

    package_match || metadata_match
}

fn infer_release_name(product: &plist::Dictionary) -> String {
    if let Some(name) = product
        .get("ExtendedMetaInfo")
        .and_then(Value::as_dictionary)
        .and_then(|meta| meta.get("InstallAssistantPackageIdentifiers"))
        .and_then(Value::as_dictionary)
        .and_then(|identifiers| identifiers.values().find_map(Value::as_string))
        .and_then(release_name_from_text)
    {
        return name;
    }

    if let Some(metadata_url) = get_string(product, "ServerMetadataURL")
        && let Some(name) = release_name_from_text(&metadata_url)
    {
        return name;
    }

    "macOS".to_string()
}

fn release_name_from_text(value: &str) -> Option<String> {
    let lowered = value.to_ascii_lowercase();
    if lowered.contains("tahoe") {
        return Some("macOS Tahoe".to_string());
    }
    if lowered.contains("sequoia") {
        return Some("macOS Sequoia".to_string());
    }
    if lowered.contains("sonoma") {
        return Some("macOS Sonoma".to_string());
    }
    if lowered.contains("ventura") {
        return Some("macOS Ventura".to_string());
    }
    if lowered.contains("monterey") {
        return Some("macOS Monterey".to_string());
    }
    None
}

fn infer_version(product: &plist::Dictionary) -> String {
    if let Some(server_metadata_url) = get_string(product, "ServerMetadataURL")
        && let Some(version) = extract_version_like(&server_metadata_url)
    {
        return version;
    }

    if let Some(url) = first_package_url(product)
        && let Some(version) = extract_version_like(&url)
    {
        return version;
    }

    "unknown".to_string()
}

fn infer_build(product: &plist::Dictionary) -> String {
    if let Some(server_metadata_url) = get_string(product, "ServerMetadataURL")
        && let Some(build) = extract_build_like(&server_metadata_url)
    {
        return build;
    }

    "unknown".to_string()
}

fn get_string(product: &plist::Dictionary, key: &str) -> Option<String> {
    product
        .get(key)
        .and_then(Value::as_string)
        .map(str::to_string)
}

fn first_package_url(product: &plist::Dictionary) -> Option<String> {
    product
        .get("Packages")
        .and_then(Value::as_array)
        .and_then(|packages| {
            packages.iter().find_map(|pkg| {
                pkg.as_dictionary()
                    .and_then(|dict| dict.get("URL"))
                    .and_then(Value::as_string)
                    .map(str::to_string)
            })
        })
}

fn extract_version_like(value: &str) -> Option<String> {
    let bytes = value.as_bytes();
    for start in 0..bytes.len() {
        let mut end = start;
        let mut dots = 0;
        while end < bytes.len() {
            let ch = bytes[end] as char;
            if ch.is_ascii_digit() {
                end += 1;
                continue;
            }
            if ch == '.' {
                dots += 1;
                end += 1;
                continue;
            }
            break;
        }

        if end > start {
            let candidate = &value[start..end];
            if dots >= 1
                && candidate
                    .chars()
                    .next()
                    .map(|ch| ch.is_ascii_digit())
                    .unwrap_or(false)
                && candidate
                    .chars()
                    .last()
                    .map(|ch| ch.is_ascii_digit())
                    .unwrap_or(false)
            {
                return Some(candidate.to_string());
            }
        }
    }
    None
}

fn extract_build_like(value: &str) -> Option<String> {
    let mut current = String::new();
    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() {
            current.push(ch);
            continue;
        }

        if is_build_candidate(&current) {
            return Some(current);
        }
        current.clear();
    }

    if is_build_candidate(&current) {
        return Some(current);
    }

    None
}

fn is_build_candidate(value: &str) -> bool {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !first.is_ascii_digit() {
        return false;
    }
    let has_alpha = value.chars().any(|ch| ch.is_ascii_alphabetic());
    has_alpha && value.len() >= 4
}

fn version_key(version: &str) -> Vec<u32> {
    version
        .split('.')
        .map(|part| part.parse::<u32>().unwrap_or(0))
        .collect()
}

fn date_to_string(value: &Value) -> String {
    match value {
        Value::Date(date) => format!("{date:?}"),
        other => other
            .as_string()
            .map(str::to_string)
            .unwrap_or_else(|| format!("{other:?}")),
    }
}

fn parse_distribution_metadata(raw: &str) -> DistributionMetadata {
    DistributionMetadata {
        title: extract_xml_tag(raw, "title"),
        version: extract_auxinfo_value(raw, "VERSION"),
        build: extract_auxinfo_value(raw, "BUILD"),
    }
}

fn extract_xml_tag(raw: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = raw.find(&open)? + open.len();
    let end = raw[start..].find(&close)? + start;
    Some(raw[start..end].trim().to_string())
}

fn extract_auxinfo_value(raw: &str, key: &str) -> Option<String> {
    let marker = format!("<key>{key}</key>");
    let start = raw.find(&marker)? + marker.len();
    let remainder = &raw[start..];
    let string_open = remainder.find("<string>")? + "<string>".len();
    let string_end = remainder[string_open..].find("</string>")? + string_open;
    Some(remainder[string_open..string_end].trim().to_string())
}

fn releases_cache_path() -> PathBuf {
    cache_root().join("catalog").join("releases.json")
}

fn load_cached_releases(path: &Path) -> Result<Option<CachedReleases>, CatalogError> {
    match fs::read_to_string(path) {
        Ok(raw) => Ok(Some(serde_json::from_str(&raw)?)),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(CatalogError::Io(err)),
    }
}

fn store_cached_releases(path: &Path, releases: &[InstallerRelease]) -> Result<(), CatalogError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let payload = CachedReleases {
        fetched_at_epoch_secs: current_epoch_secs()?,
        releases: releases.to_vec(),
    };
    fs::write(path, serde_json::to_vec_pretty(&payload)?)?;
    Ok(())
}

fn current_epoch_secs() -> Result<u64, CatalogError> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| CatalogError::InvalidCatalog("system clock is before unix epoch"))?
        .as_secs())
}

fn is_cache_fresh(cache: &CachedReleases) -> bool {
    current_epoch_secs()
        .map(|now| now.saturating_sub(cache.fetched_at_epoch_secs) < CACHE_TTL.as_secs())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::{
        CachedReleases, default_catalog_urls, fetch_releases_with_cache, is_cache_fresh,
        parse_catalog_bytes, parse_distribution_metadata,
    };
    use crate::catalog::InstallerRelease;

    #[test]
    fn parses_install_assistant_entries_from_fixture() {
        let fixture = include_bytes!("../tests/fixtures/sample_catalog.plist");
        let releases =
            parse_catalog_bytes(fixture, default_catalog_urls()[0]).expect("catalog parses");

        assert_eq!(releases.len(), 1);
        assert_eq!(releases[0].product_id, "001-00001");
        assert_eq!(releases[0].name, "macOS Sonoma");
        assert_eq!(releases[0].catalog_url, default_catalog_urls()[0]);
        assert!(releases[0].distribution_url.is_some());
        assert_eq!(releases[0].packages.len(), 2);
        assert_eq!(releases[0].packages[0].name, "InstallAssistant.pkg");
        assert_eq!(releases[0].packages[0].size_bytes, Some(123456));
        assert!(releases[0].packages[0].integrity_data_url.is_some());
    }

    #[test]
    fn parses_distribution_metadata() {
        let metadata = parse_distribution_metadata(
            r#"
            <installer-gui-script>
                <title>macOS Tahoe</title>
                <auxinfo>
                    <dict>
                        <key>BUILD</key>
                        <string>25B78</string>
                        <key>VERSION</key>
                        <string>26.1</string>
                    </dict>
                </auxinfo>
            </installer-gui-script>
            "#,
        );

        assert_eq!(metadata.title.as_deref(), Some("macOS Tahoe"));
        assert_eq!(metadata.version.as_deref(), Some("26.1"));
        assert_eq!(metadata.build.as_deref(), Some("25B78"));
    }

    #[test]
    fn uses_fresh_cache_without_hitting_loader() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time works")
            .as_nanos();
        let temp_dir = std::env::temp_dir().join(format!("ban-grapple-catalog-{unique}"));
        let cache_path = temp_dir.join("releases.json");
        fs::create_dir_all(&temp_dir).expect("temp dir created");

        let cached_release = InstallerRelease {
            product_id: "001-00001".to_string(),
            name: "macOS Sonoma".to_string(),
            version: "14.4".to_string(),
            build: "23E214".to_string(),
            catalog_url: default_catalog_urls()[0].to_string(),
            server_metadata_url: None,
            distribution_url: None,
            post_date: None,
            packages: Vec::new(),
        };
        let payload = CachedReleases {
            fetched_at_epoch_secs: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("time works")
                .as_secs(),
            releases: vec![cached_release.clone()],
        };
        fs::write(
            &cache_path,
            serde_json::to_vec_pretty(&payload).expect("payload serializes"),
        )
        .expect("cache written");

        let calls = Cell::new(0);
        let releases = fetch_releases_with_cache(&cache_path, false, || {
            calls.set(calls.get() + 1);
            Ok::<_, super::CatalogError>(Vec::new())
        })
        .expect("cache resolves");

        assert_eq!(calls.get(), 0);
        assert_eq!(releases, vec![cached_release]);
        fs::remove_dir_all(temp_dir).expect("temp dir removed");
    }

    #[test]
    fn refresh_bypasses_cache_and_updates_from_loader() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time works")
            .as_nanos();
        let temp_dir = std::env::temp_dir().join(format!("ban-grapple-refresh-{unique}"));
        let cache_path = temp_dir.join("releases.json");
        fs::create_dir_all(&temp_dir).expect("temp dir created");

        let releases = fetch_releases_with_cache(&cache_path, true, || {
            Ok::<_, super::CatalogError>(vec![InstallerRelease {
                product_id: "001-00099".to_string(),
                name: "macOS Sequoia".to_string(),
                version: "15.0".to_string(),
                build: "24A335".to_string(),
                catalog_url: default_catalog_urls()[0].to_string(),
                server_metadata_url: None,
                distribution_url: None,
                post_date: None,
                packages: Vec::new(),
            }])
        })
        .expect("refresh resolves");

        assert_eq!(releases.len(), 1);
        let raw = fs::read_to_string(&cache_path).expect("cache readable");
        assert!(raw.contains("macOS Sequoia"));
        fs::remove_dir_all(temp_dir).expect("temp dir removed");
    }

    #[test]
    fn stale_cache_is_not_fresh() {
        let stale = CachedReleases {
            fetched_at_epoch_secs: 0,
            releases: Vec::new(),
        };
        assert!(!is_cache_fresh(&stale));
    }
}
