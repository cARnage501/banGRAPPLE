use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use reqwest::blocking::Client;
use sha2::{Digest, Sha256};

use crate::cache::cache_root;

const REQUIRED_EFI_FILES: &[&str] = &["EFI/BOOT/BOOTx64.efi", "EFI/OC/OpenCore.efi"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BootloaderSource {
    UserPath(PathBuf),
    OpenCoreRelease(String),
}

impl fmt::Display for BootloaderSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UserPath(path) => write!(f, "user EFI tree ({})", path.display()),
            Self::OpenCoreRelease(version) => write!(f, "OpenCore {}", version),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedBootloader {
    pub source: BootloaderSource,
    pub efi_dir: PathBuf,
    pub cache_dir: PathBuf,
    pub archive_path: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpenCoreReleaseManifest {
    pub version: &'static str,
    pub url: &'static str,
    pub sha256: &'static str,
    pub archive_name: &'static str,
    pub extracted_efi_relpath: &'static str,
}

const OPENCORE_0_9_9: OpenCoreReleaseManifest = OpenCoreReleaseManifest {
    version: "0.9.9",
    url: "https://github.com/acidanthera/OpenCorePkg/releases/download/0.9.9/OpenCore-0.9.9-RELEASE.zip",
    sha256: "8eeec35ca218b466381fa3af25e3deae414d97cb9ec3d608bb4947e8723212d4",
    archive_name: "OpenCore-0.9.9-RELEASE.zip",
    extracted_efi_relpath: "X64/EFI",
};

pub fn default_bootloader_source() -> BootloaderSource {
    BootloaderSource::OpenCoreRelease(OPENCORE_0_9_9.version.to_string())
}

pub fn resolve_bootloader(
    source: &BootloaderSource,
    force_refresh: bool,
) -> Result<ResolvedBootloader, String> {
    match source {
        BootloaderSource::UserPath(path) => resolve_user_bootloader(path),
        BootloaderSource::OpenCoreRelease(version) => {
            resolve_opencore_release(version, force_refresh)
        }
    }
}

pub fn parse_bootloader_source(args: &[String]) -> Result<BootloaderSource, String> {
    let mut iter = args.iter().skip(2);
    let mut efi_path: Option<PathBuf> = None;
    let mut fetch_opencore = false;

    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--efi" => {
                let value = iter
                    .next()
                    .ok_or_else(|| "usage: --efi <path-to-EFI-tree>".to_string())?;
                efi_path = Some(PathBuf::from(value));
            }
            "--fetch-opencore" => {
                fetch_opencore = true;
            }
            _ => {}
        }
    }

    match (efi_path, fetch_opencore) {
        (Some(_), true) => Err("use either --efi or --fetch-opencore, not both".to_string()),
        (Some(path), false) => Ok(BootloaderSource::UserPath(path)),
        (None, true) => Ok(default_bootloader_source()),
        (None, false) => {
            Err("installer mode requires either --efi <path> or --fetch-opencore".to_string())
        }
    }
}

pub fn pinned_opencore_release(version: &str) -> Result<OpenCoreReleaseManifest, String> {
    match version {
        "0.9.9" => Ok(OPENCORE_0_9_9),
        other => Err(format!(
            "no pinned OpenCore manifest is configured for version '{other}'"
        )),
    }
}

fn resolve_user_bootloader(path: &Path) -> Result<ResolvedBootloader, String> {
    validate_efi_tree(path)?;
    Ok(ResolvedBootloader {
        source: BootloaderSource::UserPath(path.to_path_buf()),
        efi_dir: path.to_path_buf(),
        cache_dir: path.to_path_buf(),
        archive_path: None,
    })
}

fn resolve_opencore_release(
    version: &str,
    force_refresh: bool,
) -> Result<ResolvedBootloader, String> {
    let release = pinned_opencore_release(version)?;
    let cache_dir = cache_root()
        .join("bootloader")
        .join("opencore")
        .join(release.version);
    let archive_path = cache_dir.join(release.archive_name);
    let extract_root = cache_dir.join("extracted");
    let efi_dir = extract_root.join(release.extracted_efi_relpath);

    fs::create_dir_all(&cache_dir).map_err(|err| {
        format!(
            "failed to create bootloader cache '{}': {err}",
            cache_dir.display()
        )
    })?;

    let needs_download = force_refresh || !archive_path.exists();
    if needs_download {
        download_file(release.url, &archive_path)?;
    }

    verify_sha256(&archive_path, release.sha256)?;

    if force_refresh && extract_root.exists() {
        fs::remove_dir_all(&extract_root).map_err(|err| {
            format!(
                "failed to clear previous bootloader extraction '{}': {err}",
                extract_root.display()
            )
        })?;
    }

    if !efi_dir.exists() {
        extract_archive(&archive_path, &extract_root)?;
    }
    validate_efi_tree(&efi_dir)?;

    Ok(ResolvedBootloader {
        source: BootloaderSource::OpenCoreRelease(release.version.to_string()),
        efi_dir,
        cache_dir,
        archive_path: Some(archive_path),
    })
}

fn validate_efi_tree(path: &Path) -> Result<(), String> {
    if !path.exists() {
        return Err(format!("EFI tree '{}' does not exist", path.display()));
    }
    for relative in REQUIRED_EFI_FILES {
        let candidate = path.join(relative.strip_prefix("EFI/").unwrap_or(relative));
        if !candidate.exists() {
            return Err(format!(
                "EFI tree '{}' is missing required file '{}'",
                path.display(),
                relative
            ));
        }
    }
    Ok(())
}

fn download_file(url: &str, destination: &Path) -> Result<(), String> {
    let client = Client::builder()
        .build()
        .map_err(|err| format!("failed to build bootloader download client: {err}"))?;
    let response = client
        .get(url)
        .send()
        .and_then(|resp| resp.error_for_status())
        .map_err(|err| format!("failed to download bootloader archive '{url}': {err}"))?;
    let bytes = response
        .bytes()
        .map_err(|err| format!("failed to read bootloader archive response: {err}"))?;
    fs::write(destination, &bytes).map_err(|err| {
        format!(
            "failed to write bootloader archive '{}': {err}",
            destination.display()
        )
    })
}

fn verify_sha256(path: &Path, expected: &str) -> Result<(), String> {
    let bytes = fs::read(path).map_err(|err| {
        format!(
            "failed to read bootloader archive '{}': {err}",
            path.display()
        )
    })?;
    let actual = hex_sha256(&bytes);
    if actual != expected {
        return Err(format!(
            "bootloader archive checksum mismatch for '{}': expected {}, got {}",
            path.display(),
            expected,
            actual
        ));
    }
    Ok(())
}

fn extract_archive(archive_path: &Path, extract_root: &Path) -> Result<(), String> {
    fs::create_dir_all(extract_root).map_err(|err| {
        format!(
            "failed to create bootloader extraction directory '{}': {err}",
            extract_root.display()
        )
    })?;
    let output = Command::new("7z")
        .arg("x")
        .arg(archive_path)
        .arg(format!("-o{}", extract_root.display()))
        .arg("-y")
        .output()
        .map_err(|err| format!("failed to start 7z for bootloader extraction: {err}"))?;
    if !output.status.success() {
        return Err(format!(
            "7z failed to extract bootloader archive '{}': {}",
            archive_path.display(),
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok(())
}

fn hex_sha256(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut rendered = String::with_capacity(digest.len() * 2);
    for byte in digest {
        rendered.push_str(&format!("{byte:02x}"));
    }
    rendered
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::{
        BootloaderSource, default_bootloader_source, hex_sha256, parse_bootloader_source,
        pinned_opencore_release, resolve_bootloader,
    };

    #[test]
    fn parses_user_bootloader_source() {
        let args = vec![
            "ban-grapple".to_string(),
            "plan-installer".to_string(),
            "--efi".to_string(),
            "./EFI".to_string(),
            "/dev/sdb".to_string(),
        ];
        let source = parse_bootloader_source(&args).expect("bootloader parses");
        assert!(matches!(source, BootloaderSource::UserPath(_)));
    }

    #[test]
    fn parses_fetch_opencore_source() {
        let args = vec![
            "ban-grapple".to_string(),
            "plan-installer".to_string(),
            "--fetch-opencore".to_string(),
            "/dev/sdb".to_string(),
        ];
        let source = parse_bootloader_source(&args).expect("bootloader parses");
        assert_eq!(source, default_bootloader_source());
    }

    #[test]
    fn resolves_user_bootloader_tree() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time works")
            .as_nanos();
        let temp_dir = std::env::temp_dir().join(format!("ban-grapple-efi-{unique}"));
        fs::create_dir_all(temp_dir.join("EFI/BOOT")).expect("boot dir created");
        fs::create_dir_all(temp_dir.join("EFI/OC")).expect("oc dir created");
        fs::write(temp_dir.join("EFI/BOOT/BOOTx64.efi"), b"boot").expect("boot file written");
        fs::write(temp_dir.join("EFI/OC/OpenCore.efi"), b"oc").expect("oc file written");

        let resolved = resolve_bootloader(&BootloaderSource::UserPath(temp_dir.join("EFI")), false)
            .expect("user bootloader resolves");
        assert!(resolved.efi_dir.ends_with("EFI"));

        fs::remove_dir_all(temp_dir).expect("temp dir removed");
    }

    #[test]
    fn exposes_pinned_opencore_release() {
        let release = pinned_opencore_release("0.9.9").expect("release exists");
        assert_eq!(release.archive_name, "OpenCore-0.9.9-RELEASE.zip");
        assert!(release.url.contains("OpenCorePkg/releases/download/0.9.9"));
    }

    #[test]
    fn computes_sha256_hex() {
        assert_eq!(
            hex_sha256(b"ban-grapple"),
            "4fae31fe245e45631e4ea324b83a1f59fbcb1e3a1d8e4fe2165f6aebe8c2a5d3"
        );
    }
}
