use std::fmt;
use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use serde::Serialize;
use sha2::{Digest, Sha256};
use xz2::read::XzDecoder;

use crate::rebuild::{PBZX_MAGIC, RebuildError, XZ_MAGIC};

const BXDIFF_MAGIC: &[u8; 8] = b"BXDIFF50";
const RIDIFF_MAGIC: &[u8; 8] = b"RIDIFF10";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PatchWrapperKind {
    Bxdiff50,
    Ridiff10,
}

impl PatchWrapperKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::Bxdiff50 => "bxdiff50",
            Self::Ridiff10 => "ridiff10",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PatchLayerProbe {
    pub path: PathBuf,
    pub wrapper_kind: PatchWrapperKind,
    pub size_bytes: u64,
    pub pbzx_offset: usize,
    pub wrapper_prefix_len: usize,
    pub wrapper_prefix_sha256_16: String,
    pub decoded_size: u64,
    pub decoded_sha256: String,
    pub application_law: PatchApplicationLaw,
    pub disk_image: Option<DecodedDiskImageSummary>,
    pub ridiff_program: Option<RidiffExtentProgramSummary>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedPatchLayer {
    pub path: PathBuf,
    pub wrapper_kind: PatchWrapperKind,
    pub decoded_path: PathBuf,
    pub decoded_size: u64,
    pub decoded_sha256: String,
    pub application_law: PatchApplicationLaw,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PatchApplicationLaw {
    WrappedDiskImage,
    OrderedExtentProgram,
    OpaqueDecodedPayload,
}

impl PatchApplicationLaw {
    pub fn label(self) -> &'static str {
        match self {
            Self::WrappedDiskImage => "wrapped-disk-image",
            Self::OrderedExtentProgram => "ordered-extent-program",
            Self::OpaqueDecodedPayload => "opaque-decoded-payload",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DecodedDiskImageSummary {
    pub has_efi_part_header: bool,
    pub has_koly_trailer: bool,
    pub koly_offset: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RidiffExtentProgramSummary {
    pub target_size_bytes: u64,
    pub declared_record_width: u64,
    pub header_count_a: u64,
    pub header_count_b: u64,
    pub primary_extent_pair_count: u64,
    pub spillover_extent_pair_count: u64,
    pub total_extent_pair_count: u64,
    pub primary_extent_table_end_offset: u64,
    pub total_extent_table_end_offset: u64,
    pub control_region_bytes: u64,
    pub covered_bytes: u64,
    pub max_extent_end: u64,
    pub monotonic_offsets: bool,
    pub requires_external_base_or_transform: bool,
}

#[derive(Debug)]
pub enum PatchError {
    Io(io::Error),
    UnsupportedWrapper(PathBuf),
    MissingPbzx(PathBuf),
    Decode(RebuildError),
}

impl fmt::Display for PatchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => write!(f, "{err}"),
            Self::UnsupportedWrapper(path) => write!(
                f,
                "patch layer '{}' is not a supported BXDIFF50/RIDIFF10 wrapper",
                path.display()
            ),
            Self::MissingPbzx(path) => write!(
                f,
                "patch layer '{}' does not expose an inner pbzx stream",
                path.display()
            ),
            Self::Decode(err) => write!(f, "{err}"),
        }
    }
}

impl From<io::Error> for PatchError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<RebuildError> for PatchError {
    fn from(value: RebuildError) -> Self {
        Self::Decode(value)
    }
}

pub fn inspect_patch_layer(path: &Path) -> Result<PatchLayerProbe, PatchError> {
    let bytes = fs::read(path)?;
    let wrapper_kind =
        detect_wrapper_kind(&bytes).ok_or_else(|| PatchError::UnsupportedWrapper(path.to_path_buf()))?;
    let pbzx_offset =
        locate_pbzx_offset(&bytes).ok_or_else(|| PatchError::MissingPbzx(path.to_path_buf()))?;
    let decoded = decode_patch_pbzx_bytes(&bytes[pbzx_offset..])?;
    let size_bytes = u64::try_from(bytes.len()).map_err(|_| io::Error::other("patch too large"))?;
    let decoded_size =
        u64::try_from(decoded.len()).map_err(|_| io::Error::other("decoded patch too large"))?;
    let (application_law, disk_image, ridiff_program) =
        classify_application_law(wrapper_kind, &decoded);

    Ok(PatchLayerProbe {
        path: path.to_path_buf(),
        wrapper_kind,
        size_bytes,
        pbzx_offset,
        wrapper_prefix_len: pbzx_offset,
        wrapper_prefix_sha256_16: short_sha256_hex(&bytes[..pbzx_offset]),
        decoded_size,
        decoded_sha256: full_sha256_hex(&decoded),
        application_law,
        disk_image,
        ridiff_program,
    })
}

pub fn decode_patch_layer(
    path: &Path,
    output_path: &Path,
) -> Result<DecodedPatchLayer, PatchError> {
    let bytes = fs::read(path)?;
    let wrapper_kind =
        detect_wrapper_kind(&bytes).ok_or_else(|| PatchError::UnsupportedWrapper(path.to_path_buf()))?;
    let pbzx_offset =
        locate_pbzx_offset(&bytes).ok_or_else(|| PatchError::MissingPbzx(path.to_path_buf()))?;
    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut output = File::create(output_path)?;
    let decoded_size = decode_patch_pbzx_to_writer(&bytes[pbzx_offset..], &mut output)?;
    output.flush()?;
    let decoded_bytes = fs::read(output_path)?;
    let decoded_sha256 = full_sha256_hex(&decoded_bytes);
    let (application_law, _, _) = classify_application_law(wrapper_kind, &decoded_bytes);

    Ok(DecodedPatchLayer {
        path: path.to_path_buf(),
        wrapper_kind,
        decoded_path: output_path.to_path_buf(),
        decoded_size,
        decoded_sha256,
        application_law,
    })
}

fn detect_wrapper_kind(bytes: &[u8]) -> Option<PatchWrapperKind> {
    if bytes.starts_with(BXDIFF_MAGIC) {
        Some(PatchWrapperKind::Bxdiff50)
    } else if bytes.starts_with(RIDIFF_MAGIC) {
        Some(PatchWrapperKind::Ridiff10)
    } else {
        None
    }
}

fn decode_patch_pbzx_bytes(data: &[u8]) -> Result<Vec<u8>, RebuildError> {
    let mut decoded = Vec::new();
    decode_patch_pbzx_to_writer(data, &mut decoded)?;
    Ok(decoded)
}

fn decode_patch_pbzx_to_writer(data: &[u8], out: &mut impl Write) -> Result<u64, RebuildError> {
    if !data.starts_with(PBZX_MAGIC) {
        return Err(RebuildError::Parse(
            "patch payload does not start with pbzx".to_string(),
        ));
    }
    if data.len() < 12 {
        return Err(RebuildError::Parse(
            "patch payload is truncated before the pbzx header completes".to_string(),
        ));
    }

    let mut cursor = 12usize;
    let mut written = 0u64;
    while cursor + 16 <= data.len() {
        let flags = u64::from_be_bytes(
            data[cursor..cursor + 8]
                .try_into()
                .map_err(|_| RebuildError::Parse("failed to read pbzx chunk flags".to_string()))?,
        );
        cursor += 8;
        let length = u64::from_be_bytes(
            data[cursor..cursor + 8].try_into().map_err(|_| {
                RebuildError::Parse("failed to read pbzx chunk length".to_string())
            })?,
        );
        cursor += 8;
        let Ok(length_usize) = usize::try_from(length) else {
            break;
        };
        let Some(end) = cursor.checked_add(length_usize) else {
            break;
        };
        if end > data.len() {
            break;
        }
        let chunk = &data[cursor..end];
        if chunk.starts_with(XZ_MAGIC) {
            let mut decoder = XzDecoder::new(chunk);
            written += io::copy(&mut decoder, out)?;
        } else {
            out.write_all(chunk)?;
            written += u64::try_from(chunk.len()).map_err(|_| {
                RebuildError::Parse("decoded raw pbzx chunk length overflowed".to_string())
            })?;
        }
        cursor = end;
        if flags == 0 {
            break;
        }
    }

    Ok(written)
}

fn locate_pbzx_offset(bytes: &[u8]) -> Option<usize> {
    bytes.windows(PBZX_MAGIC.len())
        .position(|window| window == PBZX_MAGIC)
}

fn classify_application_law(
    wrapper_kind: PatchWrapperKind,
    decoded: &[u8],
) -> (
    PatchApplicationLaw,
    Option<DecodedDiskImageSummary>,
    Option<RidiffExtentProgramSummary>,
) {
    match wrapper_kind {
        PatchWrapperKind::Bxdiff50 => {
            let disk_image = inspect_decoded_disk_image(decoded);
            if disk_image.is_some() {
                (PatchApplicationLaw::WrappedDiskImage, disk_image, None)
            } else {
                (PatchApplicationLaw::OpaqueDecodedPayload, None, None)
            }
        }
        PatchWrapperKind::Ridiff10 => {
            let ridiff_program = inspect_ridiff_extent_program(decoded);
            if ridiff_program.is_some() {
                (PatchApplicationLaw::OrderedExtentProgram, None, ridiff_program)
            } else {
                (PatchApplicationLaw::OpaqueDecodedPayload, None, None)
            }
        }
    }
}

fn inspect_decoded_disk_image(decoded: &[u8]) -> Option<DecodedDiskImageSummary> {
    let has_efi_part_header = decoded.len() >= 520 && &decoded[512..520] == b"EFI PART";
    let koly_offset = decoded
        .windows(4)
        .rposition(|window| window == b"koly")
        .and_then(|offset| u64::try_from(offset).ok());
    let has_koly_trailer = koly_offset.is_some();

    if !has_efi_part_header && !has_koly_trailer {
        return None;
    }

    Some(DecodedDiskImageSummary {
        has_efi_part_header,
        has_koly_trailer,
        koly_offset,
    })
}

fn inspect_ridiff_extent_program(decoded: &[u8]) -> Option<RidiffExtentProgramSummary> {
    if decoded.len() < 0x40 {
        return None;
    }

    let target_size_bytes = read_le_u64(decoded, 0x20)?;
    let declared_record_width = read_le_u64(decoded, 0x28)?;
    let header_count_a = read_le_u64(decoded, 0x30)?;
    let header_count_b = read_le_u64(decoded, 0x38)?;
    if target_size_bytes == 0 || declared_record_width != 24 || header_count_a == 0 {
        return None;
    }

    let primary_extent_count = usize::try_from(header_count_b).ok()?;
    let total_extent_count = usize::try_from(header_count_a).ok()?;
    if total_extent_count < primary_extent_count {
        return None;
    }

    let table_start = 0x40usize;
    let primary_table_bytes = primary_extent_count.checked_mul(16)?;
    let primary_table_end = table_start.checked_add(primary_table_bytes)?;
    let total_table_bytes = total_extent_count.checked_mul(16)?;
    let total_table_end = table_start.checked_add(total_table_bytes)?;
    if total_table_end > decoded.len() {
        return None;
    }

    let mut covered_bytes = 0u64;
    let mut max_extent_end = 0u64;
    let mut monotonic_offsets = true;
    let mut previous_offset = None;
    for index in 0..total_extent_count {
        let offset = table_start + index * 16;
        let extent_offset = read_le_u64(decoded, offset)?;
        let extent_length = read_le_u64(decoded, offset + 8)?;
        if let Some(previous) = previous_offset {
            if extent_offset < previous {
                monotonic_offsets = false;
            }
        }
        previous_offset = Some(extent_offset);
        covered_bytes = covered_bytes.checked_add(extent_length)?;
        let end = extent_offset.checked_add(extent_length)?;
        if end > max_extent_end {
            max_extent_end = end;
        }
    }

    if max_extent_end > target_size_bytes {
        return None;
    }

    Some(RidiffExtentProgramSummary {
        target_size_bytes,
        declared_record_width,
        header_count_a,
        header_count_b,
        primary_extent_pair_count: header_count_b,
        spillover_extent_pair_count: header_count_a - header_count_b,
        total_extent_pair_count: header_count_a,
        primary_extent_table_end_offset: u64::try_from(primary_table_end).ok()?,
        total_extent_table_end_offset: u64::try_from(total_table_end).ok()?,
        control_region_bytes: u64::try_from(decoded.len() - total_table_end).ok()?,
        covered_bytes,
        max_extent_end,
        monotonic_offsets,
        requires_external_base_or_transform: u64::try_from(decoded.len() - total_table_end).ok()?
            < covered_bytes,
    })
}

fn read_le_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    let window = bytes.get(offset..offset + 8)?;
    Some(u64::from_le_bytes(window.try_into().ok()?))
}

fn short_sha256_hex(data: &[u8]) -> String {
    let digest = Sha256::digest(data);
    let full = format!("{digest:x}");
    full[..16].to_string()
}

fn full_sha256_hex(data: &[u8]) -> String {
    let digest = Sha256::digest(data);
    format!("{digest:x}")
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::Write;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use xz2::write::XzEncoder;

    use super::{
        PatchApplicationLaw, PatchWrapperKind, decode_patch_layer, inspect_patch_layer,
    };

    fn unique_dir(label: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("ban-grapple-patch-{label}-{nanos}"))
    }

    fn wrap_pbzx(decoded: &[u8]) -> Vec<u8> {
        let mut encoder = XzEncoder::new(Vec::new(), 6);
        encoder.write_all(decoded).unwrap();
        let compressed = encoder.finish().unwrap();

        let mut wrapped = Vec::new();
        wrapped.extend_from_slice(b"pbzx");
        wrapped.extend_from_slice(&0x0010_0000_u64.to_be_bytes());
        wrapped.extend_from_slice(&0x0010_0000_u64.to_be_bytes());
        wrapped.extend_from_slice(&(compressed.len() as u64).to_be_bytes());
        wrapped.extend_from_slice(&compressed);
        wrapped
    }

    fn wrap_bxdiff(decoded: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0u8; 60];
        bytes[..8].copy_from_slice(b"BXDIFF50");
        bytes.extend_from_slice(&wrap_pbzx(decoded));
        bytes
    }

    fn wrap_ridiff(decoded: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0u8; 62];
        bytes[..8].copy_from_slice(b"RIDIFF10");
        bytes.extend_from_slice(&wrap_pbzx(decoded));
        bytes
    }

    fn synthetic_udif_image() -> Vec<u8> {
        let mut bytes = vec![0u8; 4096];
        bytes[512..520].copy_from_slice(b"EFI PART");
        let koly_offset = bytes.len() - 512;
        bytes[koly_offset..koly_offset + 4].copy_from_slice(b"koly");
        bytes
    }

    fn synthetic_ridiff_program() -> Vec<u8> {
        let mut bytes = vec![0u8; 0x40 + 3 * 16 + 64];
        bytes[..32].copy_from_slice(&[0x11; 32]);
        bytes[0x20..0x28].copy_from_slice(&0x0012_0000_u64.to_le_bytes());
        bytes[0x28..0x30].copy_from_slice(&24u64.to_le_bytes());
        bytes[0x30..0x38].copy_from_slice(&5u64.to_le_bytes());
        bytes[0x38..0x40].copy_from_slice(&3u64.to_le_bytes());

        let extents = [(0x1000_u64, 0x2000_u64), (0x4000, 0x1000), (0x8000, 0x3000)];
        for (index, (offset, length)) in extents.into_iter().enumerate() {
            let base = 0x40 + index * 16;
            bytes[base..base + 8].copy_from_slice(&offset.to_le_bytes());
            bytes[base + 8..base + 16].copy_from_slice(&length.to_le_bytes());
        }

        bytes
    }

    #[test]
    fn inspects_bxdiff_wrapper_and_decodes_payload() {
        let root = unique_dir("bxdiff");
        fs::create_dir_all(&root).unwrap();
        let patch_path = root.join("patch.bin");
        fs::write(&patch_path, wrap_bxdiff(&synthetic_udif_image())).unwrap();

        let probe = inspect_patch_layer(&patch_path).unwrap();
        assert_eq!(probe.wrapper_kind, PatchWrapperKind::Bxdiff50);
        assert_eq!(probe.pbzx_offset, 60);
        assert_eq!(probe.application_law, PatchApplicationLaw::WrappedDiskImage);
        assert!(probe.disk_image.as_ref().unwrap().has_efi_part_header);
        assert!(probe.disk_image.as_ref().unwrap().has_koly_trailer);

        let decoded = decode_patch_layer(&patch_path, &root.join("decoded.bin")).unwrap();
        assert_eq!(decoded.wrapper_kind, PatchWrapperKind::Bxdiff50);
        assert_eq!(decoded.application_law, PatchApplicationLaw::WrappedDiskImage);
        assert_eq!(fs::read(decoded.decoded_path).unwrap(), synthetic_udif_image());

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn inspects_ridiff_wrapper_and_decodes_payload() {
        let root = unique_dir("ridiff");
        fs::create_dir_all(&root).unwrap();
        let patch_path = root.join("patch.bin");
        fs::write(&patch_path, wrap_ridiff(&synthetic_ridiff_program())).unwrap();

        let probe = inspect_patch_layer(&patch_path).unwrap();
        assert_eq!(probe.wrapper_kind, PatchWrapperKind::Ridiff10);
        assert_eq!(probe.pbzx_offset, 62);
        assert_eq!(probe.application_law, PatchApplicationLaw::OrderedExtentProgram);
        let summary = probe.ridiff_program.as_ref().unwrap();
        assert_eq!(summary.target_size_bytes, 0x0012_0000);
        assert_eq!(summary.primary_extent_pair_count, 3);
        assert_eq!(summary.spillover_extent_pair_count, 2);
        assert_eq!(summary.total_extent_pair_count, 5);
        assert_eq!(summary.primary_extent_table_end_offset, 0x70);
        assert_eq!(summary.total_extent_table_end_offset, 0x90);
        assert_eq!(summary.covered_bytes, 0x6000);
        assert!(summary.requires_external_base_or_transform);

        let decoded = decode_patch_layer(&patch_path, &root.join("decoded.bin")).unwrap();
        assert_eq!(decoded.wrapper_kind, PatchWrapperKind::Ridiff10);
        assert_eq!(decoded.application_law, PatchApplicationLaw::OrderedExtentProgram);
        assert_eq!(
            fs::read(decoded.decoded_path).unwrap(),
            synthetic_ridiff_program()
        );

        fs::remove_dir_all(root).unwrap();
    }
}
