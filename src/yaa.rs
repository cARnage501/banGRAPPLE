use std::collections::BTreeMap;
use std::ffi::CString;
use std::fmt;
use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Component, Path, PathBuf};

use serde::Serialize;
use sha2::{Digest, Sha256};

const YAA_MAGIC: &[u8; 4] = b"YAA1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum YaaTag {
    Type,
    Path,
    LinkPath,
    Uid8,
    Uid16,
    Uid32,
    Gid8,
    Gid16,
    Gid32,
    Mode,
    Flags8,
    Flags16,
    Flags32,
    InlineFlags32,
    AccessFlags8,
    AccessFlags16,
    AccessFlags32,
    AccessReference8,
    AccessReference16,
    AccessReference32,
    ModifiedTimeSeconds,
    ModifiedTimeTimespec,
    Data,
    DataBig,
    Xattr,
    Unknown([u8; 4]),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum YaaObjectType {
    Directory,
    File,
    Link,
    Other(u8),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct YaaTimespec {
    pub seconds: u64,
    pub nanos: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct YaaExternalPayload {
    pub tag: YaaTag,
    pub length: u64,
    pub payload_offset: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum YaaField {
    Type(YaaObjectType),
    Path(String),
    LinkTarget(String),
    Uid(u32),
    Gid(u32),
    Mode(u16),
    Flags(u32),
    InlineFlags(u32),
    AccessFlags(u32),
    AccessReference(u32),
    ModifiedTime(YaaTimespec),
    ExternalDescriptor(YaaExternalPayload),
    XattrDescriptor { length: u64 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct YaaRecord {
    pub offset: u64,
    pub declared_length: u16,
    pub metadata_length: u64,
    pub parsed_length: u64,
    pub next_record_offset: u64,
    pub object_type: Option<YaaObjectType>,
    pub path: Option<String>,
    pub link_target: Option<String>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub mode: Option<u16>,
    pub flags: Option<u32>,
    pub modified_time: Option<YaaTimespec>,
    pub tags: Vec<YaaTag>,
    pub inline_flags: Vec<u32>,
    pub fields: Vec<YaaField>,
    pub external_payloads: Vec<YaaExternalPayload>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum YaaError {
    Truncated { offset: u64, context: &'static str },
    InvalidMagic { offset: u64 },
    DeclaredLengthTooSmall { offset: u64, declared_length: u16 },
    UnknownTag { offset: u64, tag: [u8; 4] },
    InvalidUtf8Path { offset: u64 },
    IntegerOverflow,
}

#[derive(Debug)]
pub enum YaaStreamError {
    Io(io::Error),
    Parse(YaaError),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct YaaPayloadSummary {
    pub path: Option<String>,
    pub tag: YaaTag,
    pub length: u64,
    pub record_offset: u64,
    pub payload_offset: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct YaaObjectCounts {
    pub directories: u64,
    pub files: u64,
    pub links: u64,
    pub others: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct YaaWalkSummary {
    pub start_offset: u64,
    pub record_count: u64,
    pub last_next_record_offset: u64,
    pub skipped_payload_bytes: u64,
    pub object_counts: YaaObjectCounts,
    pub tag_counts: BTreeMap<String, u64>,
    pub largest_payload: Option<YaaPayloadSummary>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct YaaRegionSummary {
    pub region_index: usize,
    pub summary: YaaWalkSummary,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct YaaMaterializationResult {
    pub output_root: PathBuf,
    pub records_written: u64,
    pub directories_created: u64,
    pub files_created: u64,
    pub links_created: u64,
    pub mode_updates_applied: u64,
    pub ownership_updates_applied: u64,
    pub ownership_update_failures: u64,
    pub xattr_sidecars_written: u64,
    pub last_next_record_offset: u64,
    pub metadata_path: PathBuf,
    pub xattr_root: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DeferredModeUpdate {
    path: PathBuf,
    mode: u16,
}

#[derive(Debug, Serialize)]
struct MaterializedRecordMetadata {
    path: Option<String>,
    link_target: Option<String>,
    object_type: Option<String>,
    record_offset: u64,
    next_record_offset: u64,
    uid: Option<u32>,
    gid: Option<u32>,
    mode: Option<u16>,
    payloads: Vec<MaterializedPayloadMetadata>,
}

#[derive(Debug, Serialize)]
struct MaterializedPayloadMetadata {
    tag: String,
    length: u64,
    payload_offset: u64,
    sha256_16: Option<String>,
    preview_hex: Option<String>,
    sidecar_path: Option<String>,
}

pub struct YaaStreamReader<R> {
    inner: R,
    offset: u64,
}

impl fmt::Display for YaaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated { offset, context } => {
                write!(
                    f,
                    "truncated YAA record at offset {offset} while reading {context}"
                )
            }
            Self::InvalidMagic { offset } => {
                write!(f, "invalid YAA magic at offset {offset}")
            }
            Self::DeclaredLengthTooSmall {
                offset,
                declared_length,
            } => write!(
                f,
                "declared YAA metadata length {declared_length} is too small at offset {offset}"
            ),
            Self::UnknownTag { offset, tag } => write!(
                f,
                "unknown YAA tag '{}' at offset {offset}",
                String::from_utf8_lossy(tag)
            ),
            Self::InvalidUtf8Path { offset } => {
                write!(f, "invalid UTF-8 path payload at offset {offset}")
            }
            Self::IntegerOverflow => write!(f, "integer conversion overflow while parsing YAA"),
        }
    }
}

impl fmt::Display for YaaStreamError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => write!(f, "{err}"),
            Self::Parse(err) => write!(f, "{err}"),
        }
    }
}

impl From<io::Error> for YaaStreamError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<YaaError> for YaaStreamError {
    fn from(value: YaaError) -> Self {
        Self::Parse(value)
    }
}

pub fn parse_record(data: &[u8], offset: usize) -> Result<Option<YaaRecord>, YaaError> {
    parse_record_with_base(data, offset, offset as u64)
}

pub fn parse_record_at(data: &[u8], absolute_offset: u64) -> Result<Option<YaaRecord>, YaaError> {
    parse_record_with_base(data, 0, absolute_offset)
}

fn parse_record_with_base(
    data: &[u8],
    offset: usize,
    absolute_offset: u64,
) -> Result<Option<YaaRecord>, YaaError> {
    if offset >= data.len() {
        return Ok(None);
    }
    if data.len().saturating_sub(offset) < 6 {
        return Err(YaaError::Truncated {
            offset: absolute_offset,
            context: "record header",
        });
    }
    if &data[offset..offset + 4] != YAA_MAGIC {
        return Ok(None);
    }

    let declared_length = read_u16le(data, offset + 4, absolute_offset, "declared length")?;
    if declared_length < 6 {
        return Err(YaaError::DeclaredLengthTooSmall {
            offset: absolute_offset,
            declared_length,
        });
    }

    let metadata_end = offset
        .checked_add(usize::from(declared_length))
        .ok_or(YaaError::IntegerOverflow)?;
    if metadata_end > data.len() {
        return Err(YaaError::Truncated {
            offset: absolute_offset,
            context: "metadata block",
        });
    }

    let mut cursor = offset + 6;
    let mut record = YaaRecord {
        offset: absolute_offset,
        declared_length,
        metadata_length: u64::from(declared_length),
        parsed_length: 0,
        next_record_offset: 0,
        object_type: None,
        path: None,
        link_target: None,
        uid: None,
        gid: None,
        mode: None,
        flags: None,
        modified_time: None,
        tags: Vec::new(),
        inline_flags: Vec::new(),
        fields: Vec::new(),
        external_payloads: Vec::new(),
    };

    while cursor < metadata_end {
        if metadata_end.saturating_sub(cursor) < 4 {
            return Err(YaaError::Truncated {
                offset: absolute_offset + (cursor - offset) as u64,
                context: "tag",
            });
        }

        let tag_bytes: [u8; 4] = data[cursor..cursor + 4]
            .try_into()
            .map_err(|_| YaaError::IntegerOverflow)?;
        cursor += 4;
        let tag_offset = absolute_offset + (cursor - 4 - offset) as u64;
        let tag = decode_tag(tag_bytes);
        record.tags.push(tag.clone());

        match tag {
            YaaTag::Type => {
                let value = read_u8(data, cursor, tag_offset, "TYP1 value")?;
                cursor += 1;
                let kind = decode_object_type(value);
                record.object_type = Some(kind);
                record.fields.push(YaaField::Type(kind));
            }
            YaaTag::Path => {
                let length = usize::from(read_u16le(data, cursor, tag_offset, "PATP length")?);
                cursor += 2;
                let bytes = read_bytes(data, cursor, length, tag_offset, "PATP payload")?;
                cursor += length;
                let path = std::str::from_utf8(bytes)
                    .map_err(|_| YaaError::InvalidUtf8Path { offset: tag_offset })?
                    .to_string();
                record.path = Some(path.clone());
                record.fields.push(YaaField::Path(path));
            }
            YaaTag::LinkPath => {
                let length = usize::from(read_u16le(data, cursor, tag_offset, "LNKP length")?);
                cursor += 2;
                let bytes = read_bytes(data, cursor, length, tag_offset, "LNKP payload")?;
                cursor += length;
                let target = std::str::from_utf8(bytes)
                    .map_err(|_| YaaError::InvalidUtf8Path { offset: tag_offset })?
                    .to_string();
                record.link_target = Some(target.clone());
                record.fields.push(YaaField::LinkTarget(target));
            }
            YaaTag::Uid8 | YaaTag::Uid16 | YaaTag::Uid32 => {
                let width = integer_width(&tag);
                let value = read_width_uint(data, cursor, width, tag_offset, "UID payload")?;
                cursor += width;
                record.uid = Some(value);
                record.fields.push(YaaField::Uid(value));
            }
            YaaTag::Gid8 | YaaTag::Gid16 | YaaTag::Gid32 => {
                let width = integer_width(&tag);
                let value = read_width_uint(data, cursor, width, tag_offset, "GID payload")?;
                cursor += width;
                record.gid = Some(value);
                record.fields.push(YaaField::Gid(value));
            }
            YaaTag::Mode => {
                let value = read_u16le(data, cursor, tag_offset, "MOD2 payload")?;
                cursor += 2;
                record.mode = Some(value);
                record.fields.push(YaaField::Mode(value));
            }
            YaaTag::Flags8 => {
                let value = u32::from(read_u8(data, cursor, tag_offset, "FLG1 payload")?);
                cursor += 1;
                record.flags = Some(value);
                record.fields.push(YaaField::Flags(value));
            }
            YaaTag::Flags16 => {
                let value = u32::from(read_u16le(data, cursor, tag_offset, "FLG2 payload")?);
                cursor += 2;
                record.flags = Some(value);
                record.fields.push(YaaField::Flags(value));
            }
            YaaTag::Flags32 => {
                let value = read_u32le(data, cursor, tag_offset, "FLG4 payload")?;
                cursor += 4;
                record.flags = Some(value);
                record.fields.push(YaaField::Flags(value));
            }
            YaaTag::InlineFlags32 => {
                let value = read_u32le(data, cursor, tag_offset, "FLI4 payload")?;
                cursor += 4;
                record.inline_flags.push(value);
                record.fields.push(YaaField::InlineFlags(value));
            }
            YaaTag::AccessFlags8 | YaaTag::AccessFlags16 | YaaTag::AccessFlags32 => {
                let width = integer_width(&tag);
                let value = read_width_uint(data, cursor, width, tag_offset, "AFT payload")?;
                cursor += width;
                record.fields.push(YaaField::AccessFlags(value));
            }
            YaaTag::AccessReference8 | YaaTag::AccessReference16 | YaaTag::AccessReference32 => {
                let width = integer_width(&tag);
                let value = read_width_uint(data, cursor, width, tag_offset, "AFR payload")?;
                cursor += width;
                record.fields.push(YaaField::AccessReference(value));
            }
            YaaTag::ModifiedTimeSeconds => {
                let seconds = read_u64le(data, cursor, tag_offset, "MTMS payload")?;
                cursor += 8;
                let time = YaaTimespec {
                    seconds,
                    nanos: None,
                };
                record.modified_time = Some(time.clone());
                record.fields.push(YaaField::ModifiedTime(time));
            }
            YaaTag::ModifiedTimeTimespec => {
                let seconds = read_u64le(data, cursor, tag_offset, "MTMT seconds")?;
                cursor += 8;
                let nanos = read_u32le(data, cursor, tag_offset, "MTMT nanos")?;
                cursor += 4;
                let time = YaaTimespec {
                    seconds,
                    nanos: Some(nanos),
                };
                record.modified_time = Some(time.clone());
                record.fields.push(YaaField::ModifiedTime(time));
            }
            YaaTag::Data => {
                let length = u64::from(read_u16le(data, cursor, tag_offset, "DATA length")?);
                cursor += 2;
                let payload_offset = absolute_offset
                    + (metadata_end - offset) as u64
                    + total_payload_length(&record.external_payloads);
                let payload = YaaExternalPayload {
                    tag: YaaTag::Data,
                    length,
                    payload_offset,
                };
                record.external_payloads.push(payload.clone());
                record.fields.push(YaaField::ExternalDescriptor(payload));
            }
            YaaTag::DataBig => {
                let length = u64::from(read_u32le(data, cursor, tag_offset, "DATB length")?);
                cursor += 4;
                let payload_offset = absolute_offset
                    + (metadata_end - offset) as u64
                    + total_payload_length(&record.external_payloads);
                let payload = YaaExternalPayload {
                    tag: YaaTag::DataBig,
                    length,
                    payload_offset,
                };
                record.external_payloads.push(payload.clone());
                record.fields.push(YaaField::ExternalDescriptor(payload));
            }
            YaaTag::Xattr => {
                let length = u64::from(read_u16le(data, cursor, tag_offset, "XATA length")?);
                cursor += 2;
                let payload_offset = absolute_offset
                    + (metadata_end - offset) as u64
                    + total_payload_length(&record.external_payloads);
                let payload = YaaExternalPayload {
                    tag: YaaTag::Xattr,
                    length,
                    payload_offset,
                };
                record.external_payloads.push(payload);
                record.fields.push(YaaField::XattrDescriptor { length });
            }
            YaaTag::Unknown(tag) => {
                return Err(YaaError::UnknownTag {
                    offset: tag_offset,
                    tag,
                });
            }
        }
    }

    let payload_bytes = total_payload_length(&record.external_payloads);
    record.parsed_length = u64::from(declared_length) + payload_bytes;
    record.next_record_offset = absolute_offset + record.parsed_length;

    Ok(Some(record))
}

pub fn parse_records(
    data: &[u8],
    limit: usize,
    start_offset: usize,
) -> Result<Vec<YaaRecord>, YaaError> {
    let mut records = Vec::new();
    let mut offset = start_offset;

    while records.len() < limit {
        let Some(record) = parse_record(data, offset)? else {
            break;
        };
        let next_offset =
            usize::try_from(record.next_record_offset).map_err(|_| YaaError::IntegerOverflow)?;
        if next_offset <= offset {
            break;
        }
        records.push(record);
        offset = next_offset;
    }

    Ok(records)
}

impl<R: Read + Seek> YaaStreamReader<R> {
    pub fn new(inner: R) -> Self {
        Self { inner, offset: 0 }
    }

    pub fn offset(&self) -> u64 {
        self.offset
    }

    pub fn seek_to(&mut self, offset: u64) -> Result<(), YaaStreamError> {
        self.inner.seek(SeekFrom::Start(offset))?;
        self.offset = offset;
        Ok(())
    }

    pub fn next_record(&mut self) -> Result<Option<YaaRecord>, YaaStreamError> {
        let start_offset = self.offset;
        let mut header = [0u8; 6];
        let bytes_read = self.inner.read(&mut header)?;
        if bytes_read == 0 {
            return Ok(None);
        }
        if bytes_read < header.len() {
            self.inner.read_exact(&mut header[bytes_read..])?;
        }

        if &header[..4] != YAA_MAGIC {
            return Err(YaaError::InvalidMagic {
                offset: start_offset,
            }
            .into());
        }

        let declared_length = u16::from_le_bytes([header[4], header[5]]);
        if declared_length < 6 {
            return Err(YaaError::DeclaredLengthTooSmall {
                offset: start_offset,
                declared_length,
            }
            .into());
        }

        let metadata_remaining = usize::from(declared_length) - 6;
        let mut record_bytes = Vec::with_capacity(usize::from(declared_length));
        record_bytes.extend_from_slice(&header);
        record_bytes.resize(usize::from(declared_length), 0);
        self.inner
            .read_exact(&mut record_bytes[6..6 + metadata_remaining])?;

        let Some(record) = parse_record_at(&record_bytes, start_offset)? else {
            return Ok(None);
        };
        self.inner
            .seek(SeekFrom::Start(record.next_record_offset))?;
        self.offset = record.next_record_offset;
        Ok(Some(record))
    }

    pub fn summarize(&mut self, limit: usize) -> Result<YaaWalkSummary, YaaStreamError> {
        let start_offset = self.offset;
        let mut summary = YaaWalkSummary {
            start_offset,
            record_count: 0,
            last_next_record_offset: start_offset,
            skipped_payload_bytes: 0,
            object_counts: YaaObjectCounts::default(),
            tag_counts: BTreeMap::new(),
            largest_payload: None,
        };

        while summary.record_count < limit as u64 {
            let Some(record) = self.next_record()? else {
                break;
            };

            summary.record_count += 1;
            summary.last_next_record_offset = record.next_record_offset;
            summary.skipped_payload_bytes = summary
                .skipped_payload_bytes
                .saturating_add(total_payload_length(&record.external_payloads));

            match record.object_type {
                Some(YaaObjectType::Directory) => summary.object_counts.directories += 1,
                Some(YaaObjectType::File) => summary.object_counts.files += 1,
                Some(YaaObjectType::Link) => summary.object_counts.links += 1,
                Some(YaaObjectType::Other(_)) | None => summary.object_counts.others += 1,
            }

            for tag in &record.tags {
                let label = tag_label(tag);
                *summary.tag_counts.entry(label).or_insert(0) += 1;
            }

            for payload in &record.external_payloads {
                let candidate = YaaPayloadSummary {
                    path: record.path.clone(),
                    tag: payload.tag.clone(),
                    length: payload.length,
                    record_offset: record.offset,
                    payload_offset: payload.payload_offset,
                };
                let should_replace = summary
                    .largest_payload
                    .as_ref()
                    .is_none_or(|current| candidate.length > current.length);
                if should_replace {
                    summary.largest_payload = Some(candidate);
                }
            }
        }

        Ok(summary)
    }

    pub fn summarize_regions(
        &mut self,
        records_per_region: usize,
        region_count: usize,
    ) -> Result<Vec<YaaRegionSummary>, YaaStreamError> {
        let mut regions = Vec::new();
        for region_index in 0..region_count {
            let summary = self.summarize(records_per_region)?;
            if summary.record_count == 0 {
                break;
            }
            regions.push(YaaRegionSummary {
                region_index,
                summary,
            });
        }
        Ok(regions)
    }

    pub fn materialize_prefix(
        &mut self,
        output_root: &Path,
        record_limit: usize,
    ) -> Result<YaaMaterializationResult, YaaStreamError> {
        self.materialize_records(output_root, Some(record_limit))
    }

    pub fn materialize_all(
        &mut self,
        output_root: &Path,
    ) -> Result<YaaMaterializationResult, YaaStreamError> {
        self.materialize_records(output_root, None)
    }

    fn materialize_records(
        &mut self,
        output_root: &Path,
        record_limit: Option<usize>,
    ) -> Result<YaaMaterializationResult, YaaStreamError> {
        fs::create_dir_all(output_root)?;
        let metadata_path = output_root.join("_yaa_materialized.jsonl");
        let xattr_root = output_root.join("_yaa_xattrs");
        fs::create_dir_all(&xattr_root)?;
        let mut metadata_file = File::create(&metadata_path)?;
        let mut deferred_directory_modes = Vec::new();
        let mut result = YaaMaterializationResult {
            output_root: output_root.to_path_buf(),
            records_written: 0,
            directories_created: 0,
            files_created: 0,
            links_created: 0,
            mode_updates_applied: 0,
            ownership_updates_applied: 0,
            ownership_update_failures: 0,
            xattr_sidecars_written: 0,
            last_next_record_offset: self.offset,
            metadata_path,
            xattr_root,
        };

        while record_limit
            .map(|limit| result.records_written < limit as u64)
            .unwrap_or(true)
        {
            let Some(record) = self.next_record()? else {
                break;
            };
            result.records_written += 1;
            result.last_next_record_offset = record.next_record_offset;

            if let Some(relative_path) = record.path.as_deref().and_then(materialized_relative_path)
            {
                let target_path = output_root.join(relative_path);
                match record.object_type {
                    Some(YaaObjectType::Directory) => {
                        fs::create_dir_all(&target_path)?;
                        result.directories_created += 1;
                        queue_directory_mode_if_present(
                            &target_path,
                            record.mode,
                            &mut deferred_directory_modes,
                        );
                        apply_ownership_if_present(&target_path, &record, &mut result);
                    }
                    Some(YaaObjectType::File) => {
                        if let Some(parent) = target_path.parent() {
                            fs::create_dir_all(parent)?;
                        }
                        let mut out = File::create(&target_path)?;
                        for payload in &record.external_payloads {
                            if matches!(payload.tag, YaaTag::Data | YaaTag::DataBig) {
                                self.copy_payload(payload, &mut out)?;
                            }
                        }
                        result.files_created += 1;
                        apply_mode_if_present(&target_path, record.mode, &mut result)?;
                        apply_ownership_if_present(&target_path, &record, &mut result);
                    }
                    Some(YaaObjectType::Link) => {
                        if let Some(parent) = target_path.parent() {
                            fs::create_dir_all(parent)?;
                        }
                        if let Some(link_target) = record.link_target.as_deref() {
                            symlink(link_target, &target_path)?;
                            result.links_created += 1;
                            apply_ownership_if_present(&target_path, &record, &mut result);
                        }
                    }
                    _ => {}
                }
            }

            let payloads = self.capture_payload_metadata(&record, &result.xattr_root)?;
            result.xattr_sidecars_written += payloads
                .iter()
                .filter(|payload| payload.sidecar_path.is_some())
                .count() as u64;
            let metadata = MaterializedRecordMetadata {
                path: record.path.clone(),
                link_target: record.link_target.clone(),
                object_type: record.object_type.map(object_type_label),
                record_offset: record.offset,
                next_record_offset: record.next_record_offset,
                uid: record.uid,
                gid: record.gid,
                mode: record.mode,
                payloads,
            };
            serde_json::to_writer(&mut metadata_file, &metadata).map_err(io::Error::other)?;
            writeln!(&mut metadata_file)?;
        }

        apply_deferred_directory_modes(&deferred_directory_modes, &mut result)?;

        Ok(result)
    }

    fn copy_payload(
        &mut self,
        payload: &YaaExternalPayload,
        out: &mut File,
    ) -> Result<(), YaaStreamError> {
        let blob = self.read_payload_blob(payload)?;
        out.write_all(&blob)?;
        Ok(())
    }

    fn capture_payload_metadata(
        &mut self,
        record: &YaaRecord,
        xattr_root: &Path,
    ) -> Result<Vec<MaterializedPayloadMetadata>, YaaStreamError> {
        let mut payloads = Vec::new();
        for (index, payload) in record.external_payloads.iter().enumerate() {
            let blob = self.read_payload_blob(payload)?;
            let mut metadata = MaterializedPayloadMetadata {
                tag: tag_label(&payload.tag),
                length: payload.length,
                payload_offset: payload.payload_offset,
                sha256_16: Some(short_sha256_hex(&blob)),
                preview_hex: Some(preview_hex(&blob, 32)),
                sidecar_path: None,
            };
            if matches!(payload.tag, YaaTag::Xattr) {
                let sidecar_path =
                    xattr_root.join(format!("{:016x}-{index:02}.bin", record.offset));
                fs::write(&sidecar_path, &blob)?;
                metadata.sidecar_path = Some(sidecar_path.display().to_string());
            }
            payloads.push(metadata);
        }
        Ok(payloads)
    }

    fn read_payload_blob(
        &mut self,
        payload: &YaaExternalPayload,
    ) -> Result<Vec<u8>, YaaStreamError> {
        let restore_offset = self.offset;
        self.inner.seek(SeekFrom::Start(payload.payload_offset))?;
        let mut limited = (&mut self.inner).take(payload.length);
        let mut blob = Vec::new();
        limited.read_to_end(&mut blob)?;
        self.inner.seek(SeekFrom::Start(restore_offset))?;
        Ok(blob)
    }
}

fn total_payload_length(payloads: &[YaaExternalPayload]) -> u64 {
    payloads.iter().map(|payload| payload.length).sum()
}

fn integer_width(tag: &YaaTag) -> usize {
    match tag {
        YaaTag::Uid8
        | YaaTag::Gid8
        | YaaTag::Flags8
        | YaaTag::AccessFlags8
        | YaaTag::AccessReference8 => 1,
        YaaTag::Uid16
        | YaaTag::Gid16
        | YaaTag::Flags16
        | YaaTag::AccessFlags16
        | YaaTag::AccessReference16 => 2,
        YaaTag::Uid32
        | YaaTag::Gid32
        | YaaTag::Flags32
        | YaaTag::InlineFlags32
        | YaaTag::AccessFlags32
        | YaaTag::AccessReference32
        | YaaTag::DataBig => 4,
        _ => 0,
    }
}

fn decode_tag(tag: [u8; 4]) -> YaaTag {
    match &tag {
        b"TYP1" => YaaTag::Type,
        b"PATP" => YaaTag::Path,
        b"LNKP" => YaaTag::LinkPath,
        b"UID1" => YaaTag::Uid8,
        b"UID2" => YaaTag::Uid16,
        b"UID4" => YaaTag::Uid32,
        b"GID1" => YaaTag::Gid8,
        b"GID2" => YaaTag::Gid16,
        b"GID4" => YaaTag::Gid32,
        b"MOD2" => YaaTag::Mode,
        b"FLG1" => YaaTag::Flags8,
        b"FLG2" => YaaTag::Flags16,
        b"FLG4" => YaaTag::Flags32,
        b"FLI4" => YaaTag::InlineFlags32,
        b"AFT1" => YaaTag::AccessFlags8,
        b"AFT2" => YaaTag::AccessFlags16,
        b"AFT4" => YaaTag::AccessFlags32,
        b"AFR1" => YaaTag::AccessReference8,
        b"AFR2" => YaaTag::AccessReference16,
        b"AFR4" => YaaTag::AccessReference32,
        b"MTMS" => YaaTag::ModifiedTimeSeconds,
        b"MTMT" => YaaTag::ModifiedTimeTimespec,
        b"DATA" => YaaTag::Data,
        b"DATB" => YaaTag::DataBig,
        b"XATA" => YaaTag::Xattr,
        _ => YaaTag::Unknown(tag),
    }
}

fn tag_label(tag: &YaaTag) -> String {
    match tag {
        YaaTag::Type => "TYP1",
        YaaTag::Path => "PATP",
        YaaTag::LinkPath => "LNKP",
        YaaTag::Uid8 => "UID1",
        YaaTag::Uid16 => "UID2",
        YaaTag::Uid32 => "UID4",
        YaaTag::Gid8 => "GID1",
        YaaTag::Gid16 => "GID2",
        YaaTag::Gid32 => "GID4",
        YaaTag::Mode => "MOD2",
        YaaTag::Flags8 => "FLG1",
        YaaTag::Flags16 => "FLG2",
        YaaTag::Flags32 => "FLG4",
        YaaTag::InlineFlags32 => "FLI4",
        YaaTag::AccessFlags8 => "AFT1",
        YaaTag::AccessFlags16 => "AFT2",
        YaaTag::AccessFlags32 => "AFT4",
        YaaTag::AccessReference8 => "AFR1",
        YaaTag::AccessReference16 => "AFR2",
        YaaTag::AccessReference32 => "AFR4",
        YaaTag::ModifiedTimeSeconds => "MTMS",
        YaaTag::ModifiedTimeTimespec => "MTMT",
        YaaTag::Data => "DATA",
        YaaTag::DataBig => "DATB",
        YaaTag::Xattr => "XATA",
        YaaTag::Unknown(tag) => return String::from_utf8_lossy(tag).to_string(),
    }
    .to_string()
}

fn decode_object_type(value: u8) -> YaaObjectType {
    match value {
        b'D' => YaaObjectType::Directory,
        b'F' => YaaObjectType::File,
        b'L' => YaaObjectType::Link,
        other => YaaObjectType::Other(other),
    }
}

fn object_type_label(value: YaaObjectType) -> String {
    match value {
        YaaObjectType::Directory => "directory",
        YaaObjectType::File => "file",
        YaaObjectType::Link => "link",
        YaaObjectType::Other(_) => "other",
    }
    .to_string()
}

fn materialized_relative_path(path: &str) -> Option<PathBuf> {
    if path.is_empty() {
        return None;
    }
    let candidate = PathBuf::from(path);
    if candidate.is_absolute() {
        return None;
    }
    if candidate
        .components()
        .any(|component| matches!(component, Component::ParentDir))
    {
        return None;
    }
    if let Some(Component::Normal(name)) = candidate.components().next()
        && matches!(
            name.to_str(),
            Some(".file" | ".nofollow" | ".resolve" | ".vol")
        )
    {
        return None;
    }
    Some(candidate)
}

fn apply_mode_if_present(
    target_path: &Path,
    mode: Option<u16>,
    result: &mut YaaMaterializationResult,
) -> Result<(), YaaStreamError> {
    let Some(mode) = mode else {
        return Ok(());
    };
    let permissions = fs::Permissions::from_mode(u32::from(mode));
    fs::set_permissions(target_path, permissions)?;
    result.mode_updates_applied += 1;
    Ok(())
}

fn queue_directory_mode_if_present(
    target_path: &Path,
    mode: Option<u16>,
    deferred_directory_modes: &mut Vec<DeferredModeUpdate>,
) {
    if let Some(mode) = mode {
        deferred_directory_modes.push(DeferredModeUpdate {
            path: target_path.to_path_buf(),
            mode,
        });
    }
}

fn apply_deferred_directory_modes(
    deferred_directory_modes: &[DeferredModeUpdate],
    result: &mut YaaMaterializationResult,
) -> Result<(), YaaStreamError> {
    for update in deferred_directory_modes.iter().rev() {
        let permissions = fs::Permissions::from_mode(u32::from(update.mode));
        fs::set_permissions(&update.path, permissions)?;
        result.mode_updates_applied += 1;
    }
    Ok(())
}

fn apply_ownership_if_present(
    target_path: &Path,
    record: &YaaRecord,
    result: &mut YaaMaterializationResult,
) {
    let uid = record.uid.map_or(u32::MAX, |value| value);
    let gid = record.gid.map_or(u32::MAX, |value| value);
    if uid == u32::MAX && gid == u32::MAX {
        return;
    }

    match lchown_path(target_path, uid, gid) {
        Ok(()) => result.ownership_updates_applied += 1,
        Err(_) => result.ownership_update_failures += 1,
    }
}

fn lchown_path(path: &Path, uid: u32, gid: u32) -> io::Result<()> {
    let bytes = path.as_os_str().as_bytes();
    let c_path = CString::new(bytes).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("path '{}' contains an interior NUL byte", path.display()),
        )
    })?;
    let uid = if uid == u32::MAX {
        !0 as libc::uid_t
    } else {
        uid as libc::uid_t
    };
    let gid = if gid == u32::MAX {
        !0 as libc::gid_t
    } else {
        gid as libc::gid_t
    };

    // Use lchown so symbolic links keep their recorded ownership without dereferencing.
    let status = unsafe { libc::lchown(c_path.as_ptr(), uid, gid) };
    if status == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn short_sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let digest = hasher.finalize();
    let mut out = String::with_capacity(16);
    for byte in &digest[..8] {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}

fn preview_hex(data: &[u8], max_bytes: usize) -> String {
    let preview = &data[..data.len().min(max_bytes)];
    let mut out = String::with_capacity(preview.len() * 2);
    for byte in preview {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}

fn read_bytes<'a>(
    data: &'a [u8],
    offset: usize,
    length: usize,
    record_offset: u64,
    context: &'static str,
) -> Result<&'a [u8], YaaError> {
    let end = offset
        .checked_add(length)
        .ok_or(YaaError::IntegerOverflow)?;
    if end > data.len() {
        return Err(YaaError::Truncated {
            offset: record_offset,
            context,
        });
    }
    Ok(&data[offset..end])
}

fn read_u8(
    data: &[u8],
    offset: usize,
    record_offset: u64,
    context: &'static str,
) -> Result<u8, YaaError> {
    if offset >= data.len() {
        return Err(YaaError::Truncated {
            offset: record_offset,
            context,
        });
    }
    Ok(data[offset])
}

fn read_u16le(
    data: &[u8],
    offset: usize,
    record_offset: u64,
    context: &'static str,
) -> Result<u16, YaaError> {
    let bytes = read_bytes(data, offset, 2, record_offset, context)?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn read_u32le(
    data: &[u8],
    offset: usize,
    record_offset: u64,
    context: &'static str,
) -> Result<u32, YaaError> {
    let bytes = read_bytes(data, offset, 4, record_offset, context)?;
    Ok(u32::from_le_bytes(bytes.try_into().unwrap()))
}

fn read_u64le(
    data: &[u8],
    offset: usize,
    record_offset: u64,
    context: &'static str,
) -> Result<u64, YaaError> {
    let bytes = read_bytes(data, offset, 8, record_offset, context)?;
    Ok(u64::from_le_bytes(bytes.try_into().unwrap()))
}

fn read_width_uint(
    data: &[u8],
    offset: usize,
    width: usize,
    record_offset: u64,
    context: &'static str,
) -> Result<u32, YaaError> {
    match width {
        1 => Ok(u32::from(read_u8(data, offset, record_offset, context)?)),
        2 => Ok(u32::from(read_u16le(data, offset, record_offset, context)?)),
        4 => read_u32le(data, offset, record_offset, context),
        _ => Err(YaaError::IntegerOverflow),
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::Cursor;
    use std::os::unix::fs::MetadataExt;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::{YaaField, YaaObjectType, YaaStreamReader, YaaTag, parse_record, parse_records};

    fn push_tag(bytes: &mut Vec<u8>, tag: &[u8; 4]) {
        bytes.extend_from_slice(tag);
    }

    fn build_directory_record(path: &str, uid_tag: &[u8; 4], uid: u32) -> Vec<u8> {
        let mut metadata = Vec::new();
        push_tag(&mut metadata, b"TYP1");
        metadata.push(b'D');
        push_tag(&mut metadata, b"PATP");
        metadata.extend_from_slice(&(path.len() as u16).to_le_bytes());
        metadata.extend_from_slice(path.as_bytes());
        push_tag(&mut metadata, uid_tag);
        match uid_tag {
            b"UID1" => metadata.push(uid as u8),
            b"UID2" => metadata.extend_from_slice(&(uid as u16).to_le_bytes()),
            b"UID4" => metadata.extend_from_slice(&uid.to_le_bytes()),
            _ => unreachable!(),
        }
        push_tag(&mut metadata, b"GID1");
        metadata.push(0);
        push_tag(&mut metadata, b"MOD2");
        metadata.extend_from_slice(&0o755u16.to_le_bytes());
        push_tag(&mut metadata, b"FLG1");
        metadata.push(0);
        push_tag(&mut metadata, b"MTMS");
        metadata.extend_from_slice(&123u64.to_le_bytes());

        let mut record = Vec::new();
        record.extend_from_slice(b"YAA1");
        record.extend_from_slice(&((metadata.len() + 6) as u16).to_le_bytes());
        record.extend_from_slice(&metadata);
        record
    }

    fn build_file_record(path: &str, payload: &[u8], big: bool) -> Vec<u8> {
        build_file_record_with_metadata(path, payload, big, 0, 0, 0o644)
    }

    fn build_file_record_with_metadata(
        path: &str,
        payload: &[u8],
        big: bool,
        uid: u32,
        gid: u32,
        mode: u16,
    ) -> Vec<u8> {
        let mut metadata = Vec::new();
        push_tag(&mut metadata, b"TYP1");
        metadata.push(b'F');
        push_tag(&mut metadata, b"PATP");
        metadata.extend_from_slice(&(path.len() as u16).to_le_bytes());
        metadata.extend_from_slice(path.as_bytes());
        push_tag(&mut metadata, b"UID4");
        metadata.extend_from_slice(&uid.to_le_bytes());
        push_tag(&mut metadata, b"GID4");
        metadata.extend_from_slice(&gid.to_le_bytes());
        push_tag(&mut metadata, b"MOD2");
        metadata.extend_from_slice(&mode.to_le_bytes());
        push_tag(&mut metadata, b"FLG4");
        metadata.extend_from_slice(&524288u32.to_le_bytes());
        push_tag(&mut metadata, b"MTMS");
        metadata.extend_from_slice(&456u64.to_le_bytes());
        if big {
            push_tag(&mut metadata, b"DATB");
            metadata.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        } else {
            push_tag(&mut metadata, b"DATA");
            metadata.extend_from_slice(&(payload.len() as u16).to_le_bytes());
        }
        push_tag(&mut metadata, b"FLI4");
        metadata.extend_from_slice(&131072u32.to_le_bytes());

        let mut record = Vec::new();
        record.extend_from_slice(b"YAA1");
        record.extend_from_slice(&((metadata.len() + 6) as u16).to_le_bytes());
        record.extend_from_slice(&metadata);
        record.extend_from_slice(payload);
        record
    }

    fn build_link_record(path: &str, target: &str) -> Vec<u8> {
        let mut metadata = Vec::new();
        push_tag(&mut metadata, b"TYP1");
        metadata.push(b'L');
        push_tag(&mut metadata, b"PATP");
        metadata.extend_from_slice(&(path.len() as u16).to_le_bytes());
        metadata.extend_from_slice(path.as_bytes());
        push_tag(&mut metadata, b"LNKP");
        metadata.extend_from_slice(&(target.len() as u16).to_le_bytes());
        metadata.extend_from_slice(target.as_bytes());
        push_tag(&mut metadata, b"UID1");
        metadata.push(0);
        push_tag(&mut metadata, b"GID1");
        metadata.push(0);

        let mut record = Vec::new();
        record.extend_from_slice(b"YAA1");
        record.extend_from_slice(&((metadata.len() + 6) as u16).to_le_bytes());
        record.extend_from_slice(&metadata);
        record
    }

    #[test]
    fn parses_directory_record_with_uid2() {
        let bytes = build_directory_record("System", b"UID2", 0x1234);
        let record = parse_record(&bytes, 0).unwrap().unwrap();

        assert_eq!(record.object_type, Some(YaaObjectType::Directory));
        assert_eq!(record.path.as_deref(), Some("System"));
        assert_eq!(record.uid, Some(0x1234));
        assert_eq!(record.mode, Some(0o755));
        assert_eq!(record.next_record_offset as usize, bytes.len());
    }

    #[test]
    fn parses_file_record_with_datb_descriptor() {
        let payload = b"ttcf\0\0\0\0";
        let bytes = build_file_record("System/Library/Fonts/Apple Color Emoji.ttc", payload, true);
        let record = parse_record(&bytes, 0).unwrap().unwrap();

        assert_eq!(record.object_type, Some(YaaObjectType::File));
        assert_eq!(
            record.path.as_deref(),
            Some("System/Library/Fonts/Apple Color Emoji.ttc")
        );
        assert_eq!(record.external_payloads.len(), 1);
        assert_eq!(record.external_payloads[0].tag, YaaTag::DataBig);
        assert_eq!(record.external_payloads[0].length, payload.len() as u64);
        assert!(
            record
                .fields
                .iter()
                .any(|field| matches!(field, YaaField::InlineFlags(131072)))
        );
    }

    #[test]
    fn parses_multiple_records_sequentially() {
        let first = build_directory_record("System", b"UID1", 0);
        let second = build_file_record("System/.localized", b"", false);
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&first);
        bytes.extend_from_slice(&second);

        let records = parse_records(&bytes, 10, 0).unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].path.as_deref(), Some("System"));
        assert_eq!(records[1].path.as_deref(), Some("System/.localized"));
    }

    #[test]
    fn parses_link_record_with_lnkp_target() {
        let bytes = build_link_record(".VolumeIcon.icns", "System/Volumes/Data/.VolumeIcon.icns");
        let record = parse_record(&bytes, 0).unwrap().unwrap();

        assert_eq!(record.object_type, Some(YaaObjectType::Link));
        assert_eq!(record.path.as_deref(), Some(".VolumeIcon.icns"));
        assert_eq!(
            record.link_target.as_deref(),
            Some("System/Volumes/Data/.VolumeIcon.icns")
        );
    }

    #[test]
    fn stream_reader_skips_external_payloads() {
        let first = build_file_record("System/.localized", b"hello", false);
        let second = build_directory_record("System/Applications", b"UID1", 0);
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&first);
        bytes.extend_from_slice(&second);

        let mut reader = YaaStreamReader::new(Cursor::new(bytes));
        let first_record = reader.next_record().unwrap().unwrap();
        let second_record = reader.next_record().unwrap().unwrap();

        assert_eq!(first_record.path.as_deref(), Some("System/.localized"));
        assert_eq!(second_record.path.as_deref(), Some("System/Applications"));
    }

    #[test]
    fn stream_summary_counts_tags_and_largest_payload() {
        let first = build_file_record("System/.localized", b"hello", false);
        let second = build_file_record("System/Fonts/Fancy.ttc", b"12345678", true);
        let third = build_directory_record("System/Applications", b"UID1", 0);
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&first);
        bytes.extend_from_slice(&second);
        bytes.extend_from_slice(&third);

        let mut reader = YaaStreamReader::new(Cursor::new(bytes));
        let summary = reader.summarize(10).unwrap();

        assert_eq!(summary.record_count, 3);
        assert_eq!(summary.object_counts.files, 2);
        assert_eq!(summary.object_counts.directories, 1);
        assert_eq!(summary.tag_counts.get("DATB"), Some(&1));
        assert_eq!(
            summary
                .largest_payload
                .as_ref()
                .and_then(|payload| payload.path.as_deref()),
            Some("System/Fonts/Fancy.ttc")
        );
    }

    #[test]
    fn summarize_regions_walks_consecutive_windows() {
        let first = build_file_record("System/.localized", b"hello", false);
        let second = build_file_record("System/Fonts/Fancy.ttc", b"12345678", true);
        let third = build_directory_record("System/Applications", b"UID1", 0);
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&first);
        bytes.extend_from_slice(&second);
        bytes.extend_from_slice(&third);

        let mut reader = YaaStreamReader::new(Cursor::new(bytes));
        let regions = reader.summarize_regions(2, 2).unwrap();

        assert_eq!(regions.len(), 2);
        assert_eq!(regions[0].summary.record_count, 2);
        assert_eq!(regions[1].summary.record_count, 1);
    }

    #[test]
    fn materialize_prefix_writes_directories_files_and_metadata() {
        let first = build_directory_record("System", b"UID1", 0);
        let second = build_file_record("System/.localized", b"hello", false);
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&first);
        bytes.extend_from_slice(&second);

        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let output_root = std::env::temp_dir().join(format!("yaa-materialize-{unique}"));

        let mut reader = YaaStreamReader::new(Cursor::new(bytes));
        let result = reader.materialize_prefix(&output_root, 10).unwrap();

        assert!(output_root.join("System").is_dir());
        assert_eq!(
            fs::read(output_root.join("System/.localized")).unwrap(),
            b"hello"
        );
        assert_eq!(
            fs::metadata(output_root.join("System")).unwrap().mode() & 0o7777,
            0o755
        );
        assert_eq!(
            fs::metadata(output_root.join("System/.localized"))
                .unwrap()
                .mode()
                & 0o7777,
            0o644
        );
        assert_eq!(result.mode_updates_applied, 2);
        assert!(result.metadata_path.exists());
        assert!(result.xattr_root.exists());

        let _ = fs::remove_dir_all(output_root);
    }

    #[test]
    fn materialize_prefix_applies_current_user_ownership() {
        let first = build_file_record_with_metadata(
            "System/owned.txt",
            b"owned",
            false,
            unsafe { libc::geteuid() },
            unsafe { libc::getegid() },
            0o640,
        );
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let output_root = std::env::temp_dir().join(format!("yaa-materialize-ownership-{unique}"));

        let mut reader = YaaStreamReader::new(Cursor::new(first));
        let result = reader.materialize_prefix(&output_root, 10).unwrap();
        let metadata = fs::metadata(output_root.join("System/owned.txt")).unwrap();

        assert_eq!(metadata.mode() & 0o7777, 0o640);
        assert_eq!(metadata.uid(), unsafe { libc::geteuid() });
        assert_eq!(metadata.gid(), unsafe { libc::getegid() });
        assert_eq!(result.mode_updates_applied, 1);
        assert_eq!(result.ownership_updates_applied, 1);
        assert_eq!(result.ownership_update_failures, 0);

        let _ = fs::remove_dir_all(output_root);
    }

    #[test]
    fn materialize_prefix_skips_control_roots() {
        let first = build_directory_record(".file", b"UID1", 0);
        let second = build_directory_record("System", b"UID1", 0);
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&first);
        bytes.extend_from_slice(&second);

        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let output_root = std::env::temp_dir().join(format!("yaa-materialize-skip-{unique}"));

        let mut reader = YaaStreamReader::new(Cursor::new(bytes));
        reader.materialize_prefix(&output_root, 10).unwrap();

        assert!(!output_root.join(".file").exists());
        assert!(output_root.join("System").exists());

        let _ = fs::remove_dir_all(output_root);
    }

    #[test]
    fn materialize_prefix_writes_symlink_records() {
        let first = build_directory_record("System", b"UID1", 0);
        let second = build_link_record(".VolumeIcon.icns", "System/Volumes/Data/.VolumeIcon.icns");
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&first);
        bytes.extend_from_slice(&second);

        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let output_root = std::env::temp_dir().join(format!("yaa-materialize-link-{unique}"));

        let mut reader = YaaStreamReader::new(Cursor::new(bytes));
        reader.materialize_prefix(&output_root, 10).unwrap();

        let link_path = output_root.join(".VolumeIcon.icns");
        assert!(
            fs::symlink_metadata(&link_path)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(
            fs::read_link(&link_path).unwrap(),
            PathBuf::from("System/Volumes/Data/.VolumeIcon.icns")
        );

        let _ = fs::remove_dir_all(output_root);
    }

    #[test]
    fn materialize_prefix_writes_xattr_sidecars() {
        let mut metadata = Vec::new();
        push_tag(&mut metadata, b"TYP1");
        metadata.push(b'D');
        push_tag(&mut metadata, b"PATP");
        metadata.extend_from_slice(&(6u16).to_le_bytes());
        metadata.extend_from_slice(b"System");
        push_tag(&mut metadata, b"XATA");
        let xattr_blob = {
            let mut blob = Vec::new();
            blob.extend_from_slice(&(20u32).to_le_bytes());
            blob.extend_from_slice(b"com.apple.rootless\0");
            blob.extend_from_slice(b"plist");
            blob
        };
        metadata.extend_from_slice(&(xattr_blob.len() as u16).to_le_bytes());

        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"YAA1");
        bytes.extend_from_slice(&((metadata.len() + 6) as u16).to_le_bytes());
        bytes.extend_from_slice(&metadata);
        bytes.extend_from_slice(&xattr_blob);

        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let output_root = std::env::temp_dir().join(format!("yaa-materialize-xattr-{unique}"));

        let mut reader = YaaStreamReader::new(Cursor::new(bytes));
        let result = reader.materialize_prefix(&output_root, 10).unwrap();

        assert_eq!(result.xattr_sidecars_written, 1);
        let sidecars = fs::read_dir(&result.xattr_root).unwrap().count();
        assert_eq!(sidecars, 1);
        let metadata_text = fs::read_to_string(&result.metadata_path).unwrap();
        assert!(metadata_text.contains("sha256_16"));
        assert!(metadata_text.contains("sidecar_path"));

        let _ = fs::remove_dir_all(output_root);
    }
}
