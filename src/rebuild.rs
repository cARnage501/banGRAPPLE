use std::fmt;
use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use xz2::read::XzDecoder;

use crate::yaa::{YaaMaterializationResult, YaaStreamReader};

const PBZX_MAGIC: &[u8; 4] = b"pbzx";
const XZ_MAGIC: &[u8; 6] = b"\xfd7zXZ\x00";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PayloadChunk {
    pub index: usize,
    pub target_size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedShard {
    pub index: usize,
    pub path: PathBuf,
    pub compressed_size: u64,
    pub decoded_size: u64,
    pub target_size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RebuildImageResult {
    pub payload_root: PathBuf,
    pub decoded_stream_path: PathBuf,
    pub materialized: YaaMaterializationResult,
    pub decoded_shards: Vec<DecodedShard>,
}

#[derive(Debug)]
pub enum RebuildError {
    Io(io::Error),
    Parse(String),
    MissingShard(PathBuf),
    InvalidPayloadRoot(PathBuf),
    Yaa(crate::yaa::YaaStreamError),
}

impl fmt::Display for RebuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => write!(f, "{err}"),
            Self::Parse(err) => write!(f, "{err}"),
            Self::MissingShard(path) => {
                write!(f, "required payload shard '{}' is missing", path.display())
            }
            Self::InvalidPayloadRoot(path) => write!(
                f,
                "expected '{}' to be a payloadv2 directory or an AssetData root containing payloadv2",
                path.display()
            ),
            Self::Yaa(err) => write!(f, "{err}"),
        }
    }
}

impl From<io::Error> for RebuildError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<crate::yaa::YaaStreamError> for RebuildError {
    fn from(value: crate::yaa::YaaStreamError) -> Self {
        Self::Yaa(value)
    }
}

pub fn rebuild_image(
    source_root: &Path,
    output_root: &Path,
) -> Result<RebuildImageResult, RebuildError> {
    let payload_root = resolve_payload_root(source_root)?;
    let chunks = read_payload_chunks(&payload_root)?;
    if chunks.is_empty() {
        return Err(RebuildError::Parse(format!(
            "payload chunk order file '{}' did not contain any entries",
            payload_root.join("payload_chunks.txt").display()
        )));
    }

    fs::create_dir_all(output_root)?;
    let decoded_stream_path = output_root.join("_payloadv2_decoded.yaa");
    let decoded_shards = decode_payload_stream(&payload_root, &chunks, &decoded_stream_path)?;

    let file = File::open(&decoded_stream_path)?;
    let mut reader = YaaStreamReader::new(file);
    let materialized = reader.materialize_all(output_root)?;

    Ok(RebuildImageResult {
        payload_root,
        decoded_stream_path,
        materialized,
        decoded_shards,
    })
}

fn resolve_payload_root(source_root: &Path) -> Result<PathBuf, RebuildError> {
    if source_root.file_name().and_then(|value| value.to_str()) == Some("payloadv2") {
        return Ok(source_root.to_path_buf());
    }

    let asset_payload = source_root.join("payloadv2");
    if asset_payload.is_dir() {
        return Ok(asset_payload);
    }

    let nested_asset_payload = source_root.join("AssetData").join("payloadv2");
    if nested_asset_payload.is_dir() {
        return Ok(nested_asset_payload);
    }

    Err(RebuildError::InvalidPayloadRoot(source_root.to_path_buf()))
}

fn read_payload_chunks(payload_root: &Path) -> Result<Vec<PayloadChunk>, RebuildError> {
    let path = payload_root.join("payload_chunks.txt");
    let raw = fs::read(&path)?;
    let text = if raw.starts_with(PBZX_MAGIC) {
        let decoded = decode_pbzx_bytes(&raw)?;
        String::from_utf8(decoded).map_err(|err| {
            RebuildError::Parse(format!(
                "decoded payload chunk order '{}' is not valid UTF-8: {err}",
                path.display()
            ))
        })?
    } else {
        String::from_utf8(raw).map_err(|err| {
            RebuildError::Parse(format!(
                "payload chunk order '{}' is not valid UTF-8: {err}",
                path.display()
            ))
        })?
    };

    parse_payload_chunks(&text)
}

fn parse_payload_chunks(text: &str) -> Result<Vec<PayloadChunk>, RebuildError> {
    let mut ordered = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let (index_text, size_text) = line.split_once(':').ok_or_else(|| {
            RebuildError::Parse(format!(
                "payload chunk order line '{line}' is missing the ':' delimiter"
            ))
        })?;
        let index = index_text.trim().parse::<usize>().map_err(|err| {
            RebuildError::Parse(format!(
                "payload chunk order index '{}' is invalid: {err}",
                index_text.trim()
            ))
        })?;
        let target_size = size_text.trim().parse::<u64>().map_err(|err| {
            RebuildError::Parse(format!(
                "payload chunk target size '{}' is invalid: {err}",
                size_text.trim()
            ))
        })?;
        ordered.push(PayloadChunk { index, target_size });
    }
    ordered.sort_by_key(|entry| entry.index);
    Ok(ordered)
}

fn decode_payload_stream(
    payload_root: &Path,
    chunks: &[PayloadChunk],
    decoded_stream_path: &Path,
) -> Result<Vec<DecodedShard>, RebuildError> {
    let mut output = File::create(decoded_stream_path)?;
    let mut decoded_shards = Vec::with_capacity(chunks.len());

    for chunk in chunks {
        let shard_path = payload_root.join(format!("payload.{:03}", chunk.index));
        if !shard_path.is_file() {
            return Err(RebuildError::MissingShard(shard_path));
        }

        let compressed_size = fs::metadata(&shard_path)?.len();
        let data = fs::read(&shard_path)?;
        let decoded_size = decode_pbzx_to_writer(&data, &mut output)?;
        decoded_shards.push(DecodedShard {
            index: chunk.index,
            path: shard_path,
            compressed_size,
            decoded_size,
            target_size: chunk.target_size,
        });
    }

    output.flush()?;
    Ok(decoded_shards)
}

fn decode_pbzx_bytes(data: &[u8]) -> Result<Vec<u8>, RebuildError> {
    let mut decoded = Vec::new();
    decode_pbzx_to_writer(data, &mut decoded)?;
    Ok(decoded)
}

fn decode_pbzx_to_writer(data: &[u8], out: &mut impl Write) -> Result<u64, RebuildError> {
    if !data.starts_with(PBZX_MAGIC) {
        return Err(RebuildError::Parse(
            "payload shard does not start with pbzx".to_string(),
        ));
    }
    if data.len() < 12 {
        return Err(RebuildError::Parse(
            "payload shard is truncated before the pbzx header completes".to_string(),
        ));
    }

    let mut cursor = 4usize;
    let _initial_flags = read_u64be(data, &mut cursor, "pbzx initial flags")?;
    let mut written = 0u64;

    while cursor < data.len() {
        let _flags = read_u64be(data, &mut cursor, "pbzx chunk flags")?;
        let length = read_u64be(data, &mut cursor, "pbzx chunk length")?;
        let length_usize = usize::try_from(length).map_err(|_| {
            RebuildError::Parse(format!("pbzx chunk length {length} does not fit in memory"))
        })?;
        let end = cursor.checked_add(length_usize).ok_or_else(|| {
            RebuildError::Parse("pbzx chunk length overflowed while decoding".to_string())
        })?;
        if end > data.len() {
            return Err(RebuildError::Parse(
                "pbzx chunk declared more bytes than are present in the shard".to_string(),
            ));
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
    }

    Ok(written)
}

fn read_u64be(data: &[u8], cursor: &mut usize, context: &str) -> Result<u64, RebuildError> {
    let end = cursor
        .checked_add(8)
        .ok_or_else(|| RebuildError::Parse(format!("{context} overflowed while decoding pbzx")))?;
    if end > data.len() {
        return Err(RebuildError::Parse(format!(
            "{context} is truncated in the pbzx stream"
        )));
    }
    let value = u64::from_be_bytes(
        data[*cursor..end]
            .try_into()
            .map_err(|_| RebuildError::Parse(format!("failed to read {context}")))?,
    );
    *cursor = end;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::Write;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use xz2::write::XzEncoder;

    use super::{decode_pbzx_bytes, parse_payload_chunks, rebuild_image};

    fn push_tag(target: &mut Vec<u8>, tag: &[u8; 4]) {
        target.extend_from_slice(tag);
    }

    fn build_directory_record(path: &str) -> Vec<u8> {
        let mut metadata = Vec::new();
        push_tag(&mut metadata, b"TYP1");
        metadata.push(b'D');
        push_tag(&mut metadata, b"PATP");
        metadata.extend_from_slice(&(path.len() as u16).to_le_bytes());
        metadata.extend_from_slice(path.as_bytes());
        push_tag(&mut metadata, b"UID1");
        metadata.push(0);
        push_tag(&mut metadata, b"GID1");
        metadata.push(0);
        push_tag(&mut metadata, b"MOD2");
        metadata.extend_from_slice(&0o755u16.to_le_bytes());

        let mut record = Vec::new();
        record.extend_from_slice(b"YAA1");
        record.extend_from_slice(&((metadata.len() + 6) as u16).to_le_bytes());
        record.extend_from_slice(&metadata);
        record
    }

    fn build_file_record(path: &str, payload: &[u8]) -> Vec<u8> {
        let mut metadata = Vec::new();
        push_tag(&mut metadata, b"TYP1");
        metadata.push(b'F');
        push_tag(&mut metadata, b"PATP");
        metadata.extend_from_slice(&(path.len() as u16).to_le_bytes());
        metadata.extend_from_slice(path.as_bytes());
        push_tag(&mut metadata, b"UID1");
        metadata.push(0);
        push_tag(&mut metadata, b"GID1");
        metadata.push(0);
        push_tag(&mut metadata, b"MOD2");
        metadata.extend_from_slice(&0o644u16.to_le_bytes());
        push_tag(&mut metadata, b"DATA");
        metadata.extend_from_slice(&(payload.len() as u16).to_le_bytes());

        let mut record = Vec::new();
        record.extend_from_slice(b"YAA1");
        record.extend_from_slice(&((metadata.len() + 6) as u16).to_le_bytes());
        record.extend_from_slice(&metadata);
        record.extend_from_slice(payload);
        record
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

    fn unique_dir(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("ban-grapple-{name}-{nanos}"))
    }

    #[test]
    fn parses_payload_chunks_text() {
        let chunks = parse_payload_chunks("1:20\n0:10\n").unwrap();
        assert_eq!(chunks[0].index, 0);
        assert_eq!(chunks[1].target_size, 20);
    }

    #[test]
    fn decodes_pbzx_wrapped_xz_payload() {
        let wrapped = wrap_pbzx(b"hello world");
        let decoded = decode_pbzx_bytes(&wrapped).unwrap();
        assert_eq!(decoded, b"hello world");
    }

    #[test]
    fn rebuilds_image_tree_from_payload_shards() {
        let payload_root = unique_dir("payloadv2").join("AssetData/payloadv2");
        fs::create_dir_all(&payload_root).unwrap();
        fs::write(payload_root.join("payload_chunks.txt"), b"0:35\n1:36\n").unwrap();

        let first = build_directory_record("System");
        let second = build_file_record("System/.localized", b"hello");
        fs::write(payload_root.join("payload.000"), wrap_pbzx(&first)).unwrap();
        fs::write(payload_root.join("payload.001"), wrap_pbzx(&second)).unwrap();

        let output_root = unique_dir("rebuilt-tree");
        let result = rebuild_image(
            payload_root.parent().unwrap().parent().unwrap(),
            &output_root,
        )
        .unwrap();

        assert!(output_root.join("System").is_dir());
        assert_eq!(
            fs::read(output_root.join("System/.localized")).unwrap(),
            b"hello"
        );
        assert_eq!(result.decoded_shards.len(), 2);
        assert!(result.decoded_stream_path.exists());
        assert!(result.materialized.metadata_path.exists());

        let _ = fs::remove_dir_all(payload_root.parent().unwrap().parent().unwrap());
        let _ = fs::remove_dir_all(output_root);
    }
}
