use flate2::read::ZlibDecoder;
use roxmltree::Document;
use std::fmt;
use std::fs::{self, File};
use std::io::{self, BufWriter, Read, Seek, SeekFrom};
use std::path::Path;

const XAR_MAGIC: &[u8; 4] = b"xar!";
const XAR_HEADER_SIZE: usize = 28;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XarHeader {
    pub header_size: u16,
    pub version: u16,
    pub toc_compressed_size: u64,
    pub toc_uncompressed_size: u64,
    pub checksum_algorithm: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XarMember {
    pub name: String,
    pub offset: u64,
    pub absolute_offset: u64,
    pub length: u64,
    pub size: Option<u64>,
    pub encoding_style: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XarArchive {
    pub header: XarHeader,
    pub heap_start: u64,
    pub members: Vec<XarMember>,
}

#[derive(Debug)]
pub enum XarError {
    Io(io::Error),
    Xml(roxmltree::Error),
    InvalidArchive(&'static str),
    MemberNotFound(String),
    UnexpectedMemberSize { expected: u64, actual: u64 },
}

impl fmt::Display for XarError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => write!(f, "xar IO failed: {err}"),
            Self::Xml(err) => write!(f, "xar TOC parse failed: {err}"),
            Self::InvalidArchive(message) => write!(f, "invalid xar archive: {message}"),
            Self::MemberNotFound(name) => write!(f, "xar member not found: {name}"),
            Self::UnexpectedMemberSize { expected, actual } => {
                write!(
                    f,
                    "xar member size mismatch: expected {expected}, got {actual}"
                )
            }
        }
    }
}

impl From<io::Error> for XarError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<roxmltree::Error> for XarError {
    fn from(value: roxmltree::Error) -> Self {
        Self::Xml(value)
    }
}

pub fn inspect_archive(path: &Path) -> Result<XarArchive, XarError> {
    let mut file = File::open(path)?;
    let header = read_header(&mut file)?;
    let heap_start = u64::from(header.header_size) + header.toc_compressed_size;
    let toc = read_toc(&mut file, &header)?;
    let members = parse_members(&toc, heap_start)?;

    Ok(XarArchive {
        header,
        heap_start,
        members,
    })
}

pub fn extract_named_member(
    archive_path: &Path,
    member_name: &str,
    output_path: &Path,
) -> Result<XarMember, XarError> {
    let archive = inspect_archive(archive_path)?;
    let member = archive
        .members
        .iter()
        .find(|candidate| candidate.name == member_name)
        .cloned()
        .ok_or_else(|| XarError::MemberNotFound(member_name.to_string()))?;

    if let Some(parent) = output_path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)?;
    }

    let mut input = File::open(archive_path)?;
    input.seek(SeekFrom::Start(member.absolute_offset))?;
    let mut limited = input.take(member.length);
    let mut output = BufWriter::new(File::create(output_path)?);
    let written = io::copy(&mut limited, &mut output)?;

    if written != member.length {
        return Err(XarError::UnexpectedMemberSize {
            expected: member.length,
            actual: written,
        });
    }

    Ok(member)
}

fn read_header(reader: &mut File) -> Result<XarHeader, XarError> {
    let mut bytes = [0u8; XAR_HEADER_SIZE];
    reader.read_exact(&mut bytes)?;

    if &bytes[0..4] != XAR_MAGIC {
        return Err(XarError::InvalidArchive("missing xar magic"));
    }

    let header_size = u16::from_be_bytes([bytes[4], bytes[5]]);
    let version = u16::from_be_bytes([bytes[6], bytes[7]]);
    let toc_compressed_size = u64::from_be_bytes(bytes[8..16].try_into().unwrap());
    let toc_uncompressed_size = u64::from_be_bytes(bytes[16..24].try_into().unwrap());
    let checksum_algorithm = u32::from_be_bytes(bytes[24..28].try_into().unwrap());

    if header_size < XAR_HEADER_SIZE as u16 {
        return Err(XarError::InvalidArchive("header smaller than 28 bytes"));
    }

    Ok(XarHeader {
        header_size,
        version,
        toc_compressed_size,
        toc_uncompressed_size,
        checksum_algorithm,
    })
}

fn read_toc(reader: &mut File, header: &XarHeader) -> Result<String, XarError> {
    if header.header_size as usize > XAR_HEADER_SIZE {
        reader.seek(SeekFrom::Current(
            i64::from(header.header_size) - XAR_HEADER_SIZE as i64,
        ))?;
    }

    let toc_len = usize::try_from(header.toc_compressed_size)
        .map_err(|_| XarError::InvalidArchive("TOC is too large to fit in memory"))?;
    let mut compressed = vec![0u8; toc_len];
    reader.read_exact(&mut compressed)?;

    let mut decoder = ZlibDecoder::new(compressed.as_slice());
    let mut xml = String::new();
    decoder.read_to_string(&mut xml)?;

    Ok(xml)
}

fn parse_members(xml: &str, heap_start: u64) -> Result<Vec<XarMember>, XarError> {
    let document = Document::parse(xml)?;
    let mut members = Vec::new();

    for file_node in document
        .descendants()
        .filter(|node| node.is_element() && node.tag_name().name() == "file")
    {
        let Some(name) = child_text(file_node, "name") else {
            continue;
        };

        let Some(data_node) = file_node
            .children()
            .find(|node| node.is_element() && node.tag_name().name() == "data")
        else {
            continue;
        };

        let Some(offset) = child_text(data_node, "offset").and_then(|value| value.parse().ok())
        else {
            continue;
        };
        let Some(length) = child_text(data_node, "length").and_then(|value| value.parse().ok())
        else {
            continue;
        };

        let size = child_text(data_node, "size").and_then(|value| value.parse().ok());
        let encoding_style = data_node
            .children()
            .find(|node| node.is_element() && node.tag_name().name() == "encoding")
            .and_then(|encoding_node| child_text(encoding_node, "style"));

        members.push(XarMember {
            name,
            offset,
            absolute_offset: heap_start + offset,
            length,
            size,
            encoding_style,
        });
    }

    Ok(members)
}

fn child_text<'a, 'input>(node: roxmltree::Node<'a, 'input>, tag: &str) -> Option<String> {
    node.children()
        .find(|child| child.is_element() && child.tag_name().name() == tag)
        .and_then(|child| child.text())
        .map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::{extract_named_member, inspect_archive};
    use flate2::Compression;
    use flate2::write::ZlibEncoder;
    use std::fs;
    use std::io::Write;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn unique_path(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("ban-grapple-{name}-{nanos}"))
    }

    fn write_sample_xar(path: &std::path::Path) {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<xar>
  <toc>
    <file>
      <name>SharedSupport.dmg</name>
      <data>
        <offset>0</offset>
        <length>11</length>
        <size>11</size>
      </data>
    </file>
  </toc>
</xar>"#;

        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(xml.as_bytes()).unwrap();
        let compressed = encoder.finish().unwrap();

        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"xar!");
        bytes.extend_from_slice(&28u16.to_be_bytes());
        bytes.extend_from_slice(&1u16.to_be_bytes());
        bytes.extend_from_slice(&(compressed.len() as u64).to_be_bytes());
        bytes.extend_from_slice(&(xml.len() as u64).to_be_bytes());
        bytes.extend_from_slice(&0u32.to_be_bytes());
        bytes.extend_from_slice(&compressed);
        bytes.extend_from_slice(b"hello world");

        fs::write(path, bytes).unwrap();
    }

    #[test]
    fn inspects_synthetic_archive() {
        let archive_path = unique_path("sample.xar");
        write_sample_xar(&archive_path);

        let archive = inspect_archive(&archive_path).unwrap();
        assert_eq!(archive.header.header_size, 28);
        assert_eq!(archive.members.len(), 1);
        assert_eq!(archive.members[0].name, "SharedSupport.dmg");
        assert_eq!(archive.members[0].absolute_offset, archive.heap_start);

        fs::remove_file(archive_path).unwrap();
    }

    #[test]
    fn extracts_named_member_from_synthetic_archive() {
        let archive_path = unique_path("extract.xar");
        let output_path = unique_path("SharedSupport.dmg");
        write_sample_xar(&archive_path);

        let member =
            extract_named_member(&archive_path, "SharedSupport.dmg", &output_path).unwrap();
        assert_eq!(member.length, 11);
        assert_eq!(fs::read(output_path).unwrap(), b"hello world");

        fs::remove_file(archive_path).unwrap();
    }
}
