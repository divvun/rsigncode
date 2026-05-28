use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};

use crate::error::{Error, Result};

const DOS_MAGIC: u16 = 0x5A4D; // "MZ"
const PE_SIGNATURE: u32 = 0x0000_4550; // "PE\0\0"
const PE32_MAGIC: u16 = 0x10B;
const PE32PLUS_MAGIC: u16 = 0x20B;

pub const WIN_CERT_REVISION_2_0: u16 = 0x0200;
pub const WIN_CERT_TYPE_PKCS_SIGNED_DATA: u16 = 0x0002;

/// Parsed PE header info needed for Authenticode operations.
#[derive(Debug, Clone)]
pub struct PeInfo {
    /// Whether this is a PE32+ (64-bit) image.
    pub pe32plus: bool,
    /// Offset to PE signature (from DOS header e_lfanew).
    pub header_size: u32,
    /// File offset of the PE checksum field.
    pub checksum_offset: u64,
    /// File offset of the certificate table directory entry.
    pub cert_table_offset: u64,
    /// Certificate table RVA (0 if unsigned).
    pub sigpos: u32,
    /// Certificate table size in bytes.
    pub siglen: u32,
    /// Total file size.
    pub fileend: u32,
}

/// Parse PE headers and extract the offsets needed for Authenticode.
///
/// Port of `pe_ctx_get` in `pe.c:541-611`.
pub fn parse_pe(f: &mut File) -> Result<PeInfo> {
    let filesize = f.seek(SeekFrom::End(0))? as u32;
    f.seek(SeekFrom::Start(0))?;

    if filesize < 64 {
        return Err(Error::InvalidPe("file too short".into()));
    }

    // DOS magic
    let magic = read_u16(f)?;
    if magic != DOS_MAGIC {
        return Err(Error::InvalidPe("bad DOS magic".into()));
    }

    // e_lfanew at offset 0x3C
    f.seek(SeekFrom::Start(0x3C))?;
    let header_size = read_u32(f)?;
    if header_size < 44 || header_size > filesize {
        return Err(Error::InvalidPe(format!(
            "unexpected SizeOfHeaders: 0x{header_size:08X}"
        )));
    }
    if filesize < header_size + 176 {
        return Err(Error::InvalidPe("PE file too short for headers".into()));
    }

    // PE signature
    f.seek(SeekFrom::Start(header_size as u64))?;
    let pe_sig = read_u32(f)?;
    if pe_sig != PE_SIGNATURE {
        return Err(Error::InvalidPe("bad PE signature".into()));
    }

    // Optional header magic at header_size + 24
    f.seek(SeekFrom::Start(header_size as u64 + 24))?;
    let opt_magic = read_u16(f)?;
    let pe32plus = match opt_magic {
        PE32PLUS_MAGIC => true,
        PE32_MAGIC => false,
        _ => {
            return Err(Error::InvalidPe(format!(
                "unknown optional header magic: 0x{opt_magic:04X}"
            )))
        }
    };

    let pe32plus_offset = if pe32plus { 16u64 } else { 0 };

    // NumberOfRvaAndSizes
    f.seek(SeekFrom::Start(
        header_size as u64 + 116 + pe32plus_offset,
    ))?;
    let nrvas = read_u32(f)?;
    if nrvas < 5 {
        return Err(Error::InvalidPe(
            "PE file has no certificate table resource".into(),
        ));
    }

    // Certificate table directory entry
    let cert_table_offset = header_size as u64 + 152 + pe32plus_offset;
    f.seek(SeekFrom::Start(cert_table_offset))?;
    let mut sigpos = read_u32(f)?;
    let mut siglen = read_u32(f)?;

    // Signature must be at end of file (MS12-024)
    if (sigpos != 0 || siglen != 0)
        && (sigpos == 0
            || siglen == 0
            || sigpos >= filesize
            || sigpos + siglen != filesize)
    {
        // Ignore non-trailing signature
        sigpos = 0;
        siglen = 0;
    }

    Ok(PeInfo {
        pe32plus,
        header_size,
        checksum_offset: header_size as u64 + 88,
        cert_table_offset,
        sigpos,
        siglen,
        fileend: filesize,
    })
}

/// Calculate the Authenticode digest of a PE file.
///
/// Hashes the entire file except:
/// 1. The checksum field (4 bytes)
/// 2. The certificate table directory entry (8 bytes)
/// 3. The certificate table data itself (existing signature)
///
/// Port of `pe_digest_calc_bio` in `pe.c:781-835`.
pub fn authenticode_digest(
    f: &mut File,
    pe: &PeInfo,
    hasher: &mut impl digest::Update,
) -> Result<()> {
    let fileend = if pe.sigpos > 0 {
        pe.sigpos as u64
    } else {
        pe.fileend as u64
    };

    // Region 1: start → checksum field
    hash_range(f, hasher, 0, pe.checksum_offset)?;
    // Skip 4 bytes (checksum)

    // Region 2: after checksum → cert table dir entry
    hash_range(f, hasher, pe.checksum_offset + 4, pe.cert_table_offset)?;
    // Skip 8 bytes (cert table directory entry)

    // Region 3: after cert table entry → end of data (before signature)
    hash_range(f, hasher, pe.cert_table_offset + 8, fileend)?;

    // Pad to 8-byte boundary with zeros
    let pad = ((8 - (fileend % 8)) % 8) as usize;
    if pad > 0 {
        hasher.update(&vec![0u8; pad]);
    }

    Ok(())
}

/// Extract the DER-encoded PKCS#7 signature from a PE file's certificate table.
///
/// Port of `pe_pkcs7_get_file` in `pe.c:620-642`.
pub fn extract_signature(f: &mut File, pe: &PeInfo) -> Result<Option<Vec<u8>>> {
    if pe.sigpos == 0 || pe.siglen == 0 {
        return Ok(None);
    }

    let mut pos: u32 = 0;
    while pos < pe.siglen {
        f.seek(SeekFrom::Start((pe.sigpos + pos) as u64))?;
        let len = read_u32(f)?;
        if len < 8 {
            return Err(Error::InvalidPe(format!(
                "malformed WIN_CERTIFICATE: length {len} < 8"
            )));
        }
        let revision = read_u16(f)?;
        let cert_type = read_u16(f)?;

        if revision == WIN_CERT_REVISION_2_0 && cert_type == WIN_CERT_TYPE_PKCS_SIGNED_DATA {
            let der_len = (len - 8) as usize;
            let mut der = vec![0u8; der_len];
            f.read_exact(&mut der)?;
            return Ok(Some(der));
        }

        // Quad-word align to next entry
        let aligned = len + ((8 - (len % 8)) % 8);
        pos += aligned;
    }

    Ok(None)
}

/// Write a signed PE file: copy the input (stripping any existing signature),
/// append the new PKCS#7 signature, and update PE headers.
///
/// The output file is created with read+write access (needed for checksum recalculation).
///
/// Port of `pe_process_data` + `pe_append_pkcs7` + `pe_update_data_size`.
pub fn write_signed_pe(
    input: &mut File,
    output_path: &std::path::Path,
    pe: &PeInfo,
    pkcs7_der: &[u8],
) -> Result<()> {
    let mut output = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(output_path)?;
    write_signed_pe_to(input, &mut output, pe, pkcs7_der)
}

/// Lower-level version that writes to an already-opened read+write File handle.
pub fn write_signed_pe_to(
    input: &mut File,
    output: &mut File,
    pe: &PeInfo,
    pkcs7_der: &[u8],
) -> Result<()> {
    // Step 1: Copy file data (excluding any existing signature)
    let data_end = if pe.sigpos > 0 {
        pe.sigpos
    } else {
        pe.fileend
    };
    copy_range(input, output, 0, data_end as u64)?;

    // Step 2: Zero the checksum field
    output.seek(SeekFrom::Start(pe.checksum_offset))?;
    output.write_all(&[0u8; 4])?;

    // Step 3: Zero the cert table directory entry
    output.seek(SeekFrom::Start(pe.cert_table_offset))?;
    output.write_all(&[0u8; 8])?;

    // Step 4: Pad file to 8-byte boundary
    output.seek(SeekFrom::End(0))?;
    let file_len = output.stream_position()?;
    let file_pad = ((8 - (file_len % 8)) % 8) as usize;
    if file_pad > 0 {
        output.write_all(&vec![0u8; file_pad])?;
    }
    let new_sigpos = output.stream_position()? as u32;

    // Step 5: Write WIN_CERTIFICATE header + PKCS#7 + padding
    let sig_pad = ((8 - (pkcs7_der.len() % 8)) % 8) as usize;
    let total_cert_len = (pkcs7_der.len() + 8 + sig_pad) as u32;

    output.write_all(&total_cert_len.to_le_bytes())?; // dwLength
    output.write_all(&WIN_CERT_REVISION_2_0.to_le_bytes())?; // wRevision
    output.write_all(&WIN_CERT_TYPE_PKCS_SIGNED_DATA.to_le_bytes())?; // wCertificateType
    output.write_all(pkcs7_der)?;
    if sig_pad > 0 {
        output.write_all(&vec![0u8; sig_pad])?;
    }

    // Step 6: Update cert table directory entry
    output.seek(SeekFrom::Start(pe.cert_table_offset))?;
    output.write_all(&new_sigpos.to_le_bytes())?;
    output.write_all(&total_cert_len.to_le_bytes())?;

    // Step 7: Recalculate and write PE checksum
    let checksum = pe_calc_checksum(output, pe.checksum_offset)?;
    output.seek(SeekFrom::Start(pe.checksum_offset))?;
    output.write_all(&checksum.to_le_bytes())?;
    output.flush()?;

    Ok(())
}

/// Remove the signature from a PE file.
pub fn write_unsigned_pe(
    input: &mut File,
    output_path: &std::path::Path,
    pe: &PeInfo,
) -> Result<()> {
    let mut output = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(output_path)?;
    write_unsigned_pe_to(input, &mut output, pe)
}

/// Lower-level version that writes to an already-opened read+write File handle.
pub fn write_unsigned_pe_to(input: &mut File, output: &mut File, pe: &PeInfo) -> Result<()> {
    if pe.sigpos == 0 {
        return Err(Error::NoSignature);
    }

    // Copy everything up to the signature
    copy_range(input, output, 0, pe.sigpos as u64)?;

    // Zero checksum
    output.seek(SeekFrom::Start(pe.checksum_offset))?;
    output.write_all(&[0u8; 4])?;

    // Zero cert table directory entry
    output.seek(SeekFrom::Start(pe.cert_table_offset))?;
    output.write_all(&[0u8; 8])?;

    // Recalculate checksum
    let checksum = pe_calc_checksum(output, pe.checksum_offset)?;
    output.seek(SeekFrom::Start(pe.checksum_offset))?;
    output.write_all(&checksum.to_le_bytes())?;
    output.flush()?;

    Ok(())
}

/// PE checksum: 16-bit folding checksum over the entire file, skipping
/// the checksum field itself, plus the file size added at the end.
///
/// Port of `pe_calc_checksum` in `pe.c:652-676`.
pub fn pe_calc_checksum(f: &mut File, checksum_offset: u64) -> Result<u32> {
    let file_len = f.seek(SeekFrom::End(0))? as u32;
    f.seek(SeekFrom::Start(0))?;

    let mut checksum: u32 = 0;
    let mut offset: u32 = 0;
    let mut buf = [0u8; 65536];

    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        // Process pairs of bytes
        let pairs = n - (n % 2);
        for i in (0..pairs).step_by(2) {
            let val = if offset == checksum_offset as u32
                || offset == checksum_offset as u32 + 2
            {
                0u16 // skip checksum field itself
            } else {
                u16::from_le_bytes([buf[i], buf[i + 1]])
            };
            checksum += val as u32;
            checksum = (checksum & 0xFFFF) + (checksum >> 16);
            offset += 2;
        }
    }
    checksum = (checksum & 0xFFFF) + (checksum >> 16);
    checksum += file_len;
    Ok(checksum)
}

// --- Internal helpers ---

fn hash_range(
    f: &mut File,
    hasher: &mut impl digest::Update,
    start: u64,
    end: u64,
) -> Result<()> {
    if end <= start {
        return Ok(());
    }
    f.seek(SeekFrom::Start(start))?;
    let mut remaining = (end - start) as usize;
    let mut buf = [0u8; 65536];
    while remaining > 0 {
        let to_read = remaining.min(buf.len());
        let n = f.read(&mut buf[..to_read])?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        remaining -= n;
    }
    Ok(())
}

fn copy_range(src: &mut File, dst: &mut File, start: u64, end: u64) -> Result<()> {
    if end <= start {
        return Ok(());
    }
    src.seek(SeekFrom::Start(start))?;
    dst.seek(SeekFrom::Start(start))?;
    let mut remaining = (end - start) as usize;
    let mut buf = [0u8; 65536];
    while remaining > 0 {
        let to_read = remaining.min(buf.len());
        let n = src.read(&mut buf[..to_read])?;
        if n == 0 {
            break;
        }
        dst.write_all(&buf[..n])?;
        remaining -= n;
    }
    Ok(())
}

fn read_u16(f: &mut File) -> Result<u16> {
    let mut buf = [0u8; 2];
    f.read_exact(&mut buf)?;
    Ok(u16::from_le_bytes(buf))
}

fn read_u32(f: &mut File) -> Result<u32> {
    let mut buf = [0u8; 4];
    f.read_exact(&mut buf)?;
    Ok(u32::from_le_bytes(buf))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_unsigned_exe() {
        let test_exe = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/files/unsigned.exe");
        if !test_exe.exists() {
            eprintln!("skipping test: {test_exe:?} not found");
            return;
        }
        let mut f = File::open(&test_exe).unwrap();
        let pe = parse_pe(&mut f).unwrap();
        assert!(pe.header_size >= 44);
        assert_eq!(pe.sigpos, 0, "unsigned file should have no signature");
        assert_eq!(pe.siglen, 0);
    }

    #[test]
    fn checksum_unsigned_exe() {
        let test_exe = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/files/unsigned.exe");
        if !test_exe.exists() {
            eprintln!("skipping test: {test_exe:?} not found");
            return;
        }
        let mut f = File::open(&test_exe).unwrap();
        let pe = parse_pe(&mut f).unwrap();
        let checksum = pe_calc_checksum(&mut f, pe.checksum_offset).unwrap();
        // Just verify it returns something reasonable (non-zero)
        assert!(checksum > 0, "checksum should be non-zero");
    }

    #[test]
    fn digest_unsigned_exe() {
        use sha2::Digest;

        let test_exe = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/files/unsigned.exe");
        if !test_exe.exists() {
            eprintln!("skipping test: {test_exe:?} not found");
            return;
        }
        let mut f = File::open(&test_exe).unwrap();
        let pe = parse_pe(&mut f).unwrap();

        let mut hasher = sha2::Sha256::new();
        authenticode_digest(&mut f, &pe, &mut hasher).unwrap();
        let digest = hasher.finalize();

        // Verify we get a 32-byte hash
        assert_eq!(digest.len(), 32);
        // Verify it's not all zeros (sanity check)
        assert!(digest.iter().any(|&b| b != 0));
    }
}
