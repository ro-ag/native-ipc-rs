//! Content identity for the held executable and the running child image.
//!
//! The held file's code-directory hashes are computed directly from the
//! retained descriptor, and the running child reports its kernel-registered
//! code-directory hash through `csops_audittoken`. Comparing the two binds the
//! started image to the retained file by content, independent of pathnames
//! and of who signed the image: an ad-hoc linker signature carries a code
//! directory exactly like a certificate-backed one.

use std::ffi::{c_int, c_void};
use std::fs::File;
use std::os::unix::fs::FileExt;

use sha2::{Digest, Sha256, Sha384};

/// Kernel code-directory hash length; longer digests are truncated by XNU.
pub(crate) const CDHASH_LEN: usize = 20;

const CS_OPS_CDHASH: u32 = 5;

const FAT_MAGIC: u32 = 0xcafe_babe;
const FAT_MAGIC_64: u32 = 0xcafe_babf;
const MH_MAGIC_64: u32 = 0xfeed_facf;
const MH_EXECUTE: u32 = 0x2;
const LC_CODE_SIGNATURE: u32 = 0x1d;
const CSMAGIC_EMBEDDED_SIGNATURE: u32 = 0xfade_0cc0;
const CSMAGIC_CODEDIRECTORY: u32 = 0xfade_0c02;
const CS_HASHTYPE_SHA256: u8 = 2;
const CS_HASHTYPE_SHA256_TRUNCATED: u8 = 3;
const CS_HASHTYPE_SHA384: u8 = 4;

const MACH_HEADER_64_LEN: usize = 32;
const FAT_HEADER_LEN: usize = 8;
const FAT_ARCH_LEN: usize = 20;
const FAT_ARCH_64_LEN: usize = 32;
const LOAD_COMMAND_LEN: usize = 8;
const LINKEDIT_DATA_COMMAND_LEN: usize = 16;
const BLOB_HEADER_LEN: usize = 8;
const SUPERBLOB_HEADER_LEN: usize = 12;
const SUPERBLOB_INDEX_LEN: usize = 8;
const CODEDIRECTORY_HASH_TYPE_OFFSET: usize = 37;

const MAX_FAT_SLICES: u32 = 16;
const MAX_COMMANDS_BYTES: u32 = 4 << 20;
const MAX_SIGNATURE_BYTES: u32 = 16 << 20;
const MAX_SUPERBLOB_ENTRIES: u32 = 64;

unsafe extern "C" {
    fn csops(pid: c_int, ops: u32, useraddr: *mut c_void, usersize: usize) -> c_int;
    fn csops_audittoken(
        pid: c_int,
        ops: u32,
        useraddr: *mut c_void,
        usersize: usize,
        token: *mut [u32; 8],
    ) -> c_int;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ImageIdentityError {
    /// The file is not a bindable signed 64-bit Mach-O executable.
    UnsupportedImage,
    /// The file claims a structure its bytes cannot satisfy.
    MalformedImage,
    Native(Option<i32>),
}

/// Every code-directory hash carried by the held file, across all slices and
/// alternate code directories. The kernel reports exactly one of these for a
/// process executing any slice of this file.
pub(crate) fn held_image_cdhashes(
    file: &File,
) -> Result<Vec<[u8; CDHASH_LEN]>, ImageIdentityError> {
    let mut header = [0_u8; FAT_HEADER_LEN];
    read_at(file, 0, &mut header)?;
    let big_endian_magic = u32::from_be_bytes(slice4(&header, 0)?);
    let mut hashes = Vec::new();
    match big_endian_magic {
        FAT_MAGIC | FAT_MAGIC_64 => {
            let slice_count = u32::from_be_bytes(slice4(&header, 4)?);
            if slice_count == 0 || slice_count > MAX_FAT_SLICES {
                return Err(ImageIdentityError::MalformedImage);
            }
            let entry_len = if big_endian_magic == FAT_MAGIC {
                FAT_ARCH_LEN
            } else {
                FAT_ARCH_64_LEN
            };
            for index in 0..slice_count {
                let entry_offset = (FAT_HEADER_LEN as u64)
                    .checked_add(
                        u64::from(index)
                            .checked_mul(entry_len as u64)
                            .ok_or(ImageIdentityError::MalformedImage)?,
                    )
                    .ok_or(ImageIdentityError::MalformedImage)?;
                let mut entry = [0_u8; FAT_ARCH_64_LEN];
                read_at(file, entry_offset, &mut entry[..entry_len])?;
                let (slice_offset, slice_len) = if big_endian_magic == FAT_MAGIC {
                    (
                        u64::from(u32::from_be_bytes(slice4(&entry, 8)?)),
                        u64::from(u32::from_be_bytes(slice4(&entry, 12)?)),
                    )
                } else {
                    (
                        u64::from_be_bytes(slice8(&entry, 8)?),
                        u64::from_be_bytes(slice8(&entry, 16)?),
                    )
                };
                slice_cdhashes(file, slice_offset, slice_len, true, &mut hashes)?;
            }
        }
        _ => {
            let length = file
                .metadata()
                .map_err(|error| ImageIdentityError::Native(error.raw_os_error()))?
                .len();
            slice_cdhashes(file, 0, length, false, &mut hashes)?;
        }
    }
    if hashes.is_empty() {
        return Err(ImageIdentityError::UnsupportedImage);
    }
    Ok(hashes)
}

/// Kernel-registered code-directory hash of the process the supplied audit
/// token names. The kernel refuses the lookup when the PID no longer carries
/// that exact token, so a reused PID or a post-capture `exec` reports `ESRCH`
/// instead of another process's identity.
pub(crate) fn process_cdhash_with_token(
    pid: u32,
    mut token_values: [u32; 8],
) -> Result<[u8; CDHASH_LEN], Option<i32>> {
    let mut hash = [0_u8; CDHASH_LEN];
    // SAFETY: the output buffer and token are live locals of the exact
    // documented sizes for CS_OPS_CDHASH.
    let result = unsafe {
        csops_audittoken(
            pid as c_int,
            CS_OPS_CDHASH,
            hash.as_mut_ptr().cast(),
            hash.len(),
            &mut token_values,
        )
    };
    if result == 0 {
        Ok(hash)
    } else {
        Err(std::io::Error::last_os_error().raw_os_error())
    }
}

/// PID-only variant for self-inspection oracles; the caller must pin the PID.
#[cfg(test)]
pub(crate) fn process_cdhash_for_test(pid: u32) -> Result<[u8; CDHASH_LEN], Option<i32>> {
    let mut hash = [0_u8; CDHASH_LEN];
    // SAFETY: the output buffer is a live local of the documented size.
    let result = unsafe {
        csops(
            pid as c_int,
            CS_OPS_CDHASH,
            hash.as_mut_ptr().cast(),
            hash.len(),
        )
    };
    if result == 0 {
        Ok(hash)
    } else {
        Err(std::io::Error::last_os_error().raw_os_error())
    }
}

fn slice_cdhashes(
    file: &File,
    slice_offset: u64,
    slice_len: u64,
    inside_fat: bool,
    hashes: &mut Vec<[u8; CDHASH_LEN]>,
) -> Result<(), ImageIdentityError> {
    let mut magic = [0_u8; 4];
    if slice_len < magic.len() as u64 {
        return Err(ImageIdentityError::MalformedImage);
    }
    read_at(file, slice_offset, &mut magic)?;
    if u32::from_le_bytes(magic) != MH_MAGIC_64 {
        // Only 64-bit little-endian slices can execute on supported targets;
        // other fat members cannot become the running image.
        return if inside_fat {
            Ok(())
        } else {
            Err(ImageIdentityError::UnsupportedImage)
        };
    }
    if slice_len < MACH_HEADER_64_LEN as u64 {
        return Err(ImageIdentityError::MalformedImage);
    }
    let mut header = [0_u8; MACH_HEADER_64_LEN];
    read_at(file, slice_offset, &mut header)?;
    if u32::from_le_bytes(slice4(&header, 12)?) != MH_EXECUTE {
        return if inside_fat {
            Ok(())
        } else {
            Err(ImageIdentityError::UnsupportedImage)
        };
    }
    let command_count = u32::from_le_bytes(slice4(&header, 16)?);
    let commands_len = u32::from_le_bytes(slice4(&header, 20)?);
    if commands_len > MAX_COMMANDS_BYTES
        || u64::from(commands_len)
            > slice_len
                .checked_sub(MACH_HEADER_64_LEN as u64)
                .ok_or(ImageIdentityError::MalformedImage)?
        || u64::from(command_count) > u64::from(commands_len) / LOAD_COMMAND_LEN as u64
    {
        return Err(ImageIdentityError::MalformedImage);
    }
    let mut commands =
        vec![0_u8; usize::try_from(commands_len).map_err(|_| ImageIdentityError::MalformedImage)?];
    read_at(
        file,
        slice_offset
            .checked_add(MACH_HEADER_64_LEN as u64)
            .ok_or(ImageIdentityError::MalformedImage)?,
        &mut commands,
    )?;

    let mut cursor = 0_usize;
    let mut signature: Option<(u32, u32)> = None;
    for _ in 0..command_count {
        let end = cursor
            .checked_add(LOAD_COMMAND_LEN)
            .filter(|end| *end <= commands.len())
            .ok_or(ImageIdentityError::MalformedImage)?;
        let command = u32::from_le_bytes(slice4(&commands[cursor..end], 0)?);
        let command_len = u32::from_le_bytes(slice4(&commands[cursor..end], 4)?);
        let command_len =
            usize::try_from(command_len).map_err(|_| ImageIdentityError::MalformedImage)?;
        if command_len < LOAD_COMMAND_LEN || command_len % 4 != 0 {
            return Err(ImageIdentityError::MalformedImage);
        }
        let command_end = cursor
            .checked_add(command_len)
            .filter(|end| *end <= commands.len())
            .ok_or(ImageIdentityError::MalformedImage)?;
        if command == LC_CODE_SIGNATURE {
            if command_len < LINKEDIT_DATA_COMMAND_LEN || signature.is_some() {
                return Err(ImageIdentityError::MalformedImage);
            }
            signature = Some((
                u32::from_le_bytes(slice4(&commands[cursor..command_end], 8)?),
                u32::from_le_bytes(slice4(&commands[cursor..command_end], 12)?),
            ));
        }
        cursor = command_end;
    }
    let Some((signature_offset, signature_len)) = signature else {
        return if inside_fat {
            Ok(())
        } else {
            Err(ImageIdentityError::UnsupportedImage)
        };
    };
    if signature_len < SUPERBLOB_HEADER_LEN as u32
        || signature_len > MAX_SIGNATURE_BYTES
        || u64::from(signature_offset)
            .checked_add(u64::from(signature_len))
            .is_none_or(|end| end > slice_len)
    {
        return Err(ImageIdentityError::MalformedImage);
    }
    let mut blob =
        vec![0_u8; usize::try_from(signature_len).map_err(|_| ImageIdentityError::MalformedImage)?];
    read_at(
        file,
        slice_offset
            .checked_add(u64::from(signature_offset))
            .ok_or(ImageIdentityError::MalformedImage)?,
        &mut blob,
    )?;
    superblob_cdhashes(&blob, hashes)
}

fn superblob_cdhashes(
    blob: &[u8],
    hashes: &mut Vec<[u8; CDHASH_LEN]>,
) -> Result<(), ImageIdentityError> {
    if u32::from_be_bytes(slice4(blob, 0)?) != CSMAGIC_EMBEDDED_SIGNATURE {
        return Err(ImageIdentityError::UnsupportedImage);
    }
    let declared_len = u32::from_be_bytes(slice4(blob, 4)?);
    let entry_count = u32::from_be_bytes(slice4(blob, 8)?);
    let declared_len =
        usize::try_from(declared_len).map_err(|_| ImageIdentityError::MalformedImage)?;
    if declared_len > blob.len() || entry_count > MAX_SUPERBLOB_ENTRIES {
        return Err(ImageIdentityError::MalformedImage);
    }
    let mut found = false;
    for index in 0..entry_count {
        let entry_offset = SUPERBLOB_HEADER_LEN
            .checked_add(
                usize::try_from(index)
                    .ok()
                    .and_then(|index| index.checked_mul(SUPERBLOB_INDEX_LEN))
                    .ok_or(ImageIdentityError::MalformedImage)?,
            )
            .ok_or(ImageIdentityError::MalformedImage)?;
        let member_offset = u32::from_be_bytes(slice4(
            blob,
            entry_offset
                .checked_add(4)
                .ok_or(ImageIdentityError::MalformedImage)?,
        )?);
        let member_offset =
            usize::try_from(member_offset).map_err(|_| ImageIdentityError::MalformedImage)?;
        let member_magic = u32::from_be_bytes(slice4(blob, member_offset)?);
        if member_magic != CSMAGIC_CODEDIRECTORY {
            continue;
        }
        let member_len = u32::from_be_bytes(slice4(
            blob,
            member_offset
                .checked_add(4)
                .ok_or(ImageIdentityError::MalformedImage)?,
        )?);
        let member_len =
            usize::try_from(member_len).map_err(|_| ImageIdentityError::MalformedImage)?;
        let member_end = member_offset
            .checked_add(member_len)
            .filter(|end| *end <= declared_len)
            .ok_or(ImageIdentityError::MalformedImage)?;
        if member_len <= CODEDIRECTORY_HASH_TYPE_OFFSET {
            return Err(ImageIdentityError::MalformedImage);
        }
        let directory = &blob[member_offset..member_end];
        found = true;
        if let Some(hash) = code_directory_cdhash(directory)?
            && !hashes.contains(&hash)
        {
            hashes.push(hash);
        }
    }
    if found {
        Ok(())
    } else {
        Err(ImageIdentityError::UnsupportedImage)
    }
}

fn code_directory_cdhash(directory: &[u8]) -> Result<Option<[u8; CDHASH_LEN]>, ImageIdentityError> {
    let mut hash = [0_u8; CDHASH_LEN];
    match directory[CODEDIRECTORY_HASH_TYPE_OFFSET] {
        CS_HASHTYPE_SHA256 | CS_HASHTYPE_SHA256_TRUNCATED => {
            hash.copy_from_slice(&Sha256::digest(directory)[..CDHASH_LEN]);
            Ok(Some(hash))
        }
        CS_HASHTYPE_SHA384 => {
            hash.copy_from_slice(&Sha384::digest(directory)[..CDHASH_LEN]);
            Ok(Some(hash))
        }
        // A SHA-1-only code directory cannot be the kernel identity of any
        // modern arm64 execution; producing no hash keeps the caller
        // fail-closed instead of trusting a digest this crate does not carry.
        _ => Ok(None),
    }
}

fn read_at(file: &File, offset: u64, buffer: &mut [u8]) -> Result<(), ImageIdentityError> {
    file.read_exact_at(buffer, offset).map_err(|error| {
        if error.kind() == std::io::ErrorKind::UnexpectedEof {
            ImageIdentityError::MalformedImage
        } else {
            ImageIdentityError::Native(error.raw_os_error())
        }
    })
}

fn slice4(bytes: &[u8], offset: usize) -> Result<[u8; 4], ImageIdentityError> {
    bytes
        .get(
            offset
                ..offset
                    .checked_add(4)
                    .ok_or(ImageIdentityError::MalformedImage)?,
        )
        .and_then(|window| window.try_into().ok())
        .ok_or(ImageIdentityError::MalformedImage)
}

fn slice8(bytes: &[u8], offset: usize) -> Result<[u8; 8], ImageIdentityError> {
    bytes
        .get(
            offset
                ..offset
                    .checked_add(8)
                    .ok_or(ImageIdentityError::MalformedImage)?,
        )
        .and_then(|window| window.try_into().ok())
        .ok_or(ImageIdentityError::MalformedImage)
}
