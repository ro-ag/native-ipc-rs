use std::fs::File;
use std::io::Write;
use std::path::PathBuf;

use super::vnext_image_identity::{
    CDHASH_LEN, ImageIdentityError, held_image_cdhashes, process_cdhash_for_test,
};

fn unique_scratch(label: &str) -> PathBuf {
    let directory = std::env::temp_dir().join(format!(
        "native-ipc-image-identity-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&directory).unwrap();
    directory
}

fn self_kernel_cdhash() -> [u8; CDHASH_LEN] {
    process_cdhash_for_test(std::process::id()).unwrap()
}

#[test]
fn held_hashes_of_the_running_test_image_contain_the_kernel_cdhash() {
    let executable = File::open(std::env::current_exe().unwrap()).unwrap();
    let hashes = held_image_cdhashes(&executable).unwrap();
    assert!(!hashes.is_empty());
    assert!(hashes.contains(&self_kernel_cdhash()));
}

#[test]
fn fat_wrappers_report_every_bindable_slice_and_skip_foreign_members() {
    let image = std::fs::read(std::env::current_exe().unwrap()).unwrap();
    let directory = unique_scratch("fat");

    // 32-bit fat entries: one skipped non-64-bit member, then the real image.
    let skipped_member = [0_u8; 64];
    let header_len: usize = 8 + 2 * 20;
    let skipped_offset = header_len.next_multiple_of(16);
    let image_offset = (skipped_offset + skipped_member.len()).next_multiple_of(16);
    let mut fat = Vec::new();
    fat.extend_from_slice(&0xcafe_babe_u32.to_be_bytes());
    fat.extend_from_slice(&2_u32.to_be_bytes());
    for (offset, size) in [
        (skipped_offset, skipped_member.len()),
        (image_offset, image.len()),
    ] {
        fat.extend_from_slice(&0x0100_000c_i32.to_be_bytes());
        fat.extend_from_slice(&0_i32.to_be_bytes());
        fat.extend_from_slice(&u32::try_from(offset).unwrap().to_be_bytes());
        fat.extend_from_slice(&u32::try_from(size).unwrap().to_be_bytes());
        fat.extend_from_slice(&4_u32.to_be_bytes());
    }
    fat.resize(skipped_offset, 0);
    fat.extend_from_slice(&skipped_member);
    fat.resize(image_offset, 0);
    fat.extend_from_slice(&image);
    let fat_path = directory.join("fat32");
    File::create(&fat_path).unwrap().write_all(&fat).unwrap();
    let hashes = held_image_cdhashes(&File::open(&fat_path).unwrap()).unwrap();
    assert!(hashes.contains(&self_kernel_cdhash()));

    // 64-bit fat entries around the same image.
    let header_len: usize = 8 + 32;
    let image_offset = header_len.next_multiple_of(16);
    let mut fat = Vec::new();
    fat.extend_from_slice(&0xcafe_babf_u32.to_be_bytes());
    fat.extend_from_slice(&1_u32.to_be_bytes());
    fat.extend_from_slice(&0x0100_000c_i32.to_be_bytes());
    fat.extend_from_slice(&0_i32.to_be_bytes());
    fat.extend_from_slice(&(image_offset as u64).to_be_bytes());
    fat.extend_from_slice(&(image.len() as u64).to_be_bytes());
    fat.extend_from_slice(&4_u32.to_be_bytes());
    fat.extend_from_slice(&0_u32.to_be_bytes());
    fat.resize(image_offset, 0);
    fat.extend_from_slice(&image);
    let fat_path = directory.join("fat64");
    File::create(&fat_path).unwrap().write_all(&fat).unwrap();
    let hashes = held_image_cdhashes(&File::open(&fat_path).unwrap()).unwrap();
    assert!(hashes.contains(&self_kernel_cdhash()));

    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn unbindable_and_malformed_inputs_fail_closed() {
    let directory = unique_scratch("negative");

    let script = directory.join("script");
    File::create(&script)
        .unwrap()
        .write_all(b"#!/bin/sh\nexit 0\n")
        .unwrap();
    assert_eq!(
        held_image_cdhashes(&File::open(&script).unwrap()),
        Err(ImageIdentityError::UnsupportedImage)
    );

    let empty = directory.join("empty");
    File::create(&empty).unwrap();
    assert_eq!(
        held_image_cdhashes(&File::open(&empty).unwrap()),
        Err(ImageIdentityError::MalformedImage)
    );

    // A truncated real image declares structures its bytes cannot satisfy.
    let image = std::fs::read(std::env::current_exe().unwrap()).unwrap();
    let truncated = directory.join("truncated");
    File::create(&truncated)
        .unwrap()
        .write_all(&image[..4096])
        .unwrap();
    assert!(matches!(
        held_image_cdhashes(&File::open(&truncated).unwrap()),
        Err(ImageIdentityError::MalformedImage | ImageIdentityError::UnsupportedImage)
    ));

    // A fat header naming an out-of-range member must not be accepted.
    let mut fat = Vec::new();
    fat.extend_from_slice(&0xcafe_babe_u32.to_be_bytes());
    fat.extend_from_slice(&1_u32.to_be_bytes());
    fat.extend_from_slice(&0x0100_000c_i32.to_be_bytes());
    fat.extend_from_slice(&0_i32.to_be_bytes());
    fat.extend_from_slice(&0x0010_0000_u32.to_be_bytes());
    fat.extend_from_slice(&0x0010_0000_u32.to_be_bytes());
    fat.extend_from_slice(&4_u32.to_be_bytes());
    let hostile = directory.join("hostile-fat");
    File::create(&hostile).unwrap().write_all(&fat).unwrap();
    assert_eq!(
        held_image_cdhashes(&File::open(&hostile).unwrap()),
        Err(ImageIdentityError::MalformedImage)
    );

    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn foreign_platform_binaries_report_a_different_content_identity() {
    let foreign = File::open("/bin/ls").unwrap();
    match held_image_cdhashes(&foreign) {
        Ok(hashes) => {
            assert!(!hashes.is_empty());
            assert!(!hashes.contains(&self_kernel_cdhash()));
        }
        // Platform binaries may carry SHA-1-only legacy slices in some fat
        // layouts; failing closed is equally acceptable for a foreign image.
        Err(error) => assert_eq!(error, ImageIdentityError::UnsupportedImage),
    }
}
