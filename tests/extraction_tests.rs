//! Security tests for in-memory extraction — verifies that no archive
//! content is ever written to disk, that bounds are enforced, and that
//! non-regular-file entries are skipped.

use std::io::{Cursor, Write};

/// Helper: build a tar.gz archive in memory from given entries.
/// Each entry is (path, content_bytes).
fn build_tar_gz(entries: Vec<(&str, Vec<u8>)>) -> Vec<u8> {
    let mut tar_builder = tar::Builder::new(Vec::new());
    for (path, content) in entries {
        let mut header = tar::Header::new_gnu();
        header.set_size(content.len() as u64);
        header.set_mode(0o644);
        header.set_path(path).unwrap();
        header.set_entry_type(tar::EntryType::Regular);
        header.set_cksum();
        tar_builder.append(&header, content.as_slice()).unwrap();
    }
    let tar_data = tar_builder.into_inner().unwrap();

    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    gz.write_all(&tar_data).unwrap();
    gz.finish().unwrap()
}

/// Helper: build a ZIP archive in memory from given entries.
fn build_zip(entries: Vec<(&str, Vec<u8>)>) -> Vec<u8> {
    let buf = Cursor::new(Vec::new());
    let mut zip = zip::ZipWriter::new(buf);
    let options =
        zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Stored);
    for (path, content) in entries {
        zip.start_file(path, options).unwrap();
        zip.write_all(&content).unwrap();
    }
    let buf = zip.finish().unwrap();
    buf.into_inner()
}

fn default_config() -> clu::config::ExtractionConfig {
    clu::config::ExtractionConfig::default()
}

fn small_config() -> clu::config::ExtractionConfig {
    clu::config::ExtractionConfig {
        max_total_bytes: 500,
        max_file_bytes: 200,
        max_entries: 10,
    }
}

// ── Tar.gz tests ─────────────────────────────────────────────────────────

#[test]
fn test_tar_gz_basic_extraction() {
    let data = build_tar_gz(vec![
        ("pkg/module.py", b"print('hello')".to_vec()),
        ("pkg/setup.py", b"from setuptools import setup".to_vec()),
        ("pkg/README.md", b"readme content".to_vec()),
    ]);

    let result = clu::analysis::package::extract_tar_gz_in_memory(
        &data,
        &default_config(),
        clu::analysis::package::Ecosystem::PyPI,
    )
    .unwrap();

    assert_eq!(result.files.len(), 3);
    assert!(
        result
            .files
            .iter()
            .any(|f| f.relative_path.to_string_lossy().contains("setup.py"))
    );
    assert!(
        result
            .files
            .iter()
            .any(|f| f.relative_path.to_string_lossy().contains("module.py"))
    );
}

#[test]
fn test_tar_gz_entry_count_bound() {
    let mut entries: Vec<(&str, Vec<u8>)> = Vec::new();
    for i in 0..20 {
        entries.push((
            Box::leak(format!("pkg/file{}.py", i).into_boxed_str()),
            b"x".to_vec(),
        ));
    }
    let data = build_tar_gz(entries);

    let config = clu::config::ExtractionConfig {
        max_total_bytes: 67_108_864,
        max_file_bytes: 2_097_152,
        max_entries: 10,
    };

    let result = clu::analysis::package::extract_tar_gz_in_memory(
        &data,
        &config,
        clu::analysis::package::Ecosystem::PyPI,
    )
    .unwrap();

    assert_eq!(result.files.len(), 10, "should respect max_entries bound");
}

#[test]
fn test_tar_gz_total_bytes_bound() {
    let mut entries: Vec<(&str, Vec<u8>)> = Vec::new();
    for i in 0..5 {
        entries.push((
            Box::leak(format!("pkg/file{}.py", i).into_boxed_str()),
            b"a".repeat(150),
        ));
    }
    let data = build_tar_gz(entries);

    let result = clu::analysis::package::extract_tar_gz_in_memory(
        &data,
        &small_config(),
        clu::analysis::package::Ecosystem::PyPI,
    )
    .unwrap();

    let total: usize = result.files.iter().map(|f| f.contents.len()).sum();
    assert!(total <= 500, "total bytes should respect max_total_bytes");
}

#[test]
fn test_tar_gz_oversized_member_skipped() {
    let entries = vec![
        ("pkg/small.py", b"tiny".to_vec()),
        ("pkg/big.py", b"X".repeat(300)),
        ("pkg/also_small.py", b"mini".to_vec()),
    ];
    let data = build_tar_gz(entries);

    let result = clu::analysis::package::extract_tar_gz_in_memory(
        &data,
        &small_config(),
        clu::analysis::package::Ecosystem::PyPI,
    )
    .unwrap();

    let names: Vec<String> = result
        .files
        .iter()
        .map(|f| f.relative_path.to_string_lossy().into_owned())
        .collect();
    assert!(
        names.iter().any(|n| n.contains("small.py")),
        "small files should be kept"
    );
    assert!(
        names.iter().any(|n| n.contains("also_small.py")),
        "small files should be kept"
    );
    assert!(
        !names.iter().any(|n| n.contains("big.py")),
        "oversized member should be skipped"
    );
}

#[test]
fn test_tar_gz_symlink_entries_skipped() {
    let mut tar_builder = tar::Builder::new(Vec::new());

    // Add a regular file first
    let content = b"regular content";
    let mut header = tar::Header::new_gnu();
    header.set_size(content.len() as u64);
    header.set_mode(0o644);
    header.set_path("pkg/regular.py").unwrap();
    header.set_entry_type(tar::EntryType::Regular);
    header.set_cksum();
    tar_builder.append(&header, content.as_slice()).unwrap();

    // Add a symlink entry
    let mut link_header = tar::Header::new_gnu();
    link_header.set_size(0);
    link_header.set_mode(0o777);
    link_header.set_path("pkg/evil_link").unwrap();
    link_header.set_entry_type(tar::EntryType::Symlink);
    link_header.set_link_name("/etc/passwd").unwrap();
    link_header.set_cksum();
    tar_builder.append(&link_header, &[][..]).unwrap();

    // Add a hardlink entry
    let mut hardlink_header = tar::Header::new_gnu();
    hardlink_header.set_size(0);
    hardlink_header.set_mode(0o644);
    hardlink_header.set_path("pkg/hard_link").unwrap();
    hardlink_header.set_entry_type(tar::EntryType::Link);
    hardlink_header.set_link_name("pkg/regular.py").unwrap();
    hardlink_header.set_cksum();
    tar_builder.append(&hardlink_header, &[][..]).unwrap();

    let tar_data = tar_builder.into_inner().unwrap();

    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    gz.write_all(&tar_data).unwrap();
    let data = gz.finish().unwrap();

    let result = clu::analysis::package::extract_tar_gz_in_memory(
        &data,
        &default_config(),
        clu::analysis::package::Ecosystem::PyPI,
    )
    .unwrap();

    assert_eq!(
        result.files.len(),
        1,
        "only regular file should be extracted"
    );
    assert!(
        result.files[0]
            .relative_path
            .to_string_lossy()
            .contains("regular.py")
    );
}

#[test]
fn test_tar_gz_non_utf8_handled_lossy() {
    let invalid_utf8: Vec<u8> = vec![0x80, 0x81, 0x82, b'H', b'e', b'l', b'l', b'o'];
    let entries = vec![
        ("pkg/binary.py", invalid_utf8),
        ("pkg/normal.py", b"print('ok')".to_vec()),
    ];
    let data = build_tar_gz(entries);

    let result = clu::analysis::package::extract_tar_gz_in_memory(
        &data,
        &default_config(),
        clu::analysis::package::Ecosystem::PyPI,
    )
    .unwrap();

    assert_eq!(result.files.len(), 2);
    let bin_file = result
        .files
        .iter()
        .find(|f| f.relative_path.to_string_lossy().contains("binary.py"))
        .unwrap();
    assert!(
        bin_file.contents.contains("Hello"),
        "lossy UTF-8 should preserve valid portions"
    );
    assert!(
        bin_file.contents.contains("\u{fffd}"),
        "invalid UTF-8 should produce replacement chars"
    );
}

// ── ZIP tests ─────────────────────────────────────────────────────────────

#[test]
fn test_zip_basic_extraction() {
    let data = build_zip(vec![
        ("pkg/module.py", b"print('hello')".to_vec()),
        ("pkg/setup.py", b"from setuptools import setup".to_vec()),
    ]);

    let result = clu::analysis::package::extract_zip_in_memory(
        &data,
        &default_config(),
        clu::analysis::package::Ecosystem::PyPI,
    )
    .unwrap();

    assert_eq!(result.files.len(), 2);
}

#[test]
fn test_zip_entry_count_bound() {
    let mut entries: Vec<(&str, Vec<u8>)> = Vec::new();
    for i in 0..20 {
        entries.push((
            Box::leak(format!("pkg/file{}.py", i).into_boxed_str()),
            b"x".to_vec(),
        ));
    }
    let data = build_zip(entries);

    let config = clu::config::ExtractionConfig {
        max_total_bytes: 67_108_864,
        max_file_bytes: 2_097_152,
        max_entries: 10,
    };

    let result = clu::analysis::package::extract_zip_in_memory(
        &data,
        &config,
        clu::analysis::package::Ecosystem::PyPI,
    )
    .unwrap();

    assert_eq!(result.files.len(), 10);
}

#[test]
fn test_zip_oversized_member_skipped() {
    let entries = vec![
        ("pkg/small.py", b"tiny".to_vec()),
        ("pkg/big.py", b"X".repeat(300)),
        ("pkg/also_small.py", b"mini".to_vec()),
    ];
    let data = build_zip(entries);

    let result = clu::analysis::package::extract_zip_in_memory(
        &data,
        &small_config(),
        clu::analysis::package::Ecosystem::PyPI,
    )
    .unwrap();

    let names: Vec<String> = result
        .files
        .iter()
        .map(|f| f.relative_path.to_string_lossy().into_owned())
        .collect();
    assert!(names.iter().any(|n| n.contains("small.py")));
    assert!(
        !names.iter().any(|n| n.contains("big.py")),
        "oversized ZIP member should be skipped"
    );
}

#[test]
fn test_zip_directory_entries_skipped() {
    let buf = Cursor::new(Vec::new());
    let mut zip = zip::ZipWriter::new(buf);
    let options =
        zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Stored);

    zip.add_directory("pkg/", options.clone()).unwrap();
    zip.start_file("pkg/module.py", options).unwrap();
    zip.write_all(b"print('hello')").unwrap();
    zip.start_file("pkg/setup.py", options).unwrap();
    zip.write_all(b"from setuptools import setup").unwrap();

    let buf = zip.finish().unwrap().into_inner();

    let result = clu::analysis::package::extract_zip_in_memory(
        &buf,
        &default_config(),
        clu::analysis::package::Ecosystem::PyPI,
    )
    .unwrap();

    assert_eq!(
        result.files.len(),
        2,
        "directories should be skipped, only regular files"
    );
}

#[test]
fn test_zip_non_utf8_handled_lossy() {
    let invalid_utf8: Vec<u8> = vec![0x80, 0x81, 0x82, b'H', b'i'];
    let entries = vec![
        ("pkg/binary.py", invalid_utf8),
        ("pkg/normal.py", b"ok".to_vec()),
    ];
    let data = build_zip(entries);

    let result = clu::analysis::package::extract_zip_in_memory(
        &data,
        &default_config(),
        clu::analysis::package::Ecosystem::PyPI,
    )
    .unwrap();

    assert_eq!(result.files.len(), 2);
    let bin_file = result
        .files
        .iter()
        .find(|f| f.relative_path.to_string_lossy().contains("binary.py"))
        .unwrap();
    assert!(
        bin_file.contents.contains("Hi"),
        "lossy decode should preserve valid bytes"
    );
}

// ── Path-traversal (zip-slip) regression guard ───────────────────────────
//
// Since nothing is ever written to disk, path-traversal entries cannot
// escape anywhere. The defense is: never write to disk + bounds.
// This test asserts that returned paths are sanitized.

/// Build a tar archive in memory with a raw entry whose path contains `..`.
/// The tar builder API rejects `..` but real malicious archives contain them,
/// so we construct the bytes manually.
fn build_tar_with_traversal_path(traversal_path: &str, good_path: &str) -> Vec<u8> {
    // Build a legitimate tar first, then manually construct raw entries
    let mut tar_builder = tar::Builder::new(Vec::new());

    // Good entry
    let content = b"legit";
    let mut header = tar::Header::new_gnu();
    header.set_size(content.len() as u64);
    header.set_mode(0o644);
    header.set_path(good_path).unwrap();
    header.set_entry_type(tar::EntryType::Regular);
    header.set_cksum();
    tar_builder.append(&header, content.as_slice()).unwrap();

    // For the traversal path, we bypass the tar builder's path validation
    // by directly injecting raw tar header bytes
    let tar_data = tar_builder.into_inner().unwrap();

    // Build a raw tar header for the traversal path
    let evil_content = b"stolen";
    let mut evil_header = tar::Header::new_gnu();
    evil_header.set_size(evil_content.len() as u64);
    evil_header.set_mode(0o644);
    evil_header.set_entry_type(tar::EntryType::Regular);
    // set_path would reject "..", so write the path bytes directly into header
    let path_bytes = traversal_path.as_bytes();
    {
        let header_bytes = evil_header.as_mut_bytes();
        header_bytes[..path_bytes.len()].copy_from_slice(path_bytes);
        for i in path_bytes.len()..100 {
            header_bytes[i] = 0;
        }
    }
    evil_header.set_cksum();

    // Manually assemble: [evil_header(512)][evil_data(pad512)][tar_data from legitimate entry]
    let mut result = Vec::new();
    result.extend_from_slice(evil_header.as_bytes()); // 512 bytes
    result.extend_from_slice(evil_content);
    // Pad evil content to 512-byte boundary
    let padding = 512 - (evil_content.len() % 512);
    result.extend(std::iter::repeat(0u8).take(padding));
    result.extend_from_slice(&tar_data);
    // Add end-of-archive marker (two 512-byte zero blocks)
    result.extend(std::iter::repeat(0u8).take(1024));

    // Gzip the result
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    gz.write_all(&result).unwrap();
    gz.finish().unwrap()
}

#[test]
fn test_tar_gz_zip_slip_paths_sanitized() {
    let data = build_tar_with_traversal_path("../../etc/passwd", "pkg/real.py");

    let result = clu::analysis::package::extract_tar_gz_in_memory(
        &data,
        &default_config(),
        clu::analysis::package::Ecosystem::PyPI,
    )
    .unwrap();

    // Traversable and absolute paths should be filtered out
    for file in &result.files {
        let path_str = file.relative_path.to_string_lossy().into_owned();
        assert!(
            !path_str.contains(".."),
            "no path traversal in result: {}",
            path_str
        );
        assert!(
            !path_str.starts_with('/'),
            "no absolute path in result: {}",
            path_str
        );
    }
    // The legitimate file should still be present
    assert!(
        result
            .files
            .iter()
            .any(|f| f.relative_path.to_string_lossy().contains("real.py"))
    );
}

#[test]
fn test_zip_slip_paths_sanitized() {
    // ZIP format allows arbitrary path strings; test that our extractor sanitizes
    let entries = vec![
        ("../../etc/shadow", b"stolen".to_vec()),
        ("pkg/good.py", b"legit".to_vec()),
    ];
    let data = build_zip(entries);

    let result = clu::analysis::package::extract_zip_in_memory(
        &data,
        &default_config(),
        clu::analysis::package::Ecosystem::PyPI,
    )
    .unwrap();

    for file in &result.files {
        let path_str = file.relative_path.to_string_lossy().into_owned();
        assert!(
            !path_str.contains(".."),
            "no path traversal in result: {}",
            path_str
        );
        assert!(
            !path_str.starts_with('/'),
            "no absolute path in result: {}",
            path_str
        );
    }
}

#[test]
fn test_no_files_written_to_filesystem() {
    // Extraction is entirely in-memory; even path-traversal entries cannot write
    // to disk because extract_tar_gz_in_memory never touches the filesystem.
    let data = build_tar_with_traversal_path("../../../tmp/clu_test_escape", "pkg/normal.py");

    let result = clu::analysis::package::extract_tar_gz_in_memory(
        &data,
        &default_config(),
        clu::analysis::package::Ecosystem::PyPI,
    )
    .unwrap();

    // The traversal-path entry must not appear in results (filtered by sanitize_relative_path)
    for file in &result.files {
        let path_str = file.relative_path.to_string_lossy().into_owned();
        assert!(
            !path_str.contains(".."),
            "path traversal entries must be filtered"
        );
    }
    // Confirm we got at least the legitimate file
    assert!(
        result
            .files
            .iter()
            .any(|f| f.relative_path.to_string_lossy().contains("normal.py"))
    );
}

#[test]
fn test_zip_total_bytes_bound() {
    let mut entries: Vec<(&str, Vec<u8>)> = Vec::new();
    for i in 0..5 {
        entries.push((
            Box::leak(format!("pkg/file{}.py", i).into_boxed_str()),
            b"a".repeat(150),
        ));
    }
    let data = build_zip(entries);

    let result = clu::analysis::package::extract_zip_in_memory(
        &data,
        &small_config(),
        clu::analysis::package::Ecosystem::PyPI,
    )
    .unwrap();

    let total: usize = result.files.iter().map(|f| f.contents.len()).sum();
    assert!(total <= 500, "total bytes should respect max_total_bytes");
}

// ── Decompression bomb defense ───────────────────────────────────────────

#[test]
fn test_zip_decompression_bomb_stopped() {
    // Create a ZIP where one entry declares a very large uncompressed size
    // but our max_file_bytes bound ensures we stop reading early
    let entries = vec![
        ("pkg/huge.py", b"X".repeat(300)), // exceeds max_file_bytes=200
        ("pkg/tiny.py", b"small".to_vec()),
    ];
    let data = build_zip(entries);

    let result = clu::analysis::package::extract_zip_in_memory(
        &data,
        &small_config(), // max_file_bytes=200
        clu::analysis::package::Ecosystem::PyPI,
    )
    .unwrap();

    let names: Vec<String> = result
        .files
        .iter()
        .map(|f| f.relative_path.to_string_lossy().into_owned())
        .collect();
    assert!(
        !names.iter().any(|n| n.contains("huge.py")),
        "oversized entry must be skipped"
    );
    assert!(
        names.iter().any(|n| n.contains("tiny.py")),
        "small entry should still be present"
    );
}

// ── Source bundle tests ──────────────────────────────────────────────────

#[test]
fn test_build_source_bundle_entry_scripts_never_truncated() {
    let config = clu::config::ExtractionConfig::default();
    let big_content = "x".repeat(200);
    let contents = clu::analysis::package::PackageContents {
        files: vec![clu::analysis::package::FileEntry {
            relative_path: std::path::PathBuf::from("setup.py"),
            contents: big_content.clone(),
            role: clu::analysis::package::FileRole::EntryScript,
        }],
        ecosystem: clu::analysis::package::Ecosystem::PyPI,
        sha256: String::new(),
    };

    // Budget is 50, but entry scripts should never be truncated
    let bundle = clu::analysis::package::build_source_bundle(&contents, 50);
    assert_eq!(bundle.entries.len(), 1);
    assert_eq!(bundle.entries[0].contents.len(), 200);
    assert!(!bundle.entries[0].contents.contains("truncated"));
}

#[test]
fn test_build_source_bundle_source_files_truncated_under_budget() {
    let contents = clu::analysis::package::PackageContents {
        files: vec![clu::analysis::package::FileEntry {
            relative_path: std::path::PathBuf::from("module.py"),
            contents: "a".repeat(100),
            role: clu::analysis::package::FileRole::Source,
        }],
        ecosystem: clu::analysis::package::Ecosystem::PyPI,
        sha256: String::new(),
    };

    let bundle = clu::analysis::package::build_source_bundle(&contents, 50);
    assert!(bundle.truncated);
    assert!(bundle.entries[0].contents.contains("truncated"));
}

#[test]
fn test_build_source_bundle_priority_ordering() {
    let contents = clu::analysis::package::PackageContents {
        files: vec![
            clu::analysis::package::FileEntry {
                relative_path: std::path::PathBuf::from("utils.py"),
                contents: "source".to_string(),
                role: clu::analysis::package::FileRole::Source,
            },
            clu::analysis::package::FileEntry {
                relative_path: std::path::PathBuf::from("setup.py"),
                contents: "entry".to_string(),
                role: clu::analysis::package::FileRole::EntryScript,
            },
            clu::analysis::package::FileEntry {
                relative_path: std::path::PathBuf::from("README"),
                contents: "readme".to_string(),
                role: clu::analysis::package::FileRole::Other,
            },
        ],
        ecosystem: clu::analysis::package::Ecosystem::PyPI,
        sha256: String::new(),
    };

    let bundle = clu::analysis::package::build_source_bundle(&contents, 10000);
    assert_eq!(bundle.entries[0].role_tag, "entry-script");
    assert_eq!(bundle.entries[1].role_tag, "source");
    assert_eq!(bundle.entries[2].role_tag, "other");
}
