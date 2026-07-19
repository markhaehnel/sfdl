#![allow(clippy::unwrap_used)]

use sfdl::SfdlFile;

const PASSWORD: &str = "S3cr3tP4ssw0rd!";

fn load_sample(name: &str) -> SfdlFile {
    let path = format!("tests/data/{name}");
    SfdlFile::from_file(&path).unwrap_or_else(|e| panic!("failed to parse {name}: {e}"))
}

fn round_trip(sfdl: &SfdlFile) {
    let mut encrypted = sfdl.clone();
    encrypted.encrypt(PASSWORD).unwrap();
    assert!(encrypted.encrypted);

    let mut decrypted = encrypted.clone();
    decrypted.decrypt(PASSWORD).unwrap();
    assert!(!decrypted.encrypted);

    assert_eq!(decrypted, *sfdl);
}

#[test]
fn single_package_bulkfolder_round_trip() {
    round_trip(&load_sample("single_package_bulkfolder.xml"));
}

#[test]
fn multi_package_bulkfolders_round_trip() {
    round_trip(&load_sample("multi_package_bulkfolders.xml"));
}

#[test]
fn filelist_mode_round_trip() {
    round_trip(&load_sample("filelist_mode.xml"));
}

#[test]
fn mixed_mode_round_trip() {
    round_trip(&load_sample("mixed_mode.xml"));
}

#[test]
fn default_path_is_not_altered_by_encryption() {
    let mut sfdl = load_sample("single_package_bulkfolder.xml");
    let expected = sfdl.connection_info.default_path.clone();

    sfdl.encrypt(PASSWORD).unwrap();

    assert_eq!(sfdl.connection_info.default_path, expected);
}

#[test]
fn wrong_password_returns_decrypt_error() {
    let mut sfdl = load_sample("single_package_bulkfolder.xml");
    sfdl.encrypt(PASSWORD).unwrap();

    let result = sfdl.decrypt("wrong-password");
    assert!(result.is_err());
}

#[test]
fn ciphertext_generated_by_this_crate_decrypts_correctly() {
    let mut encrypted =
        SfdlFile::from_file("tests/data/minimal_encrypted.xml").unwrap_or_else(|e| {
            panic!("failed to parse minimal_encrypted.xml: {e}");
        });
    let expected = load_sample("single_package_bulkfolder.xml");

    encrypted.decrypt(PASSWORD).unwrap();

    assert_eq!(encrypted, expected);
}
