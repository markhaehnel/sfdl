//! Cryptographic functions for decrypting and encrypting SFDL files.
//!
//! This module implements the same low-level primitive as the official
//! `n0ix/SFDL.Container` reference implementation:
//!
//! - AES-128-CBC with PKCS#7 padding.
//! - Key = MD5(password). The password bytes are interpreted as UTF-8.
//! - A 16-byte random IV is generated for every field.
//! - The IV is prepended to the ciphertext and the whole blob is base64 encoded.
//!
//! The crate encrypts and decrypts exactly the fields the reference
//! implementation operates on:
//!
//! - `SFDLFile.Description`
//! - `SFDLFile.Uploader`
//! - `ConnectionInfo.Host`
//! - `ConnectionInfo.Password`
//! - `ConnectionInfo.Username`
//! - `ConnectionInfo.DefaultPath`
//! - For every `SFDLPackage`:
//!   - `SFDLPackage.Packagename`
//!   - For every `BulkFolder`:
//!     - `BulkFolder.BulkFolderPath`
//!     - `BulkFolder.PackageName`
//!   - For every `FileInfo` in an optional `FileList`:
//!     - `FileInfo.DirectoryPath`
//!     - `FileInfo.DirectoryRoot`
//!     - `FileInfo.FileName`
//!     - `FileInfo.FileFullPath`
//!     - `FileInfo.PackageName`
//!
//! # Security note
//!
//! The SFDL format itself uses unsalted MD5 key derivation and provides no
//! integrity check (MAC/HMAC/AEAD). This means encrypted containers are
//! malleable and passwords should be strong enough to resist brute-force
//! attacks. These limitations are inherent to the format, not a bug in this
//! crate.
//!
//! # Atomicity
//!
//! `encrypt_sfdl` and `decrypt_sfdl` are pure functions that return a new
//! struct. The public [`SfdlFile::encrypt`](crate::SfdlFile::encrypt)
//! and [`SfdlFile::decrypt`](crate::SfdlFile::decrypt) methods only
//! replace the caller's value after the whole operation succeeds, so a
//! malformed field or wrong password never leaves the object half changed.

use aes::Aes128;
use base64::prelude::BASE64_STANDARD;
use base64::Engine;
use cbc::{Decryptor, Encryptor};
use cipher::block_padding::Pkcs7;
use cipher::{BlockModeDecrypt, BlockModeEncrypt, KeyIvInit};
use rand::prelude::*;

use crate::error::DecryptError;
use crate::sfdl::SfdlFile;

const AES_BLOCK_SIZE: usize = 16;

/// Decrypts a single value using the SFDL AES-128-CBC primitive.
pub fn decrypt_value(encrypted_data: &str, password: &str) -> Result<String, DecryptError> {
    let digest = md5::compute(password.as_bytes());
    let key: &[u8; AES_BLOCK_SIZE] = &digest.0;

    let decoded = BASE64_STANDARD.decode(encrypted_data)?;
    if decoded.len() < AES_BLOCK_SIZE {
        return Err(DecryptError::InvalidCiphertextLength {
            expected: AES_BLOCK_SIZE,
            got: decoded.len(),
        });
    }

    let (iv, ciphertext) = decoded.split_at(AES_BLOCK_SIZE);
    let iv: &[u8; AES_BLOCK_SIZE] =
        iv.try_into()
            .map_err(|_| DecryptError::InvalidCiphertextLength {
                expected: AES_BLOCK_SIZE,
                got: iv.len(),
            })?;

    let decryptor = Decryptor::<Aes128>::new(key.into(), iv.into());
    let decrypted = decryptor
        .decrypt_padded_vec::<Pkcs7>(ciphertext)
        .map_err(|_| DecryptError::InvalidPassword)?;

    Ok(String::from_utf8(decrypted)?)
}

/// Encrypts a single value using the SFDL AES-128-CBC primitive.
///
/// Empty passwords are accepted to match the reference implementation, even
/// though they result in weak encryption.
pub fn encrypt_value(data: &str, password: &str) -> String {
    let digest = md5::compute(password.as_bytes());
    let key: &[u8; AES_BLOCK_SIZE] = &digest.0;

    let iv = rand::rng().random::<[u8; AES_BLOCK_SIZE]>();
    let encryptor = Encryptor::<Aes128>::new(key.into(), (&iv).into());
    let encrypted_data = encryptor.encrypt_padded_vec::<Pkcs7>(data.as_bytes());
    let encrypted_data = [iv.to_vec(), encrypted_data].concat();
    BASE64_STANDARD.encode(&encrypted_data)
}

/// Returns a new [`SfdlFile`] with all decryptable fields decrypted.
///
/// The input is not modified. On error the original value remains unchanged.
pub fn decrypt_sfdl(sfdl: &SfdlFile, password: &str) -> Result<SfdlFile, DecryptError> {
    let mut out = sfdl.clone();
    decrypt_into(&mut out, password)?;
    Ok(out)
}

fn decrypt_into(sfdl: &mut SfdlFile, password: &str) -> Result<(), DecryptError> {
    sfdl.description = decrypt_value(&sfdl.description, password)?;
    sfdl.uploader = decrypt_value(&sfdl.uploader, password)?;
    sfdl.connection_info.host = decrypt_value(&sfdl.connection_info.host, password)?;
    sfdl.connection_info.password = decrypt_value(&sfdl.connection_info.password, password)?;
    sfdl.connection_info.username = decrypt_value(&sfdl.connection_info.username, password)?;
    sfdl.connection_info.default_path =
        decrypt_value(&sfdl.connection_info.default_path, password)?;

    for pkg in sfdl.packages.iter_mut() {
        pkg.package_name = decrypt_value(&pkg.package_name, password)?;

        for folder in &mut pkg.bulk_folder_list.bulk_folder {
            folder.bulk_folder_path = decrypt_value(&folder.bulk_folder_path, password)?;
            folder.package_name = decrypt_value(&folder.package_name, password)?;
        }

        if let Some(file_list) = pkg.file_list.as_mut() {
            for file in &mut file_list.file_info {
                file.directory_path = decrypt_value(&file.directory_path, password)?;
                file.directory_root = decrypt_value(&file.directory_root, password)?;
                file.file_name = decrypt_value(&file.file_name, password)?;
                file.file_full_path = decrypt_value(&file.file_full_path, password)?;
                file.package_name = decrypt_value(&file.package_name, password)?;
            }
        }
    }

    Ok(())
}

/// Returns a new [`SfdlFile`] with all encryptable fields encrypted.
///
/// The input is not modified.
pub fn encrypt_sfdl(sfdl: &SfdlFile, password: &str) -> SfdlFile {
    let mut out = sfdl.clone();
    encrypt_into(&mut out, password);
    out
}

fn encrypt_into(sfdl: &mut SfdlFile, password: &str) {
    sfdl.description = encrypt_value(&sfdl.description, password);
    sfdl.uploader = encrypt_value(&sfdl.uploader, password);
    sfdl.connection_info.host = encrypt_value(&sfdl.connection_info.host, password);
    sfdl.connection_info.password = encrypt_value(&sfdl.connection_info.password, password);
    sfdl.connection_info.username = encrypt_value(&sfdl.connection_info.username, password);
    sfdl.connection_info.default_path = encrypt_value(&sfdl.connection_info.default_path, password);

    for pkg in sfdl.packages.iter_mut() {
        pkg.package_name = encrypt_value(&pkg.package_name, password);

        for folder in &mut pkg.bulk_folder_list.bulk_folder {
            folder.bulk_folder_path = encrypt_value(&folder.bulk_folder_path, password);
            folder.package_name = encrypt_value(&folder.package_name, password);
        }

        if let Some(file_list) = pkg.file_list.as_mut() {
            for file in &mut file_list.file_info {
                file.directory_path = encrypt_value(&file.directory_path, password);
                file.directory_root = encrypt_value(&file.directory_root, password);
                file.file_name = encrypt_value(&file.file_name, password);
                file.file_full_path = encrypt_value(&file.file_full_path, password);
                file.package_name = encrypt_value(&file.package_name, password);
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::collections::HashMap;

    use crate::sfdl::{
        BulkFolder, BulkFolderList, ConnectionInfo, FileInfo, FileList, Packages, SfdlPackage,
    };

    use super::*;

    #[test]
    fn test_decrypt_entry() {
        let password = "S3cr3tP4ssw0rd!";
        let inputs = HashMap::from([
            (
                "MyTestString1",
                "IUi2KzSjpWJzhlu3BcUs3dqJYPAHTnaafyPhSVYn20I=",
            ),
            ("测试", "2BGA0PtZYUiRzjNnIf3gT+sV6hJZdaCVGkYbpwn4rX0="),
            ("", "HDI9t7x0lXH2AxfTAEpp/jYR9ZGnu0O0GWSXIT3dr1M="),
            ("\n", "4MScCSj3jZW2Ruw2FVOh5Kts+mH2VP6A1EWZqmb5sGA="),
            ("🧪", "bcl/lIYMP3wCvyRr+7jGi+89j55uUmpA0vbFnK6xMbc="),
        ]);

        for (plain, encrypted_data) in inputs {
            let decrypted_data = decrypt_value(encrypted_data, password).unwrap();
            assert_eq!(decrypted_data, plain);
        }
    }

    #[test]
    fn test_decrypt_entry_short_ciphertext() {
        let encrypted_data = "YQ=="; // base64("a") -> 1 byte
        let decrypted_data = decrypt_value(encrypted_data, "S3cr3tP4ssw0rd!");
        assert_eq!(
            decrypted_data,
            Err(DecryptError::InvalidCiphertextLength {
                expected: AES_BLOCK_SIZE,
                got: 1,
            })
        );
    }

    #[test]
    fn test_decrypt_entry_invalid_data_length() {
        let encrypted_data = "a";
        let decrypted_data = decrypt_value(encrypted_data, "S3cr3tP4ssw0rd!");
        assert_eq!(
            decrypted_data.err(),
            Some(DecryptError::InvalidData(
                base64::DecodeError::InvalidLength(1)
            ))
        );
    }

    #[test]
    fn test_decrypt_entry_invalid_data_bytes() {
        let encrypted_data = "invalid-data";
        let decrypted_data = decrypt_value(encrypted_data, "S3cr3tP4ssw0rd!");
        assert_eq!(
            decrypted_data.err(),
            Some(DecryptError::InvalidData(base64::DecodeError::InvalidByte(
                7, 45
            )))
        );
    }

    #[test]
    fn test_decrypt_entry_invalid_password() {
        let encrypted_data = "I604rDsXlmAwgdE224k3soM3r6CiSa7YuD5biEJipXY=";
        let decrypted_data = decrypt_value(encrypted_data, "invalid-password");
        assert_eq!(decrypted_data.err(), Some(DecryptError::InvalidPassword));
    }

    #[test]
    fn test_encrypt_entry() {
        let password = "S3cr3tP4ssw0rd!";
        let inputs = vec!["MyTestString1", "测试", "", "\n", "🧪"];

        for input in inputs {
            let encrypted_data = encrypt_value(input, password);
            let decrypted_data = decrypt_value(encrypted_data.as_str(), password).unwrap();

            assert_eq!(decrypted_data, input);
        }
    }

    #[test]
    fn test_encrypt_entry_empty_password() {
        let encrypted_data = encrypt_value("MyTestString1", "");
        let decrypted_data = decrypt_value(&encrypted_data, "").unwrap();
        assert_eq!(decrypted_data, "MyTestString1");
    }

    fn sample_sfdl() -> SfdlFile {
        SfdlFile {
            description: "MyDescription".to_string(),
            uploader: "MyUploader".to_string(),
            encrypted: true,
            connection_info: ConnectionInfo {
                host: "MyHost".to_string(),
                password: "MyPassword".to_string(),
                username: "MyUsername".to_string(),
                default_path: "MyDefaultPath".to_string(),
                ..Default::default()
            },
            packages: Packages {
                package: vec![SfdlPackage {
                    package_name: "MyPackageName".to_string(),
                    bulk_folder_list: BulkFolderList {
                        bulk_folder: vec![BulkFolder {
                            bulk_folder_path: "MyBulkFolderPath".to_string(),
                            package_name: "MyBulkFolderPackage".to_string(),
                        }],
                    },
                    ..Default::default()
                }],
            },
            ..Default::default()
        }
    }

    #[test]
    fn test_encrypt_sfdl() {
        let password = "S3cr3tP4ssw0rd!";
        let sfdl = sample_sfdl();

        let encrypted = encrypt_sfdl(&sfdl, password);

        assert_ne!(encrypted.description, sfdl.description);
        assert_ne!(encrypted.uploader, sfdl.uploader);
        assert_ne!(encrypted.connection_info.host, sfdl.connection_info.host);
        assert_ne!(
            encrypted.connection_info.password,
            sfdl.connection_info.password
        );
        assert_ne!(
            encrypted.connection_info.username,
            sfdl.connection_info.username
        );
        // DefaultPath must be encrypted.
        assert_ne!(
            encrypted.connection_info.default_path,
            sfdl.connection_info.default_path
        );
        assert_ne!(
            encrypted.packages[0].bulk_folder_list.bulk_folder[0].bulk_folder_path,
            sfdl.packages[0].bulk_folder_list.bulk_folder[0].bulk_folder_path
        );
        assert_ne!(
            encrypted.packages[0].bulk_folder_list.bulk_folder[0].package_name,
            sfdl.packages[0].bulk_folder_list.bulk_folder[0].package_name
        );
    }

    #[test]
    fn test_decrypt_sfdl() {
        let password = "S3cr3tP4ssw0rd!";
        let sfdl = sample_sfdl();

        let encrypted = encrypt_sfdl(&sfdl, password);
        let decrypted = decrypt_sfdl(&encrypted, password).unwrap();

        assert_eq!(decrypted, sfdl);
    }

    #[test]
    fn test_round_trip_multiple_packages_and_bulk_folders() {
        let password = "S3cr3tP4ssw0rd!";
        let sfdl = SfdlFile {
            description: "Desc".to_string(),
            uploader: "Uploader".to_string(),
            encrypted: true,
            connection_info: ConnectionInfo {
                host: "host1".to_string(),
                username: "user1".to_string(),
                password: "pass1".to_string(),
                default_path: "/default".to_string(),
                ..Default::default()
            },
            packages: Packages {
                package: vec![
                    SfdlPackage {
                        package_name: "PkgA".to_string(),
                        bulk_folder_list: BulkFolderList {
                            bulk_folder: vec![
                                BulkFolder {
                                    bulk_folder_path: "/a/1".to_string(),
                                    package_name: "PkgA".to_string(),
                                },
                                BulkFolder {
                                    bulk_folder_path: "/a/2".to_string(),
                                    package_name: "PkgA".to_string(),
                                },
                            ],
                        },
                        ..Default::default()
                    },
                    SfdlPackage {
                        package_name: "PkgB".to_string(),
                        bulk_folder_list: BulkFolderList {
                            bulk_folder: vec![BulkFolder {
                                bulk_folder_path: "/b".to_string(),
                                package_name: "PkgB".to_string(),
                            }],
                        },
                        ..Default::default()
                    },
                ],
            },
            ..Default::default()
        };

        let decrypted = decrypt_sfdl(&encrypt_sfdl(&sfdl, password), password).unwrap();
        assert_eq!(decrypted, sfdl);
    }

    #[test]
    fn test_round_trip_file_list() {
        let password = "S3cr3tP4ssw0rd!";
        let sfdl = SfdlFile {
            description: "FileListDesc".to_string(),
            uploader: "Uploader".to_string(),
            encrypted: true,
            connection_info: ConnectionInfo {
                host: "host".to_string(),
                username: "user".to_string(),
                password: "pass".to_string(),
                default_path: "/".to_string(),
                ..Default::default()
            },
            packages: Packages {
                package: vec![SfdlPackage {
                    package_name: "ListPkg".to_string(),
                    bulk_folder_mode: false,
                    bulk_folder_list: BulkFolderList::default(),
                    file_list: Some(FileList {
                        file_info: vec![
                            FileInfo {
                                file_name: "a.txt".to_string(),
                                directory_root: "/root".to_string(),
                                directory_path: "/root/dir".to_string(),
                                file_full_path: "/root/dir/a.txt".to_string(),
                                file_size: 100,
                                file_hash_type: "MD5".to_string(),
                                file_hash: "abc".to_string(),
                                package_name: "ListPkg".to_string(),
                            },
                            FileInfo {
                                file_name: "b.bin".to_string(),
                                directory_root: "/root".to_string(),
                                directory_path: "/root/dir".to_string(),
                                file_full_path: "/root/dir/b.bin".to_string(),
                                file_size: 200,
                                file_hash_type: "MD5".to_string(),
                                file_hash: "def".to_string(),
                                package_name: "ListPkg".to_string(),
                            },
                        ],
                    }),
                }],
            },
            ..Default::default()
        };

        let decrypted = decrypt_sfdl(&encrypt_sfdl(&sfdl, password), password).unwrap();
        assert_eq!(decrypted, sfdl);
    }
}
