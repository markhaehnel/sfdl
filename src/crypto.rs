//! Cryptographic functions for decrypting and encrypting SFDL files.

use aes::Aes128;
use base64::prelude::BASE64_STANDARD;
use base64::Engine;
use cbc::{Decryptor, Encryptor};
use cipher::block_padding::Pkcs7;
use cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use rand::prelude::*;

use crate::error::{DecryptError, EncryptError};
use crate::sfdl::SfdlFile;

/// Decrypts a value using AES-128-CBC with PKCS7 padding. The password is hashed using MD5 and used as the encryption key.
pub(crate) fn decrypt_value(encrypted_data: &str, password: &str) -> Result<String, DecryptError> {
    let digest = md5::compute(password);
    let key = digest.as_slice();

    let decoded = BASE64_STANDARD.decode(encrypted_data)?;
    let (iv, encrypted_data) = decoded.split_at(16);
    let decryptor = Decryptor::<Aes128>::new(key.into(), iv.into());

    let decrypted = decryptor
        .decrypt_padded_vec_mut::<Pkcs7>(encrypted_data)
        .map_err(|_| DecryptError::InvalidPassword)?;

    Ok(String::from_utf8(decrypted)?)
}

/// Encrypts a value using AES-128-CBC with PKCS7 padding. The password is hashed using MD5 and used as the encryption key.
pub(crate) fn encrypt_value(data: &str, password: &str) -> Result<String, EncryptError> {
    if password.is_empty() {
        return Err(EncryptError::EmptyPassword);
    }

    let digest = md5::compute(password.as_bytes());
    let key = digest.as_slice();

    let iv = rand::rng().random::<[u8; 16]>();
    let encryptor = Encryptor::<Aes128>::new(key.into(), &iv.into());
    let encrypted_data = encryptor.encrypt_padded_vec_mut::<Pkcs7>(data.as_bytes());
    let encrypted_data = [iv.to_vec(), encrypted_data].concat();
    Ok(BASE64_STANDARD.encode(&encrypted_data))
}

/// Decrypts all encrypted values in a SFDL file.
pub(crate) fn decrypt_sfdl(sfdl: &mut SfdlFile, password: &str) -> Result<(), DecryptError> {
    sfdl.description = decrypt_value(sfdl.description.as_str(), password)?;
    sfdl.uploader = decrypt_value(sfdl.uploader.as_str(), password)?;
    sfdl.connection_info.host = decrypt_value(sfdl.connection_info.host.as_str(), password)?;
    sfdl.connection_info.password =
        decrypt_value(sfdl.connection_info.password.as_str(), password)?;
    sfdl.connection_info.username =
        decrypt_value(sfdl.connection_info.username.as_str(), password)?;
    sfdl.connection_info.default_path =
        decrypt_value(sfdl.connection_info.default_path.as_str(), password)?;
    sfdl.packages[0]
        .sfdl_package
        .bulk_folder_list
        .bulk_folder
        .bulk_folder_path = decrypt_value(
        sfdl.packages[0]
            .sfdl_package
            .bulk_folder_list
            .bulk_folder
            .bulk_folder_path
            .as_str(),
        password,
    )?;
    sfdl.packages[0]
        .sfdl_package
        .bulk_folder_list
        .bulk_folder
        .package_name = decrypt_value(
        sfdl.packages[0]
            .sfdl_package
            .bulk_folder_list
            .bulk_folder
            .package_name
            .as_str(),
        password,
    )?;

    Ok(())
}

/// Encrypts all sensitive values in a SFDL file.
pub(crate) fn encrypt_sfdl(sfdl: &mut SfdlFile, password: &str) -> Result<(), EncryptError> {
    sfdl.description = encrypt_value(sfdl.description.as_str(), password)?;
    sfdl.uploader = encrypt_value(sfdl.uploader.as_str(), password)?;
    sfdl.connection_info.host = encrypt_value(sfdl.connection_info.host.as_str(), password)?;
    sfdl.connection_info.password =
        encrypt_value(sfdl.connection_info.password.as_str(), password)?;
    sfdl.connection_info.username =
        encrypt_value(sfdl.connection_info.username.as_str(), password)?;
    sfdl.connection_info.default_path =
        encrypt_value(sfdl.connection_info.default_path.as_str(), password)?;
    sfdl.packages[0]
        .sfdl_package
        .bulk_folder_list
        .bulk_folder
        .bulk_folder_path = encrypt_value(
        sfdl.packages[0]
            .sfdl_package
            .bulk_folder_list
            .bulk_folder
            .bulk_folder_path
            .as_str(),
        password,
    )?;
    sfdl.packages[0]
        .sfdl_package
        .bulk_folder_list
        .bulk_folder
        .package_name = encrypt_value(
        sfdl.packages[0]
            .sfdl_package
            .bulk_folder_list
            .bulk_folder
            .package_name
            .as_str(),
        password,
    )?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use crate::sfdl::{BulkFolder, BulkFolderList, ConnectionInfo, Package, SfdlPackage};

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
            let encrypted_data = encrypt_value(input, password).unwrap();
            let decrypted_data = decrypt_value(encrypted_data.as_str(), password).unwrap();

            assert_eq!(decrypted_data, input);
        }
    }

    #[test]
    fn test_encrypt_entry_empty_password() {
        let encrypted_data = encrypt_value("MyTestString1", "").err();
        assert_eq!(encrypted_data, Some(EncryptError::EmptyPassword));
    }

    #[test]
    fn test_encrypt_sfdl() {
        let password = "S3cr3tP4ssw0rd!";

        let mut sfdl = SfdlFile {
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
            packages: vec![Package {
                sfdl_package: SfdlPackage {
                    bulk_folder_list: BulkFolderList {
                        bulk_folder: BulkFolder {
                            bulk_folder_path: "MyBulkFolderPath".to_string(),
                            package_name: "MyPackageName".to_string(),
                        },
                    },
                    ..Default::default()
                },
            }],
            ..Default::default()
        };

        let sfdl_clone = sfdl.clone();

        encrypt_sfdl(&mut sfdl, password).unwrap();

        assert_ne!(sfdl.description, sfdl_clone.description);
        assert_ne!(sfdl.uploader, sfdl_clone.uploader);
        assert_ne!(sfdl.connection_info.host, sfdl_clone.connection_info.host);
        assert_ne!(
            sfdl.connection_info.password,
            sfdl_clone.connection_info.password
        );
        assert_ne!(
            sfdl.connection_info.username,
            sfdl_clone.connection_info.username
        );
        assert_ne!(
            sfdl.connection_info.default_path,
            sfdl_clone.connection_info.default_path
        );
        assert_ne!(
            sfdl.packages[0]
                .sfdl_package
                .bulk_folder_list
                .bulk_folder
                .bulk_folder_path,
            sfdl_clone.packages[0]
                .sfdl_package
                .bulk_folder_list
                .bulk_folder
                .bulk_folder_path
        );
        assert_ne!(
            sfdl.packages[0]
                .sfdl_package
                .bulk_folder_list
                .bulk_folder
                .package_name,
            sfdl_clone.packages[0]
                .sfdl_package
                .bulk_folder_list
                .bulk_folder
                .package_name
        );

        decrypt_sfdl(&mut sfdl, password).unwrap();

        assert_eq!(sfdl.description, sfdl_clone.description);
    }

    #[test]
    fn test_decrypt_sfdl() {
        let password = "S3cr3tP4ssw0rd!";

        let mut sfdl = SfdlFile {
            description: "XzfqqoMjo1SmIOjtmZNLHXrF490d2n6lg+gTkRgCKoE=".to_string(),
            uploader: "9UOvz1YkIDBCYa0QICNyHg3jl9WNcI6qxCP0C/hGVOk=".to_string(),
            encrypted: true,
            connection_info: ConnectionInfo {
                host: "7KWh4OBnP4Jsef/L6IQLs+vdmeuqx0SdOUjcekxGeQk=".to_string(),
                username: "LwSvdBsjAOsb1LSK6SzJanRrAtAZrRitDEmKte6RJqo=".to_string(),
                password: "GBIBRNcq6XIkcN5DSUWpo6nlkdjdXTjQdTvA1y1ZCSc=".to_string(),
                default_path: "QLXmGG+Q45RX2dH4RVmzApj155uMQoMsSBdaZJQ2Z6Q=".to_string(),
                ..Default::default()
            },
            packages: vec![Package {
                sfdl_package: SfdlPackage {
                    bulk_folder_list: BulkFolderList {
                        bulk_folder: BulkFolder {
                            bulk_folder_path:
                                "u8TayXwCs5dvXGfT45eTfGdkWDVp3NZLC5/bQ+7foM4vdqWhK36gzA1TLsZzSea9"
                                    .to_string(),
                            package_name: "fFbUrccronJv4nif7AnQr2b5CpePeafFT4dbzV+yvpU="
                                .to_string(),
                        },
                    },
                    ..Default::default()
                },
            }],
            ..Default::default()
        };

        decrypt_sfdl(&mut sfdl, password).unwrap();

        assert_eq!(sfdl.description, "MyDescription");
        assert_eq!(sfdl.uploader, "MyUploader");
        assert_eq!(sfdl.connection_info.host, "MyHost");
        assert_eq!(sfdl.connection_info.username, "MyUsername");
        assert_eq!(sfdl.connection_info.password, "MyPassword");
        assert_eq!(sfdl.connection_info.default_path, "MyDefaultPath");
        assert_eq!(
            sfdl.packages[0]
                .sfdl_package
                .bulk_folder_list
                .bulk_folder
                .bulk_folder_path,
            "MyBulkFolderPath"
        );
        assert_eq!(
            sfdl.packages[0]
                .sfdl_package
                .bulk_folder_list
                .bulk_folder
                .package_name,
            "MyPackageName"
        );
    }
}
