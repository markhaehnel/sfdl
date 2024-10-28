//! SFDL file format parser and writer
//!
//! This module provides functionality to parse, write, encrypt, and decrypt SFDL files.
//!
//! # Overview
//!
//! The SFDL file format is used to describe download packages, including connection information
//! and package details. This module defines the `SfdlFile` struct and related types to represent
//! the structure of a SFDL file, and provides methods to read from and write to SFDL files.
//!
//! # Examples
//!
//! ### Reading and parsing a SFDL file
//!
//! Convenience method for reading and parsing a SFDL file from a file.
//!
//! ```rust
//! let sfdl = sfdl::sfdl::SfdlFile::from_file("examples/encrypted.sfdl").unwrap();
//! ```
//!
//! #### From reader
//!
//! Reading and parsing a SFDL file from a reader.
//!
//! ```rust
//! # use sfdl::sfdl::SfdlFile;
//! let file = std::fs::File::open("examples/encrypted.sfdl").unwrap();
//! let reader = std::io::BufReader::new(file);
//!
//! let sfdl = SfdlFile::from_reader(reader).unwrap();
//! ```
//!
//! #### From string
//!
//! It's also possible to parse a SFDL file from a string.
//!
//! ```rust
//! # use sfdl::sfdl::SfdlFile;
//! # let string_contents = std::fs::read_to_string("examples/encrypted.sfdl").unwrap();
//! let sfdl: SfdlFile = string_contents.parse().unwrap();
//! ```
//!
//! ### Encryption and Decryption
//!
//! #### Encryption
//!
//! Encrypts and decrypts sfdl values using AES-128-CBC with PKCS7 padding.
//! Passwords are hashed using MD5 and used as the encryption key.
//!
//! ```rust
//! # let mut sfdl = sfdl::sfdl::SfdlFile::from_file("examples/decrypted.sfdl").unwrap();
//! sfdl.encrypt("S3cr3tP4ssw0rd!").unwrap();
//! ```
//!
//! #### Decryption
//!
//! ```rust
//! # let mut sfdl = sfdl::sfdl::SfdlFile::from_file("examples/encrypted.sfdl").unwrap();
//! sfdl.decrypt("S3cr3tP4ssw0rd!").unwrap();
//! ```

use std::{fs, io::BufRead, path::Path, str::FromStr};

use serde::{Deserialize, Serialize};

use crate::{
    crypto,
    error::{ParseError, SfdlError},
};

pub fn default_xmlns_xsd() -> String {
    "http://www.w3.org/2001/XMLSchema".to_string()
}

pub fn default_xmlns_xsi() -> String {
    "http://www.w3.org/2001/XMLSchema-instance".to_string()
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename = "SFDLFile")]
pub struct SfdlFile {
    #[serde(rename = "@xmlns:xsd", default = "default_xmlns_xsd")]
    pub xmlns_xsd: String,
    #[serde(rename = "@xmlns:xsi", default = "default_xmlns_xsi")]
    pub xmlns_xsi: String,
    #[serde(rename = "Description")]
    pub description: String,
    #[serde(rename = "Uploader")]
    pub uploader: String,
    #[serde(rename = "SFDLFileVersion")]
    pub sfdlfile_version: u16,
    #[serde(rename = "Encrypted")]
    pub encrypted: bool,
    #[serde(rename = "ConnectionInfo")]
    pub connection_info: ConnectionInfo,
    #[serde(rename = "Packages")]
    pub packages: Vec<Package>,
    #[serde(rename = "MaxDownloadThreads")]
    pub max_download_threads: u16,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ConnectionInfo {
    #[serde(rename = "Host")]
    pub host: String,
    #[serde(rename = "Port")]
    pub port: u16,
    #[serde(rename = "Username")]
    pub username: String,
    #[serde(rename = "Password")]
    pub password: String,
    #[serde(rename = "AuthRequired")]
    pub auth_required: bool,
    #[serde(rename = "DataConnectionType")]
    pub data_connection_type: DataConnectionType,
    #[serde(rename = "DataType")]
    pub data_type: DataType,
    #[serde(rename = "CharacterEncoding")]
    pub character_encoding: CharacterEncoding,
    #[serde(rename = "EncryptionMode")]
    pub encryption_mode: EncryptionMode,
    #[serde(rename = "ListMethod")]
    pub list_method: String,
    #[serde(rename = "DefaultPath")]
    pub default_path: String,
    #[serde(rename = "ForceSingleConnection")]
    pub force_single_connection: bool,
    #[serde(rename = "DataStaleDetection")]
    pub data_stale_detection: bool,
    #[serde(rename = "SpecialServerMode")]
    pub special_server_mode: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Package {
    #[serde(rename = "SFDLPackage")]
    pub sfdl_package: SfdlPackage,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SfdlPackage {
    #[serde(rename = "Packagename")]
    pub package_name: String,
    #[serde(rename = "BulkFolderMode")]
    pub bulk_folder_mode: bool,
    #[serde(rename = "BulkFolderList")]
    pub bulk_folder_list: BulkFolderList,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BulkFolderList {
    #[serde(rename = "BulkFolder")]
    pub bulk_folder: BulkFolder,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BulkFolder {
    #[serde(rename = "BulkFolderPath")]
    pub bulk_folder_path: String,
    #[serde(rename = "PackageName")]
    pub package_name: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum DataConnectionType {
    // AutoPassive, AutoActive, EPRT, EPSV, PASV, PASVEX, PORT
    AutoPassive,
    AutoActive,
    EPRT,
    EPSV,
    PASV,
    PASVEX,
    PORT,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum DataType {
    Binary,
    ASCII,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum CharacterEncoding {
    Standard,
    UTF8,
    UTF7,
    ASCII,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum EncryptionMode {
    None,
    SSL,
    TLS,
}

impl SfdlFile {
    /// Parse a SFDL file from a reader.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use sfdl::sfdl::SfdlFile;
    /// # use std::fs;
    /// # use std::io;
    /// let file = fs::File::open("examples/encrypted.sfdl").unwrap();
    /// let reader = io::BufReader::new(file);
    ///
    /// let sfdl = SfdlFile::from_reader(reader).unwrap();
    /// ```
    pub fn from_reader<R>(reader: R) -> Result<SfdlFile, ParseError>
    where
        R: BufRead,
    {
        quick_xml::de::from_reader(reader).map_err(ParseError::InvalidSfdlDeserialize)
    }

    /// Read a file from a string.
    ///
    /// This is a convenience function for using [`fs::read_to_string`]
    /// with fewer imports.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use sfdl::sfdl::SfdlFile;
    /// SfdlFile::from_file("examples/encrypted.sfdl").unwrap();
    /// ```
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<SfdlFile, SfdlError> {
        let content = fs::read_to_string(path)?;
        let sfdl: SfdlFile = content.parse()?;

        Ok(sfdl)
    }

    pub fn encrypt(&mut self, password: &str) -> Result<(), SfdlError> {
        if self.encrypted {
            return Err(SfdlError::AlreadyEncrypted);
        }

        crypto::encrypt_sfdl(self, password).unwrap();
        self.encrypted = true;
        Ok(())
    }

    pub fn decrypt(&mut self, password: &str) -> Result<(), SfdlError> {
        if !self.encrypted {
            return Err(SfdlError::NotEncrypted);
        }

        crypto::decrypt_sfdl(self, password)?;
        self.encrypted = false;
        Ok(())
    }

    pub fn write<P: AsRef<Path>>(&self, path: P) -> Result<(), SfdlError> {
        let content = quick_xml::se::to_string(self).map_err(ParseError::InvalidSfdlSerialize)?;
        fs::write(path, content)?;

        Ok(())
    }
}

impl FromStr for SfdlFile {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        quick_xml::de::from_str(s).map_err(ParseError::InvalidSfdlDeserialize)
    }
}

impl Default for SfdlFile {
    fn default() -> Self {
        SfdlFile {
            xmlns_xsd: default_xmlns_xsd(),
            xmlns_xsi: default_xmlns_xsi(),
            description: "".to_string(),
            uploader: "".to_string(),
            sfdlfile_version: 6,
            encrypted: false,
            connection_info: ConnectionInfo {
                ..Default::default()
            },
            packages: vec![Package {
                sfdl_package: SfdlPackage {
                    ..Default::default()
                },
            }],
            max_download_threads: 3,
        }
    }
}

impl Default for ConnectionInfo {
    fn default() -> Self {
        ConnectionInfo {
            host: "".to_string(),
            port: 21,
            username: "".to_string(),
            password: "".to_string(),
            auth_required: false,
            data_connection_type: DataConnectionType::AutoPassive,
            data_type: DataType::Binary,
            character_encoding: CharacterEncoding::Standard,
            encryption_mode: EncryptionMode::None,
            list_method: "ForceList".to_string(),
            default_path: "/".to_string(),
            force_single_connection: false,
            data_stale_detection: true,
            special_server_mode: false,
        }
    }
}

impl Default for SfdlPackage {
    fn default() -> Self {
        SfdlPackage {
            package_name: "".to_string(),
            bulk_folder_mode: true,
            bulk_folder_list: BulkFolderList {
                bulk_folder: BulkFolder {
                    bulk_folder_path: "".to_string(),
                    package_name: "".to_string(),
                },
            },
        }
    }
}
