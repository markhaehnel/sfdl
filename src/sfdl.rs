//! SFDL file format parser and writer
//!
//! This module provides functionality to parse, write, encrypt, and decrypt SFDL files.
//!
//! # Overview
//!
//! The SFDL file format is used to describe download packages, including connection information
//! and package details. This module defines the [`SfdlFile`] struct and related types to represent
//! the structure of a SFDL file, and provides methods to read from and write to SFDL files.
//!
//! # Examples
//!
//! ### Reading and parsing a SFDL file
//!
//! Convenience method for reading and parsing a SFDL file from a file.
//!
//! ```rust
//! let sfdl = sfdl::SfdlFile::from_file("examples/encrypted.sfdl").unwrap();
//! ```
//!
//! #### From reader
//!
//! Reading and parsing a SFDL file from a reader.
//!
//! ```rust
//! # use sfdl::SfdlFile;
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
//! # use sfdl::SfdlFile;
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
//! # let mut sfdl = sfdl::SfdlFile::from_file("examples/decrypted.sfdl").unwrap();
//! sfdl.encrypt("S3cr3tP4ssw0rd!").unwrap();
//! ```
//!
//! #### Decryption
//!
//! ```rust
//! # let mut sfdl = sfdl::SfdlFile::from_file("examples/encrypted.sfdl").unwrap();
//! sfdl.decrypt("S3cr3tP4ssw0rd!").unwrap();
//! ```

use std::fmt::Write as FmtWrite;
use std::fs;
use std::io::BufRead;
use std::path::Path;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::crypto;
use crate::error::{ParseError, SfdlError};

const XMLNS_XSD: &str = "http://www.w3.org/2001/XMLSchema";
const XMLNS_XSI: &str = "http://www.w3.org/2001/XMLSchema-instance";

#[allow(clippy::must_use_candidate)]
fn default_xmlns_xsd() -> String {
    XMLNS_XSD.to_string()
}

#[allow(clippy::must_use_candidate)]
fn default_xmlns_xsi() -> String {
    XMLNS_XSI.to_string()
}

/// Top-level SFDL container.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "PascalCase", rename = "SFDLFile")]
pub struct SfdlFile {
    /// XML namespace for XSD schemas.
    #[serde(rename = "@xmlns:xsd", default = "default_xmlns_xsd")]
    pub xmlns_xsd: String,
    /// XML namespace for XSI schemas.
    #[serde(rename = "@xmlns:xsi", default = "default_xmlns_xsi")]
    pub xmlns_xsi: String,
    /// Description of the SFDL container.
    pub description: String,
    /// Uploader of the SFDL container.
    pub uploader: String,
    /// Version of the SFDL file format.
    #[serde(rename = "SFDLFileVersion")]
    pub sfdlfile_version: u16,
    /// Whether the encryptable fields are currently encrypted.
    pub encrypted: bool,
    /// Connection settings for the target server.
    pub connection_info: ConnectionInfo,
    /// List of packages contained in this SFDL file.
    pub packages: Packages,
    /// Maximum number of concurrent download threads.
    pub max_download_threads: u16,
}

/// Connection settings for the server described by the SFDL container.
#[allow(clippy::struct_excessive_bools)]
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct ConnectionInfo {
    /// Server hostname or IP address.
    pub host: String,
    /// Server port.
    pub port: u16,
    /// Username for authentication.
    pub username: String,
    /// Password for authentication.
    pub password: String,
    /// Whether authentication is required.
    pub auth_required: bool,
    /// FTP data connection mode.
    pub data_connection_type: DataConnectionType,
    /// Transfer data type.
    pub data_type: DataType,
    /// Character encoding used by the server.
    pub character_encoding: CharacterEncoding,
    /// Encryption mode for the connection.
    pub encryption_mode: EncryptionMode,
    /// Method used for listing directory contents.
    pub list_method: String,
    /// Default path on the server.
    ///
    /// Note: the reference SFDL implementation leaves this field plaintext.
    pub default_path: String,
    /// Whether to force a single connection.
    pub force_single_connection: bool,
    /// Whether stale data detection is enabled.
    pub data_stale_detection: bool,
    /// Whether special server compatibility mode is enabled.
    pub special_server_mode: bool,
}

/// A list of [`SfdlPackage`] entries.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Default)]
#[serde(rename_all = "PascalCase")]
pub struct Packages {
    /// Package entries.
    #[serde(rename = "SFDLPackage")]
    pub package: Vec<SfdlPackage>,
}

impl std::ops::Deref for Packages {
    type Target = Vec<SfdlPackage>;

    fn deref(&self) -> &Self::Target {
        &self.package
    }
}

impl std::ops::DerefMut for Packages {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.package
    }
}

/// A single download package.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct SfdlPackage {
    /// Package name.
    ///
    /// Note: the XML element is spelled `Packagename`.
    #[serde(rename = "Packagename")]
    pub package_name: String,
    /// Whether this package uses bulk-folder mode.
    pub bulk_folder_mode: bool,
    /// List of bulk folders.
    #[serde(default)]
    pub bulk_folder_list: BulkFolderList,
    /// Optional list of individual files.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_list: Option<FileList>,
}

/// A list of [`BulkFolder`] entries.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Default)]
#[serde(rename_all = "PascalCase")]
pub struct BulkFolderList {
    /// Bulk folder entries.
    #[serde(default)]
    pub bulk_folder: Vec<BulkFolder>,
}

/// A bulk folder inside a package.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct BulkFolder {
    /// Path of the bulk folder on the server.
    pub bulk_folder_path: String,
    /// Package name associated with this bulk folder.
    pub package_name: String,
}

/// A list of [`FileInfo`] entries.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Default)]
#[serde(rename_all = "PascalCase")]
pub struct FileList {
    /// File entries.
    #[serde(default)]
    pub file_info: Vec<FileInfo>,
}

/// Metadata for a single file in a file-list package.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Default)]
#[serde(rename_all = "PascalCase")]
pub struct FileInfo {
    /// Name of the file.
    pub file_name: String,
    /// Root directory of the file.
    pub directory_root: String,
    /// Directory path containing the file.
    pub directory_path: String,
    /// Full path of the file on the server.
    pub file_full_path: String,
    /// Size of the file in bytes.
    pub file_size: u64,
    /// Type of hash used for the file.
    pub file_hash_type: String,
    /// Hash value of the file.
    pub file_hash: String,
    /// Package name this file belongs to.
    pub package_name: String,
}

/// FTP data connection mode.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum DataConnectionType {
    /// Automatically choose passive mode.
    #[serde(rename = "AutoPassive")]
    AutoPassive,
    /// Automatically choose active mode.
    #[serde(rename = "AutoActive")]
    AutoActive,
    /// Use the EPRT command.
    #[serde(rename = "EPRT")]
    EPRT,
    /// Use the EPSV command.
    #[serde(rename = "EPSV")]
    EPSV,
    /// Use passive mode.
    #[serde(rename = "PASV")]
    PASV,
    /// Use extended passive mode.
    #[serde(rename = "PASVEX")]
    PASVEX,
    /// Use the PORT command.
    #[serde(rename = "PORT")]
    PORT,
}

/// Transfer data type.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum DataType {
    /// Binary transfer mode.
    #[serde(rename = "Binary")]
    Binary,
    /// ASCII transfer mode.
    #[serde(rename = "ASCII")]
    ASCII,
}

/// Character encoding used by the target server.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum CharacterEncoding {
    /// Standard encoding.
    #[serde(rename = "Standard")]
    Standard,
    /// UTF-8 encoding.
    #[serde(rename = "UTF8")]
    UTF8,
    /// UTF-7 encoding.
    #[serde(rename = "UTF7")]
    UTF7,
    /// ASCII encoding.
    #[serde(rename = "ASCII")]
    ASCII,
}

/// Connection encryption mode.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum EncryptionMode {
    /// No encryption.
    #[serde(rename = "None")]
    None,
    /// SSL encryption.
    #[serde(rename = "SSL")]
    SSL,
    /// TLS encryption.
    #[serde(rename = "TLS")]
    TLS,
}

impl SfdlFile {
    /// Parse a SFDL file from a reader.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError::InvalidSfdlDeserialize`] if the XML cannot be parsed.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use sfdl::SfdlFile;
    /// # use std::fs;
    /// # use std::io;
    /// let file = fs::File::open("examples/encrypted.sfdl").unwrap();
    /// let reader = io::BufReader::new(file);
    ///
    /// let sfdl = SfdlFile::from_reader(reader).unwrap();
    /// ```
    pub fn from_reader<R>(reader: R) -> Result<Self, ParseError>
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
    /// # Errors
    ///
    /// Returns an error if the file cannot be read or parsed.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use sfdl::SfdlFile;
    /// SfdlFile::from_file("examples/encrypted.sfdl").unwrap();
    /// ```
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, SfdlError> {
        let content = fs::read_to_string(path)?;
        let sfdl: Self = content.parse()?;

        Ok(sfdl)
    }

    /// Encrypt all encryptable fields in the SFDL file.
    ///
    /// This is an atomic operation: if any field fails to encrypt, the file is
    /// left unchanged. On success the [`SfdlFile::encrypted`] flag is set to
    /// `true`.
    ///
    /// # Errors
    ///
    /// Returns [`SfdlError::AlreadyEncrypted`] if the file is already encrypted,
    /// or an encryption error if a field cannot be encrypted.
    pub fn encrypt(&mut self, password: &str) -> Result<(), SfdlError> {
        if self.encrypted {
            return Err(SfdlError::AlreadyEncrypted);
        }

        *self = crypto::encrypt_sfdl(self, password);
        self.encrypted = true;
        Ok(())
    }

    /// Decrypt all decryptable fields in the SFDL file.
    ///
    /// This is an atomic operation: if any field fails to decrypt, the file is
    /// left unchanged. On success the [`SfdlFile::encrypted`] flag is set to
    /// `false`.
    ///
    /// # Errors
    ///
    /// Returns [`SfdlError::NotEncrypted`] if the file is not encrypted,
    /// or a decryption error if the password is wrong or the ciphertext is invalid.
    pub fn decrypt(&mut self, password: &str) -> Result<(), SfdlError> {
        if !self.encrypted {
            return Err(SfdlError::NotEncrypted);
        }

        *self = crypto::decrypt_sfdl(self, password)?;
        self.encrypted = false;
        Ok(())
    }

    /// Serialize this SFDL file into an XML string.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError::InvalidSfdlSerialize`] if serialization fails.
    pub fn to_xml_string(&self) -> Result<String, ParseError> {
        quick_xml::se::to_string(self).map_err(ParseError::InvalidSfdlSerialize)
    }

    /// Serialize this SFDL file as XML into the provided writer.
    ///
    /// The writer must implement [`std::fmt::Write`].
    ///
    /// # Errors
    ///
    /// Returns [`ParseError::InvalidSfdlSerialize`] if serialization fails.
    pub fn to_xml_writer<W: FmtWrite>(&self, writer: W) -> Result<(), ParseError> {
        quick_xml::se::to_writer(writer, self).map_err(ParseError::InvalidSfdlSerialize)?;
        Ok(())
    }

    /// Serialize and write this SFDL file to a file path.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization or writing to the file fails.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use sfdl::SfdlFile;
    /// # let sfdl = SfdlFile::from_file("examples/encrypted.sfdl").unwrap();
    /// sfdl.write("out.sfdl").unwrap();
    /// ```
    pub fn write<P: AsRef<Path>>(&self, path: P) -> Result<(), SfdlError> {
        let content = self.to_xml_string()?;
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
        Self {
            xmlns_xsd: XMLNS_XSD.to_string(),
            xmlns_xsi: XMLNS_XSI.to_string(),
            description: String::new(),
            uploader: String::new(),
            sfdlfile_version: 6,
            encrypted: false,
            connection_info: ConnectionInfo::default(),
            packages: Packages {
                package: vec![SfdlPackage::default()],
            },
            max_download_threads: 3,
        }
    }
}

impl Default for ConnectionInfo {
    fn default() -> Self {
        Self {
            host: String::new(),
            port: 21,
            username: String::new(),
            password: String::new(),
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
        Self {
            package_name: String::new(),
            bulk_folder_mode: true,
            bulk_folder_list: BulkFolderList::default(),
            file_list: None,
        }
    }
}
