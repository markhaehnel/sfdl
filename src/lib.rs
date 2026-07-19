//! A rust crate for parsing, encrypting and decrypting SFDL container files.
//!
//! # Example
//!
//! ```rust
//! use sfdl::SfdlFile;
//!
//! // Reading a SFDL file from a file
//! let mut sfdl = SfdlFile::from_file("examples/decrypted.sfdl").unwrap();
//!
//! // Encrypting the SFDL file
//! sfdl.encrypt("password").unwrap();
//!
//! // Writing the encrypted SFDL file back to a file
//! sfdl.write("encrypted.sfdl").unwrap();
//!
//! // Decrypting the SFDL file
//! sfdl.decrypt("password").unwrap();
//!
//! // Writing the decrypted SFDL file back to a file
//! sfdl.write("decrypted.sfdl").unwrap();
//! ```
//!
//! For detailed information consult the [docs](https://docs.rs/sfdl).
//!
//! # Encrypted fields
//!
//! The crate follows the official `n0ix/SFDL.Container` reference implementation
//! and only encrypts/decrypts the fields the reference handles:
//!
//! - `SFDLFile.Description`
//! - `SFDLFile.Uploader`
//! - `ConnectionInfo.Host`
//! - `ConnectionInfo.Password`
//! - `ConnectionInfo.Username`
//! - `ConnectionInfo.DefaultPath`
//! - Every `SFDLPackage.Packagename`
//! - Every `BulkFolder.BulkFolderPath` and `BulkFolder.PackageName`
//! - Every `FileInfo.DirectoryPath`, `DirectoryRoot`, `FileName`,
//!   `FileFullPath`, and `PackageName` for file-list packages
//!
//! # Cryptographic primitive
//!
//! The SFDL format uses the following primitive, which this crate implements
//! exactly:
//!
//! - AES-128-CBC with PKCS#7 padding.
//! - Key = MD5(password) (password interpreted as UTF-8).
//! - A fresh 16-byte IV per field, prepended to the ciphertext.
//! - IV + ciphertext encoded with standard base64.
//!
//! # Security limitations
//!
//! The format itself has weaknesses that this crate cannot fix:
//!
//! - MD5 key derivation is fast and unsalted. Use strong, unique passwords.
//! - No integrity check (MAC/HMAC/AEAD) is performed, so encrypted containers
//!   are malleable.
//!
//! Encryption and decryption are performed atomically:
//! [`SfdlFile::encrypt`](crate::SfdlFile::encrypt) and
//! [`SfdlFile::decrypt`](crate::SfdlFile::decrypt) only replace the caller's
//! value after the whole operation succeeds, so a wrong password never leaves
//! the struct half changed.
//!
//! # References
//!
//! - [SFDL Container Format](https://github.com/n0ix/SFDL.NET/wiki/How-it-Works-(SFDL-File-documentation))
//! - [SFDL.NET](https://github.com/n0ix/SFDL.NET)
//! - [SFDL.Container .NET implementation](https://github.com/n0ix/SFDL.Container)

pub mod error;
pub mod sfdl;

mod crypto;

pub use crate::error::{DecryptError, EncryptError, ParseError, SfdlError};
pub use crate::sfdl::{
    BulkFolder, BulkFolderList, CharacterEncoding, ConnectionInfo, DataConnectionType, DataType,
    EncryptionMode, FileInfo, FileList, Packages, SfdlFile, SfdlPackage,
};
