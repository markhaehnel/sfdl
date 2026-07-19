//! Error types for io, parsing, encrypting and decrypting SFDL files.

use thiserror::Error;

/// Error returned when encrypting an SFDL value fails.
#[derive(Error, Debug, PartialEq, Eq)]
pub enum EncryptError {
    /// Base64 decoding of the input failed.
    #[error("invalid data")]
    InvalidData(#[from] base64::DecodeError),
    /// The decrypted bytes are not valid UTF-8.
    #[error("invalid encoding, expected utf-8")]
    InvalidEncoding(#[from] std::string::FromUtf8Error),
    /// An unexpected encryption error occurred.
    #[error("unknown encryption error")]
    Unknown,
}

/// Error returned when decrypting an SFDL value fails.
#[derive(Error, Debug, PartialEq, Eq)]
pub enum DecryptError {
    /// Base64 decoding of the ciphertext failed.
    #[error("invalid data")]
    InvalidData(#[from] base64::DecodeError),
    /// The decrypted bytes are not valid UTF-8.
    #[error("invalid encoding, expected utf-8")]
    InvalidEncoding(#[from] std::string::FromUtf8Error),
    /// The ciphertext is too short to contain an IV.
    #[error("invalid ciphertext length: expected at least {expected} bytes, got {got}")]
    InvalidCiphertextLength {
        /// Expected minimum length in bytes.
        expected: usize,
        /// Actual length in bytes.
        got: usize,
    },
    /// The password is wrong or the ciphertext has been tampered with.
    #[error("invalid password")]
    InvalidPassword,
    /// An unexpected decryption error occurred.
    #[error("unknown decryption error")]
    Unknown,
}

/// Error returned when parsing or serializing SFDL XML fails.
#[derive(Error, Debug)]
pub enum ParseError {
    /// Deserializing the XML into an [`SfdlFile`](crate::SfdlFile) failed.
    #[error("invalid xml deserialize")]
    InvalidSfdlDeserialize(#[from] quick_xml::DeError),
    /// Serializing the [`SfdlFile`](crate::SfdlFile) into XML failed.
    #[error("invalid xml serialize")]
    InvalidSfdlSerialize(#[from] quick_xml::SeError),
}

/// Top-level error type for operations on SFDL files.
#[derive(Error, Debug)]
pub enum SfdlError {
    /// Encryption error.
    #[error("encryption error")]
    Encrypt(#[from] EncryptError),
    /// Decryption error.
    #[error("decryption error")]
    Decrypt(#[from] DecryptError),
    /// XML parsing or serialization error.
    #[error("parsing error")]
    Parse(#[from] ParseError),
    /// File system I/O error.
    #[error("io error")]
    Io(#[from] std::io::Error),
    /// The SFDL file is already encrypted.
    #[error("already encrypted")]
    AlreadyEncrypted,
    /// The SFDL file is not encrypted.
    #[error("not encrypted")]
    NotEncrypted,
}
