//! Error types for io, parsing, encrypting and decrypting SFDL files

use thiserror::Error;

#[derive(Error, Debug, PartialEq)]
pub enum EncryptError {
    #[error("invalid data")]
    InvalidData(#[from] base64::DecodeError),
    #[error("invalid encoding, expected utf-8")]
    InvalidEncoding(#[from] std::string::FromUtf8Error),
    #[error("empty password")]
    EmptyPassword,
    #[error("unknown encyption error")]
    Unknown,
}

#[derive(Error, Debug, PartialEq)]
pub enum DecryptError {
    #[error("invalid data")]
    InvalidData(#[from] base64::DecodeError),
    #[error("invalid encoding, expected utf-8")]
    InvalidEncoding(#[from] std::string::FromUtf8Error),
    #[error("invalid password")]
    InvalidPassword,
    #[error("unknown decryption error")]
    Unknown,
}

#[derive(Error, Debug)]
pub enum ParseError {
    #[error("invalid xml deserialize")]
    InvalidSfdlDeserialize(#[from] quick_xml::DeError),
    #[error("invalid xml seriale")]
    InvalidSfdlSerialize(#[from] quick_xml::SeError),
}

#[derive(Error, Debug)]
pub enum SfdlError {
    #[error("encryption error")]
    Encrypt(#[from] EncryptError),
    #[error("decryption error")]
    Decrypt(#[from] DecryptError),
    #[error("parsing error")]
    Parse(#[from] ParseError),
    #[error("io error")]
    Io(#[from] std::io::Error),
    #[error("already encrypted")]
    AlreadyEncrypted,
    #[error("not encrypted")]
    NotEncrypted,
}
