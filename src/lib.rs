//! A rust crate for parsing, encrypting and decrypting SFDL container files.
//!
//! # Example
//!
//! ```rust
//! # use sfdl::sfdl::SfdlFile;
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
//! # References
//!
//! - [SFDL Container Format](https://github.com/n0ix/SFDL.NET/wiki/How-it-Works-(SFDL-File-documentation))
//! - [SFDL.NET](https://github.com/n0ix/SFDL.NET)
//! - [SFDL.Container .NET implementation](https://github.com/n0ix/SFDL.Container)

pub mod crypto;
pub mod error;
pub mod sfdl;
