<!-- THIS FILE IS GENERATED. USE `cargo readme > README.md` TO REGENERATE IT. (REQUIRED `cargo-readme`) -->

[![Crates.io](https://img.shields.io/crates/v/sfdl.svg?style=flat-square)](https://crates.io/crates/sfdl) [![docs.rs](https://img.shields.io/docsrs/sfdl?style=flat-square)](https://docs.rs/sfdl) ![Build](https://img.shields.io/github/actions/workflow/status/markhaehnel/sfdl/main?style=flat-square)

# sfdl

A rust crate for parsing, encrypting and decrypting SFDL container files.

## Example

```rust
use sfdl::SfdlFile;

// Reading a SFDL file from a file
let mut sfdl = SfdlFile::from_file("examples/decrypted.sfdl").unwrap();

// Encrypting the SFDL file
sfdl.encrypt("password").unwrap();

// Writing the encrypted SFDL file back to a file
sfdl.write("encrypted.sfdl").unwrap();

// Decrypting the SFDL file
sfdl.decrypt("password").unwrap();

// Writing the decrypted SFDL file back to a file
sfdl.write("decrypted.sfdl").unwrap();
```

For detailed information consult the [docs](https://docs.rs/sfdl).

## Encrypted fields

The crate follows the official `n0ix/SFDL.Container` reference implementation
and only encrypts/decrypts the fields the reference handles:

- `SFDLFile.Description`
- `SFDLFile.Uploader`
- `ConnectionInfo.Host`
- `ConnectionInfo.Password`
- `ConnectionInfo.Username`
- Every `SFDLPackage.Packagename`
- Every `BulkFolder.BulkFolderPath` and `BulkFolder.PackageName`
- Every `FileInfo.DirectoryPath`, `DirectoryRoot`, `FileName`,
  `FileFullPath`, and `PackageName` for file-list packages

`ConnectionInfo.DefaultPath` is **not** encrypted because the reference
implementation leaves it plaintext.

## Cryptographic primitive

The SFDL format uses the following primitive, which this crate implements
exactly:

- AES-128-CBC with PKCS#7 padding.
- Key = MD5(password) (password interpreted as UTF-8).
- A fresh 16-byte IV per field, prepended to the ciphertext.
- IV + ciphertext encoded with standard base64.

## Security limitations

The format itself has weaknesses that this crate cannot fix:

- MD5 key derivation is fast and unsalted. Use strong, unique passwords.
- No integrity check (MAC/HMAC/AEAD) is performed, so encrypted containers
  are malleable.

Encryption and decryption are performed atomically:
[`SfdlFile::encrypt`](crate::SfdlFile::encrypt) and
[`SfdlFile::decrypt`](crate::SfdlFile::decrypt) only replace the caller's
value after the whole operation succeeds, so a wrong password never leaves
the struct half changed.

## References

- [SFDL Container Format](https://github.com/n0ix/SFDL.NET/wiki/How-it-Works-(SFDL-File-documentation))
- [SFDL.NET](https://github.com/n0ix/SFDL.NET)
- [SFDL.Container .NET implementation](https://github.com/n0ix/SFDL.Container)

## License

Available under the Apache License (Version 2.0) or the MIT license, at your option.

Copyright 2024-present Mark Hähnel and Project Contributors. The present date is determined by the timestamp of the most recent commit in the repository. Project Contributors are all authors and committers of commits in the repository.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual licensed as above, without any additional terms or
conditions.
