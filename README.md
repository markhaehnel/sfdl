<!-- THIS FILE IS GENERATED. USE `cargo readme > README.md` TO REGENERATE IT. (REQUIRED `cargo-readme`) -->

[![Crates.io](https://img.shields.io/crates/v/sfdl.svg?style=flat-square)](https://crates.io/crates/sfdl) [![docs.rs](https://img.shields.io/docsrs/:crate?style=flat-square)](https://docs.rs/sfdl) ![Build](https://img.shields.io/github/actions/workflow/status/markhaehnel/sfdl/main?style=flat-square)

# sfdl

A rust crate for parsing, encrypting and decrypting SFDL container files.

## Example

```rust
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
