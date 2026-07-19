# Plan: Fix SFDL Encryption Correctness and Missing Features

## Goal

Make the `sfdl` crate cryptographically and structurally compatible with the
official `n0ix/SFDL.Container` reference implementation and the SFDL.NET wiki.
The low-level AES-128-CBC + PKCS7 + MD5(key) primitive is already correct; this
plan fixes the high-level integration: field coverage, data model, iteration,
atomicity, error handling, and documentation.

## References

- `ENCRYPTION_ANALYSIS.md` in repository root.
- Reference implementation: `SFDL.Container/Classes/Encryption/{Encrypt,Decrypt}.vb`
- Reference helper: `SFDL.NET 3/Modules/SFDLFileHelper.vb`
- SFDL.NET wiki container examples.

---

## Phase 1 — Analyze current state and add failing tests

### 1.1 Read existing code
Read the following files in full and keep the analysis open while implementing:

- `src/crypto.rs`
- `src/sfdl.rs`
- `src/lib.rs` and any other module entry points
- `Cargo.toml`
- existing tests under `tests/` or `src/` integration tests

### 1.2 Create a test-data snapshot directory
Create `tests/data/` and add at least these representative SFDL samples (XML,
decrypted form; exact content can be synthetic but structurally valid and based
on wiki examples):

1. `single_package_bulkfolder.xml` — one package, `BulkFolderList` with one
   `BulkFolder`.
2. `multi_package_bulkfolders.xml` — at least 2 packages, multiple bulk folders
   per package.
3. `filelist_mode.xml` — one package with `FileList` containing multiple
   `FileInfo` entries.
4. `mixed_mode.xml` — one package with both `FileList` and `BulkFolderList`, and
   one with only bulk folders.
5. `minimal_encrypted.xml` — encrypted forms of the above, generated from the
   reference implementation if possible, or from the crate after fixes are known
   to produce identical output.

### 1.3 Write reference-equivalence tests before fixing
Add tests that assert:

- All encrypted fields from `1.2` decrypt with the reference password to the
  original plaintexts.
- Round-trip encryption followed by decryption reproduces the original struct.
- Multiple packages, multiple bulk folders, and file-list entries all survive
  the round trip.
- The crate does **not** encrypt fields the reference ignores.

These tests should fail against the current code; that is expected.

---

## Phase 2 — Fix the data model (`src/sfdl.rs`)

### 2.1 `BulkFolderList` must hold a vector
Change:

```rust
pub struct BulkFolderList {
    #[serde(rename = "BulkFolder")]
    pub bulk_folder: BulkFolder,
}
```

to:

```rust
pub struct BulkFolderList {
    #[serde(rename = "BulkFolder")]
    pub bulk_folder: Vec<BulkFolder>,
}
```

Update all serde default/renaming attributes so the XML remains valid. Add
`#[serde(default)]` if the list may be absent.

### 2.2 Add `FileList` / `FileInfo` support
Model the file-list container structure. The fields to expose are based on the
reference and wiki:

```rust
pub struct FileList {
    #[serde(rename = "FileInfo")]
    pub file_info: Vec<FileInfo>,
}

pub struct FileInfo {
    pub file_name: String,
    pub directory_root: String,
    pub directory_path: String,
    #[serde(rename = "FileFullPath")]
    pub file_full_path: String,
    #[serde(rename = "FileSize")]
    pub file_size: u64,
    #[serde(rename = "FileHashType")]
    pub file_hash_type: String,
    #[serde(rename = "FileHash")]
    pub file_hash: String,
    pub package_name: String,
}
```

Add `file_list: Option<FileList>` to `SfdlPackage`.

### 2.3 Decide on field naming and optionality
Audit the wiki/reference XML to confirm exact casing for:

- `FileFullPath` vs `FullPath`
- `FileHashType` / `FileHash` presence and defaults
- `DirectoryRoot` / `DirectoryPath` presence
- `BulkFolderMode` boolean representation

Use `Option<T>` only where the reference/XML schema allows absence.

---

## Phase 3 — Expand encrypted field coverage (`src/crypto.rs`)

### 3.1 Add missing fields
The encrypt/decrypt logic must traverse every decryptable field in the
reference:

```text
SfdlFile
  ├─ description
  ├─ uploader
  └─ connection_info
        ├─ host
        ├─ password
        └─ username
  └─ packages[*].sfdl_package
        ├─ package_name
        ├─ bulk_folder_list.bulk_folder[*].bulk_folder_path
        ├─ bulk_folder_list.bulk_folder[*].package_name
        └─ file_list.file_info[*]
              ├─ directory_path
              ├─ directory_root
              ├─ file_name
              ├─ file_full_path
              └─ package_name
```

### 3.2 Stop encrypting `Connection.DefaultPath` by default
The reference does **not** decrypt `Connection.DefaultPath`. Do not encrypt it
in the standard path.

If `DefaultPath` encryption is needed for a documented SFDL v2 compatibility
mode, gate it behind an explicit `CompatibilityMode` enum with a clear default
of `Reference` that matches `SFDL.Container`. Otherwise simply remove it from the
encrypted field set and add a code comment explaining why.

### 3.3 Iterate over all packages, bulk folders, and file infos
Replace every `packages[0]` with a loop over `sfdl.packages`.

For each package:
- encrypt/decrypt `package_name`
- for each bulk folder encrypt/decrypt `bulk_folder_path` and `package_name`
- if `file_list` is present, for each file info encrypt/decrypt
  `directory_path`, `directory_root`, `file_name`, `file_full_path`, and
  `package_name`

### 3.4 Keep non-encrypted fields untouched
Do not modify fields that are not in the reference decrypt set (e.g.
`default_path`, `bulk_folder_mode`, file sizes, hashes, booleans).

---

## Phase 4 — Make encryption/decryption atomic and safe

### 4.1 Atomic two-phase decryption
Implement a helper that builds a complete decrypted clone of the input before
mutating the original:

```rust
fn decrypt_into(sfdl: &mut SfdlFile, password: &str) -> Result<(), DecryptError> {
    let decrypted = decrypt_sfdl(sfdl, password)?; // pure function, returns new struct
    *sfdl = decrypted;
    Ok(())
}
```

Do the same for encryption. This ensures that a failure in the middle of the
process does not leave the caller's struct half-changed.

### 4.2 Replace panics with structured errors
In `decrypt_value`:

- Validate base64 decoding length **before** splitting.
- Return a new `DecryptError` variant such as
  `DecryptError::InvalidCiphertextLength { expected: usize, got: usize }` when
  the decoded blob is shorter than 16 bytes (one AES block / the IV).
- Remove all `.unwrap()`/`.expect()` calls from the decryption hot path.

### 4.3 Preserve documented behavior for empty passwords
Consider whether `EncryptError::EmptyPassword` should remain. The reference
accepts empty strings. Options:

1. Keep rejecting empty passwords for safety but document the divergence.
2. Accept empty passwords for full reference parity and add tests.

Choose one and document it in `src/crypto.rs` and the crate-level docs.

---

## Phase 5 — Add interoperability and regression tests

### 5.1 Round-trip tests
For each sample in `tests/data/`:

1. Parse decrypted XML into `SfdlFile`.
2. Encrypt with a known password.
3. Decrypt with the same password.
4. Compare via `PartialEq` (derive it if missing) and any custom equality if
   needed.

### 5.2 Reference-decrypt tests
If reference-encrypted samples are available, verify that the crate decrypts
them correctly into the expected plaintexts.

### 5.3 Error-condition tests
- Short ciphertext (< 16 decoded bytes) returns `DecryptError` instead of
  panicking.
- Wrong password returns `DecryptError::InvalidPassword` or equivalent.
- Empty password obeys the documented policy.

### 5.4 Multi-element regression tests
- A container with 2+ packages, each with 2+ bulk folders, round-trips exactly.
- A file-list package round-trips exactly.
- `DefaultPath` is **not** altered by encryption/decryption.

---

## Phase 6 — Documentation and changelog

### 6.1 Update crate documentation
In the top-level crate docs (`src/lib.rs`) and `README.md` (if present):

- List exactly which fields are encrypted/decrypted and note parity with
  `SFDL.Container`.
- Document that the crate matches the reference primitive (AES-128-CBC,
  MD5-derived key, PKCS7, IV prepended, base64).
- Document limitations of the SFDL format itself: MD5 key derivation, no salt,
  no integrity check, malleability.
- Explain the atomic two-phase behavior.

### 6.2 Add a changelog entry
Create or update `CHANGELOG.md` with a `## [Unreleased]` section summarizing the
breaking model changes (`BulkFolder` → `Vec<BulkFolder>`, new `FileList`) and
correctness fixes.

---

## Phase 7 — Final review checklist

Before marking the plan complete, ensure:

- [ ] `cargo test` passes, including new reference-equivalence tests.
- [ ] `cargo clippy` reports no warnings.
- [ ] `cargo fmt` has been run.
- [ ] `cargo doc` builds without errors.
- [ ] Every `.unwrap()` and `.expect()` in `crypto.rs` is either removed or
      justified with a `SAFETY:` comment.
- [ ] The encrypted field set matches the reference or is explicitly documented
      where it intentionally differs.
- [ ] Multiple packages, multiple bulk folders, and file-list containers all
      round-trip correctly.
- [ ] A corrupted/short ciphertext returns `DecryptError`, not a panic.

---

## Estimated order of files to modify

1. `src/sfdl.rs` — data model fixes (`Vec<BulkFolder>`, `FileList`).
2. `src/crypto.rs` — expand field coverage, iterate all collections, atomic
   helpers, length validation.
3. `src/lib.rs` — crate docs.
4. `tests/` and `tests/data/` — interoperability and regression tests.
5. `README.md` and `CHANGELOG.md` — user-facing documentation.

## Open questions to resolve during implementation

1. Does the crate currently support renaming for `FileFullPath` vs `FullPath`?
   Verify against real SFDL/XML samples before finalizing `FileInfo`.
2. Should `DefaultPath` be encrypted under a compatibility mode, or dropped
   entirely from the encrypted field set?
3. Should empty passwords be accepted for full reference parity?
