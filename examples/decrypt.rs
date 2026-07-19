//! Decrypt an example SFDL file.

use std::path::Path;

use sfdl::SfdlFile;

const PASSWORD: &str = "S3cr3tP4ssw0rd!";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let input = Path::new("examples/encrypted.sfdl");
    let output_dir = Path::new("examples/out");
    let output = output_dir.join("decrypted.sfdl");

    let mut sfdl = SfdlFile::from_file(input)?;

    sfdl.decrypt(PASSWORD)?;

    std::fs::create_dir_all(output_dir)?;
    sfdl.write(&output)?;

    println!("Decrypted {} -> {}", input.display(), output.display());

    Ok(())
}
