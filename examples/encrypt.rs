use sfdl::sfdl::SfdlFile;

fn main() {
    let mut sfdl = SfdlFile::from_file("examples/decrypted.sfdl").unwrap();

    sfdl.encrypt("S3cr3tP4ssw0rd!").unwrap();

    println!("{:#?}", sfdl);

    sfdl.write("encrypted.sfdl").unwrap();
}
