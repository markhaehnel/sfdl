use sfdl::sfdl::SfdlFile;

fn main() {
    let mut sfdl = SfdlFile::from_file("examples/encrypted.sfdl").unwrap();

    sfdl.decrypt("S3cr3tP4ssw0rd!").unwrap();

    println!("{:#?}", sfdl);

    sfdl.write("decrypted.sfdl").unwrap();
}
