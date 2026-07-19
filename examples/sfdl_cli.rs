//! A command line interface to encrypt and decrypt SFDL files.
//!
//! This example shows how to use the `sfdl` crate to build a CLI
//! that encrypts or decrypts SFDL containers.
//!
//! # Usage
//!
//! Run with:
//! ```bash
//! cargo run --example sfdl_cli -- --encrypt -p "my-password" -o encrypted.sfdl decrypted.sfdl
//! ```

use std::env;
use std::io::{self, Write};
use std::path::PathBuf;

use sfdl::{SfdlError, SfdlFile};

fn print_usage() {
    println!("SFDL Command Line Interface");
    println!();
    println!("Usage:");
    println!("  cargo run --example sfdl_cli -- [options] <input-file>");
    println!();
    println!("Options:");
    println!("  -e, --encrypt              Encrypt the input SFDL file");
    println!("  -d, --decrypt              Decrypt the input SFDL file");
    println!("  -p, --password <password>  Password to encrypt/decrypt with (will prompt if not provided)");
    println!("  -o, --output <output-file> Output file path (defaults to overwriting input-file)");
    println!("  -h, --help                 Show this help message");
}

fn run() -> Result<(), SfdlError> {
    let args: Vec<String> = env::args().collect();

    let mut encrypt = false;
    let mut decrypt = false;
    let mut input_file: Option<String> = None;
    let mut output_file: Option<String> = None;
    let mut password: Option<String> = None;
    let mut help = false;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-e" | "--encrypt" => {
                encrypt = true;
                i += 1;
            }
            "-d" | "--decrypt" => {
                decrypt = true;
                i += 1;
            }
            "-p" | "--password" => {
                if i + 1 < args.len() {
                    password = Some(args[i + 1].clone());
                    i += 2;
                } else {
                    eprintln!("Error: Missing value for password option");
                    print_usage();
                    std::process::exit(1);
                }
            }
            "-o" | "--output" => {
                if i + 1 < args.len() {
                    output_file = Some(args[i + 1].clone());
                    i += 2;
                } else {
                    eprintln!("Error: Missing value for output option");
                    print_usage();
                    std::process::exit(1);
                }
            }
            "-h" | "--help" => {
                help = true;
                i += 1;
            }
            _ => {
                if args[i].starts_with('-') {
                    eprintln!("Error: Unknown option '{}'", args[i]);
                    print_usage();
                    std::process::exit(1);
                }
                if let Some(ref first) = input_file {
                    eprintln!(
                        "Error: Multiple input files specified (first was '{}', then '{}')",
                        first, args[i]
                    );
                    print_usage();
                    std::process::exit(1);
                }
                input_file = Some(args[i].clone());
                i += 1;
            }
        }
    }

    if help {
        print_usage();
        return Ok(());
    }

    // Validate mode
    if encrypt && decrypt {
        eprintln!("Error: Cannot specify both --encrypt and --decrypt");
        print_usage();
        std::process::exit(1);
    }
    if !encrypt && !decrypt {
        eprintln!("Error: Either --encrypt (-e) or --decrypt (-d) must be specified");
        print_usage();
        std::process::exit(1);
    }

    // Validate input file
    let input_path = match input_file {
        Some(path) => PathBuf::from(path),
        None => {
            eprintln!("Error: Input file is required");
            print_usage();
            std::process::exit(1);
        }
    };

    if !input_path.exists() {
        eprintln!(
            "Error: Input file '{}' does not exist",
            input_path.display()
        );
        std::process::exit(1);
    }

    // Handle password
    let password = match password {
        Some(p) => p,
        None => {
            print!("Enter password: ");
            io::stdout().flush().map_err(SfdlError::Io)?;
            let mut input = String::new();
            io::stdin().read_line(&mut input).map_err(SfdlError::Io)?;
            input
                .trim_end_matches('\r')
                .trim_end_matches('\n')
                .to_string()
        }
    };

    // Determine output file
    let output_path = match output_file {
        Some(path) => PathBuf::from(path),
        None => input_path.clone(),
    };

    // Perform action
    println!("Loading SFDL file from {}...", input_path.display());
    let mut sfdl = SfdlFile::from_file(&input_path)?;

    if encrypt {
        println!("Encrypting SFDL file...");
        sfdl.encrypt(&password)?;
        println!("Encryption successful!");
    } else {
        println!("Decrypting SFDL file...");
        sfdl.decrypt(&password)?;
        println!("Decryption successful!");
    }

    println!("Writing SFDL file to {}...", output_path.display());
    sfdl.write(&output_path)?;
    println!("Operation completed successfully.");

    Ok(())
}

fn main() {
    if let Err(e) = run() {
        match e {
            SfdlError::Encrypt(err) => eprintln!("Encryption error: {}", err),
            SfdlError::Decrypt(err) => eprintln!("Decryption error: {}", err),
            SfdlError::Parse(err) => eprintln!("Parsing error: {}", err),
            SfdlError::Io(err) => eprintln!("I/O error: {}", err),
            SfdlError::AlreadyEncrypted => eprintln!("Error: The SFDL file is already encrypted."),
            SfdlError::NotEncrypted => eprintln!("Error: The SFDL file is not encrypted."),
        }
        std::process::exit(1);
    }
}
