mod error;
mod finder;
mod key;

use clap::{App, Arg};
use std::io;
use std::path::Path;

use error::Error;
use finder::FinderConfig;

fn main_with_result() -> Result<(), Error> {
    let matches = App::new("Asymmetric key find")
        .version("0.1.0")
        .author("Nicolas Iooss")
        .about("Find asymmetric private keys in a blob (binary large object)")
        .arg(
            Arg::with_name("files")
                .takes_value(true)
                .multiple(true)
                .help("files to read (stdin by default)"),
        )
        .arg(
            Arg::with_name("public")
                .short("p")
                .long("public")
                .takes_value(false)
                .help("search for public keys too"),
        )
        .arg(
            Arg::with_name("verbose")
                .short("v")
                .long("verbose")
                .takes_value(false)
                .help("show more messages"),
        )
        .arg(
            Arg::with_name("keep_duplicate")
                .short("d")
                .long("duplicate")
                .takes_value(false)
                .help("keep duplicate keys in the output"),
        )
        .get_matches();

    let mut ctx = FinderConfig {
        verbose: matches.is_present("verbose"),
        find_public: matches.is_present("public"),
        keep_duplicate: matches.is_present("keep_duplicate"),
    }
    .into_context();
    if let Some(arg_files) = matches.values_of_os("files") {
        for file_path in arg_files {
            if Path::new(file_path).is_dir() {
                eprintln!("skipping directory {:?}", file_path);
                continue;
            }
            if ctx.cfg.verbose {
                println!("{:?}:", file_path);
            }
            ctx.find_in_file(file_path)?;
        }
    } else {
        // Use stdin
        if ctx.cfg.verbose {
            println!("[stdin]:");
        }
        ctx.find_in_reader(io::stdin())?;
    }
    if !ctx.found_keys.is_empty() {
        println!("Found {} keys:", ctx.found_keys.len());
        let mut keys: Vec<&key::AsymmetricKey> = ctx.found_keys.values().collect();
        keys.sort();
        for (idx, key) in keys.iter().enumerate() {
            println!("- Key {}: {}", idx, key);
        }
    }
    Ok(())
}

fn main() {
    if let Err(err) = main_with_result() {
        eprintln!("Error: {}", err);
        std::process::exit(1);
    }
}
