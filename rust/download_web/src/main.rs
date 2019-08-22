//! Download a web page using the `curl` crate

extern crate clap;
extern crate curl;

#[macro_use]
extern crate error_chain;

use clap::{Arg, App};
use std::fs::File;
use std::io::prelude::*;


// Declare errors
error_chain! {
    foreign_links {
        Curl(curl::Error);
        StdIo(std::io::Error);
    }
    errors {
        HttpError(code: u32) {
            description("HTTP error code")
            display("HTTP error status in response: {}", code)
        }
    }
}

/// Download the content hosted on an URL
fn download_binary(url: &str) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    let mut handle = curl::easy::Easy::new();
    handle.url(url)?;
    {
        let mut transfer = handle.transfer();
        transfer.write_function(|data| {
            buf.extend_from_slice(data);
            Ok(data.len())
        })?;
        transfer.perform()?;
    }
    let http_code = handle.response_code()?;
    if http_code != 200 {
        bail!(ErrorKind::HttpError(http_code));
    }
    Ok(buf)
}


/// Download a URL, optionally to an output file
fn download_web(url: &str, output_file: Option<&str>) -> Result<()> {
    let data = download_binary(url)?;
    if let Some(out_file_path) = output_file {
        let mut file = File::create(out_file_path)?;
        file.write_all(&data)?;
        println!("{} bytes written to {}", data.len(), out_file_path);
    } else {
        let body = String::from_utf8(data).map_err(
            |_| "data is not valid UTF8!",
        )?;
        println!("{}", body);
    }
    Ok(())
}

fn main() {
    let matches = App::new("DownloadWeb")
        .version("0.1.0")
        .author("Nicolas Iooss")
        .about("Download a web page")
        .arg(
            Arg::with_name("url")
                .required(true)
                .takes_value(true)
                .help("URL to the page"),
        )
        .arg(
            Arg::with_name("output")
                .short("o")
                .long("output")
                .takes_value(true)
                .help("Output to a file"),
        )
        .get_matches();

    if let Err(err) = download_web(matches.value_of("url").unwrap(), matches.value_of("output")) {
        match err {
            Error(ErrorKind::Curl(e), _) => eprintln!("Error in Curl: {}", e),
            _ => eprintln!("Error: {}", err),
        }
        std::process::exit(1);
    }
}
