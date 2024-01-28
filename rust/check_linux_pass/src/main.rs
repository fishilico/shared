extern crate clap;
extern crate pwhash;
extern crate termios;
extern crate uzers;

use clap::{App, Arg};
use std::error;
use std::fmt;
use std::fs::File;
use std::io::{self, BufRead, BufReader, Write};
use std::path::Path;
use termios::{tcsetattr, Termios};

#[derive(Debug)]
enum Error {
    Io(io::Error),
    PwHash(pwhash::error::Error),
    Str(String),
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Error {
        Error::Io(err)
    }
}

impl From<pwhash::error::Error> for Error {
    fn from(err: pwhash::error::Error) -> Error {
        Error::PwHash(err)
    }
}

impl From<String> for Error {
    fn from(err: String) -> Error {
        Error::Str(err)
    }
}

impl From<&str> for Error {
    fn from(err: &str) -> Error {
        Error::Str(err.to_owned())
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::Io(ref err) => write!(f, "IO error: {}", err),
            Error::PwHash(ref err) => write!(f, "PwHash error: {}", err),
            Error::Str(ref err) => f.write_str(err),
        }
    }
}

impl error::Error for Error {
    fn cause(&self) -> Option<&dyn error::Error> {
        match *self {
            Error::Io(ref err) => Some(err),
            Error::PwHash(ref err) => Some(err),
            Error::Str(_) => None,
        }
    }
}

/// Prompt the password of a user
fn prompt_password() -> Result<String, Error> {
    // Disable ECHO but echo the new line character
    let initial_term = Termios::from_fd(0)?;
    let mut term = initial_term;
    term.c_lflag &= !termios::ECHO;
    term.c_lflag |= termios::ECHONL;
    tcsetattr(0, termios::TCSANOW, &term)?;

    let mut password_line = String::new();
    eprint!("Password: ");
    let result = io::stderr()
        .flush()
        .and_then(|_| io::stdin().read_line(&mut password_line));

    // Reset the initial terminal before returning a failure
    tcsetattr(0, termios::TCSANOW, &initial_term)?;

    result?;

    Ok(password_line
        .trim_end_matches(|c| c == '\r' || c == '\n')
        .to_string())
}

/// Check a password using a `/etc/shadow` file
fn check_password_in_shadow<P: AsRef<Path>>(
    shadow_path: P,
    user: &str,
    password_opt: Option<&str>,
) -> Result<(), Error> {
    let mut is_found = false;
    let mut prompted_password = None;
    let file = File::open(shadow_path)?;
    let file_buffer = BufReader::new(&file);
    for line_result in file_buffer.lines() {
        let line = line_result?;
        let fields: Vec<&str> = line.split(':').collect();
        if fields.len() >= 2 && fields[0] == user {
            is_found = true;
            let password_hash = fields[1];
            if password_hash == "" || password_hash == "x" || password_hash.starts_with("!") {
                println!("Ignoring hash {:?} for {}", password_hash, user);
                continue;
            }
            println!("Found hash for {}: {:?}", user, password_hash);

            // Prompt the user for a password if there was none provided
            let password = match password_opt {
                Some(p) => p,
                None => {
                    if prompted_password.is_none() {
                        prompted_password = Some(prompt_password()?);
                    }
                    prompted_password.as_ref().unwrap()
                }
            };

            // TODO: use a secure hash comparison function, which is constant-time
            if pwhash::unix::crypt(password, password_hash)? == password_hash {
                println!("The password is correct :)");
                return Ok(());
            }
        }
    }
    if !is_found {
        return Err(Error::Str("user not found in shadow file".to_owned()));
    } else {
        return Err(Error::Str("incorrect password".to_owned()));
    }
}

/// Check a password using `unix_chkpwd` helper
///
/// The source code of the helper is
/// [on GitHub](https://github.com/linux-pam/linux-pam/blob/v1.3.1/modules/pam_unix/unix_chkpwd.c)
fn check_password_with_helper(user: &str, password_opt: Option<&str>) -> Result<(), Error> {
    // Find unix_chkpwd
    let mut unix_chkpwd_path_opt = None;
    for path_dir in &["/bin", "/sbin", "/usr/bin", "/usr/sbin"] {
        let path = path_dir.to_string() + "/unix_chkpwd";
        if std::fs::metadata(&path).is_ok() {
            unix_chkpwd_path_opt = Some(path);
            break;
        }
    }
    let unix_chkpwd_path = unix_chkpwd_path_opt.ok_or("unable to find unix_chkpwd helper")?;
    println!("Using helper {}", unix_chkpwd_path);

    let prompted_password;
    let password = match password_opt {
        Some(p) => p,
        None => {
            prompted_password = prompt_password()?;
            prompted_password.as_ref()
        }
    };

    let mut child = std::process::Command::new(unix_chkpwd_path)
        .args(&[user, "nullok"])
        .current_dir("/")
        .stdin(std::process::Stdio::piped())
        .spawn()?;
    {
        let stdin = child.stdin.as_mut().unwrap();
        stdin.write_all(password.as_bytes())?;
        stdin.write_all(&[0])?;
    }
    let exit_status = child.wait()?;
    if !exit_status.success() {
        if exit_status.code() == Some(7) {
            return Err(Error::Str("incorrect password".to_owned()));
        } else {
            return Err(Error::Str(format!("unknown exit status ({})", exit_status)));
        }
    }
    println!("The password is correct :)");
    Ok(())
}

fn main_with_result() -> Result<(), Error> {
    let matches = App::new("CheckLinuxPass")
        .version("0.1.0")
        .author("Nicolas Iooss")
        .about("Check a password on a Linux system")
        .arg(
            Arg::with_name("user")
                .takes_value(true)
                .help("name of the user to check the password"),
        )
        .arg(
            Arg::with_name("password")
                .short("p")
                .long("password")
                .takes_value(true)
                .help("password to test"),
        )
        .arg(
            Arg::with_name("shadow_file")
                .short("s")
                .long("shadow")
                .takes_value(true)
                .help("use a shadow file to test the password"),
        )
        .get_matches();

    let current_username;
    let username: &str = match matches.value_of("user") {
        Some(u) => u,
        None => {
            current_username =
                uzers::get_current_username().ok_or("unable to get the current user name")?;
            current_username
                .to_str()
                .ok_or("unable to convert the current user name to str")?
        }
    };
    let password_opt = matches.value_of("password");

    if let Some(shadow_path) = matches.value_of("shadow_file") {
        // Parse /etc/shadow in search for the user
        check_password_in_shadow(shadow_path, &username, password_opt)?;
    } else {
        check_password_with_helper(&username, password_opt)?;
    }
    Ok(())
}

fn main() {
    if let Err(err) = main_with_result() {
        eprintln!("Error: {}", err);
        std::process::exit(1);
    }
}
