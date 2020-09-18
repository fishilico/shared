use std::error;
use std::fmt;
use std::io;
use std::path::PathBuf;

#[derive(Debug)]
pub enum Error {
    IoWithoutPath(io::Error),
    IoWithPath(PathBuf, io::Error),
    Str(String),
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
            Error::IoWithoutPath(ref err) => write!(f, "IO error: {}", err),
            Error::IoWithPath(ref path, ref err) => {
                write!(f, "IO error in {}: {}", path.display(), err)
            }
            Error::Str(ref err) => f.write_str(err),
        }
    }
}

impl error::Error for Error {
    fn cause(&self) -> Option<&dyn error::Error> {
        match *self {
            Error::IoWithoutPath(ref err) => Some(err),
            Error::IoWithPath(_, ref err) => Some(err),
            Error::Str(_) => None,
        }
    }
}
