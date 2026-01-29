// Error types

use std::fmt;

#[derive(Debug)]
pub enum Error {
    ConfigNotFound,
    ConfigParse(String),
    SecretNotFound(String),
    SecretExists(String),
    AlreadyOpen(String),
    NotOpen(String),
    KeyNotFound(String),
    MountFailed(String),
    UnmountFailed(String),
    Io(std::io::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::ConfigNotFound => write!(f, "Config file not found"),
            Error::ConfigParse(msg) => write!(f, "Config parse error: {}", msg),
            Error::SecretNotFound(name) => write!(f, "Secret '{}' not found", name),
            Error::SecretExists(name) => write!(f, "Secret '{}' already exists", name),
            Error::AlreadyOpen(name) => write!(f, "Secret '{}' is already open", name),
            Error::NotOpen(name) => write!(f, "Secret '{}' is not open", name),
            Error::KeyNotFound(name) => write!(f, "Key file not found for '{}'", name),
            Error::MountFailed(msg) => write!(f, "Mount failed: {}", msg),
            Error::UnmountFailed(msg) => write!(f, "Unmount failed: {}", msg),
            Error::Io(e) => write!(f, "IO error: {}", e),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}
