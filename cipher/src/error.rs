use std::fmt;


/// A simple cipher module that provides encryption and decryption functionality.
#[derive(Debug)]
pub enum Error {
    /// Invalid key length for the cipher.
    InvalidKeyLength,
    InvalidIvLength,
    EncryptionFailed,
    DecryptionFailed,
    UnpaddingFailed,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::InvalidKeyLength => write!(f, "Invalid key length for the cipher"),
            Error::InvalidIvLength => write!(f, "Invalid IV length for the cipher"),
            Error::EncryptionFailed => write!(f, "Encryption failed"),
            Error::DecryptionFailed => write!(f, "Decryption failed"),
            Error::UnpaddingFailed => write!(f, "Unpadding failed"),
        }
    }
}

impl std::error::Error for Error {}
