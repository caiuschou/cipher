
use crate::{aes::{Aes, AesCbc}, Error};

pub enum Algorithm {
    AES,
}

pub enum Mode {
    ECB,
    CBC,
}

pub enum Padding {
    PKCS7,
    Iso10126,
    Iso9816,
    AnsiX923,
    ZeroPadding,
    NoPadding,
}

pub struct Cipher {

    algorithm: Algorithm,

    mode: Mode,

    aes: Box<dyn Aes>,
}

impl Cipher {
    pub fn new(algorithm: Algorithm, mode: Mode, key: Vec<u8>, iv: Option<Vec<u8>>) -> Result<Self, Error> {
        let aes = Self::new_aes(algorithm, mode, key, iv);
        if aes.is_err() {
            return Err(aes.err().unwrap());
        }
        let cipher = Cipher {
            algorithm,
            mode,
            aes: Box::new(aes.unwrap()),
        };
        Ok(cipher)
    }

    pub fn new_aes(algorithm: Algorithm, mode: Mode, key: Vec<u8>, iv: Option<Vec<u8>>) -> Result<Aes, Error> {
        AesCbc::new(key, iv.unwrap_or_else(|| vec![0; 16]));
    }

    pub fn encrypt(&self, data: &[u8]) -> Vec<u8> {
        self.aes.encrypt(data)
    }

    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, Error> {
        self.aes.decrypt(data)
    }
}