
use crate::Error;

pub enum Algorithm {
    AES,
}

pub enum Mode {
    ECB,
    CBC,
}

pub struct Cipher {

    key: Vec<u8>,

    iv: Option<Vec<u8>>,

    algorithm: Algorithm,

    mode: Mode,
}

impl Cipher {
    pub fn new(algorithm: Algorithm, mode: Mode, key: Vec<u8>, iv: Option<Vec<u8>>) -> Result<Self, Error> {
        Ok(
            Cipher {
                algorithm,
                mode,
                key,
                iv,
            }
        )
    }

    pub fn encrypt(&self, data: &[u8]) -> Vec<u8> {
        data.to_vec()
    }

    pub fn decrypt(&self, data: &[u8]) -> Vec<u8> {
        data.to_vec()
    }
}