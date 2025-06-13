
use crate::{aes::{Aes, AesCbc, AesEcb}, Algorithm, Error};



pub enum Mode {
    ECB,
    CBC,
}

#[derive(Clone)]
pub enum Padding {
    PKCS7,
    Iso10126,
    Iso7816,
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
    pub fn new(algorithm: Algorithm, mode: Mode, padding: Option<Padding>, key: Vec<u8>, iv: Option<Vec<u8>>) -> Result<Self, Error> {
        let padding = padding.unwrap_or(Padding::PKCS7);
        let aes: Result<Box<dyn Aes>, Error> = match mode {
            Mode::CBC => {
                let iv_value = iv.ok_or(Error::IvIsRequired);
                 AesCbc::new(key, iv_value?, padding.clone())
                    .map(|a| Box::new(a) as Box<dyn Aes>)
            },
            Mode::ECB => AesEcb::new(key, padding.clone()).map(|a| Box::new(a) as Box<dyn Aes>),
        };
        let aes = match aes {
            Ok(a) => a,
            Err(e) => return Err(e),
        };
        let cipher = Cipher {
            algorithm,
            mode,
            aes,
        };
        Ok(cipher)
    }

    pub fn encrypt(&self, data: &[u8]) -> Vec<u8> {
        self.aes.encrypt(data)
    }

    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, Error> {
        self.aes.decrypt(data)
    }
}