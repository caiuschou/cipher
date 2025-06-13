
use crate::{aes::{Aes, AesCbc, AesEcb}, key::{key::AsAny, secret_key_spec::SecretKeySpec}, Algorithm, Error, IvParameterSpec};
use crate::key::key::Key;

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
    
    pub fn aes_ecb(key: SecretKeySpec, padding: Option<Padding>) -> Result<Self, Error> {
        Self::new(
            Algorithm::AES,
            Mode::ECB,
            padding,
            key.key(),
            None,
        )
    }

    pub fn aes_cbc(key: SecretKeySpec, iv: IvParameterSpec, padding: Option<Padding>) -> Result<Self, Error> {
        Self::new(
            Algorithm::AES,
            Mode::CBC,
            padding,
            key.key(),
            Some(iv.iv()),
        )
    }

    pub fn encrypt(&self, data: &[u8]) -> Vec<u8> {
        self.aes.encrypt(data)
    }

    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, Error> {
        self.aes.decrypt(data)
    }
}