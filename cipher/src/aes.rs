use aes::{cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyInit, KeyIvInit}, Aes128, Aes192, Aes256};
use block_padding::{generic_array::GenericArray, Iso10126, UnpadError, ZeroPadding};
use cbc::{self, Encryptor, Decryptor};
use crate::cipher::Padding;
use crate::Error;


pub trait Aes {
    fn encrypt(&self, data: &[u8]) -> Vec<u8>;

    fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, Error>;
}

pub struct AesCbc {

    decryptor: Box<dyn DecryptorAdapter>,

    encryptor: Box<dyn EncryptorAdapter>,
}

pub struct AesEcb {

    decryptor: Box<dyn DecryptorAdapter>,

    encryptor: Box<dyn EncryptorAdapter>,
}

impl AesCbc {
    pub fn new(key: Vec<u8>, iv: Vec<u8>, padding: Padding) -> Result<Self, Error> {

        let supported_key_length = [16, 24, 32];
        if !supported_key_length.contains(&key.len()) {
            return Err(Error::InvalidKeyLength);
        }

        let size = key.len();
        let decryptor: Box<dyn DecryptorAdapter> = match size {
            16 => Box::new(DecryptorAdapterAes128::new(key.clone(), iv.clone(), padding.clone())),
            24 => Box::new(DecryptorAdapterAes192::new(key.clone(), iv.clone(), padding.clone())),
            32 => Box::new(DecryptorAdapterAes256::new(key.clone(), iv.clone(), padding.clone())),
            _ => return Err(Error::InvalidKeyLength),
        };

        let encryptor: Box<dyn EncryptorAdapter> = match size {
            16 => Box::new(EncryptorAdapterAes128::new(key.clone(), iv.clone(), padding.clone())),
            24 => Box::new(EncryptorAdapterAes192::new(key.clone(), iv.clone(), padding.clone())),
            32 => Box::new(EncryptorAdapterAes256::new(key.clone(), iv.clone(), padding.clone())),
            _ => return Err(Error::InvalidKeyLength),
        };

        let aes = AesCbc {
            decryptor,
            encryptor,
        };

        Ok(aes)
    }
}

impl Aes for AesCbc {
    

    fn encrypt(&self, data: &[u8]) -> Vec<u8> {
        self.encryptor.encrypt_vec(data)
    }

    fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, Error> {
        let result = self.decryptor.decrypt_vec(data);
        match result {
            Ok(decrypted_data) => Ok(decrypted_data),
            Err(_) => Err(Error::UnpaddingFailed),
        }
    }
    
}

impl AesEcb {
    pub fn new(key: Vec<u8>, padding: Padding) -> Result<Self, Error> {

        let supported_key_length = [16, 24, 32];
        if !supported_key_length.contains(&key.len()) {
            return Err(Error::InvalidKeyLength);
        }

        let size = key.len();
        let encryptor: Box<dyn EncryptorAdapter> = match size {
            16 => Box::new(EncryptorAdapterAesEcb128::new(key.clone(), padding.clone())),
            24 => Box::new(EncryptorAdapterAesEcb192::new(key.clone(), padding.clone())),
            32 => Box::new(EncryptorAdapterAesEcb256::new(key.clone(), padding.clone())),
            _ => return Err(Error::InvalidKeyLength),
        };

        let decryptor: Box<dyn DecryptorAdapter> = match size {
            16 => Box::new(DecryptorAdapterAesEcb128::new(key.clone(), padding.clone())),
            24 => Box::new(DecryptorAdapterAesEcb192::new(key.clone(), padding.clone())),
            32 => Box::new(DecryptorAdapterAesEcb256::new(key.clone(), padding.clone())),
            _ => return Err(Error::InvalidKeyLength),
        };

        let aes = AesEcb {
            decryptor,
            encryptor,
        };

        Ok(aes)
    }
}

impl Aes for AesEcb {
    
    fn encrypt(&self, data: &[u8]) -> Vec<u8> {
        self.encryptor.encrypt_vec(data)
    }

    fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, Error> {
        let result = self.decryptor.decrypt_vec(data);
        match result {
            Ok(decrypted_data) => Ok(decrypted_data),
            Err(_) => Err(Error::UnpaddingFailed),
        }
    }
    
}


trait DecryptorAdapter {
    fn decrypt_vec(&self, data: &[u8]) -> Result<Vec<u8>, UnpadError>;
}

trait EncryptorAdapter {
    fn encrypt_vec(&self, data: &[u8]) -> Vec<u8>;
}

macro_rules! define_decryptor_impl {
    (
        $name:tt,
        $cipher:ident,
    ) => {
        struct $name {
            decryptor: Decryptor<$cipher>,
            padding: Padding
        }

        impl $name {
            pub fn new(key: Vec<u8>, iv: Vec<u8>, padding: Padding) -> Self {
                let key_ga = GenericArray::from_slice(&key);
                let iv_ga = GenericArray::from_slice(&iv);

                let decryptor = Decryptor::<$cipher>::new(key_ga, iv_ga);

                Self {
                    decryptor,
                    padding
                }
            }
        }

        impl DecryptorAdapter for $name {
            fn decrypt_vec(&self, data: &[u8]) -> Result<Vec<u8>, UnpadError> {
                let decryptor = self.decryptor.clone();
                match self.padding {
                    Padding::PKCS7 => decryptor.decrypt_padded_vec_mut::<Pkcs7>(data),
                    Padding::ZeroPadding => decryptor.decrypt_padded_vec_mut::<block_padding::ZeroPadding>(data),
                    Padding::Iso10126 => decryptor.decrypt_padded_vec_mut::<block_padding::Iso10126>(data),
                    Padding::AnsiX923 => decryptor.decrypt_padded_vec_mut::<block_padding::AnsiX923>(data),
                    Padding::Iso7816 => decryptor.decrypt_padded_vec_mut::<block_padding::Iso7816>(data),
                    Padding::NoPadding => decryptor.decrypt_padded_vec_mut::<block_padding::NoPadding>(data),
                }
            }
        }
    };
}


define_decryptor_impl!(
    DecryptorAdapterAes128,
    Aes128,
);

define_decryptor_impl!(
    DecryptorAdapterAes192,
    Aes192,
);

define_decryptor_impl!(
    DecryptorAdapterAes256,
    Aes256,
);

macro_rules! define_encryptor_impl {
    (
        $name:tt,
        $cipher:ident,
    ) => {
        struct $name {
            encryptor: Encryptor<$cipher>,
            padding: Padding
        }

        impl $name {
            pub fn new(key: Vec<u8>, iv: Vec<u8>, padding: Padding) -> Self {
                let key_ga = GenericArray::from_slice(&key);
                let iv_ga = GenericArray::from_slice(&iv);
                let encryptor = Encryptor::<$cipher>::new(key_ga, iv_ga);

                Self {
                    encryptor,
                    padding
                }
            }
        }
    

        impl EncryptorAdapter for $name {
            fn encrypt_vec(&self, data: &[u8]) -> Vec<u8> {
                let encryptor = self.encryptor.clone();
                match self.padding {
                    Padding::PKCS7 => encryptor.encrypt_padded_vec_mut::<Pkcs7>(data),
                    Padding::ZeroPadding => encryptor.encrypt_padded_vec_mut::<block_padding::ZeroPadding>(data),
                    Padding::Iso10126 => encryptor.encrypt_padded_vec_mut::<block_padding::Iso10126>(data),
                    Padding::AnsiX923 => encryptor.encrypt_padded_vec_mut::<block_padding::AnsiX923>(data),
                    Padding::Iso7816 => encryptor.encrypt_padded_vec_mut::<block_padding::Iso7816>(data),
                    Padding::NoPadding => encryptor.encrypt_padded_vec_mut::<block_padding::NoPadding>(data),
                }
            }
        }
    };
}

define_encryptor_impl!(
    EncryptorAdapterAes128,
    Aes128,
);

define_encryptor_impl!(
    EncryptorAdapterAes192,
    Aes192,
);

define_encryptor_impl!(
    EncryptorAdapterAes256,
    Aes256,
);

macro_rules! define_ecb_encryptor_impl {
    (
        $name:tt,
        $cipher:ident,
    ) => {
        struct $name {
            encryptor: ecb::Encryptor<$cipher>,
            padding: Padding,
        }

        impl $name {
            pub fn new(key: Vec<u8>, padding: Padding) -> Self {
                let key_ga = GenericArray::from_slice(&key);
                let encryptor = ecb::Encryptor::<$cipher>::new(key_ga);

                Self {
                    encryptor,
                    padding
                }
            }
        }
    

        impl EncryptorAdapter for $name {
            fn encrypt_vec(&self, data: &[u8]) -> Vec<u8> {
                let encryptor = (&self.encryptor).clone();
                match self.padding {
                    Padding::PKCS7 => encryptor.encrypt_padded_vec_mut::<Pkcs7>(data),
                    Padding::ZeroPadding => encryptor.encrypt_padded_vec_mut::<block_padding::ZeroPadding>(data),
                    Padding::Iso10126 => encryptor.encrypt_padded_vec_mut::<block_padding::Iso10126>(data),
                    Padding::AnsiX923 => encryptor.encrypt_padded_vec_mut::<block_padding::AnsiX923>(data),
                    Padding::Iso7816 => encryptor.encrypt_padded_vec_mut::<block_padding::Iso7816>(data),
                    Padding::NoPadding => encryptor.encrypt_padded_vec_mut::<block_padding::NoPadding>(data),
                }
            }
        }
    };
}

define_ecb_encryptor_impl!(
    EncryptorAdapterAesEcb128,
    Aes128,
);

define_ecb_encryptor_impl!(
    EncryptorAdapterAesEcb192,
    Aes192,
);

define_ecb_encryptor_impl!(
    EncryptorAdapterAesEcb256,
    Aes256,
);

macro_rules! define_ecb_decryptor_impl {
    (
        $name:tt,
        $cipher:ident,
    ) => {
        struct $name {
            decryptor: ecb::Decryptor<$cipher>,
            padding: Padding,
        }

        impl $name {
            pub fn new(key: Vec<u8>, padding: Padding) -> Self {
                let key_ga = GenericArray::from_slice(&key);
                let decryptor = ecb::Decryptor::<$cipher>::new(key_ga);

                Self {
                    decryptor,
                    padding
                }
            }
        }
    

        impl DecryptorAdapter for $name {
            fn decrypt_vec(&self, data: &[u8]) -> Result<Vec<u8>, UnpadError> {
                let decryptor = self.decryptor.clone();
                match self.padding {
                    Padding::PKCS7 => decryptor.decrypt_padded_vec_mut::<Pkcs7>(data),
                    Padding::ZeroPadding => decryptor.decrypt_padded_vec_mut::<block_padding::ZeroPadding>(data),
                    Padding::Iso10126 => decryptor.decrypt_padded_vec_mut::<block_padding::Iso10126>(data),
                    Padding::AnsiX923 => decryptor.decrypt_padded_vec_mut::<block_padding::AnsiX923>(data),
                    Padding::Iso7816 => decryptor.decrypt_padded_vec_mut::<block_padding::Iso7816>(data),
                    Padding::NoPadding => decryptor.decrypt_padded_vec_mut::<block_padding::NoPadding>(data),
                }
            }
        }
    };
}

define_ecb_decryptor_impl!(
    DecryptorAdapterAesEcb128,
    Aes128,
);

define_ecb_decryptor_impl!(
    DecryptorAdapterAesEcb192,
    Aes192,
);

define_ecb_decryptor_impl!(
    DecryptorAdapterAesEcb256,
    Aes256,
);
