use crate::key::key::Key;


pub struct SecretKeySpec {
    pub algorithm: String,
    pub key: Vec<u8>,
}

impl SecretKeySpec {
    pub fn new(algorithm: String, key: Vec<u8>) -> Self {
        SecretKeySpec { algorithm, key }
    }

    pub fn algorithm(&self) -> &str {
        &self.algorithm
    }

    pub fn key(&self) -> Vec<u8> {
        self.key.clone()
    }
}

impl std::fmt::Debug for SecretKeySpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretKeySpec")
            .field("algorithm", &self.algorithm)
            .field("key", &format_args!("{} bytes", self.key.len()))
            .finish()
    }
}

impl Clone for SecretKeySpec {
    fn clone(&self) -> Self {
        SecretKeySpec {
            algorithm: self.algorithm.clone(),
            key: self.key.clone(),
        }
    }
}

impl PartialEq for SecretKeySpec {
    fn eq(&self, other: &Self) -> bool {
        self.algorithm == other.algorithm && self.key == other.key
    }
}

impl Eq for SecretKeySpec {}

impl Key for SecretKeySpec {}