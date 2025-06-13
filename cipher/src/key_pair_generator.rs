use crate::{Algorithm, Mode};

pub struct KeyPairGenerator {
    algorithm: Algorithm,
}

impl KeyPairGenerator {
    fn new(algorithm: Algorithm) -> KeyPairGenerator {
        KeyPairGenerator {
            algorithm
        }
    }
}