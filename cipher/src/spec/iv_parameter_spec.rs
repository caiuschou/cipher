
pub struct IvParameterSpec {
    pub iv: Vec<u8>,
}

impl IvParameterSpec {
    pub fn new(iv: Vec<u8>) -> Self {
        IvParameterSpec { iv }
    }

    pub fn iv(&self) -> Vec<u8> {
        self.iv.clone()
    }
}