use aes::Aes128;
use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockEncryptMut, KeyIvInit};
use block_padding::Pkcs7;

#[test]
fn test_encrypt_aes_cbc() {
    let key = GenericArray::from_slice(&[0; 16]);
    let iv = GenericArray::from_slice(&[0; 16]);
    let encryptor = cbc::Encryptor::<Aes128>::new(key, iv);
    let result = encryptor.encrypt_padded_vec_mut::<Pkcs7>(&[0; 16]);
    let result = hex::encode(result);
    assert_eq!("66e94bd4ef8a2c3b884cfa59ca342b2e9434dec2d00fdac765f00c0c11628cd1", result);
}