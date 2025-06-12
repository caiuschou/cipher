use libcipher::{Algorithm, Mode, Cipher};

#[test]
fn test_encrypt_aes() {
    let data = b"Hello, World!";
    let cipher = Cipher::new(
        Algorithm::AES,
        Mode::CBC,
        vec![0; 16],
        Some(vec![0; 16]),
    ).unwrap();

    let encrypted_data = cipher.encrypt(data);
    assert!(!encrypted_data.is_empty(), "Encryption failed, data is empty");
}