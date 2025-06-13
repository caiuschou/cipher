use libcipher::{Algorithm, Mode, Cipher};

#[test]
fn test_encrypt_aes_cbc() {
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

#[test]
fn test_encrypt_aes_ecb() {
    let data = b"Hello, World!";
    let cipher = Cipher::new(
        Algorithm::AES,
        Mode::ECB,
        vec![0; 16],
        None,
    ).unwrap();

    let encrypted_data = cipher.encrypt(data);
    assert!(!encrypted_data.is_empty(), "Encryption failed, data is empty");
}