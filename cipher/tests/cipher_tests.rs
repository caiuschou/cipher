use block_padding::Iso10126;
use libcipher::{Algorithm, Mode, Cipher, Padding};

#[test]
fn test_encrypt_aes_pkcs7_cbc() {
    let data = b"Hello, World!";
    let cipher = Cipher::new(
        Algorithm::AES,
        Mode::CBC,
        None,
        vec![0; 16],
        Some(vec![0; 16]),
    ).unwrap();

    let encrypted_data = cipher.encrypt(data);
    assert_eq!(hex::encode(encrypted_data), "8652626463653fecd2edf9db746a27f3", "Encoded data does not match expected value.");
}

#[test]
fn test_encrypt_aes_iso10126_cbc() {
    let data = b"Hello, World!";
    let cipher = Cipher::new(
        Algorithm::AES,
        Mode::CBC,
        Some(Padding::Iso10126),
        vec![0; 16],
        Some(vec![0; 16]),
    ).unwrap();

    let encrypted_data = cipher.encrypt(data);
    assert_eq!(hex::encode(encrypted_data), "8652626463653fecd2edf9db746a27f3", "Encoded data does not match expected value.");
}

#[test]
fn test_encrypt_aes_ecb() {
    let data = b"Hello, World!";
    let cipher = Cipher::new(
        Algorithm::AES,
        Mode::ECB,
        None,
        vec![0; 16],
        None,
    ).unwrap();

    let encrypted_data = cipher.encrypt(data);
    assert!(!encrypted_data.is_empty(), "Encryption failed, data is empty");
}