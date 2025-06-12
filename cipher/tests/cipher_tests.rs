use cipher::{Algorithm, Mode, Cipher};

#[test]
fn test_encrypt_aes() {
    let data = b"Hello, World!";
    let encrypt = Cipher::new(
        Algorithm::AES,
        Mode::CBC,
        vec![0; 16], // Example key
        Some(vec![0; 16]), // Example IV
    );
    let encrypted_data = encrypt.encrypt(data);
    assert_eq!(encrypted_data, data);
}