use std::fs;
use rsa::{pkcs1::EncodeRsaPublicKey, pkcs8::{DecodePublicKey, LineEnding}, RsaPrivateKey, RsaPublicKey};
use rsa::pkcs8::{DecodePrivateKey, EncodePrivateKey};

#[test]
fn test_parse_public_key() {
    let public_key_content = fs::read_to_string("tests/key/public_key_pkcs1.pem").expect("Failed to read public key file");
    let public_key = RsaPublicKey::from_public_key_pem(public_key_content.as_str())
        .expect("Failed to parse public key");

    let key_output = public_key.to_pkcs1_pem(LineEnding::LF)
        .expect("Failed to encode public key to PEM format");
    
    assert!(key_output.len() > 0, "Public key PEM output does not match input");
}

#[test]
fn test_parse_private_key_pkcs8() {
    let private_key_content = fs::read_to_string("tests/key/private_key_pkcs8.pem").expect("Failed to read public key file");
    let private_key = RsaPrivateKey::from_pkcs8_pem(private_key_content.as_str())
        .expect("Failed to parse public key");

    let key_output = private_key.to_pkcs8_pem(LineEnding::LF)
        .expect("Failed to encode public key to PEM format");

    assert!(key_output.len() > 0, "Public key PEM output does not match input");
}