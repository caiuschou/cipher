# libcipher

A Rust implementation of the Advanced Encryption Standard (AES) for secure data encryption and decryption.

## Overview

`libcipher` provides a simple and efficient way to encrypt and decrypt data using the AES algorithm. Support for different modes of operation, such as ECB and CBC, allows you to choose the best approach for your needs.

## Features

- **AES Algorithm**: Implements the Advanced Encryption Standard for secure encryption.
- **Modes of Operation**: Supports ECB (Electronic Codebook) and CBC (Cipher Block Chaining) modes.
- **Easy to Use**: Simple API for encryption and decryption.

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
libcipher = "0.1.3"  # Replace with the latest version
```

## Example 

```rust
use libcipher::{Cipher, Algorithm, Mode};

fn main() {
    let key = b"your_secret_key".to_vec();
    let iv = None; // Use None for ECB mode

    let cipher = Cipher::new(Algorithm::AES, Mode::ECB, key, iv).unwrap();

    let data = b"Hello, world!";
    let encrypted_data = cipher.encrypt(data);
    println!("Encrypted: {:?}", encrypted_data);

    let decrypted_data = cipher.decrypt(&encrypted_data);
    println!("Decrypted: {:?}", String::from_utf8(decrypted_data).unwrap());
}
```