// main.rs

use std::env;
use std::fs;
use std::io;
use std::path::Path;

use aes_gcm::{Aes256Gcm, Key, Nonce};
use rand::Rng;
use sha2::{Digest, Sha256};

fn main() -> Result<(), HandleError> {
    let args: Vec<String> = env::args().collect();

    if args.len() != 4 {
        return Err(HandleError::InvalidArgument);
    }

    let input_path = &args[1];
    let output_path = &args[2];
    let password = &args[3];

    if !Path::new(input_path).exists() {
        return Err(HandleError::InputFileNotFound);
    }

    let key = generate_key(password)?;
    let nonce = generate_nonce()?;

    let data = fs::read(input_path)?;

    let encrypted_data = encrypt_data(&key, &nonce, &data)?;

    fs::write(output_path, &encrypted_data)?;

    Ok(())
}

fn generate_key(password: &str) -> Result<Key, HandleError> {
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    let hash = hasher.finalize();
    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&hash);
    let key = Key::from_slice(&key_bytes);
    Ok(key)
}

fn generate_nonce() -> Result<Nonce, HandleError> {
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    Ok(nonce)
}

fn encrypt_data(key: &Key, nonce: &Nonce, data: &[u8]) -> Result<Vec<u8>, HandleError> {
    let cipher = Aes256Gcm::new(key);
    let encrypted_data = cipher.encrypt(nonce, data).map_err(|_| HandleError::EncryptionFailed)?;
    Ok(encrypted_data)
}

#[derive(Debug)]
enum HandleError {
    InvalidArgument,
    InputFileNotFound,
    EncryptionFailed,
    IoError(io::Error),
}

impl From<io::Error> for HandleError {
    fn from(e: io::Error) -> Self {
        HandleError::IoError(e)
    }
}
```

```rust
// Cargo.toml

[package]
name = "encryption_tool"
version = "0.1.0"
edition = "2021"

[dependencies]
aes-gcm = "0.3.0"
rand = "0.8.3"
sha2 = "0.9.2"