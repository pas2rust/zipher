# `zipher`

[![Crates.io](https://img.shields.io/crates/v/zipher.svg)](https://crates.io/crates/zipher)
[![Docs.rs](https://docs.rs/zipher/badge.svg)](https://docs.rs/zipher)
[![License](https://img.shields.io/crates/l/zipher.svg)](https://github.com/pas2rust/zipher/blob/main/LICENSE)
![GitHub top language](https://img.shields.io/github/languages/top/pas2rust/zipher?color=orange&logo=rust&style=flat&logoColor=white)
![GitHub stars](https://img.shields.io/github/stars/pas2rust/zipher?color=success&style=flat&logo=github)
![GitHub forks](https://img.shields.io/github/forks/pas2rust/zipher?color=orange&logo=Furry%20Network&style=flat&logoColor=white)
![Tests](https://raw.githubusercontent.com/pas2rust/badges/main/zipher-tests.svg)
![Crates.io downloads](https://img.shields.io/crates/d/zipher.svg)
![GitHub last commit](https://img.shields.io/github/last-commit/pas2rust/zipher?color=ff69b4&label=update&logo=git&style=flat&logoColor=white)


**`zipher`** is a comprehensive cryptography toolkit for Rust, providing modern encryption, password hashing, post-quantum algorithms, support in a unified API. Designed for security and ease of use.

---

## 🔒 Features

### 🔐 Symmetric Encryption
- **AES-GCM-SIV**: Authenticated encryption with AES-GCM-SIV
- **ChaCha20-Poly1305**: High-performance stream cipher

### 🔑 Password Hashing
- **Argon2**: Memory-hard password hashing (winner of Password Hashing Competition)
- **bcrypt**: Adaptive hashing algorithm with salt

### ⚛️ Post-Quantum Cryptography
- **ML-KEM** (Module Lattice-based Key Encapsulation Mechanism)
- **ML-DSA** (Module Lattice-based Digital Signature Algorithm)

### 🛡️ Security Features
- Type-safe API design
- Sensitive data zeroization
- Compile-time feature selection

---

## ⚙️ Installation

Enable only the features you need:

```bash
cargo add zipher --features aes,chacha20,argon2,bcrypt,pqkem,pqdsa,postquantum
```


## 🚀 Usage 

### 🔐 AES-GCM-SIV Encryption Example

This example demonstrates how to use the AES-GCM-SIV authenticated encryption mode to securely encrypt and decrypt data.
The AES-GCM-SIV mode provides nonce misuse resistance, meaning it is safer even if nonces are accidentally reused.

```rust
use zipher::components::aes_gcm_siv::{AesError, AesGcmSiv, AesGcmSivTarget};

#[test]
fn encrypt_decrypt() -> Result<(), AesError> {
    let mut aes = AesGcmSiv::new();
    let encrypt = aes.mut_target(AesGcmSivTarget::new("test")?).encrypt()?;
    let decrypt = aes.decrypt()?.to_string();

    assert_eq!(decrypt, "test");
    assert_ne!(encrypt, "test");
    Ok(())
}

#[test]
fn decrypt_without_encrypt() {
    let aes = AesGcmSiv::new();
    let result = aes.decrypt();
    assert!(
        result.is_err(),
        "Decryption should fail if no encrypted data exists"
    );
}

#[test]
fn encrypt_decrypt_large_data() -> Result<(), AesError> {
    let mut aes = AesGcmSiv::new();
    let large_text = "A".repeat(10_000);

    aes.mut_target(AesGcmSivTarget::new(large_text.clone())?)
        .encrypt()?;
    let decrypt = aes.decrypt()?.to_string();

    assert_eq!(decrypt, large_text);
    Ok(())
}

#[test]
fn reencrypt_overwrites_previous() -> Result<(), AesError> {
    let mut aes = AesGcmSiv::new();
    let first_cipher = aes.mut_target(AesGcmSivTarget::new("first")?).encrypt()?;
    let second_cipher = aes.mut_target(AesGcmSivTarget::new("second")?).encrypt()?;
    let decrypted = aes.decrypt()?.to_string();
    assert_eq!(decrypted, "second");
    assert_ne!(first_cipher, second_cipher);

    Ok(())
}

#[test]
fn encrypt_decrypt_unicode() -> Result<(), AesError> {
    let mut aes = AesGcmSiv::new();
    let text = "Hellow, world! 🐱🔒 こんにちは";

    let cipher = aes.mut_target(AesGcmSivTarget::new(text)?).encrypt()?;
    let decrypted = aes.decrypt()?.to_string();

    assert_eq!(decrypted, text);
    assert_ne!(cipher, text);

    Ok(())
}

```

### 🤔 Explanation

-  Aes::new() generates a random 256-bit key and initializes internal state.
-  .target() sets the plaintext bytes to be encrypted.
-  .encrypt() encrypts the plaintext using AES-256-GCM-SIV, producing a hexadecimal ciphertext string.
-  .decrypt() decrypts the ciphertext back to the original plaintext bytes.
-  Internally, it uses the aes_gcm_siv crate's Aes256GcmSiv with a 12-byte nonce and 32-byte key.
-  The ciphertext is encoded in hex for easy storage or transmission.
-  If encryption or decryption fails, Errs are returned with detailed kinds.
-  Additionally, the key and nonce fields can be explicitly set to use your own cryptographic key and nonce instead of the randomly generated ones. This allows full control over encryption parameters when needed.

### 🔐 ChaCha20-Poly1305 Encryption Example

This example demonstrates how to use the ChaCha20-Poly1305 authenticated encryption mode to securely encrypt and decrypt data.
ChaCha20-Poly1305 is a fast and secure AEAD cipher suitable for many applications.

```rust
use zipher::components::chacha20poly1305::{ChaCha, ChaChaError, ChaChaTarget};

#[test]
fn encrypt_decrypt() -> Result<(), ChaChaError> {
    let mut chacha = ChaCha::new();
    chacha.mut_target(ChaChaTarget::new("test")?).encrypt()?;
    let decrypt = chacha.decrypt()?.to_string();

    assert_eq!(decrypt, "test");
    Ok(())
}

#[test]
fn decrypt_without_encrypt() -> Result<(), ChaChaError> {
    let chacha = ChaCha::new();
    let result = chacha.decrypt();

    assert!(
        result.is_err(),
        "Decryption should fail if no encrypted data exists"
    );

    Ok(())
}

#[test]
fn encrypt_decrypt_large_data() -> Result<(), ChaChaError> {
    let mut chacha = ChaCha::new();
    let large_text = "A".repeat(10_000);

    chacha
        .mut_target(ChaChaTarget::new(large_text.clone())?)
        .encrypt()?;
    let decrypt = chacha.decrypt()?.to_string();

    assert_eq!(decrypt, large_text);
    Ok(())
}

```
### 🤔 Explanation

-  ChaCha::new() generates a random 256-bit key and a random 12-byte nonce, initializing internal state.
-  .target() sets the plaintext bytes to be encrypted.
-  .encrypt() encrypts the plaintext using ChaCha20-Poly1305, producing a hexadecimal ciphertext string.
-  .decrypt() decrypts the ciphertext back to the original plaintext bytes.
-  Internally, it uses the chacha20poly1305 crate’s ChaCha20Poly1305 with a 12-byte nonce and 32-byte key.
-  The ciphertext is encoded in hex for easy storage or transmission.
-  If encryption or decryption fails, detailed Err kinds are returned.
-  Additionally, the key and nonce fields can be explicitly set to use your own cryptographic key and nonce instead of the randomly generated ones. This allows full control over encryption parameters when needed.

### 🔑 Argon2 Password Hashing Example

This example demonstrates how to securely hash and verify passwords using Argon2id with customizable parameters and secret-based key hardening.

```rust
use zipher::components::argon2::{Argon, ArgonError, ArgonPassword};

#[test]
fn encrypt_verify() -> Result<(), ArgonError> {
    let mut argon = Argon::new().password(ArgonPassword::new(
        "1234567890123456789012345678901234567890",
    )?);
    argon.encrypt()?;

    assert!(
        argon.verify().is_ok(),
        "Password verification should succeed"
    );

    Ok(())
}

#[test]
fn encrypt_different_passwords() -> Result<(), ArgonError> {
    let argon1 = Argon::new();
    let hash1 = argon1
        .password(ArgonPassword::new("password123")?)
        .encrypt()?;

    let argon2 = Argon::new();
    let hash2 = argon2
        .password(ArgonPassword::new("different_password")?)
        .encrypt()?;

    assert_ne!(
        hash1, hash2,
        "Hashes for different passwords should not be equal"
    );

    Ok(())
}

#[test]
fn verify_wrong_password() -> Result<(), ArgonError> {
    let mut argon = Argon::new().password(ArgonPassword::new("correct_password")?);
    argon.encrypt()?;

    let res = argon
        .password(ArgonPassword::new("wrong_password")?)
        .verify();

    assert!(
        res.is_err(),
        "Verification should fail for incorrect password"
    );

    Ok(())
}

```
### 🤔 Explanation
- Argon::new() creates a struct with:
  - Random 32-byte salt
  - Random secret string (hex-encoded)
  - Algorithm: Argon2id
  - Version: 0x13
  - Parameters: memory cost, parallelism, iterations, and output length
- .password("...") sets the plaintext password to be hashed.
- .encrypt() creates a password hash using the Argon2id algorithm.
- .verify() verifies the password against the stored hash.
- Internally it uses the argon2 crate with secret support for extra protection.
- The output is a standard PHC string ($argon2id$v=19$m=...) suitable for storage.
- Errs are returned with typed context if hashing or verification fails.

### 🔑 Bcrypt Password Hashing Example

This example shows how to securely hash and verify passwords using the Bcrypt algorithm.
Bcrypt is a widely used password hashing function that is intentionally slow to resist brute-force attacks.

```rust
use zipher::components::bcrypt::{Bcrypt, BcryptError, BcryptPassword};

#[test]
fn encrypt_verify() -> Result<(), BcryptError> {
    let mut bcrypt = Bcrypt::new();
    bcrypt
        .mut_password(BcryptPassword::new(
            "1234567890123456789012345678901234567890",
        )?)
        .encrypt()?;

    assert!(
        bcrypt.verify().is_ok(),
        "Password verification should succeed"
    );

    Ok(())
}

#[test]
fn encrypt_different_passwords() -> Result<(), BcryptError> {
    let bcrypt1 = Bcrypt::new();
    let hash1 = bcrypt1
        .password(BcryptPassword::new("password123")?)
        .encrypt()?;

    let bcrypt2 = Bcrypt::new();
    let hash2 = bcrypt2
        .password(BcryptPassword::new("different_password")?)
        .encrypt()?;

    assert_ne!(
        hash1, hash2,
        "Hashes for different passwords should not be equal"
    );

    Ok(())
}

#[test]
fn verify_wrong_password() -> Result<(), BcryptError> {
    let mut bcrypt = Bcrypt::new();
    bcrypt
        .mut_password(BcryptPassword::new("correct_password")?)
        .encrypt()?;

    bcrypt.mut_password(BcryptPassword::new("wrong_password")?);
    let res = bcrypt.verify();

    assert!(
        res.is_err(),
        "Verification should fail for incorrect password"
    );

    Ok(())
}

```

### 🤔 Explanation

- Bcrypt::new() creates a new hasher using the default cost (currently 12).
- .password() sets the plaintext password to hash.
- .encrypt() hashes the password and stores the resulting hash internally.
- .verify() checks whether the stored hash matches the current password.
- If verification fails, an Err with kind BcryptErr::VerifyFailed is returned.

### 🧬 Post-Quantum MLDSA Signatures

MLDSA is a post-quantum digital signature scheme. This module supports both embedded and detached signatures using the [pqcrypto-mldsa] crate.

```rs
use zipher::components::mldsa::{MlDsa, MlDsaErr};

#[test]
fn sign_and_verify_embedded_message_successfully() -> Result<(), MlDsaError> {
    let mldsa = MlDsa::new();
    let message = b"Test message for embedded signature.";

    let signed_hex = mldsa.sign(message)?;
    let verified_message = mldsa.verify(&signed_hex)?;

    assert_eq!(
        message.to_vec(),
        verified_message,
        "The verified message should match the original"
    );

    Ok(())
}

#[test]
fn sign_and_verify_detached_signature_successfully() -> Result<(), MlDsaError> {
    let mldsa = MlDsa::new();
    let message = b"Test message for detached signature.";

    let signature_hex = mldsa.sign_detached(message)?;
    mldsa.verify_detached(message, &signature_hex)?;

    Ok(())
}

#[test]
fn verify_invalid_embedded_signature_should_fail() {
    let mldsa = MlDsa::new();
    let invalid_signed_hex = "00";

    let result = mldsa.verify(invalid_signed_hex);

    assert!(
        result.is_err(),
        "Verification should fail for an invalid embedded signature"
    );
}

#[test]
fn verify_invalid_detached_signature_should_fail() {
    let mldsa = MlDsa::new();
    let message = b"Test message for invalid detached signature.";
    let invalid_signature_hex = "00";

    let result = mldsa.verify_detached(message, invalid_signature_hex);

    assert!(
        result.is_err(),
        "Verification should fail for an invalid detached signature"
    );
}

#[test]
fn sign_and_verify_with_cloned_instance() -> Result<(), MlDsaError> {
    let mldsa_sender = MlDsa::new();

    let mldsa_receiver = MlDsa {
        pk_and_sk: mldsa_sender.pk_and_sk.clone(),
    };

    let message = b"Test message for cloned instances.";

    let signed_hex = mldsa_sender.sign(message)?;
    let verified_message = mldsa_receiver.verify(&signed_hex)?;

    assert_eq!(
        message.to_vec(),
        verified_message,
        "The verified message should match the original"
    );

    Ok(())
}

```
### ✂️ Detached Signature

```rs
#[test]
fn sign_and_verify_embedded_message_successfully() -> Result<(), MlDsaError> {
    let mldsa = MlDsa::new();
    let message = b"Test message for embedded signature.";

    let signed_hex = mldsa.sign(message)?;
    let verified_message = mldsa.verify(&signed_hex)?;

    assert_eq!(
        message.to_vec(),
        verified_message,
        "The verified message should match the original"
    );

    Ok(())
}

#[test]
fn sign_and_verify_detached_signature_successfully() -> Result<(), MlDsaError> {
    let mldsa = MlDsa::new();
    let message = b"Test message for detached signature.";

    let signature_hex = mldsa.sign_detached(message)?;
    mldsa.verify_detached(message, &signature_hex)?;

    Ok(())
}
```

### 🤔 Explanation

- MlDsa::new() creates a new instance with a generated keypair (or uses a static lazy keypair by default).
- .sign() signs a message and returns the signed message as hex, embedding both the message and signature.
- .verify() takes the embedded message and returns the recovered original message bytes.
- .sign_detached() signs the message and returns a hex-encoded detached signature.
- .verify_detached() verifies the detached signature using the original message.

### 📌 Notes

- MLDSA uses pqcrypto-mldsa::mldsa87, which is a post-quantum secure scheme.
- It is safe against quantum attacks, unlike traditional RSA or ECDSA.
- You can clone and share the keypair between sender and verifier using .public_key.clone() and .secret_key.clone().

### 🧬 Post-Quantum KEM (Kyber ML-KEM 1024)

This example demonstrates a key exchange using the post-quantum Kyber ML-KEM algorithm.
Two parties—Alice and Bob—securely derive a shared secret using public-key encapsulation.

```rust
use pqcrypto_mlkem::mlkem1024::keypair as mlkem1024_keypair;
use zipher::components::mlkem::MlKemPkAndSk;
use zipher::components::mlkem::{MlKem, MlKemErr};
use zipher::pqcrypto_traits::kem::PublicKey;
use zipher::pqcrypto_traits::kem::SecretKey;

#[test]
fn encapsulate_and_decapsulate_successfully() -> Result<(), MlKemErr> {
    let mut kem = MlKem::new();
    let ciphertext = kem.encapsulate()?;
    let shared_decapsulated = kem.decapsulate(&ciphertext)?;

    let shared_original = kem.shared_secret.expect("shared secret missing");

    assert_eq!(
        shared_original, shared_decapsulated,
        "Shared secrets must match"
    );
    assert_ne!(
        ciphertext, shared_decapsulated,
        "Ciphertext should differ from shared secret"
    );

    Ok(())
}

#[test]
fn decapsulate_invalid_ciphertext_should_fail() {
    let mut kem = MlKem::new();
    let result = kem.decapsulate("00");

    assert!(
        result.is_err(),
        "Decapsulation should fail for invalid ciphertext"
    );
}

#[test]
fn encapsulate_decapsulate_between_alice_and_bob() -> Result<(), MlKemErr> {
    let (pk, sk) = mlkem1024_keypair();
    let pk = pk.as_bytes().to_vec();
    let sk = sk.as_bytes().to_vec();

    let mut bob = MlKem::new().pk_and_sk(MlKemPkAndSk::new((Vec::new(), sk))?);

    let mut alice = MlKem::new().pk_and_sk(MlKemPkAndSk::new((pk, Vec::new()))?);

    let ciphertext = alice.encapsulate()?;
    let alice_shared_secret = alice.shared_secret.clone().expect("missing");
    let bob_shared_secret = bob.decapsulate(&ciphertext)?;

    assert_eq!(alice_shared_secret, bob_shared_secret);

    Ok(())
}

```

### 🤔 Explanation

- MlKem::new() creates an instance with a default (usually static) keypair for convenience.
- Bob generates a fresh post-quantum keypair explicitly using mlkem1024_keypair() and sets it on his MlKem instance.
- Alice updates her public key to Bob’s public key so she can encapsulate a secret specifically for Bob.
- Alice calls encapsulate(), producing a ciphertext and a shared secret based on Bob’s public key.
- Bob calls decapsulate() with the ciphertext, recovering the same shared secret using his secret key.
- The shared secrets match, allowing Alice and Bob to securely share a secret over an insecure channel.
- This flow uses Kyber ML-KEM 1024, a quantum-resistant cryptographic scheme designed to protect against quantum attacks.

---

<h2 align="center">
  <strong>❤️ Donate</strong>
</h2>

<p align="center">
  <a href="https://github.com/pas2rust/pas2rust/blob/main/pas-monero-donate.png" style="text-decoration:none; color:inherit;">
    <img src="https://img.shields.io/badge/Monero%20QR-FF6600?style=flat&logo=monero&logoColor=white" alt="Monero QR"/>
  </a>
  <a href="https://github.com/pas2rust/pas2rust/blob/main/pas-bitcoin-donate.png" style="text-decoration:none; color:inherit;">
    <img src="https://img.shields.io/badge/BTC%20QR-EAB300?style=flat&logo=bitcoin&logoColor=white" alt="BTC QR"/>
  </a>
  <a href="https://revolut.me/pas2rust" style="text-decoration:none; color:inherit;">
    <img src="https://img.shields.io/badge/Revolut%20QR-Blue?style=flat&logo=revolut&logoColor=white" alt="Revolut QR"/>
  </a>
  <a href="https://wise.com/pay/me/pedroaugustos99" style="text-decoration:none; color:inherit;">
    <img src="https://img.shields.io/badge/Wise%20QR-1CA0F2?style=flat&logo=wise&logoColor=white" alt="Wise QR"/>
  </a>
</p>


---