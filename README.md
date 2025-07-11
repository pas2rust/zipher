# `zipher`

[![Crates.io](https://img.shields.io/crates/v/zipher.svg)](https://crates.io/crates/zipher)
[![Docs.rs](https://docs.rs/zipher/badge.svg)](https://docs.rs/zipher)
[![License](https://img.shields.io/crates/l/zipher.svg)](https://github.com/pas2rust/zipher/blob/main/LICENSE)

**`zipher`** is a comprehensive cryptography toolkit for Rust, providing modern encryption, password hashing, post-quantum algorithms, and JWT support in a unified API. Designed for security and ease of use.

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

### 🪙 JWT Support
- Complete JWT implementation with signing/verification
- HS256/HS384/HS512 support
- Support for other algorithms (e.g., RS256, ES256) is currently under development.

### 🛡️ Security Features
- Type-safe API design
- Sensitive data zeroization
- Compile-time feature selection

---

## ⚙️ Installation

Enable only the features you need:

```bash
cargo add zipher --features aes,chacha20,argon2,bcrypt,jwt,pqkem,pqdsa,postquantum
```


## 🚀 Usage 

### 🔐 AES-GCM-SIV Encryption Example

This example demonstrates how to use the AES-GCM-SIV authenticated encryption mode to securely encrypt and decrypt data.
The AES-GCM-SIV mode provides nonce misuse resistance, meaning it is safer even if nonces are accidentally reused.

```rust
use zipher::components::aes_gcm_siv::{Aes, AesError};
use mokuya::components::error::Error;

fn main() -> Result<(), Error<AesError>> {
    // Create a new AES encryptor with a random key and nonce
    let mut aes = Aes::new();

    // Set the plaintext you want to encrypt
    aes.target("Hello, AES-GCM-SIV!");

    // Encrypt the data
    let ciphertext = aes.encrypt()?;
    println!("Encrypted (hex): {}", ciphertext);

    // Decrypt the ciphertext back to plaintext
    let decrypted = aes.decrypt()?.to_string();
    println!("Decrypted text: {}", decrypted);

    assert_eq!(decrypted, "Hello, AES-GCM-SIV!");
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
-  If encryption or decryption fails, errors are returned with detailed kinds.
-  Additionally, the key and nonce fields can be explicitly set to use your own cryptographic key and nonce instead of the randomly generated ones. This allows full control over encryption parameters when needed.

### 🔐 ChaCha20-Poly1305 Encryption Example

This example demonstrates how to use the ChaCha20-Poly1305 authenticated encryption mode to securely encrypt and decrypt data.
ChaCha20-Poly1305 is a fast and secure AEAD cipher suitable for many applications.

```rust
use zipher::components::chacha20poly1305::{ChaCha, ChaChaError};
use mokuya::components::error::Error;

fn main() -> Result<(), Error<ChaChaError>> {
    // Create a new ChaCha20-Poly1305 encryptor with a random key and nonce
    let mut chacha = ChaCha::new();

    // Set the plaintext you want to encrypt
    chacha.target("Hello, ChaCha20-Poly1305!");

    // Encrypt the data
    let ciphertext = chacha.encrypt()?;
    println!("Encrypted (hex): {}", ciphertext);

    // Decrypt the ciphertext back to plaintext
    let decrypted = chacha.decrypt()?.to_string();
    println!("Decrypted text: {}", decrypted);

    assert_eq!(decrypted, "Hello, ChaCha20-Poly1305!");
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
-  If encryption or decryption fails, detailed error kinds are returned.
-  Additionally, the key and nonce fields can be explicitly set to use your own cryptographic key and nonce instead of the randomly generated ones. This allows full control over encryption parameters when needed.

### 🪙 JWT Encoding and Decoding Example

This example demonstrates how to create, encode, and decode a JSON Web Token (JWT) using HMAC SHA algorithms (HS256, HS384, HS512). It includes claim setting and token expiration handling.

```rust
use zipher::components::jwt::{Jwt, JwtError, Claims};
use mokuya::components::error::Error;

fn main() -> Result<(), Error<JwtError>> {
    // Create a new JWT instance with a random key and default HS256 algorithm
    let mut jwt = Jwt::new();

    // Create claims: subject ("sub") and expiration time ("exp" in seconds)
    let mut claims = Claims::new();
    claims.sub("user123".to_string()).exp::<usize>(3600);

    // Assign claims to JWT and encode (sign) it
    jwt.claims(claims);
    let token = jwt.encode()?;
    println!("Encoded JWT: {}", token);

    // Decode (verify) the token and retrieve claims
    let decoded_claims = jwt.decode()?;
    println!("Decoded subject: {}", decoded_claims.sub);

    assert_eq!(decoded_claims.sub, "user123");
    Ok(())
}
```
### 🤔 Explanation

-  Jwt::new() creates a JWT object with a randomly generated secret key.
-  Claims represent the payload data, requiring a non-empty subject (sub) and expiration time (exp).
-  .encode() signs the token using the secret key and chosen HMAC SHA algorithm (default is HS256).
-  .decode() verifies and decodes the token, validating expiration and signature.
-  Supported algorithms: HS256, HS384, HS512 (others are not supported yet).
-  Expiration (exp) is calculated as the current UTC time plus the specified duration in seconds.
-  Errors are returned with detailed kinds if encoding or decoding fails.

### 🔑 Argon2 Password Hashing Example

This example demonstrates how to securely hash and verify passwords using Argon2id with customizable parameters and secret-based key hardening.

```rust
use zipher::components::argon2::{Argon, ArgonError};
use mokuya::components::error::Error;

fn main() -> Result<(), Error<ArgonError>> {
    // Create a new Argon2 hasher with random salt and secret
    let mut argon = Argon::new();

    // Set the password to hash
    argon.password("super_secure_password");

    // Generate the Argon2 hash
    let hash = argon.encrypt()?;
    println!("Password hash: {}", hash);

    // Verify the password against the stored hash
    argon.verify()?;
    println!("Password verified successfully!");

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
- Errors are returned with typed context if hashing or verification fails.

### 🔑 Bcrypt Password Hashing Example

This example shows how to securely hash and verify passwords using the Bcrypt algorithm.
Bcrypt is a widely used password hashing function that is intentionally slow to resist brute-force attacks.

```rs
use zipher::components::bcrypt::{Bcrypt, BcryptError};
use mokuya::components::error::Error;

fn main() -> Result<(), Error<BcryptError>> {
    // Create a new Bcrypt instance with default cost
    let mut bcrypt = Bcrypt::new();

    // Set the password to be hashed
    bcrypt.password("my_secure_password");

    // Hash the password
    let hash = bcrypt.encrypt()?;
    println!("Bcrypt Hash: {}", hash);

    // Verify the hashed password
    let result = bcrypt.verify();
    println!("Password verified: {}", result.is_ok());

    Ok(())
}
```

### 🤔 Explanation

- Bcrypt::new() creates a new hasher using the default cost (currently 12).
- .password() sets the plaintext password to hash.
- .encrypt() hashes the password and stores the resulting hash internally.
- .verify() checks whether the stored hash matches the current password.
- If verification fails, an error with kind BcryptError::VerifyFailed is returned.

### 🧬 Post-Quantum MLDSA Signatures

MLDSA is a post-quantum digital signature scheme. This module supports both embedded and detached signatures using the [pqcrypto-mldsa] crate.

```rs
use zipher::components::mldsa::{MlDsa, MlDsaError, MlDsaErr};
use mokuya::components::error::Error;

fn main() -> Result<(), MlDsaErr> {
    // Create a new MLDSA instance with a keypair
    let mldsa = MlDsa::new();

    // Message to sign
    let message = b"Post-quantum secure message";

    // Sign the message (embedded signature)
    let signed = mldsa.sign(message)?;
    println!("Signed message (hex): {}", signed);

    // Verify and recover the message
    let verified = mldsa.verify(&signed)?;
    println!("Recovered: {}", String::from_utf8_lossy(&verified));

    Ok(())
}
```
### ✂️ Detached Signature

```rs
let mldsa = MlDsa::new();
let message = b"Detached example";

// Sign the message
let signature = mldsa.sign_detached(message)?;

// Verify signature
mldsa.verify_detached(message, &signature)?;
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
use zipher::pqcrypto_mlkem::mlkem1024_keypair;
use zipher::components::mlkem::{MlKem, MlKemErr, MlKemError, Pk, Sk};

fn main() -> Result<(), MlKemErr> {
    // Bob generates a fresh post-quantum keypair (public and secret keys)
    let (pk, sk) = mlkem1024_keypair();

    // Bob creates a MlKem instance with his keypair
    let mut bob = MlKem::new();
    bob.public_key(Pk(pk)).secret_key(Sk(sk));

    // Alice creates a MlKem instance with a default keypair
    let mut alice = MlKem::new();

    // Alice sets her public key to Bob's public key to encapsulate a secret for Bob
    alice.public_key(bob.public_key.clone());

    // Alice encapsulates a shared secret producing ciphertext and shared secret
    let ciphertext = alice.encapsulate()?;

    // Alice's shared secret (hex encoded)
    let alice_shared_secret = alice.shared_secret.clone().expect("missing");

    // Bob decapsulates ciphertext to recover the shared secret using his secret key
    let bob_shared_secret = bob.decapsulate(&ciphertext)?;

    // Both secrets must be identical for successful key exchange
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

# ❤️ Donate

[![Monero](https://img.shields.io/badge/88NKLkhZf1nTVpaSU6vwG6dwBwb9tFVSM8Lpj3YqdL1PMt8Gm7opV7aUnMYBaAC9Y6a4kfDc3fLGoMVqeSJKNphyLpLdEvC-FF6600?style=flat&logo=monero&logoColor=white)](https://github.com/pas2rust/pas2rust/blob/main/pas-monero-donate.png)
[![Bitcoin](https://img.shields.io/badge/bc1qnlayyh84e9u5pd4m9g9sf4c5zdzswvkmudmdu5-EAB300?style=flat&logo=bitcoin&logoColor=white)](https://github.com/pas2rust/pas2rust/blob/main/pas-bitcoin-donate.png)