use zipher::components::chacha20poly1305::{ChaCha, ChaChaError};
use zipher::mokuya::components::error::Error;

#[test]
fn encrypt_decrypt() -> Result<(), Error<ChaChaError>> {
    let mut chacha = ChaCha::new();
    let encrypt = chacha.target("test").encrypt()?;
    let decrypt = chacha.decrypt()?.to_string();

    assert_eq!(decrypt, "test");
    assert_ne!(encrypt, "test");
    Ok(())
}

#[test]
fn decrypt_without_encrypt() {
    let chacha = ChaCha::new();
    let result = chacha.decrypt();
    assert!(
        result.is_err(),
        "Decryption should fail if no encrypted data exists"
    );

    if let Err(error) = result {
        assert_eq!(error.kind, ChaChaError::DecryptFailed);
    }
}

#[test]
fn encrypt_decrypt_large_data() -> Result<(), Error<ChaChaError>> {
    let mut chacha = ChaCha::new();
    let large_text = "A".repeat(10_000);

    chacha.target(large_text.clone()).encrypt()?;
    let decrypt = chacha.decrypt()?.to_string();

    assert_eq!(decrypt, large_text);
    Ok(())
}
