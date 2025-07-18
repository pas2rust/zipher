use zipher::components::aes_gcm_siv::{Aes, AesError};
use zipher::mokuya::components::error::Error;

#[test]
fn encrypt_decrypt() -> Result<(), Error<AesError>> {
    let mut aes = Aes::new();
    let encrypt = aes.target("test").encrypt()?;
    let decrypt = aes.decrypt()?.to_string();

    assert_eq!(decrypt, "test");
    assert_ne!(encrypt, "test");
    Ok(())
}

#[test]
fn decrypt_without_encrypt() {
    let aes = Aes::new();
    let result = aes.decrypt();
    assert!(
        result.is_err(),
        "Decryption should fail if no encrypted data exists"
    );

    if let Err(error) = result {
        assert_eq!(error.kind, AesError::DecryptFailed);
    }
}

#[test]
fn encrypt_decrypt_large_data() -> Result<(), Error<AesError>> {
    let mut aes = Aes::new();
    let large_text = "A".repeat(10_000);

    aes.target(large_text.clone()).encrypt()?;
    let decrypt = aes.decrypt()?.to_string();

    assert_eq!(decrypt, large_text);
    Ok(())
}
