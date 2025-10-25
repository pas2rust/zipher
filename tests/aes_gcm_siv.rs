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
