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
