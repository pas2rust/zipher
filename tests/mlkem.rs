use zipher::components::mlkem::{MlKem, MlKemErr, MlKemError};

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

    if let Err(err) = result {
        assert_eq!(err.kind, MlKemError::DecapsulationFailed);
    }
}

#[test]
fn encapsulate_decapsulate_with_cloned_instance() -> Result<(), MlKemErr> {
    let mut kem_sender = MlKem::new();

    let mut kem_receiver = MlKem {
        public_key: kem_sender.public_key.clone(),
        secret_key: kem_sender.secret_key.clone(),
        ciphertext: None,
        shared_secret: None,
    };

    let ciphertext = kem_sender.encapsulate()?;
    let shared_by_sender = kem_sender
        .shared_secret
        .clone()
        .expect("sender shared secret missing");

    let shared_by_receiver = kem_receiver.decapsulate(&ciphertext)?;

    assert_eq!(
        shared_by_sender, shared_by_receiver,
        "Shared secrets should match between sender and receiver"
    );

    Ok(())
}
