use zipher::components::mlkem::{MlKem, MlKemErr, MlKemError, Pk, Sk};
use zipher::pqcrypto_mlkem::mlkem1024_keypair;

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
fn encapsulate_decapsulate_between_alice_and_bob() -> Result<(), MlKemErr> {
    let (pk, sk) = mlkem1024_keypair();
    let mut bob = MlKem::new();
    bob.public_key(Pk(pk)).secret_key(Sk(sk));
    let mut alice = MlKem::new();
    alice.public_key(bob.public_key.clone());

    let ciphertext = alice.encapsulate()?;
    let alice_shared_secret = alice.shared_secret.clone().expect("missing");
    let bob_shared_secret = bob.decapsulate(&ciphertext)?;

    assert_eq!(alice_shared_secret, bob_shared_secret);

    Ok(())
}
