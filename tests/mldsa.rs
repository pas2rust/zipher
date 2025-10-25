use zipher::components::mldsa::{MlDsa, MlDsaError};

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
