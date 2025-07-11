use zipher::components::argon2::{Argon, ArgonError};

#[test]
fn encrypt_verify() {
    let mut argon = Argon::new();
    argon
        .password("1234567890123456789012345678901234567890")
        .encrypt()
        .unwrap();

    assert!(
        argon.verify().is_ok(),
        "Password verification should succeed"
    );
}

#[test]
fn encrypt_different_passwords() {
    let mut argon1 = Argon::new();
    let hash1 = argon1.password("password123").encrypt().unwrap();

    let mut argon2 = Argon::new();
    let hash2 = argon2.password("different_password").encrypt().unwrap();

    assert_ne!(
        hash1, hash2,
        "Hashes for different passwords should not be equal"
    );
}

#[test]
fn verify_wrong_password() {
    let mut argon = Argon::new();
    argon.password("correct_password").encrypt().unwrap();

    assert!(
        argon.password("wrong_password").verify().is_err(),
        "Verification should fail for incorrect password"
    );

    if let Err(error) = argon.password("wrong_password").verify() {
        assert_eq!(error.kind, ArgonError::VerifyFailed);
    }
}

#[test]
fn build_empty_password() {
    let mut argon = Argon::new();
    let result = argon.password("").build();

    assert!(result.is_err(), "Build should fail for an empty password");
}
