use zipher::components::bcrypt::{Bcrypt, BcryptError};

#[test]
fn encrypt_verify() {
    let mut bcrypt = Bcrypt::new();
    bcrypt
        .password("1234567890123456789012345678901234567890")
        .encrypt()
        .unwrap();

    assert!(
        bcrypt.verify().is_ok(),
        "Password verification should succeed"
    );
}

#[test]
fn encrypt_different_passwords() {
    let mut bcrypt1 = Bcrypt::new();
    let hash1 = bcrypt1.password("password123").encrypt().unwrap();

    let mut bcrypt2 = Bcrypt::new();
    let hash2 = bcrypt2.password("different_password").encrypt().unwrap();

    assert_ne!(
        hash1, hash2,
        "Hashes for different passwords should not be equal"
    );
}

#[test]
fn verify_wrong_password() {
    let mut bcrypt = Bcrypt::new();
    bcrypt.password("correct_password").encrypt().unwrap();

    assert!(
        bcrypt.password("wrong_password").verify().is_err(),
        "Verification should fail for incorrect password"
    );

    if let Err(error) = bcrypt.password("wrong_password").verify() {
        assert_eq!(error.kind, BcryptError::VerifyFailed);
    }
}

#[test]
fn build_empty_password() {
    let mut bcrypt = Bcrypt::new();
    let result = bcrypt.password("").build();

    assert!(result.is_err(), "Build should fail for an empty password");
}
