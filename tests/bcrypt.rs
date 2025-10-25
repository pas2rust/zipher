use zipher::components::bcrypt::{Bcrypt, BcryptError, BcryptPassword};

#[test]
fn encrypt_verify() -> Result<(), BcryptError> {
    let mut bcrypt = Bcrypt::new();
    bcrypt
        .mut_password(BcryptPassword::new(
            "1234567890123456789012345678901234567890",
        )?)
        .encrypt()?;

    assert!(
        bcrypt.verify().is_ok(),
        "Password verification should succeed"
    );

    Ok(())
}

#[test]
fn encrypt_different_passwords() -> Result<(), BcryptError> {
    let bcrypt1 = Bcrypt::new();
    let hash1 = bcrypt1
        .password(BcryptPassword::new("password123")?)
        .encrypt()?;

    let bcrypt2 = Bcrypt::new();
    let hash2 = bcrypt2
        .password(BcryptPassword::new("different_password")?)
        .encrypt()?;

    assert_ne!(
        hash1, hash2,
        "Hashes for different passwords should not be equal"
    );

    Ok(())
}

#[test]
fn verify_wrong_password() -> Result<(), BcryptError> {
    let mut bcrypt = Bcrypt::new();
    bcrypt
        .mut_password(BcryptPassword::new("correct_password")?)
        .encrypt()?;

    bcrypt.mut_password(BcryptPassword::new("wrong_password")?);
    let res = bcrypt.verify();

    assert!(
        res.is_err(),
        "Verification should fail for incorrect password"
    );

    Ok(())
}
