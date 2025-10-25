use zipher::components::argon2::{Argon, ArgonError, ArgonPassword};

#[test]
fn encrypt_verify() -> Result<(), ArgonError> {
    let mut argon = Argon::new().password(ArgonPassword::new(
        "1234567890123456789012345678901234567890",
    )?);
    argon.encrypt()?;

    assert!(
        argon.verify().is_ok(),
        "Password verification should succeed"
    );

    Ok(())
}

#[test]
fn encrypt_different_passwords() -> Result<(), ArgonError> {
    let argon1 = Argon::new();
    let hash1 = argon1
        .password(ArgonPassword::new("password123")?)
        .encrypt()?;

    let argon2 = Argon::new();
    let hash2 = argon2
        .password(ArgonPassword::new("different_password")?)
        .encrypt()?;

    assert_ne!(
        hash1, hash2,
        "Hashes for different passwords should not be equal"
    );

    Ok(())
}

#[test]
fn verify_wrong_password() -> Result<(), ArgonError> {
    let mut argon = Argon::new().password(ArgonPassword::new("correct_password")?);
    argon.encrypt()?;

    let res = argon
        .password(ArgonPassword::new("wrong_password")?)
        .verify();

    assert!(
        res.is_err(),
        "Verification should fail for incorrect password"
    );

    Ok(())
}
