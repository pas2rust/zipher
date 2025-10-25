use argon2::password_hash::{Error as PwhError, PasswordHash, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};
use argon2::{PasswordHasher, PasswordVerifier};
use kenzu::Builder;
use rand::Rng;
use std::{error::Error as StdError, fmt};

#[derive(Debug)]
pub enum ArgonError {
    Argon2(argon2::Error),
    PasswordHash(PwhError),
    Other(String),
}

impl fmt::Display for ArgonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ArgonError::Argon2(e) => write!(f, "argon2 error: {}", e),
            ArgonError::PasswordHash(e) => write!(f, "password-hash error: {}", e),
            ArgonError::Other(s) => write!(f, "other: {}", s),
        }
    }
}

impl StdError for ArgonError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            ArgonError::Argon2(_) => None,
            ArgonError::PasswordHash(_) => None,
            _ => None,
        }
    }
}

impl From<argon2::Error> for ArgonError {
    fn from(e: argon2::Error) -> Self {
        ArgonError::Argon2(e)
    }
}
impl From<PwhError> for ArgonError {
    fn from(e: PwhError) -> Self {
        ArgonError::PasswordHash(e)
    }
}
impl From<String> for ArgonError {
    fn from(s: String) -> Self {
        ArgonError::Other(s)
    }
}
impl From<&str> for ArgonError {
    fn from(s: &str) -> Self {
        ArgonError::Other(s.to_string())
    }
}

pub type ArgonErr = ArgonError;

#[derive(Debug, Builder)]
pub struct Argon {
    #[opt(default = rand::rng().random::<[u8; 32]>().to_vec())]
    salt: Vec<u8>,
    #[opt(default = hex::encode(rand::rng().random::<[u8; 32]>()))]
    secret: String,
    #[opt(default = Algorithm::Argon2id)]
    algorithm: Algorithm,
    #[opt(default = Version::V0x13)]
    version: Version,
    #[opt(default = Params::new(
        64_000,
        4,
        4,
        32.into()
    ).expect("Params error"))]
    params: Params,
    password: String,
    hash: String,
}

impl Argon {
    pub fn encrypt(&mut self) -> Result<String, ArgonErr> {
        let ctx = Argon2::new_with_secret(
            self.secret.as_bytes(),
            self.algorithm,
            self.version,
            self.params.clone(),
        )?;

        let base_64 = SaltString::encode_b64(&self.salt)?;
        let password_hash = ctx.hash_password(self.password.as_bytes(), base_64.as_salt())?;
        let hash = password_hash.serialize().to_string();
        self.hash = hash.clone();
        Ok(hash)
    }

    pub fn verify(&self) -> Result<(), ArgonErr> {
        let ctx = Argon2::new_with_secret(
            self.secret.as_bytes(),
            self.algorithm,
            self.version,
            self.params.clone(),
        )?;

        let password_hash = PasswordHash::new(&self.hash)?;
        ctx.verify_password(self.password.as_bytes(), &password_hash)?;
        Ok(())
    }
}
