use argon2::{
    Algorithm, Argon2, Params, PasswordHash, PasswordHasher, PasswordVerifier, Version,
    password_hash::SaltString,
};

use kenzu::M_Builder;
use mokuya::components::error::Error;
use rand::Rng;

#[derive(Debug, PartialEq, Default)]
pub enum ArgonError {
    #[default]
    InvalidParams,
    HashFailed,
    VerifyFailed,
    SaltEncodeFailed,
    InvalidHash,
}

pub type ArgonErr = Error<ArgonError>;

fn argon_err<T: ToString>(kind: ArgonError, code: u8) -> impl FnOnce(T) -> ArgonErr {
    move |err: T| {
        let mut error = ArgonErr::new();
        error.description(err.to_string()).kind(kind).code(code);
        error
    }
}

#[derive(Debug, M_Builder)]
pub struct Argon {
    #[set(value = rand::rng().random::<[u8; 32]>())]
    salt: Vec<u8>,
    #[set(value = hex::encode(rand::rng().random::<[u8; 32]>()))]
    secret: String,
    #[set(value = Algorithm::Argon2id)]
    algorithm: Algorithm,
    #[set(value = Version::V0x13)]
    version: Version,
    #[set(value = Params::new(
        6400,
        4,
        4,
        32.into()
    ).expect("Params error"))]
    params: Params,
    #[build(pattern = "^.+$", err = "Build should fail for an empty password")]
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
        )
        .map_err(argon_err(ArgonError::InvalidParams, 1))?;

        let base_64 = SaltString::encode_b64(&self.salt)
            .map_err(argon_err(ArgonError::SaltEncodeFailed, 2))?;

        match ctx.hash_password(self.password.as_bytes(), base_64.as_salt()) {
            Ok(password_hash) => {
                let hash = password_hash.serialize().to_string();
                self.hash(&hash);
                Ok(hash)
            }
            Err(err) => Err(argon_err(ArgonError::HashFailed, 3)(err)),
        }
    }

    pub fn verify(&self) -> Result<(), ArgonErr> {
        let ctx = Argon2::new_with_secret(
            self.secret.as_bytes(),
            self.algorithm,
            self.version,
            self.params.clone(),
        )
        .map_err(argon_err(ArgonError::InvalidParams, 1))?;

        let password_hash =
            PasswordHash::new(&self.hash).map_err(argon_err(ArgonError::InvalidHash, 4))?;

        ctx.verify_password(self.password.as_bytes(), &password_hash)
            .map_err(argon_err(ArgonError::VerifyFailed, 5))
    }
}
