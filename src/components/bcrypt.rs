use bcrypt::{DEFAULT_COST, hash, verify};
use kenzu::M_Builder;
use mokuya::components::error::Error;

#[derive(Debug, PartialEq, Default)]
pub enum BcryptError {
    #[default]
    InvalidCost,
    HashFailed,
    VerifyFailed,
    InvalidHash,
}

pub type BcryptErr = Error<BcryptError>;

fn bcrypt_err<T: ToString>(kind: BcryptError, code: u8) -> impl FnOnce(T) -> BcryptErr {
    move |err: T| {
        let mut error = BcryptErr::new();
        error.description(err.to_string()).kind(kind).code(code);
        error
    }
}

#[derive(Debug, M_Builder)]
pub struct Bcrypt {
    #[build(pattern = "^.+$", err = "Password cannot be empty")]
    password: String,
    #[set(value = DEFAULT_COST)]
    cost: u32,
    hash: String,
}

impl Bcrypt {
    pub fn encrypt(&mut self) -> Result<String, BcryptErr> {
        hash(&self.password, self.cost)
            .map(|hash| {
                self.hash(&hash);
                hash
            })
            .map_err(bcrypt_err(BcryptError::HashFailed, 1))
    }

    pub fn verify(&self) -> Result<(), BcryptErr> {
        verify(&self.password, &self.hash)
            .map_err(bcrypt_err(BcryptError::VerifyFailed, 2))
            .and_then(|valid| {
                if valid {
                    Ok(())
                } else {
                    Err(bcrypt_err(BcryptError::VerifyFailed, 3)("Invalid password"))
                }
            })
    }
}
