use bcrypt::{BcryptError as RawBcryptError, DEFAULT_COST, hash, verify};
use kenzu::Builder;
use std::{error::Error as StdError, fmt};

#[derive(Debug)]
pub enum BcryptError {
    Bcrypt(RawBcryptError),
    InvalidCost(String),
    Other(String),
}

impl fmt::Display for BcryptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BcryptError::Bcrypt(e) => write!(f, "bcrypt error: {}", e),
            BcryptError::InvalidCost(s) => write!(f, "invalid cost: {}", s),
            BcryptError::Other(s) => write!(f, "other: {}", s),
        }
    }
}

impl StdError for BcryptError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            BcryptError::Bcrypt(e) => Some(e),
            _ => None,
        }
    }
}

impl From<RawBcryptError> for BcryptError {
    fn from(e: RawBcryptError) -> Self {
        BcryptError::Bcrypt(e)
    }
}

impl From<String> for BcryptError {
    fn from(s: String) -> Self {
        BcryptError::Other(s)
    }
}

impl From<&str> for BcryptError {
    fn from(s: &str) -> Self {
        BcryptError::Other(s.to_string())
    }
}

#[derive(Debug, Builder)]
pub struct Bcrypt {
    pub password: String,
    #[opt(default = DEFAULT_COST)]
    pub cost: u32,
    pub hash: String,
}

impl Bcrypt {
    pub fn encrypt(&mut self) -> Result<String, BcryptError> {
        if self.cost < 4 || self.cost > 31 {
            return Err(BcryptError::InvalidCost(format!(
                "cost must be between 4 and 31, got {}",
                self.cost
            )));
        }

        let h = hash(&self.password, self.cost)?;
        self.hash = h.clone();
        Ok(h)
    }

    pub fn verify(&self) -> Result<(), BcryptError> {
        if self.hash.is_empty() {
            return Err(BcryptError::Other("empty stored hash".into()));
        }

        let valid = verify(&self.password, &self.hash)?;
        if valid {
            Ok(())
        } else {
            Err(BcryptError::Other("invalid password".into()))
        }
    }

    pub fn verify_hash(&self, other_hash: &str) -> Result<(), BcryptError> {
        let valid = verify(&self.password, other_hash)?;
        if valid {
            Ok(())
        } else {
            Err(BcryptError::Other("invalid password".into()))
        }
    }
}
