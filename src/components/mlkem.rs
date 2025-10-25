use hex;
use kenzu::Builder;
use pqcrypto_mlkem::mlkem1024::*;
use pqcrypto_traits::kem::{Ciphertext, PublicKey, SecretKey, SharedSecret};
use std::{error::Error as StdError, fmt};

#[derive(Debug, PartialEq, Default)]
pub enum MlKemError {
    #[default]
    KeyGenerationFailed,
    EncapsulationFailed,
    DecapsulationFailed,
    HexEncodingFailed,
    HexDecodingFailed,
    Other(String),
}

impl fmt::Display for MlKemError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MlKemError::KeyGenerationFailed => write!(f, "key generation failed"),
            MlKemError::EncapsulationFailed => write!(f, "encapsulation failed"),
            MlKemError::DecapsulationFailed => write!(f, "decapsulation failed"),
            MlKemError::HexEncodingFailed => write!(f, "hex encoding failed"),
            MlKemError::HexDecodingFailed => write!(f, "hex decoding failed"),
            MlKemError::Other(s) => write!(f, "other: {}", s),
        }
    }
}

impl StdError for MlKemError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        None
    }
}

impl From<hex::FromHexError> for MlKemError {
    fn from(_: hex::FromHexError) -> Self {
        MlKemError::HexDecodingFailed
    }
}
impl From<String> for MlKemError {
    fn from(s: String) -> Self {
        MlKemError::Other(s)
    }
}
impl From<&str> for MlKemError {
    fn from(s: &str) -> Self {
        MlKemError::Other(s.to_string())
    }
}

pub type MlKemErr = MlKemError;
pub type MlKemPublicKeyType = Vec<u8>;
pub type MlKemSecretKeyType = Vec<u8>;

fn keys() -> (MlKemPublicKeyType, MlKemSecretKeyType) {
    let (pk, sk) = keypair();
    (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
}

#[derive(Builder)]
pub struct MlKem {
    #[opt(default = keys())]
    pub pk_and_sk: (MlKemPublicKeyType, MlKemSecretKeyType),
    pub ciphertext: Option<String>,
    pub shared_secret: Option<String>,
}

impl MlKem {
    pub fn encapsulate(&mut self) -> Result<String, MlKemErr> {
        let (pk, _) = &self.pk_and_sk;
        let pk = PublicKey::from_bytes(pk).map_err(|_| MlKemError::KeyGenerationFailed)?;
        let (shared_secret, ciphertext) = encapsulate(&pk);
        self.ciphertext = Some(hex::encode(ciphertext.as_bytes()));
        self.shared_secret = Some(hex::encode(shared_secret.as_bytes()));
        Ok(self.ciphertext.clone().unwrap())
    }

    pub fn decapsulate(&mut self, ciphertext_hex: &str) -> Result<String, MlKemErr> {
        let (_, sk) = &self.pk_and_sk;
        let sk = SecretKey::from_bytes(sk).map_err(|_| MlKemError::KeyGenerationFailed)?;
        let ciphertext_bytes = hex::decode(ciphertext_hex)?;
        let ciphertext = Ciphertext::from_bytes(&ciphertext_bytes)
            .map_err(|_| MlKemError::DecapsulationFailed)?;
        let shared_secret = decapsulate(&ciphertext, &sk);
        let shared_secret_hex = hex::encode(shared_secret.as_bytes());
        self.shared_secret = Some(shared_secret_hex.clone());
        Ok(shared_secret_hex)
    }
}
