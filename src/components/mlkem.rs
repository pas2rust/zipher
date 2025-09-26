use hex;
use kenzu::M_Builder;
use mokuya::components::error::Error;
use pqcrypto_mlkem::mlkem1024::*;
use pqcrypto_traits::kem::{Ciphertext, SharedSecret};
use std::sync::LazyLock;

#[derive(Debug, PartialEq, Default)]
pub enum MlKemError {
    #[default]
    KeyGenerationFailed,
    EncapsulationFailed,
    DecapsulationFailed,
    HexEncodingFailed,
    HexDecodingFailed,
}

pub type MlKemErr = Error<MlKemError>;

fn mlkem_err<T: ToString>(kind: MlKemError, code: u8) -> impl FnOnce(T) -> MlKemErr {
    move |err: T| {
        let mut error = MlKemErr::new();
        error.description(err.to_string()).kind(kind).code(code);
        error
    }
}

#[derive(Clone)]
pub struct Sk(pub SecretKey);

#[derive(Clone)]
pub struct Pk(pub PublicKey);

static KEYPAIR: LazyLock<(PublicKey, SecretKey)> = LazyLock::new(keypair);

impl Sk {
    pub fn get(&self) -> SecretKey {
        self.0
    }
}

impl Pk {
    pub fn get(&self) -> PublicKey {
        self.0
    }
}

impl Default for Sk {
    fn default() -> Self {
        Self(KEYPAIR.1)
    }
}

impl Default for Pk {
    fn default() -> Self {
        Self(KEYPAIR.0)
    }
}

#[derive(M_Builder)]
#[derive(Default)]
pub struct MlKem {
    pub public_key: Pk,
    pub secret_key: Sk,
    pub ciphertext: Option<String>,
    pub shared_secret: Option<String>,
}


impl MlKem {
    pub fn encapsulate(&mut self) -> Result<String, MlKemErr> {
        let (shared_secret, ciphertext) = encapsulate(&self.public_key.get());
        let ciphertext_hex = hex::encode(ciphertext.as_bytes());
        let shared_secret_hex = hex::encode(shared_secret.as_bytes());
        self.ciphertext = Some(ciphertext_hex.clone());
        self.shared_secret = Some(shared_secret_hex.clone());
        Ok(ciphertext_hex)
    }

    pub fn decapsulate(&mut self, ciphertext_hex: &str) -> Result<String, MlKemErr> {
        let ciphertext_bytes =
            hex::decode(ciphertext_hex).map_err(mlkem_err(MlKemError::HexDecodingFailed, 1))?;

        let ciphertext = Ciphertext::from_bytes(&ciphertext_bytes)
            .map_err(mlkem_err(MlKemError::DecapsulationFailed, 2))?;

        let shared_secret = decapsulate(&ciphertext, &self.secret_key.get());
        let shared_secret_hex = hex::encode(shared_secret.as_bytes());
        self.shared_secret = Some(shared_secret_hex.clone());
        Ok(shared_secret_hex)
    }
}
