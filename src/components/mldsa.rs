use hex;
use kenzu::M_Builder;
use mokuya::components::error::Error;
use pqcrypto_mldsa::mldsa87::*;
use pqcrypto_traits::sign::{DetachedSignature, SignedMessage};
use std::sync::LazyLock;

#[derive(Debug, PartialEq, Default)]
pub enum MlDsaError {
    #[default]
    KeyGenerationFailed,
    SigningFailed,
    VerificationFailed,
    HexEncodingFailed,
    HexDecodingFailed,
}

pub type MlDsaErr = Error<MlDsaError>;

fn mldsa_err<T: ToString>(kind: MlDsaError, code: u8) -> impl FnOnce(T) -> MlDsaErr {
    move |err: T| {
        let mut error = MlDsaErr::new();
        error.description(err.to_string()).kind(kind).code(code);
        error
    }
}

#[derive(Clone)]
pub struct Sk(pub SecretKey);
#[derive(Clone)]
pub struct Pk(pub PublicKey);

static KEYPAIR: LazyLock<(PublicKey, SecretKey)> = LazyLock::new(keypair);

impl Pk {
    pub fn get(&self) -> PublicKey {
        self.0
    }
}

impl Sk {
    pub fn get(&self) -> SecretKey {
        self.0
    }
}

impl Default for Pk {
    fn default() -> Self {
        let pk = &KEYPAIR.0;
        Self(*pk)
    }
}

impl Default for Sk {
    fn default() -> Self {
        let sk = &KEYPAIR.1;
        Self(*sk)
    }
}

#[derive(M_Builder)]
pub struct MlDsa {
    pub public_key: Pk,
    pub secret_key: Sk,
}

impl MlDsa {
    pub fn sign(&self, message: &[u8]) -> Result<String, MlDsaErr> {
        let signed_message = sign(message, &self.secret_key.get());
        Ok(hex::encode(signed_message.as_bytes()))
    }

    pub fn verify(&self, signed_message_hex: &str) -> Result<Vec<u8>, MlDsaErr> {
        let signed_message_bytes =
            hex::decode(signed_message_hex).map_err(mldsa_err(MlDsaError::HexDecodingFailed, 1))?;
        let signed_message = SignedMessage::from_bytes(&signed_message_bytes)
            .map_err(mldsa_err(MlDsaError::VerificationFailed, 2))?;
        let message = open(&signed_message, &self.public_key.get())
            .map_err(mldsa_err(MlDsaError::VerificationFailed, 3))?;
        Ok(message)
    }

    pub fn sign_detached(&self, message: &[u8]) -> Result<String, MlDsaErr> {
        let signature = detached_sign(message, &self.secret_key.get());
        Ok(hex::encode(signature.as_bytes()))
    }

    pub fn verify_detached(&self, message: &[u8], signature_hex: &str) -> Result<(), MlDsaErr> {
        let signature_bytes =
            hex::decode(signature_hex).map_err(mldsa_err(MlDsaError::HexDecodingFailed, 4))?;
        let signature = DetachedSignature::from_bytes(&signature_bytes)
            .map_err(mldsa_err(MlDsaError::VerificationFailed, 5))?;
        verify_detached_signature(&signature, message, &self.public_key.get())
            .map_err(mldsa_err(MlDsaError::VerificationFailed, 6))
    }
}
