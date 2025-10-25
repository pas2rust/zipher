use hex;
use kenzu::Builder;
use pqcrypto_mldsa::mldsa87::*;
use pqcrypto_traits::sign::PublicKey;
use pqcrypto_traits::sign::SecretKey;
use pqcrypto_traits::sign::{DetachedSignature, SignedMessage};
use std::{error::Error as StdError, fmt};

pub type MlDsaPublicKeyType = Vec<u8>;
pub type MlDsaSecretKeyType = Vec<u8>;

#[derive(Debug, PartialEq, Default)]
pub enum MlDsaError {
    #[default]
    KeyGenerationFailed,
    SigningFailed,
    VerificationFailed,
    HexEncodingFailed,
    HexDecodingFailed,
    Other(String),
}

impl fmt::Display for MlDsaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MlDsaError::KeyGenerationFailed => write!(f, "key generation failed"),
            MlDsaError::SigningFailed => write!(f, "signing failed"),
            MlDsaError::VerificationFailed => write!(f, "verification failed"),
            MlDsaError::HexEncodingFailed => write!(f, "hex encoding failed"),
            MlDsaError::HexDecodingFailed => write!(f, "hex decoding failed"),
            MlDsaError::Other(s) => write!(f, "other: {}", s),
        }
    }
}

impl StdError for MlDsaError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        None
    }
}

impl From<hex::FromHexError> for MlDsaError {
    fn from(_: hex::FromHexError) -> Self {
        MlDsaError::HexDecodingFailed
    }
}
impl From<String> for MlDsaError {
    fn from(s: String) -> Self {
        MlDsaError::Other(s)
    }
}
impl From<&str> for MlDsaError {
    fn from(s: &str) -> Self {
        MlDsaError::Other(s.to_string())
    }
}

fn keys() -> (MlDsaPublicKeyType, MlDsaSecretKeyType) {
    let (pk, sk) = keypair();
    let pk = pk.as_bytes().to_vec();
    let sk = sk.as_bytes().to_vec();
    (pk, sk)
}

#[derive(Builder)]
pub struct MlDsa {
    #[opt(default = keys())]
    pub pk_and_sk: (MlDsaPublicKeyType, MlDsaSecretKeyType),
}

impl MlDsa {
    pub fn sign(&self, message: &[u8]) -> Result<String, MlDsaError> {
        let (_, sk) = &self.pk_and_sk;
        let sk = SecretKey::from_bytes(sk).map_err(|_| MlDsaError::KeyGenerationFailed)?;
        let signed_message = sign(message, &sk);
        Ok(hex::encode(signed_message.as_bytes()))
    }

    pub fn verify(&self, signed_message_hex: &str) -> Result<Vec<u8>, MlDsaError> {
        let (pk, _) = &self.pk_and_sk;
        let pk = &PublicKey::from_bytes(pk).map_err(|_| MlDsaError::KeyGenerationFailed)?;
        let signed_message_bytes = hex::decode(signed_message_hex)?;
        let signed_message = SignedMessage::from_bytes(&signed_message_bytes)
            .map_err(|_| MlDsaError::VerificationFailed)?;
        let message = open(&signed_message, pk).map_err(|_| MlDsaError::VerificationFailed)?;
        Ok(message)
    }

    pub fn sign_detached(&self, message: &[u8]) -> Result<String, MlDsaError> {
        let (_, sk) = &self.pk_and_sk;
        let sk = SecretKey::from_bytes(sk).map_err(|_| MlDsaError::KeyGenerationFailed)?;
        let signature = detached_sign(message, &sk);
        Ok(hex::encode(signature.as_bytes()))
    }

    pub fn verify_detached(&self, message: &[u8], signature_hex: &str) -> Result<(), MlDsaError> {
        let (pk, _) = &self.pk_and_sk;
        let pk = &PublicKey::from_bytes(pk).map_err(|_| MlDsaError::KeyGenerationFailed)?;
        let signature_bytes = hex::decode(signature_hex)?;
        let signature = DetachedSignature::from_bytes(&signature_bytes)
            .map_err(|_| MlDsaError::VerificationFailed)?;
        verify_detached_signature(&signature, message, pk)
            .map_err(|_| MlDsaError::VerificationFailed)
    }
}
