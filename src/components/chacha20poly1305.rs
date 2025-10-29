use std::{error::Error as StdError, fmt};

use chacha20poly1305::{
    ChaCha20Poly1305, KeyInit,
    aead::{Aead, generic_array::GenericArray},
    consts::{U12, U32},
};
use kenzu::Builder;
use rand::Rng;

#[derive(Debug)]
pub enum ChaChaError {
    ChaCha(chacha20poly1305::Error),
    Hex(hex::FromHexError),
    TryFrom(std::array::TryFromSliceError),
    Utf8(std::string::FromUtf8Error),
    Other(String),
}

impl fmt::Display for ChaChaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ChaChaError::ChaCha(_) => write!(f, "ChaCha20Poly1305 error"),
            ChaChaError::Hex(e) => write!(f, "hex decode error: {}", e),
            ChaChaError::TryFrom(e) => write!(f, "slice->array conversion error: {}", e),
            ChaChaError::Utf8(e) => write!(f, "utf8 error: {}", e),
            ChaChaError::Other(s) => write!(f, "other: {}", s),
        }
    }
}

impl From<Vec<u8>> for ChaChaError {
    fn from(v: Vec<u8>) -> Self {
        match String::from_utf8(v) {
            Ok(s) => ChaChaError::Other(s),
            Err(e) => ChaChaError::Other(format!("non-utf8 bytes: {:?}", e.into_bytes())),
        }
    }
}

impl StdError for ChaChaError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            ChaChaError::Hex(e) => Some(e),
            ChaChaError::TryFrom(e) => Some(e),
            ChaChaError::Utf8(e) => Some(e),
            _ => None,
        }
    }
}

impl From<chacha20poly1305::Error> for ChaChaError {
    fn from(e: chacha20poly1305::Error) -> Self {
        ChaChaError::ChaCha(e)
    }
}
impl From<hex::FromHexError> for ChaChaError {
    fn from(e: hex::FromHexError) -> Self {
        ChaChaError::Hex(e)
    }
}
impl From<std::array::TryFromSliceError> for ChaChaError {
    fn from(e: std::array::TryFromSliceError) -> Self {
        ChaChaError::TryFrom(e)
    }
}
impl From<std::string::FromUtf8Error> for ChaChaError {
    fn from(e: std::string::FromUtf8Error) -> Self {
        ChaChaError::Utf8(e)
    }
}
impl From<String> for ChaChaError {
    fn from(s: String) -> Self {
        ChaChaError::Other(s)
    }
}
impl From<&str> for ChaChaError {
    fn from(s: &str) -> Self {
        ChaChaError::Other(s.to_string())
    }
}

#[derive(Debug, Builder)]
pub struct ChaCha {
    #[opt(default = hex::encode(rand::rng().random::<[u8; 32]>()))]
    pub key: String,
    #[opt(default = hex::encode(rand::rng().random::<[u8; 12]>()))]
    pub nonce: String,
    #[opt(pattern = "^.+$", err = "Build should fail for an empty target")]
    pub target: Vec<u8>,
    pub ciphertext: String,
}

#[derive(Debug)]
pub struct ChaChaDecrypt(Vec<u8>);

impl fmt::Display for ChaChaDecrypt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", String::from_utf8_lossy(&self.0))
    }
}

type KeyGA = GenericArray<u8, U32>;
type NonceGA = GenericArray<u8, U12>;

fn key_and_nonce_from_hex(key_hex: &str, nonce_hex: &str) -> Result<(KeyGA, NonceGA), ChaChaError> {
    let key_bytes = hex::decode(key_hex).map_err(ChaChaError::from)?;
    let nonce_bytes = hex::decode(nonce_hex).map_err(ChaChaError::from)?;
    let key_arr: [u8; 32] = key_bytes.as_slice().try_into().map_err(ChaChaError::from)?;
    let nonce_arr: [u8; 12] = nonce_bytes
        .as_slice()
        .try_into()
        .map_err(ChaChaError::from)?;
    let key_ga = *GenericArray::from_slice(&key_arr);
    let nonce_ga = *GenericArray::from_slice(&nonce_arr);

    Ok((key_ga, nonce_ga))
}

impl ChaCha {
    pub fn encrypt(&mut self) -> Result<String, ChaChaError> {
        let (key, nonce) = key_and_nonce_from_hex(&self.key, &self.nonce)?;
        let cipher = ChaCha20Poly1305::new(&key);

        let ciphertext_bytes = cipher.encrypt(&nonce, self.target.as_ref())?;
        let ciphertext_hex = hex::encode(ciphertext_bytes);

        self.ciphertext = ciphertext_hex.clone();
        Ok(ciphertext_hex)
    }

    pub fn decrypt(&self) -> Result<ChaChaDecrypt, ChaChaError> {
        let (key, nonce) = key_and_nonce_from_hex(&self.key, &self.nonce)?;
        let cipher = ChaCha20Poly1305::new(&key);

        let ciphertext_bytes = hex::decode(&self.ciphertext)?;
        let decrypted = cipher.decrypt(&nonce, ciphertext_bytes.as_ref())?;
        Ok(ChaChaDecrypt(decrypted))
    }
}
