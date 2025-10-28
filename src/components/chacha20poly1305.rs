use std::{convert::TryInto, error::Error as StdError, fmt};

use chacha20poly1305::{
    ChaCha20Poly1305, KeyInit,
    aead::{Aead, generic_array::GenericArray},
};
use kenzu::Builder;
use rand::Rng;

pub type ChaChaKeyType = [u8; 32];
pub type ChaChaNonceType = [u8; 12];

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

pub type ChaChaErr = ChaChaError;

#[derive(Debug, Builder)]
pub struct ChaCha {
    #[opt(default = rand::rng().random::<[u8; 32]>())]
    key: ChaChaKeyType,
    #[opt(default = rand::rng().random::<[u8; 12]>())]
    pub nonce: ChaChaNonceType,
    #[opt(pattern = "^.+$", err = "Build should fail for an empty target")]
    target: Vec<u8>,
    ciphertext: String,
}

#[derive(Debug)]
pub struct ChaChaDecrypt(Vec<u8>);

impl fmt::Display for ChaChaDecrypt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", String::from_utf8_lossy(&self.0))
    }
}

macro_rules! key_and_nonce {
    ($key:expr, $nonce:expr) => {{
        let key_array = GenericArray::from_slice($key);
        let nonce_array = GenericArray::from_slice($nonce);
        (key_array, nonce_array)
    }};
}

impl ChaCha {
    pub fn try_key<T: Into<Vec<u8>>>(&mut self, new: T) -> Result<&mut Self, ChaChaErr> {
        let new_bytes: Vec<u8> = new.into();
        let key: [u8; 32] = new_bytes.try_into()?;
        self.key = key;
        Ok(self)
    }

    pub fn encrypt(&mut self) -> Result<String, ChaChaErr> {
        let (key, nonce) = key_and_nonce!(&self.key, &self.nonce);
        let cipher = ChaCha20Poly1305::new(key);

        let ciphertext_bytes = cipher.encrypt(nonce, self.target.as_ref())?;
        let ciphertext_hex = hex::encode(ciphertext_bytes);

        self.ciphertext = ciphertext_hex.clone();
        Ok(ciphertext_hex)
    }

    pub fn decrypt(&self) -> Result<ChaChaDecrypt, ChaChaErr> {
        let (key, nonce) = key_and_nonce!(&self.key, &self.nonce);
        let cipher = ChaCha20Poly1305::new(key);

        let ciphertext_bytes = hex::decode(&self.ciphertext)?;
        let decrypted = cipher.decrypt(nonce, ciphertext_bytes.as_ref())?;
        Ok(ChaChaDecrypt(decrypted))
    }
}
