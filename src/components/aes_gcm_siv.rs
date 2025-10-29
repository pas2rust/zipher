use std::{error::Error as StdError, fmt};

use aes_gcm_siv::{
    Aes256GcmSiv, KeyInit,
    aead::{
        Aead,
        generic_array::{
            GenericArray,
            typenum::{U12, U32},
        },
    },
};

use kenzu::Builder;
use rand::Rng;

#[derive(Debug)]
pub enum AesError {
    Aead(aes_gcm_siv::Error),
    Hex(hex::FromHexError),
    TryFrom(std::array::TryFromSliceError),
    Utf8(std::string::FromUtf8Error),
    Other(String),
}

impl fmt::Display for AesError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AesError::Aead(e) => write!(f, "AEAD error: {}", e),
            AesError::Hex(e) => write!(f, "hex decode error: {}", e),
            AesError::TryFrom(e) => write!(f, "slice->array conversion error: {}", e),
            AesError::Utf8(e) => write!(f, "utf8 error: {}", e),
            AesError::Other(s) => write!(f, "other: {}", s),
        }
    }
}

impl StdError for AesError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            AesError::Aead(_) => None,
            AesError::Hex(e) => Some(e),
            AesError::TryFrom(e) => Some(e),
            AesError::Utf8(e) => Some(e),
            AesError::Other(_) => None,
        }
    }
}

impl From<aes_gcm_siv::Error> for AesError {
    fn from(e: aes_gcm_siv::Error) -> Self {
        AesError::Aead(e)
    }
}
impl From<hex::FromHexError> for AesError {
    fn from(e: hex::FromHexError) -> Self {
        AesError::Hex(e)
    }
}
impl From<std::array::TryFromSliceError> for AesError {
    fn from(e: std::array::TryFromSliceError) -> Self {
        AesError::TryFrom(e)
    }
}
impl From<std::string::FromUtf8Error> for AesError {
    fn from(e: std::string::FromUtf8Error) -> Self {
        AesError::Utf8(e)
    }
}
impl From<String> for AesError {
    fn from(s: String) -> Self {
        AesError::Other(s)
    }
}
impl From<&str> for AesError {
    fn from(s: &str) -> Self {
        AesError::Other(s.to_string())
    }
}

impl From<Vec<u8>> for AesError {
    fn from(v: Vec<u8>) -> Self {
        match String::from_utf8(v) {
            Ok(s) => AesError::Other(s),
            Err(e) => AesError::Other(format!("non-utf8 bytes: {:?}", e.into_bytes())),
        }
    }
}

#[derive(Builder, Debug)]
pub struct AesGcmSiv {
    #[opt(default = hex::encode(rand::rng().random::<[u8; 32]>()))]
    pub key: String,
    #[opt(default = hex::encode(rand::rng().random::<[u8; 12]>()))]
    pub nonce: String,
    #[opt(pattern = "^.+$", err = "Build should fail for an empty target")]
    pub target: Vec<u8>,
    pub ciphertext: String,
}

#[derive(Debug)]
pub struct AesDecrypt(Vec<u8>);

impl fmt::Display for AesDecrypt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", String::from_utf8_lossy(&self.0))
    }
}
type KeyGA = GenericArray<u8, U32>;
type NonceGA = GenericArray<u8, U12>;

fn key_and_nonce_from_hex(key_hex: &str, nonce_hex: &str) -> Result<(KeyGA, NonceGA), AesError> {
    let key_bytes = hex::decode(key_hex).map_err(AesError::from)?;
    let nonce_bytes = hex::decode(nonce_hex).map_err(AesError::from)?;
    let key_arr: [u8; 32] = key_bytes.as_slice().try_into().map_err(AesError::from)?;
    let nonce_arr: [u8; 12] = nonce_bytes.as_slice().try_into().map_err(AesError::from)?;
    let key_ga = *GenericArray::from_slice(&key_arr);
    let nonce_ga = *GenericArray::from_slice(&nonce_arr);

    Ok((key_ga, nonce_ga))
}

impl AesGcmSiv {
    pub fn encrypt(&mut self) -> Result<String, AesError> {
        let (key, nonce) = key_and_nonce_from_hex(&self.key, &self.nonce)?;
        let ciphertext_vec = Aes256GcmSiv::new(&key)
            .encrypt(&nonce, self.target.as_ref())
            .map_err(AesError::from)?;
        let ciphertext = hex::encode(ciphertext_vec);
        self.ciphertext = ciphertext.clone();
        Ok(ciphertext)
    }

    pub fn decrypt(&self) -> Result<AesDecrypt, AesError> {
        let (key, nonce) = key_and_nonce_from_hex(&self.key, &self.nonce)?;
        let ciphertext = hex::decode(&self.ciphertext).map_err(AesError::from)?;
        let decrypted = Aes256GcmSiv::new(&key)
            .decrypt(&nonce, ciphertext.as_ref())
            .map_err(AesError::from)?;
        Ok(AesDecrypt(decrypted))
    }
}
