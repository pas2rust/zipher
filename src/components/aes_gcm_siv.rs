use aes_gcm_siv::{
    Aes256GcmSiv, KeyInit,
    aead::{Aead, generic_array::GenericArray},
};

use kenzu::M_Builder;
use mokuya::components::error::Error;
use rand::Rng;

#[derive(Debug, PartialEq, Default)]
pub enum AesError {
    #[default]
    InvalidKeyLenght,
    EncryptFailed,
    DecryptFailed,
    HexDecodeFailed,
}

fn aes_err<T: ToString>(kind: AesError, code: u8) -> impl FnOnce(T) -> AesErr {
    move |err: T| {
        let mut error = AesErr::new();
        error.description(err.to_string()).kind(kind).code(code);
        error
    }
}

pub type AesKey = [u8; 32];
pub type AesNonce = [u8; 12];
pub type AesErr = Error<AesError>;

#[derive(Debug, M_Builder)]
pub struct Aes {
    #[set(value = rand::rng().random::<AesKey>())]
    key: AesKey,
    nonce: AesNonce,
    target: Vec<u8>,
    ciphertext: String,
}

#[derive(Debug)]
pub struct AesDecrypt(Vec<u8>);

impl AesDecrypt {
    pub fn to_string(&self) -> String {
        String::from_utf8_lossy(&self.0).into_owned()
    }
}

macro_rules! key_and_nonce {
    ($key:expr, $nonce:expr) => {{
        let key_gen_array = GenericArray::from_slice($key);
        let nonce_gen_array = GenericArray::from_slice($nonce);

        (key_gen_array, nonce_gen_array)
    }};
}

impl Aes {
    pub fn try_key<T: Into<Vec<u8>>>(&mut self, new: T) -> Result<&mut Self, AesErr> {
        let new_bytes: Vec<u8> = new.into();

        let key: [u8; 32] = new_bytes.try_into().map_err(|_| {
            let mut error = AesErr::new();
            error
                .description("Key must be 256 bits (32 bytes)")
                .kind(AesError::InvalidKeyLenght)
                .code(1);
            error
        })?;

        Ok(self.key(key))
    }

    pub fn encrypt(&mut self) -> Result<String, AesErr> {
        self.nonce(rand::rng().random::<AesNonce>());
        let (key, nonce) = key_and_nonce!(&self.key, &self.nonce);
        let ciphertext = Aes256GcmSiv::new(key)
            .encrypt(nonce, self.target.as_ref())
            .map_err(aes_err(AesError::EncryptFailed, 1))?;
        let ciphertext = hex::encode(ciphertext);

        self.ciphertext(ciphertext.clone());
        Ok(ciphertext)
    }
    pub fn decrypt(&self) -> Result<AesDecrypt, AesErr> {
        let (key, nonce) = key_and_nonce!(&self.key, &self.nonce);
        let ciphertext =
            hex::decode(&self.ciphertext).map_err(aes_err(AesError::HexDecodeFailed, 3))?;
        let decrypted = Aes256GcmSiv::new(key)
            .decrypt(nonce, ciphertext.as_ref())
            .map_err(aes_err(AesError::DecryptFailed, 2))?;

        Ok(AesDecrypt(decrypted))
    }
}
