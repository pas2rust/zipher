use chacha20poly1305::{
    ChaCha20Poly1305, KeyInit,
    aead::{Aead, generic_array::GenericArray},
};
use kenzu::M_Builder;
use mokuya::components::error::Error;
use rand::Rng;

#[derive(Debug, PartialEq, Default)]
pub enum ChaChaError {
    #[default]
    InvalidKeyLenght,
    EncryptFailed,
    DecryptFailed,
    HexDecodeFailed,
}

fn chacha_err<T: ToString>(kind: ChaChaError, code: u8) -> impl FnOnce(T) -> ChaChaErr {
    move |err: T| {
        let mut error = ChaChaErr::new();
        error.description(err.to_string()).kind(kind).code(code);
        error
    }
}

type ChaChaKey = [u8; 32];
type ChaChaNonce = [u8; 12];
type ChaChaErr = Error<ChaChaError>;

#[derive(Debug)]
pub struct ChaChaDecrypt(Vec<u8>);

impl ChaChaDecrypt {
    pub fn to_string(&self) -> String {
        String::from_utf8_lossy(&self.0).into_owned()
    }
}

#[derive(Debug, M_Builder)]
pub struct ChaCha {
    #[set(value = rand::rng().random::<ChaChaKey>())]
    key: ChaChaKey,
    nonce: ChaChaNonce,
    target: Vec<u8>,
    ciphertext: String,
}

macro_rules! chacha_key_and_nonce {
    ($key:expr, $nonce:expr) => {{
        let key_gen_array = GenericArray::from_slice($key);
        let nonce_gen_array = GenericArray::from_slice($nonce);
        (key_gen_array, nonce_gen_array)
    }};
}

impl ChaCha {
    pub fn try_key<T: Into<Vec<u8>>>(&mut self, new: T) -> Result<&mut Self, ChaChaErr> {
        let new_bytes: Vec<u8> = new.into();

        let key: [u8; 32] = new_bytes.try_into().map_err(|_| {
            let mut error = ChaChaErr::new();
            error
                .description("Key must be 256 bits (32 bytes)")
                .kind(ChaChaError::InvalidKeyLenght)
                .code(1);
            error
        })?;

        Ok(self.key(key))
    }

    pub fn encrypt(&mut self) -> Result<String, ChaChaErr> {
        self.nonce(rand::rng().random::<ChaChaNonce>());
        let (key, nonce) = chacha_key_and_nonce!(&self.key, &self.nonce);
        let ciphertext = ChaCha20Poly1305::new(key)
            .encrypt(nonce, self.target.as_ref())
            .map_err(chacha_err(ChaChaError::EncryptFailed, 1))?;
        let ciphertext = hex::encode(ciphertext);

        self.ciphertext(ciphertext.clone());
        Ok(ciphertext)
    }

    pub fn decrypt(&self) -> Result<ChaChaDecrypt, ChaChaErr> {
        let (key, nonce) = chacha_key_and_nonce!(&self.key, &self.nonce);
        let ciphertext =
            hex::decode(&self.ciphertext).map_err(chacha_err(ChaChaError::HexDecodeFailed, 3))?;
        let decrypted = ChaCha20Poly1305::new(key)
            .decrypt(nonce, ciphertext.as_ref())
            .map_err(chacha_err(ChaChaError::DecryptFailed, 2))?;

        Ok(ChaChaDecrypt(decrypted))
    }
}
