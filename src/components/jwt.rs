use chrono::{Duration, Utc};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use kenzu::M_Builder;
use mokuya::components::error::Error;
use rand::Rng;
use serde::{Deserialize, Serialize};

#[derive(Debug, M_Builder)]
pub struct Jwt {
    #[set(value = rand::rng().random::<[u8; 64]>())]
    key: Vec<u8>,
    token: String,
    algorithm: Algorithm,
    pub claims: Claims,
}

#[derive(Debug, PartialEq, Default)]
pub enum JwtError {
    #[default]
    OnlyHS,
    EncodingError,
    DecodingError,
}

type JwtErr = Error<JwtError>;

#[derive(Debug, Serialize, Deserialize, M_Builder, Default)]
pub struct Claims {
    #[build(pattern = "^.+$", err = "Build should fail for an empty sub")]
    pub sub: String,
    pub exp: usize,
}

fn jwt_err<T: ToString>(kind: JwtError, code: u8) -> impl FnOnce(T) -> JwtErr {
    move |err: T| {
        let mut error = JwtErr::new();
        error.description(err.to_string()).kind(kind).code(code);
        error
    }
}

fn switch(key: &Vec<u8>, algorithm: Algorithm) -> Result<Vec<u8>, JwtErr> {
    let size = match algorithm {
        Algorithm::HS256 => 32,
        Algorithm::HS384 => 48,
        Algorithm::HS512 => 64,
        _ => {
            let mut err = JwtErr::new();
            err.code(1)
                .kind(JwtError::OnlyHS)
                .description("Only HS256, HS384, and HS512 are supported.");
            return Err(err);
        }
    };

    Ok(key[..size].to_vec())
}

impl Jwt {
    pub fn encode(&mut self) -> Result<String, JwtErr> {
        let key = switch(&self.key, self.algorithm)?;
        let exp = Utc::now()
            .checked_add_signed(Duration::seconds(self.claims.exp as i64))
            .expect("Error to calculate exp")
            .timestamp() as usize;

        self.claims.exp(exp);

        let token = encode(
            &Header::new(self.algorithm),
            &self.claims,
            &EncodingKey::from_secret(&key),
        )
        .map_err(jwt_err(JwtError::EncodingError, 2))?;

        self.token(token.clone());
        Ok(token)
    }

    pub fn decode(&self) -> Result<Claims, JwtErr> {
        let key = switch(&self.key, self.algorithm)?;
        let mut validation = Validation::new(self.algorithm);
        validation.leeway = 0;
        let token_data =
            decode::<Claims>(&self.token, &DecodingKey::from_secret(&key), &validation)
                .map_err(jwt_err(JwtError::DecodingError, 3))?;

        Ok(token_data.claims)
    }
}
