use zipher::components::jwt::JwtError;
use zipher::components::jwt::{Claims, Jwt};

#[test]
fn jwt_encode_decode() {
    let mut jwt = Jwt::new();
    let mut claims = Claims::new();
    claims.sub("user123").exp::<usize>(3600);

    jwt.claims(claims);
    jwt.encode().unwrap();
    let decoded = jwt.decode().unwrap();
    assert_eq!(decoded.sub, "user123");
}

#[test]
fn jwt_expired_token() {
    let mut jwt = Jwt::new();
    let mut claims = Claims::new();
    claims.sub("user123".to_string()).exp::<usize>(2);

    jwt.claims(claims).encode().unwrap();
    std::thread::sleep(std::time::Duration::from_secs(3));

    let result = jwt.decode();

    assert!(result.is_err(), "{:#?}", result);

    if let Err(err) = result {
        assert_eq!(err.kind, JwtError::DecodingError);
        assert_eq!(err.code, 3);
    }
}

#[test]
fn jwt_invalid_token() {
    let mut jwt = Jwt::new();
    let invalid_token = "invalid.token.here";

    let result = jwt.token(invalid_token).decode();

    assert!(result.is_err());

    if let Err(err) = result {
        assert_eq!(err.kind, JwtError::DecodingError);
        assert_eq!(err.code, 3);
    }
}

#[test]
fn jwt_empty_sub() {
    let mut claims = Claims::new();
    let result = claims.sub("".to_string()).exp::<usize>(3600).build();

    assert!(result.is_err(), "Building an empty sub should fail");
}
