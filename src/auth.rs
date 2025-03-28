pub mod cached_jwk_set;

use std::{convert::Infallible, ops::Deref, sync::Arc};

use async_trait::async_trait;
use axum::{
    Json,
    extract::{FromRequestParts, Request, State},
    http::{StatusCode, request::Parts},
    middleware::Next,
    response::{IntoResponse, Response},
};
use axum_extra::TypedHeader;
use headers::{Authorization, authorization::Bearer};
use jsonwebtoken::{
    DecodingKey, TokenData, Validation, decode, decode_header,
    jwk::{AlgorithmParameters, JwkSet},
};

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("Invalid token: {0}")]
    InvalidToken(String),
    #[error("Missing credentials: {0}")]
    MissingCredentials(String),
    #[error("Unsupported algorithm")]
    UnsupportedAlgorithm,
}

impl AuthError {
    fn status(&self) -> StatusCode {
        match self {
            AuthError::InvalidToken(_) => StatusCode::UNAUTHORIZED,
            AuthError::MissingCredentials(_) | AuthError::UnsupportedAlgorithm => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
        }
    }
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let body = Json(serde_json::json!({
            "error": self.to_string(),
        }));

        (self.status(), body).into_response()
    }
}

#[async_trait]
pub trait AuthProvider: Send + Sync {
    async fn jwk_set(&self) -> Result<JwkSet, AuthError>;

    fn decode_validation(&self, validation: Validation) -> Validation {
        validation
    }

    async fn verify(&self, token: &str) -> Result<TokenData<Claims>, AuthError> {
        let token_sections: Vec<&str> = token.split('.').collect();
        if token_sections.len() < 2 {
            return Err(AuthError::InvalidToken("invalid format".into()));
        }

        let header =
            decode_header(&token).map_err(|err| AuthError::InvalidToken(err.to_string()))?;

        let jwk_set = self.jwk_set().await?;

        let Some(kid) = header.kid else {
            return Err(AuthError::InvalidToken("missing `kid` header field".into()));
        };

        let Some(jwk) = jwk_set.find(&kid) else {
            return Err(AuthError::InvalidToken(
                "no matching JWK found for the given kid".into(),
            ));
        };

        let decoding_key = match &jwk.algorithm {
            AlgorithmParameters::RSA(rsa) => DecodingKey::from_rsa_components(&rsa.n, &rsa.e)
                .map_err(|err| AuthError::InvalidToken(err.to_string())),
            AlgorithmParameters::EllipticCurve(ec) => DecodingKey::from_ec_components(&ec.x, &ec.y)
                .map_err(|err| AuthError::InvalidToken(err.to_string())),
            _ => Err(AuthError::UnsupportedAlgorithm),
        }?;

        let validation = self.decode_validation(Validation::new(header.alg));

        Ok(decode::<Claims>(token, &decoding_key, &validation)
            .map_err(|err| AuthError::InvalidToken(err.to_string()))?)
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Claims {
    pub sub: String,
    pub exp: usize,
}

pub async fn auth_middleware(
    State(auth_provider): State<Arc<dyn AuthProvider>>,
    TypedHeader(authorization): TypedHeader<Authorization<Bearer>>,
    mut request: Request,
    next: Next,
) -> Result<Response, Infallible> {
    let claims = match auth_provider.verify(authorization.token()).await {
        Ok(claims) => claims,
        Err(err) => return Ok(err.into_response()),
    };

    request.extensions_mut().insert(claims);

    Ok(next.run(request).await)
}

pub struct Token(TokenData<Claims>);

impl Deref for Token {
    type Target = TokenData<Claims>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<S> FromRequestParts<S> for Token {
    type Rejection = StatusCode;
    fn from_request_parts(
        parts: &mut Parts,
        _: &S,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> {
        async move {
            let token = parts
                .extensions
                .get::<TokenData<Claims>>()
                .ok_or_else(|| StatusCode::INTERNAL_SERVER_ERROR)?;

            Ok(Token(token.to_owned()))
        }
    }
}
