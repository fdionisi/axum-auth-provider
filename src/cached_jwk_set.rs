use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use axum::async_trait;
use jsonwebtoken::{jwk::JwkSet, Validation};
use tokio::sync::Mutex;

use crate::{AuthError, AuthProvider};

struct SingleCache<T>(Option<CacheEntry<T>>);

struct CacheEntry<T> {
    value: T,
    expiry: Instant,
}

impl<T> SingleCache<T> {
    fn is_none(&self) -> bool {
        self.0.is_none()
    }

    fn is_expired(&self) -> bool {
        self.0.as_ref().unwrap().expiry < Instant::now()
    }

    fn inner(&self) -> &T {
        &self.0.as_ref().unwrap().value
    }
}

impl<T> Default for SingleCache<T> {
    fn default() -> Self {
        Self(None)
    }
}

impl<T> From<(Duration, T)> for SingleCache<T> {
    fn from((duration, value): (Duration, T)) -> Self {
        Self(Some(CacheEntry {
            value,
            expiry: Instant::now() + duration,
        }))
    }
}

pub struct CachedJwkSet {
    issuer: String,
    duration: Duration,
    validator: Arc<dyn Fn(Validation) -> Validation + Send + Sync>,
    cached_keys: Arc<Mutex<SingleCache<JwkSet>>>,
}

pub struct CachedJwkSetBuilder {
    issuer: Option<String>,
    duration: Option<Duration>,
    validator: Option<Arc<dyn Fn(Validation) -> Validation + Send + Sync>>,
}

impl CachedJwkSet {
    pub fn builder() -> CachedJwkSetBuilder {
        CachedJwkSetBuilder {
            issuer: None,
            duration: None,
            validator: None,
        }
    }
}

impl CachedJwkSetBuilder {
    pub fn issuer(mut self, issuer: String) -> Self {
        self.issuer = Some(issuer);
        self
    }

    pub fn duration(mut self, duration: Duration) -> Self {
        self.duration = Some(duration);
        self
    }

    pub fn validator(
        mut self,
        validator: Arc<dyn Fn(Validation) -> Validation + Send + Sync>,
    ) -> Self {
        self.validator = Some(validator);
        self
    }

    pub fn build(&self) -> anyhow::Result<CachedJwkSet> {
        Ok(CachedJwkSet {
            issuer: self
                .issuer
                .to_owned()
                .ok_or_else(|| anyhow::anyhow!("Issuer is required".to_string()))?,
            duration: self
                .duration
                .to_owned()
                .ok_or_else(|| anyhow::anyhow!("Duration is required".to_string()))?,
            validator: self
                .validator
                .to_owned()
                .ok_or_else(|| anyhow::anyhow!("Validation is required".to_string()))?,
            cached_keys: Arc::new(Mutex::new(SingleCache::default())),
        })
    }
}

#[async_trait]
impl AuthProvider for CachedJwkSet {
    async fn jwk_set(&self) -> Result<JwkSet, AuthError> {
        let mut cached_keys = self.cached_keys.lock().await;
        if cached_keys.is_none() || cached_keys.is_expired() {
            let client = reqwest::Client::new();
            let jwk_set = client
                .get(format!("{}/.well-known/jwks.json", self.issuer))
                .send()
                .await
                .map_err(|err| AuthError::MissingCredentials(err.to_string()))?
                .json::<JwkSet>()
                .await
                .map_err(|err| AuthError::MissingCredentials(err.to_string()))?;

            *cached_keys = SingleCache::from((self.duration, jwk_set));
        }
        Ok(cached_keys.inner().to_owned())
    }

    fn decode_validation(&self, validation: Validation) -> Validation {
        let validator = self.validator.clone();

        validator(validation)
    }
}
