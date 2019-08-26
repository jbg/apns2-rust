mod types;
mod error;

use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use biscuit::{jwa, jws, JWT};
use futures::{compat::{Future01CompatExt, Stream01CompatExt}, TryStreamExt};
use hyper::{client::connect::Connect, Client, Request};
use ring::signature::{EcdsaKeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use failure::{Error, format_err};

pub use self::error::{ApiError, SendError};
use self::error::ErrorResponse;
pub use self::types::*;


struct CachedToken {
    token: String,
    cached_at: i64
}

pub struct ApplePushClient<T: Connect + 'static> {
    production: bool,
    client: Client<T>,
    team_id: String,
    jwt_kid: String,
    jwt_key: jws::Secret,
    jwt: RwLock<Option<CachedToken>>
}

impl<T: Connect + 'static> ApplePushClient<T> {
    pub fn new(client: Client<T>, team_id: &str, jwt_kid: &str, jwt_key: &[u8]) -> Result<Self, Error> {
        let keypair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, jwt_key).map_err(|e| format_err!("bad key: {:?}", e))?;
        Ok(Self {
            production: true,
            client,
            team_id: team_id.to_owned(),
            jwt_kid: jwt_kid.to_owned(),
            jwt_key: jws::Secret::EcdsaKeyPair(Arc::new(keypair)),
            jwt: RwLock::new(None)
        })
    }

    /// Set API endpoint to use (production or development sandbox).
    pub fn set_production(&mut self, production: bool) {
        self.production = production;
    }

    /// Build the url for a device token.
    fn build_url(&self, device_token: &str) -> String {
        let root = if self.production {
            APN_URL_PRODUCTION
        } else {
            APN_URL_DEV
        };
        format!("{}/3/device/{}", root, device_token)
    }

    fn generate_jwt(&self) -> Result<String, Error> {
        let since_the_epoch = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;

        if let Some(ref token) = *self.jwt.read().unwrap() {
            if since_the_epoch - token.cached_at < (3600 - 60) {
                return Ok(token.token.clone());
            }
        }

        #[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
        struct PrivateClaims {}
        let claims = biscuit::ClaimsSet::<PrivateClaims> {
            registered: biscuit::RegisteredClaims {
                issuer: Some(self.team_id.parse()?),
                issued_at: Some(since_the_epoch.into()),
                ..Default::default()
            },
            private: PrivateClaims {},
        };
        let header = jws::RegisteredHeader {
            algorithm: jwa::SignatureAlgorithm::ES256,
            key_id: Some(self.jwt_kid.clone()),
            ..Default::default()
        };
        let jwt = JWT::new_decoded(header.into(), claims);
        let encoded = jwt.into_encoded(&self.jwt_key).unwrap().unwrap_encoded().to_string();
        
        *self.jwt.write().unwrap() = Some(CachedToken {
            cached_at: since_the_epoch,
            token: encoded.clone()
        });
        Ok(encoded)
    }

    /// Send a notification.
    /// Returns the UUID of the notification.
    pub async fn send(&self, n: Notification) -> Result<Uuid, SendError> {
        let id = n.id.unwrap_or_else(Uuid::new_v4);
        let body = ApnsRequest { aps: n.payload };
        let jwt = self.generate_jwt().map_err(|e| SendError::from(e))?;
        let body = serde_json::to_vec(&body)?;

        let mut req = Request::post(&self.build_url(&n.device_token));
        let headers = req.headers_mut().unwrap();
        headers.insert("authorization", format!("bearer {}", jwt).parse()?);
        headers.insert("apns-id", id.to_string().parse()?);
        headers.insert("apns-topic", n.topic.parse()?);
        
        if let Some(expiration) = n.expiration {
            headers.insert("apns-expiration", expiration.to_string().parse()?);
        }
        if let Some(priority) = n.priority {
            headers.insert("apns-priority", priority.to_int().to_string().parse()?);
        }
        if let Some(collapse_id) = n.collapse_id {
            headers.insert("apns-collapse-id", collapse_id.as_str().parse()?);
        }

        let res = self.client.request(req.body(body.into())?).compat().await?;
        let status = res.status();
        if status.is_success() {
            Ok(id)
        }
        else {
            let body = res.into_body().compat().try_concat().await?;
            let reason = ErrorResponse::parse_payload(&body);
            Err(ApiError {
                status: status.as_u16() as u32,
                reason,
            }.into())
        }
    }
}

