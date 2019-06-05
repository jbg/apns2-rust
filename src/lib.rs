#[macro_use]
extern crate failure;
extern crate futures;
extern crate reqwest;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;
extern crate uuid;

mod types;
pub use self::types::*;

mod error;
pub use self::error::{ApiError, SendError};
use self::error::ErrorResponse;

use std::future::Future;
use std::sync::RwLock;
use std::time::{SystemTime, UNIX_EPOCH};

use futures::{compat::{Future01CompatExt, Stream01CompatExt}, future, FutureExt, TryFutureExt, TryStreamExt};
use reqwest::r#async::Client;
use uuid::Uuid;
use failure::Error;


struct CachedToken {
    token: String,
    cached_at: u64
}

#[derive(Serialize, Debug)]
struct Claim<'a> {
    iss: &'a str,
    iat: u64
}

pub struct ApplePushClient {
    production: bool,
    client: Client,
    team_id: String,
    jwt_kid: String,
    jwt_key: Vec<u8>,
    jwt: RwLock<Option<CachedToken>>
}

impl ApplePushClient {
    pub fn new(team_id: &str, jwt_kid: &str, jwt_key: &[u8]) -> Self {
        let client = Client::builder()
            .use_rustls_tls()
            .h2_prior_knowledge()
            .build()
            .unwrap();
        Self {
            production: true,
            client,
            team_id: team_id.to_owned(),
            jwt_kid: jwt_kid.to_owned(),
            jwt_key: jwt_key.to_owned(),
            jwt: RwLock::new(None)
        }
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
        let since_the_epoch = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

        if let Some(ref token) = *self.jwt.read().unwrap() {
            if since_the_epoch - token.cached_at < (3600 - 60) {
                return Ok(token.token.clone());
            }
        }

        let mut header = jsonwebtoken::Header::default();
        header.kid = Some(self.jwt_kid.clone());
        header.alg = jsonwebtoken::Algorithm::ES256;  // APNS supports only ES256
        let jwt = jsonwebtoken::encode(
            &header,
            &Claim {
                iss: &self.team_id,
                iat: since_the_epoch
            },
            &self.jwt_key
        )?;
        
        *self.jwt.write().unwrap() = Some(CachedToken {
            cached_at: since_the_epoch,
            token: jwt.clone()
        });
        Ok(jwt)
    }

    /// Send a notification.
    /// Returns the UUID of the notification.
    pub fn send(&self, n: Notification) -> impl Future<Output=Result<Uuid, SendError>> {
        let id = n.id.unwrap_or_else(Uuid::new_v4);
        let body = ApnsRequest { aps: n.payload };
        let jwt = match self.generate_jwt() {
            Ok(t) => t,
            Err(e) => return future::err(e.into()).boxed()
        };
        let body = match serde_json::to_vec(&body) {
            Ok(b) => b,
            Err(e) => return future::err(e.into()).boxed()
        };

        let mut req = self.client
            .post(&self.build_url(&n.device_token))
            .header("authorization", format!("bearer {}", jwt))
            .header("apns-id", id.to_string())
            .header("apns-topic", n.topic)
            .body(body);
        
        if let Some(expiration) = n.expiration {
            req = req.header("apns-expiration", expiration.to_string());
        }
        if let Some(priority) = n.priority {
            req = req.header("apns-priority", priority.to_int().to_string());
        }
        if let Some(collapse_id) = n.collapse_id {
            req = req.header("apns-collapse-id", collapse_id.as_str());
        }

        req.send()
            .compat()
            .map_err(|e| e.into())
            .and_then(move |response| {
                let status = response.status();
                if status.is_success() {
                    future::ok(id).boxed()
                }
                else {
                    response
                        .into_body()
                        .compat()
                        .try_concat()
                        .map_err(|e| e.into())
                        .and_then(move |body| {
                            let reason = ErrorResponse::parse_payload(&body);
                            future::err(ApiError {
                                status: u32::from(status.as_u16()),
                                reason
                            }.into())
                        })
                        .boxed()
                }
            })
            .boxed()
    }
}

#[cfg(test)]
mod test {
    extern crate base64;
    extern crate tokio;

    use std::env;

    use super::{ApplePushClient, NotificationBuilder};


    #[test]
    fn test() {
        let team_id = env::var("APNS_TEAM_ID").unwrap();
        let key_id = env::var("APNS_KEY_ID").unwrap();
        let key = base64::decode(&env::var("APNS_KEY").unwrap()).unwrap();
        let topic = env::var("APNS_TOPIC").unwrap();
        let token = env::var("APNS_DEVICE_TOKEN").unwrap();

        let apns = ApplePushClient::new(&team_id, &key_id, &key);
        let n = NotificationBuilder::new(&topic, &token)
            .title("title")
            .build();

        let mut rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(apns.send(n)).unwrap();
    }
}
