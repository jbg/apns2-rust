#[macro_use]
extern crate failure;
extern crate futures;
extern crate hyper;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;
extern crate uuid;

mod types;
pub use self::types::*;

mod error;
use self::error::*;

use std::time::{SystemTime, UNIX_EPOCH};

use futures::{future, Future, Stream};
use hyper::{Body, Client, Method, Request, StatusCode, Uri};
use hyper::client::connect::Connect;
use uuid::Uuid;
use failure::Error;


pub struct ApnsSync<C: Connect> {
    production: bool,
    client: Client<C>,
    team_id: String,
    jwt_kid: String,
    jwt_key: Vec<u8>
}

#[derive(Serialize, Debug)]
struct Claim<'a> {
    iss: &'a str,
    iat: u64
}

impl<C: Connect + 'static> ApnsSync<C> {
    pub fn new(connector: C, team_id: String, jwt_kid: String, jwt_key: Vec<u8>) -> Result<Self, Error> {
        let client = Client::builder()
            .http2_only(true)
            .build(connector);
        let apns = ApnsSync {
            production: true,
            client,
            team_id,
            jwt_kid,
            jwt_key
        };
        Ok(apns)
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
        let mut header = jsonwebtoken::Header::default();
        header.kid = Some(self.jwt_kid.clone());
        let since_the_epoch = SystemTime::now().duration_since(UNIX_EPOCH)?;
        Ok(
            jsonwebtoken::encode(
                &header,
                &Claim {
                    iss: &self.team_id,
                    iat: since_the_epoch.as_secs()
                },
                &self.jwt_key
            )?
        )
    }

    /// Send a notification.
    /// Returns the UUID of the notification.
    pub fn send(&self, n: Notification) -> Box<Future<Item=Uuid, Error=SendError> + Send> {
        let id = n.id.unwrap_or_else(Uuid::new_v4);
        let body = ApnsRequest { aps: n.payload };
        let url: Uri = match self.build_url(&n.device_token).parse() {
            Ok(u) => u,
            Err(e) => return Box::new(future::err(e.into()))
        };
        let jwt = match self.generate_jwt() {
            Ok(t) => t,
            Err(e) => return Box::new(future::err(e.into()))
        };
        let body = match serde_json::to_vec(&body) {
            Ok(b) => b,
            Err(e) => return Box::new(future::err(e.into()))
        };

        let req = match Request::builder()
            .method(Method::POST)
            .uri(url)
            .header("authorization", format!("bearer {}", jwt))
            .header("apns-id", id.to_string())
            .header("apns-expiration", n.expiration.map(|x| x.to_string()).unwrap_or_else(|| "".to_string()))
            .header("apns-priority", n.priority.map(|x| x.to_int().to_string()).unwrap_or_else(|| "".to_string()))
            .header("apns-topic", n.topic)
            .header("apns-collapse-id", n.collapse_id.map(|x| x.as_str().to_string()).unwrap_or_else(|| "".to_string()))
            .body(Body::from(body)) {
            Ok(r) => r,
            Err(e) => return Box::new(future::err(e.into()))
        };

        Box::new(
            self.client
                .request(req)
                .map_err(|e| e.into())
                .and_then(move |response| {
                    let (head, body) = response.into_parts();
                    if head.status == StatusCode::OK {
                        Box::new(future::ok(id)) as Box<Future<Item=Uuid, Error=SendError> + Send>
                    }
                    else {
                        Box::new(
                            body
                                .concat2()
                                .map_err(|e| e.into())
                                .and_then(move |body| {
                                    let reason = ErrorResponse::parse_payload(&body);
                                    Err(ApiError {
                                        status: u32::from(head.status.as_u16()),
                                        reason
                                    }.into())
                                })
                        ) as Box<Future<Item=Uuid, Error=SendError> + Send>
                    }
                })
        )
    }
}

#[cfg(test)]
mod test {
    extern crate base64;
    extern crate hyper_rustls;
    extern crate tokio;

    use std::env;

    use self::hyper_rustls::HttpsConnector;

    use super::{ApnsSync, NotificationBuilder};


    #[test]
    fn test() {
        let team_id = env::var("APNS_TEAM_ID").unwrap();
        let key_id = env::var("APNS_KEY_ID").unwrap();
        let key = base64::decode(&env::var("APNS_KEY").unwrap()).unwrap();
        let topic = env::var("APNS_TOPIC").unwrap();
        let token = env::var("APNS_DEVICE_TOKEN").unwrap();

        let tls_connector = HttpsConnector::new(4);
        let apns = ApnsSync::new(tls_connector, team_id, key_id, key)
            .unwrap();
        let n = NotificationBuilder::new(topic, token)
            .title("title")
            .build();

        let mut rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(apns.send(n)).unwrap();
    }
}
