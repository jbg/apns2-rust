# apple-push

A Rust crate for sending push notifications to iOS devices via the [APNS][apns] http/2 API.

## Usage

Cargo.toml:
```rust
use apple_push::ApplePushClient;
use hyper_tls::HttpsConnector;
use tokio::runtime::Runtime;

let connector = HttpsConnector::new(4);
let apns = ApplePushClient::new(connector, "TEAM_ID", "KEY_ID", "KEY");
let notification = NotificationBuilder::new("TOPIC", "DEVICE_TOKEN")
    .title("TITLE")
    .body("BODY")
    .sound("SOUND_FILE")
    .badge(5)
    .build();
let mut rt = Runtime::new().unwrap();
rt.block_on(apns.send(n)).unwrap();
```

## Client

This library is based on [apns2-rust][apns2-rust] which uses cURL bindings and only supports certificate authentication. It has been rewritten to use [hyper][hyper] and JSON web token authentication. A [fork of jsonwebtoken][jsonwebtoken-fork] is currently used to add ECDSA support.

A TLS connector must be provided; the example above uses [hyper-tls][hyper-tls]. Sadly, due to an [issue][ring-issue] with the Ring crypto library, [rustls][rustls] cannot be used, because the jsonwebtoken fork uses a newer version of ring than rustls does (to get ECDSA signing support) and ring does not support multiple versions being linked into the same project.

## License

This library is dual-licensed under Apache and MIT.

Check the license files in this repo for details.

[apns]: https://developer.apple.com/library/content/documentation/NetworkingInternet/Conceptual/RemoteNotificationsPG/APNSOverview.html
[apns2-rust]: https://github.com/theduke/apns2-rust
[hyper]: https://github.com/hyperium/hyper
[jsonwebtoken-fork]: https://github.com/jbg/jsonwebtoken
[hyper-tls]: https://github.com/hyperium/hyper-tls
[ring-issue]: https://github.com/briansmith/ring/issues/535
[rustls]: https://github.com/ctz/rustls
