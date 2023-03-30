use actix_web::dev::Payload;
use actix_web::{error, FromRequest, HttpRequest};
use futures::future;

#[derive(Debug)]
pub struct AppVersion(pub String);

impl FromRequest for AppVersion {
    type Error = error::Error;
    type Future = future::Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        const NO_VERSION_HEADER_MESSAGE: &str = "AppVersion header is missing or invalid";

        let app_version = match req.headers().get("AppVersion") {
            Some(header) => header,
            None => return future::err(error::ErrorBadRequest(NO_VERSION_HEADER_MESSAGE)),
        };

        let app_verion = match app_version.to_str() {
            Ok(v) => v,
            Err(_) => return future::err(error::ErrorBadRequest(NO_VERSION_HEADER_MESSAGE)),
        };

        if app_version.len() > 24 {
            return future::err(error::ErrorBadRequest(NO_VERSION_HEADER_MESSAGE));
        }

        future::ok(AppVersion(String::from(app_verion)))
    }
}
