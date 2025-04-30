use actix_web::dev::Payload;
use actix_web::{FromRequest, HttpRequest};
use futures::future;

use crate::handlers::error::HttpErrorResponse;

#[derive(Debug)]
#[allow(dead_code)]
pub struct AppVersion(pub String);

impl FromRequest for AppVersion {
    type Error = HttpErrorResponse;
    type Future = future::Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        const NO_VERSION_HEADER_MESSAGE: &str = "AppVersion header is missing or invalid";

        let app_version = match req.headers().get("AppVersion") {
            Some(header) => header,
            None => {
                return future::err(HttpErrorResponse::MissingHeader(String::from(
                    NO_VERSION_HEADER_MESSAGE,
                )))
            }
        };

        let app_verion = match app_version.to_str() {
            Ok(v) => v,
            Err(_) => {
                return future::err(HttpErrorResponse::IncorrectlyFormed(String::from(
                    NO_VERSION_HEADER_MESSAGE,
                )))
            }
        };

        if app_version.len() > 24 {
            return future::err(HttpErrorResponse::IncorrectlyFormed(String::from(
                NO_VERSION_HEADER_MESSAGE,
            )));
        }

        future::ok(AppVersion(String::from(app_verion)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use actix_web::dev::Payload;
    use actix_web::test::TestRequest;

    use entries_common::threadrand::SecureRng;

    #[actix_web::test]
    async fn test_app_version_required() {
        let app_version = format!(
            "{}.{}.{}",
            SecureRng::next_u8(),
            SecureRng::next_u8(),
            SecureRng::next_u8(),
        );

        let req = TestRequest::default()
            .insert_header(("AppVersion", app_version.as_str()))
            .to_http_request();

        assert!(AppVersion::from_request(&req, &mut Payload::None)
            .await
            .is_ok());

        let req = TestRequest::default().to_http_request();

        assert!(AppVersion::from_request(&req, &mut Payload::None)
            .await
            .is_err());
    }
}
