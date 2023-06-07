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

#[cfg(test)]
mod tests {
    use super::*;

    use actix_web::dev::Payload;
    use actix_web::test::TestRequest;
    use rand::{thread_rng, Rng};

    #[tokio::test]
    async fn test_app_version_required() {
        let app_version = format!(
            "{}.{}.{}",
            thread_rng().gen::<u8>(),
            thread_rng().gen::<u8>(),
            thread_rng().gen::<u8>(),
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
