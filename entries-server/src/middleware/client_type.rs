use actix_web::dev::{Payload, ServiceRequest};
use actix_web::http::header::HeaderMap;
use actix_web::{FromRequest, HttpRequest};
use futures::future::{ready, Ready};

use crate::handlers::BROWSER_CLIENT_HEADER;

#[derive(Copy, Clone, Debug)]
pub struct ClientType(bool);

impl ClientType {
    pub fn is_browser(&self) -> bool {
        self.0
    }

    pub fn from_service_request(req: &ServiceRequest) -> Self {
        ClientType(headers_indicate_browser(req.headers()))
    }
}

impl FromRequest for ClientType {
    type Error = actix_web::Error;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        ready(Ok(ClientType(headers_indicate_browser(req.headers()))))
    }
}

fn headers_indicate_browser(headers: &HeaderMap) -> bool {
    headers
        .get(BROWSER_CLIENT_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::{headers_indicate_browser, ClientType};
    use actix_web::http::header::{HeaderMap, HeaderName, HeaderValue};
    use actix_web::{test, web, App, HttpResponse};

    use crate::handlers::BROWSER_CLIENT_HEADER;

    fn header_map_with(header_value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        if !header_value.is_empty() {
            headers.insert(
                HeaderName::from_static(BROWSER_CLIENT_HEADER),
                HeaderValue::from_str(header_value).unwrap(),
            );
        }
        headers
    }

    #[actix_web::test]
    async fn headers_indicate_browser_true_when_header_is_true() {
        assert!(headers_indicate_browser(&header_map_with("true")));
        assert!(headers_indicate_browser(&header_map_with("TRUE")));
        assert!(headers_indicate_browser(&header_map_with("True")));
    }

    #[actix_web::test]
    async fn headers_indicate_browser_false_when_header_not_true() {
        assert!(!headers_indicate_browser(&header_map_with("false")));
        assert!(!headers_indicate_browser(&header_map_with("1")));
        assert!(!headers_indicate_browser(&header_map_with("0")));
        assert!(!headers_indicate_browser(&header_map_with("yes")));
    }

    #[actix_web::test]
    async fn headers_indicate_browser_false_when_header_absent() {
        assert!(!headers_indicate_browser(&header_map_with("")));
        assert!(!headers_indicate_browser(&HeaderMap::new()));
    }

    #[actix_web::test]
    async fn from_request_extractor() {
        let app = test::init_service(App::new().route(
            "/",
            web::get().to(|client_type: ClientType| async move {
                HttpResponse::Ok().body(if client_type.is_browser() {
                    "browser"
                } else {
                    "not-browser"
                })
            }),
        ))
        .await;

        let req = test::TestRequest::get()
            .uri("/")
            .append_header((BROWSER_CLIENT_HEADER, "true"))
            .to_request();
        let resp = test::call_service(&app, req).await;
        let body = test::read_body(resp).await;
        assert_eq!(body, "browser");

        let req = test::TestRequest::get()
            .uri("/")
            .append_header((BROWSER_CLIENT_HEADER, "1"))
            .to_request();
        let resp = test::call_service(&app, req).await;
        let body = test::read_body(resp).await;
        assert_eq!(body, "not-browser");

        let req = test::TestRequest::get().uri("/").to_request();
        let resp = test::call_service(&app, req).await;
        let body = test::read_body(resp).await;
        assert_eq!(body, "not-browser");
    }
}
