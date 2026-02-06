use std::future::{ready, Ready};

use actix_web::{
    body::{BoxBody, MessageBody},
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    http::header::{self, HeaderValue},
    Error,
};
use futures::future::LocalBoxFuture;

use crate::{env, handlers::CORS_ALLOWED_HEADERS_VALUE, middleware::client_type::ClientType};

/// CORS middleware that validates origins and sets appropriate headers.
///
/// Only processes requests from browser clients (identified by `X-Client-Is-Browser` header).
/// Validates the `Origin` header against the configured allowed origins.
/// Sets CORS headers for both preflight (OPTIONS) and actual requests.
pub struct CorsMiddleware {
    allowed_origins: Vec<String>,
}

impl Default for CorsMiddleware {
    fn default() -> Self {
        Self {
            allowed_origins: env::CONF.cors_allowed_origins.clone(),
        }
    }
}

impl<S, B> Transform<S, ServiceRequest> for CorsMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: MessageBody + 'static,
{
    type Response = ServiceResponse<BoxBody>;
    type Error = Error;
    type InitError = ();
    type Transform = CorsMiddlewareService<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        let allowed_origin_headers: Vec<(String, HeaderValue)> = self
            .allowed_origins
            .iter()
            .map(|origin| {
                let hv = HeaderValue::from_str(origin)
                    .expect("CORS allowed origin must be a valid header value");
                (origin.clone(), hv)
            })
            .collect();
        ready(Ok(CorsMiddlewareService {
            service,
            allowed_origin_headers,
        }))
    }
}

pub struct CorsMiddlewareService<S> {
    service: S,
    allowed_origin_headers: Vec<(String, HeaderValue)>,
}

impl<S, B> Service<ServiceRequest> for CorsMiddlewareService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: MessageBody + 'static,
{
    type Response = ServiceResponse<BoxBody>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let include_cors = ClientType::from_service_request(&req).is_browser()
            && !self.allowed_origin_headers.is_empty();

        if !include_cors {
            let req_fut = self.service.call(req);
            return Box::pin(async move { Ok(req_fut.await?.map_into_boxed_body()) });
        }

        let origin = req
            .headers()
            .get(header::ORIGIN)
            .and_then(|h| h.to_str().ok())
            .map(|s| s.to_string());
        let is_options = req.method() == actix_web::http::Method::OPTIONS;

        let allowed_origin_header = origin.as_ref().and_then(|o| {
            self.allowed_origin_headers
                .iter()
                .find(|(allowed, _)| allowed == o)
                .map(|(_, hv)| hv.clone())
        });

        if is_options {
            let (req_parts, _) = req.into_parts();
            let mut res = actix_web::HttpResponse::Ok();

            if let Some(origin_header) = &allowed_origin_header {
                res.insert_header((header::ACCESS_CONTROL_ALLOW_ORIGIN, origin_header));
                res.insert_header((
                    header::ACCESS_CONTROL_ALLOW_METHODS,
                    HeaderValue::from_static("GET, POST, PUT, DELETE, OPTIONS"),
                ));
                res.insert_header((
                    header::ACCESS_CONTROL_ALLOW_HEADERS,
                    HeaderValue::from_static(CORS_ALLOWED_HEADERS_VALUE),
                ));
                res.insert_header((
                    header::ACCESS_CONTROL_ALLOW_CREDENTIALS,
                    HeaderValue::from_static("true"),
                ));
                res.insert_header((
                    header::ACCESS_CONTROL_MAX_AGE,
                    HeaderValue::from_static("86400"),
                ));
            }

            let res = res.finish();
            let res = ServiceResponse::new(req_parts, res).map_into_boxed_body();
            return Box::pin(async move { Ok(res) });
        }

        let req_fut = self.service.call(req);

        Box::pin(async move {
            let mut res = req_fut.await?.map_into_boxed_body();

            if let Some(origin_header) = allowed_origin_header {
                res.headers_mut()
                    .insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, origin_header);
                res.headers_mut().insert(
                    header::ACCESS_CONTROL_ALLOW_CREDENTIALS,
                    HeaderValue::from_static("true"),
                );
            }

            Ok(res)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::CorsMiddleware;
    use actix_web::{
        http::{header, Method, StatusCode},
        test, web, App, HttpResponse,
    };

    impl CorsMiddleware {
        pub fn with_origins(origins: Vec<&str>) -> Self {
            Self {
                allowed_origins: origins.into_iter().map(|s| s.to_string()).collect(),
            }
        }
    }

    #[actix_web::test]
    async fn no_cors_headers_when_not_browser_client() {
        let cors = CorsMiddleware::with_origins(vec!["https://example.com"]);
        let app = test::init_service(App::new().wrap(cors).route(
            "/",
            web::get().to(|| async { HttpResponse::Ok().body("ok") }),
        ))
        .await;

        let req = test::TestRequest::get()
            .uri("/")
            .append_header((header::ORIGIN, "https://example.com"))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(
            resp.headers()
                .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .is_none(),
            "Should not add CORS headers when X-Client-Is-Browser is absent"
        );
    }

    #[actix_web::test]
    async fn no_cors_headers_when_browser_header_not_true() {
        let cors = CorsMiddleware::with_origins(vec!["https://example.com"]);
        let app = test::init_service(App::new().wrap(cors).route(
            "/",
            web::get().to(|| async { HttpResponse::Ok().body("ok") }),
        ))
        .await;

        for value in ["1", "false", "0", "yes", ""] {
            let req = test::TestRequest::get()
                .uri("/")
                .append_header((crate::handlers::BROWSER_CLIENT_HEADER, value))
                .append_header((header::ORIGIN, "https://example.com"))
                .to_request();
            let resp = test::call_service(&app, req).await;
            assert_eq!(resp.status(), StatusCode::OK);
            assert!(
                resp.headers()
                    .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                    .is_none(),
                "Should not add CORS headers when X-Client-Is-Browser is '{}' (only 'true' counts)",
                value
            );
        }
    }

    #[actix_web::test]
    async fn no_cors_headers_when_no_allowed_origins() {
        let cors = CorsMiddleware::with_origins(vec![]);
        let app = test::init_service(App::new().wrap(cors).route(
            "/",
            web::get().to(|| async { HttpResponse::Ok().body("ok") }),
        ))
        .await;

        let req = test::TestRequest::get()
            .uri("/")
            .append_header((crate::handlers::BROWSER_CLIENT_HEADER, "true"))
            .append_header((header::ORIGIN, "https://example.com"))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(
            resp.headers()
                .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .is_none(),
            "Should not add CORS headers when no origins configured"
        );
    }

    #[actix_web::test]
    async fn cors_headers_on_actual_request_when_origin_allowed() {
        let cors = CorsMiddleware::with_origins(vec!["https://example.com"]);
        let app = test::init_service(App::new().wrap(cors).route(
            "/",
            web::get().to(|| async { HttpResponse::Ok().body("ok") }),
        ))
        .await;

        let req = test::TestRequest::get()
            .uri("/")
            .append_header((crate::handlers::BROWSER_CLIENT_HEADER, "true"))
            .append_header((header::ORIGIN, "https://example.com"))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .and_then(|v| v.to_str().ok()),
            Some("https://example.com")
        );
        assert_eq!(
            resp.headers()
                .get(header::ACCESS_CONTROL_ALLOW_CREDENTIALS)
                .and_then(|v| v.to_str().ok()),
            Some("true")
        );
    }

    #[actix_web::test]
    async fn no_cors_headers_when_origin_not_allowed() {
        let cors = CorsMiddleware::with_origins(vec!["https://example.com"]);
        let app = test::init_service(App::new().wrap(cors).route(
            "/",
            web::get().to(|| async { HttpResponse::Ok().body("ok") }),
        ))
        .await;

        let req = test::TestRequest::get()
            .uri("/")
            .append_header((crate::handlers::BROWSER_CLIENT_HEADER, "true"))
            .append_header((header::ORIGIN, "https://evil.com"))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(
            resp.headers()
                .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .is_none(),
            "Should not add CORS headers when origin is not in allowed list"
        );
    }

    #[actix_web::test]
    async fn preflight_options_returns_cors_headers_when_origin_allowed() {
        let cors = CorsMiddleware::with_origins(vec!["https://example.com"]);
        let app = test::init_service(App::new().wrap(cors).route(
            "/",
            web::get().to(|| async { HttpResponse::Ok().body("ok") }),
        ))
        .await;

        let req = test::TestRequest::default()
            .method(Method::OPTIONS)
            .uri("/")
            .append_header((crate::handlers::BROWSER_CLIENT_HEADER, "true"))
            .append_header((header::ORIGIN, "https://example.com"))
            .append_header((header::ACCESS_CONTROL_REQUEST_METHOD, "GET"))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .and_then(|v| v.to_str().ok()),
            Some("https://example.com")
        );
        assert_eq!(
            resp.headers()
                .get(header::ACCESS_CONTROL_ALLOW_METHODS)
                .and_then(|v| v.to_str().ok()),
            Some("GET, POST, PUT, DELETE, OPTIONS")
        );
        assert_eq!(
            resp.headers()
                .get(header::ACCESS_CONTROL_ALLOW_HEADERS)
                .and_then(|v| v.to_str().ok()),
            Some(crate::handlers::CORS_ALLOWED_HEADERS_VALUE)
        );
        assert_eq!(
            resp.headers()
                .get(header::ACCESS_CONTROL_ALLOW_CREDENTIALS)
                .and_then(|v| v.to_str().ok()),
            Some("true")
        );
        assert_eq!(
            resp.headers()
                .get(header::ACCESS_CONTROL_MAX_AGE)
                .and_then(|v| v.to_str().ok()),
            Some("86400")
        );
    }

    #[actix_web::test]
    async fn preflight_options_no_cors_headers_when_origin_not_allowed() {
        let cors = CorsMiddleware::with_origins(vec!["https://example.com"]);
        let app = test::init_service(App::new().wrap(cors).route(
            "/",
            web::get().to(|| async { HttpResponse::Ok().body("ok") }),
        ))
        .await;

        let req = test::TestRequest::default()
            .method(Method::OPTIONS)
            .uri("/")
            .append_header((crate::handlers::BROWSER_CLIENT_HEADER, "true"))
            .append_header((header::ORIGIN, "https://evil.com"))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(
            resp.headers()
                .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .is_none(),
            "Preflight should not add CORS headers when origin not allowed"
        );
    }

    #[actix_web::test]
    async fn preflight_options_no_cors_headers_when_no_origin_header() {
        let cors = CorsMiddleware::with_origins(vec!["https://example.com"]);
        let app = test::init_service(App::new().wrap(cors).route(
            "/",
            web::get().to(|| async { HttpResponse::Ok().body("ok") }),
        ))
        .await;

        let req = test::TestRequest::default()
            .method(Method::OPTIONS)
            .uri("/")
            .append_header((crate::handlers::BROWSER_CLIENT_HEADER, "true"))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(
            resp.headers()
                .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .is_none(),
            "Preflight should not add CORS headers when Origin header missing"
        );
    }

    #[actix_web::test]
    async fn multiple_allowed_origins() {
        let cors =
            CorsMiddleware::with_origins(vec!["https://example.com", "https://app.example.com"]);
        let app = test::init_service(App::new().wrap(cors).route(
            "/",
            web::get().to(|| async { HttpResponse::Ok().body("ok") }),
        ))
        .await;

        for origin in ["https://example.com", "https://app.example.com"] {
            let req = test::TestRequest::get()
                .uri("/")
                .append_header((crate::handlers::BROWSER_CLIENT_HEADER, "true"))
                .append_header((header::ORIGIN, origin))
                .to_request();
            let resp = test::call_service(&app, req).await;
            assert_eq!(resp.status(), StatusCode::OK);
            assert_eq!(
                resp.headers()
                    .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                    .and_then(|v| v.to_str().ok()),
                Some(origin)
            );
        }
    }
}
