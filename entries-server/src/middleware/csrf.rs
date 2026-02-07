use std::{
    borrow::Cow,
    future::{ready, Ready},
};

use actix_web::{
    body::BoxBody,
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    Error, ResponseError,
};
use base64::engine::general_purpose::STANDARD as b64;
use base64::Engine;
use futures::future::LocalBoxFuture;
use rand::RngCore;

use crate::handlers::error::HttpErrorResponse;
use crate::middleware::{
    ACCESS_TOKEN_NAME, CSRF_TOKEN_NAME, REFRESH_TOKEN_NAME, SIGNIN_TOKEN_NAME,
};

pub struct CsrfMiddleware;

impl<S, B> Transform<S, ServiceRequest> for CsrfMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: actix_web::body::MessageBody + 'static,
{
    type Response = ServiceResponse<BoxBody>;
    type Error = Error;
    type InitError = ();
    type Transform = CsrfMiddlewareService<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(CsrfMiddlewareService { service }))
    }
}

pub struct CsrfMiddlewareService<S> {
    service: S,
}

impl<S, B> Service<ServiceRequest> for CsrfMiddlewareService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: actix_web::body::MessageBody + 'static,
{
    type Response = ServiceResponse<BoxBody>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        if req.method().is_safe() {
            let fut = self.service.call(req);
            return Box::pin(async move { Ok(fut.await?.map_into_boxed_body()) });
        }

        if !has_auth_or_csrf_cookie(&req) {
            let fut = self.service.call(req);
            return Box::pin(async move { Ok(fut.await?.map_into_boxed_body()) });
        }

        let csrf_cookie = req.cookie(CSRF_TOKEN_NAME);
        let cookie_token = csrf_cookie.as_ref().map(|c| c.value().as_bytes());
        let header_token = req
            .headers()
            .get(CSRF_TOKEN_NAME)
            .and_then(|h| h.to_str().ok())
            .map(|s| s.as_bytes());

        let valid = match (cookie_token, header_token) {
            (Some(c), Some(h)) if !c.is_empty() && !h.is_empty() => constant_time_eq(c, h),
            _ => false,
        };

        if !valid {
            let err =
                HttpErrorResponse::UserDisallowed(Cow::Borrowed("Invalid or missing CSRF token"));
            let (req, _) = req.into_parts();
            let res = err.error_response().map_into_boxed_body();
            return Box::pin(async move { Ok(ServiceResponse::new(req, res)) });
        }

        let fut = self.service.call(req);
        Box::pin(async move { Ok(fut.await?.map_into_boxed_body()) })
    }
}

pub fn generate_csrf_token() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    b64.encode(bytes)
}

fn has_auth_or_csrf_cookie(req: &ServiceRequest) -> bool {
    req.cookie(CSRF_TOKEN_NAME).is_some()
        || req.cookie(ACCESS_TOKEN_NAME).is_some()
        || req.cookie(REFRESH_TOKEN_NAME).is_some()
        || req.cookie(SIGNIN_TOKEN_NAME).is_some()
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{http::StatusCode, test, web, App, HttpResponse};

    #[actix_web::test]
    async fn post_browser_without_csrf_fails() {
        let token = generate_csrf_token();
        let app = test::init_service(App::new().wrap(CsrfMiddleware).route(
            "/",
            web::post().to(|| async { HttpResponse::Ok().body("ok") }),
        ))
        .await;

        let req = test::TestRequest::post()
            .uri("/")
            .cookie(actix_web::cookie::Cookie::new(ACCESS_TOKEN_NAME, "token"))
            .cookie(actix_web::cookie::Cookie::new(
                CSRF_TOKEN_NAME,
                token.as_str(),
            ))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[actix_web::test]
    async fn post_with_valid_csrf_passes() {
        let token = generate_csrf_token();
        let app = test::init_service(App::new().wrap(CsrfMiddleware).route(
            "/",
            web::post().to(|| async { HttpResponse::Ok().body("ok") }),
        ))
        .await;

        let req = test::TestRequest::post()
            .uri("/")
            .append_header((CSRF_TOKEN_NAME, token.as_str()))
            .cookie(actix_web::cookie::Cookie::new(ACCESS_TOKEN_NAME, "token"))
            .cookie(actix_web::cookie::Cookie::new(
                CSRF_TOKEN_NAME,
                token.as_str(),
            ))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[actix_web::test]
    async fn post_without_csrf_cookie_passes() {
        let app = test::init_service(App::new().wrap(CsrfMiddleware).route(
            "/",
            web::post().to(|| async { HttpResponse::Ok().body("ok") }),
        ))
        .await;

        let req = test::TestRequest::post().uri("/").to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[actix_web::test]
    async fn post_browser_without_csrf_fails_even_without_auth_cookie() {
        let token = generate_csrf_token();
        let app = test::init_service(App::new().wrap(CsrfMiddleware).route(
            "/",
            web::post().to(|| async { HttpResponse::Ok().body("ok") }),
        ))
        .await;

        let req = test::TestRequest::post()
            .uri("/")
            .cookie(actix_web::cookie::Cookie::new(
                CSRF_TOKEN_NAME,
                token.as_str(),
            ))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[actix_web::test]
    async fn get_with_auth_cookie_passes() {
        let app = test::init_service(App::new().wrap(CsrfMiddleware).route(
            "/",
            web::get().to(|| async { HttpResponse::Ok().body("ok") }),
        ))
        .await;

        let req = test::TestRequest::get()
            .uri("/")
            .cookie(actix_web::cookie::Cookie::new(ACCESS_TOKEN_NAME, "token"))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }
}
