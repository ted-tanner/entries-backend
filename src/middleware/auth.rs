pub(crate) use actix_web::dev::Payload;
pub(crate) use actix_web::{error, FromRequest, HttpRequest};
use futures::future;

pub(crate) use crate::utils::jwt;

#[derive(Debug)]
pub struct AuthorizedUserClaims(pub jwt::TokenClaims);

impl FromRequest for AuthorizedUserClaims {
    type Error = error::Error;
    type Future = future::Ready<Result<Self, Self::Error>>;
    type Config = ();

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        const INVALID_TOKEN_MSG: &'static str = "Token is invalid";

        let auth_header = match req.headers().get("Authorization") {
            Some(header) => header,
            None => return future::err(error::ErrorUnauthorized("No token provided")),
        };

        let mut header_parts_iter = match auth_header.to_str() {
            Ok(h) => h,
            Err(_) => return future::err(error::ErrorUnauthorized(INVALID_TOKEN_MSG)),
        }
        .split_ascii_whitespace();

        match header_parts_iter.next() {
            Some(str) => {
                if str.to_ascii_lowercase() != "bearer" {
                    return future::err(error::ErrorUnauthorized(INVALID_TOKEN_MSG));
                }
            }
            None => return future::err(error::ErrorUnauthorized(INVALID_TOKEN_MSG)),
        };

        let token = match header_parts_iter.next() {
            Some(str) => str,
            None => return future::err(error::ErrorUnauthorized(INVALID_TOKEN_MSG)),
        };

        let claims = match jwt::validate_access_token(token) {
            Ok(c) => c,
            Err(_) => return future::err(error::ErrorUnauthorized(INVALID_TOKEN_MSG)),
        };

        future::ok(AuthorizedUserClaims(claims))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use actix_web::http::header;
    use actix_web::test;
    use uuid::Uuid;

    #[test]
    fn test_jwt_user_auth_middleware() {
        let user_id = Uuid::new_v4();

        let token = jwt::generate_access_token(&user_id).unwrap();

        let req = test::TestRequest::with_header(
            "authorization",
            format!("Bearer {}", &token.to_string()),
        )
        .to_http_request();

        let user_claims = AuthorizedUserClaims::from_request(&req, &mut Payload::None)
            .into_inner()
            .unwrap()
            .0;

        assert_eq!(&user_claims.uid, &user_id);

        let req = test::TestRequest::with_header(
            "Authorization",
            format!("bearer {}", &token.to_string()),
        )
        .to_http_request();

        let user_claims = AuthorizedUserClaims::from_request(&req, &mut Payload::None)
            .into_inner()
            .unwrap()
            .0;

        assert_eq!(&user_claims.uid, &user_id);
    }

    #[test]
    fn test_auth_middleware_rejects_request_without_auth_header() {
        let user_id = Uuid::new_v4();

        let token = jwt::generate_access_token(&user_id).unwrap();

        let req = test::TestRequest::with_header(
            header::CONTENT_TYPE,
            format!("bearer {}", &token.to_string()),
        )
        .to_http_request();

        let res = AuthorizedUserClaims::from_request(&req, &mut Payload::None).into_inner();

        assert!(res.is_err());
    }

    #[test]
    fn test_auth_middleware_rejects_header_without_bearer_keyword() {
        let user_id = Uuid::new_v4();

        let token = jwt::generate_access_token(&user_id).unwrap();

        let req = test::TestRequest::with_header(
            header::AUTHORIZATION,
            format!("{}", &token.to_string()),
        )
        .to_http_request();

        let res = AuthorizedUserClaims::from_request(&req, &mut Payload::None).into_inner();

        assert!(res.is_err());
    }

    #[test]
    fn test_auth_middleware_rejects_header_without_token() {
        let user_id = Uuid::new_v4();

        let _ = jwt::generate_access_token(&user_id).unwrap();

        let req = test::TestRequest::with_header(header::AUTHORIZATION, "bearer").to_http_request();
        let res = AuthorizedUserClaims::from_request(&req, &mut Payload::None).into_inner();

        assert!(res.is_err());
    }

    #[test]
    fn test_auth_middleware_rejects_invalid_token() {
        let user_id = Uuid::new_v4();

        let token = jwt::generate_access_token(&user_id).unwrap().to_string();

        // Remove the last char of the token
        let broken_token = &token[0..token.len() - 1];

        let req = test::TestRequest::with_header(
            header::AUTHORIZATION,
            format!("bearer {}", broken_token),
        )
        .to_http_request();

        let res = AuthorizedUserClaims::from_request(&req, &mut Payload::None).into_inner();

        assert!(res.is_err());
    }

    #[test]
    fn test_auth_middleware_rejects_refresh_token_in_auth_header() {
        let user_id = Uuid::new_v4();

        let token = jwt::generate_refresh_token(&user_id).unwrap();

        let req = test::TestRequest::with_header(
            header::AUTHORIZATION,
            format!("bearer {}", &token.to_string()),
        )
        .to_http_request();

        let res = AuthorizedUserClaims::from_request(&req, &mut Payload::None).into_inner();

        assert!(res.is_err());
    }
}
