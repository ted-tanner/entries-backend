pub mod auth;
pub mod budget;
pub mod index;
pub mod user;

pub mod error {
    use budgetapp_utils::token::TokenError;

    use actix_web::http::{header, StatusCode};
    use actix_web::{HttpResponse, HttpResponseBuilder};
    use std::fmt;
    use tokio::sync::oneshot;

    #[allow(dead_code)]
    #[derive(Debug)]
    pub enum ServerError {
        // 400 Errors
        InvalidFormat(&'static str),
        InputRejected(&'static str),
        AlreadyExists(&'static str),
        UserUnauthorized(&'static str),
        AccessForbidden(&'static str),
        NotFound(&'static str),

        // 500 Errors
        InternalError(&'static str),
        DatabaseTransactionError(&'static str),
    }

    impl std::error::Error for ServerError {}

    impl fmt::Display for ServerError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                ServerError::InvalidFormat(msg) => format_err(f, "Invalid request format", msg),
                ServerError::InputRejected(msg) => format_err(f, "Input rejected", msg),
                ServerError::AlreadyExists(msg) => format_err(f, "Already exists", msg),
                ServerError::UserUnauthorized(msg) => format_err(f, "User unauthorized", msg),
                ServerError::AccessForbidden(msg) => format_err(f, "Access forbidden", msg),
                ServerError::NotFound(msg) => format_err(f, "Not found", msg),
                ServerError::InternalError(msg) => format_err(f, "Internal server error", msg),
                ServerError::DatabaseTransactionError(msg) => {
                    format_err(f, "Database transaction failed", msg)
                }
            }
        }
    }

    impl actix_web::error::ResponseError for ServerError {
        fn error_response(&self) -> HttpResponse {
            HttpResponseBuilder::new(self.status_code())
                .insert_header((header::CONTENT_TYPE, "text/html; charset=utf-8"))
                .body(self.to_string())
        }

        fn status_code(&self) -> StatusCode {
            match *self {
                ServerError::InvalidFormat(_)
                | ServerError::InputRejected(_)
                | ServerError::AlreadyExists(_) => StatusCode::BAD_REQUEST,
                ServerError::UserUnauthorized(_) => StatusCode::UNAUTHORIZED,
                ServerError::AccessForbidden(_) => StatusCode::FORBIDDEN,
                ServerError::NotFound(_) => StatusCode::NOT_FOUND,
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            }
        }
    }

    impl From<actix_web::error::BlockingError> for ServerError {
        fn from(_result: actix_web::error::BlockingError) -> Self {
            ServerError::InternalError("Actix thread pool failure")
        }
    }

    impl From<oneshot::error::RecvError> for ServerError {
        fn from(_result: oneshot::error::RecvError) -> Self {
            ServerError::InternalError("Rayon thread pool failure")
        }
    }

    impl From<std::result::Result<HttpResponse, ServerError>> for ServerError {
        fn from(result: std::result::Result<HttpResponse, ServerError>) -> Self {
            match result {
                Ok(_) => ServerError::InternalError("Unknown error"),
                Err(e) => e,
            }
        }
    }

    impl From<TokenError> for ServerError {
        fn from(result: TokenError) -> Self {
            match result {
                TokenError::TokenInvalid => ServerError::UserUnauthorized("Invalid token"),
                TokenError::TokenExpired => ServerError::UserUnauthorized("Token expired"),
                TokenError::TokenMissing => ServerError::UserUnauthorized("Missing token"),
                TokenError::WrongTokenType => ServerError::UserUnauthorized("Wrong token type"),
            }
        }
    }

    fn format_err(f: &mut fmt::Formatter<'_>, error_txt: &str, msg: &str) -> fmt::Result {
        write!(f, "{{ \"error_msg\": \"{}: {}\" }}", error_txt, msg,)
    }
}
