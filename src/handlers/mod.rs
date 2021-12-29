pub mod auth;
pub mod index;
pub mod user;

pub mod request_io;

// TODO: Move all expensive operations inside actix_web::web::block closures

pub mod error {
    use actix_web::dev::HttpResponseBuilder;
    use actix_web::http::{header, StatusCode};
    use actix_web::HttpResponse;
    use std::fmt;

    #[derive(Debug)]
    pub enum ServerError {
        // 400 Errors
        InvalidFormat(Option<&'static str>),
        InputRejected(Option<&'static str>),
        AlreadyExists(Option<&'static str>),
        UserUnauthorized(Option<&'static str>),
        AccessForbidden(Option<&'static str>),

        // 500 Errors
        InternalServerError(Option<&'static str>),
        DatabaseTransactionError(Option<&'static str>),
    }

    impl std::error::Error for ServerError {}

    impl fmt::Display for ServerError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                ServerError::InvalidFormat(msg) => format_err(f, "Invalid request format", msg),
                ServerError::InputRejected(msg) => format_err(f, "Insecure password", msg),
                ServerError::AlreadyExists(msg) => format_err(f, "Insecure password", msg),
                ServerError::UserUnauthorized(msg) => format_err(f, "User unauthorized", msg),
                ServerError::AccessForbidden(msg) => format_err(f, "Access forbidden", msg),
                ServerError::InternalServerError(msg) => {
                    format_err(f, "Internal server error", msg)
                }
                ServerError::DatabaseTransactionError(msg) => {
                    format_err(f, "Database transaction failed", msg)
                }
            }
        }
    }

    impl actix_web::error::ResponseError for ServerError {
        fn error_response(&self) -> HttpResponse {
            HttpResponseBuilder::new(self.status_code())
                .set_header(header::CONTENT_TYPE, "text/html; charset=utf-8")
                .body(self.to_string())
        }

        fn status_code(&self) -> StatusCode {
            match *self {
                ServerError::InvalidFormat(_) => StatusCode::BAD_REQUEST,
                ServerError::UserUnauthorized(_) => StatusCode::UNAUTHORIZED,
                ServerError::AccessForbidden(_) => StatusCode::FORBIDDEN,
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            }
        }
    }

    impl From<std::result::Result<HttpResponse, ServerError>> for ServerError {
        fn from(result: std::result::Result<HttpResponse, ServerError>) -> Self {
            match result {
                Ok(_) => ServerError::InternalServerError(None),
                Err(e) => e,
            }
        }
    }

    fn format_err(
        f: &mut fmt::Formatter<'_>,
        error_txt: &str,
        msg: &Option<&'static str>,
    ) -> fmt::Result {
        write!(
            f,
            "{}{}",
            error_txt,
            if msg.is_some() {
                format!(": {}", msg.as_ref().unwrap())
            } else {
                String::new()
            }
        )
    }
}
