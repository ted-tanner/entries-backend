pub mod auth;
pub mod budget;
pub mod index;
pub mod user;

pub mod error {
    use entries_utils::token::TokenError;

    use actix_web::http::{header, StatusCode};
    use actix_web::{HttpResponse, HttpResponseBuilder};
    use std::fmt;
    use tokio::sync::oneshot;

    #[derive(Debug)]
    pub enum HttpErrorResponse {
        // 400
        IncorrectlyFormed(&'static str),
        OutOfDate(&'static str),
        InvalidState(&'static str),
        ConflictWithExisting(&'static str),

        // 401
        IncorrectCredential(&'static str),
        TokenExpired(&'static str),
        TokenMissing(&'static str),
        WrongTokenType(&'static str),

        // 403
        UserDisallowed(&'static str),
        PendingAction(&'static str),
        IncorrectNonce(&'static str),
        TooManyAttempts(&'static str),
        ReadOnlyAccess(&'static str),

        // 404
        DoesNotExist(&'static str),
        ForeignKeyDoesNotExist(&'static str),

        // 418
        InputTooLong(&'static str),

        // 500
        InternalError(&'static str),
    }

    impl std::error::Error for HttpErrorResponse {}

    impl fmt::Display for HttpErrorResponse {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                // 400
                HttpErrorResponse::IncorrectlyFormed(msg) => {
                    format_err(f, "WHATHE", "Incorrectly formed request", msg)
                }
                HttpErrorResponse::OutOfDate(msg) => format_err(f, "U2SLOW", "Out of date", msg),
                HttpErrorResponse::InvalidState(msg) => {
                    format_err(f, "UTBETR", "Invalid state", msg)
                }
                HttpErrorResponse::ConflictWithExisting(msg) => {
                    format_err(f, "UNOWIN", "Conflict with existing data", msg)
                }

                // 401
                HttpErrorResponse::IncorrectCredential(msg) => {
                    format_err(f, "DISNOU", "Incorrect credential", msg)
                }
                HttpErrorResponse::TokenExpired(msg) => {
                    format_err(f, "I2FAST", "Token expired", msg)
                }
                HttpErrorResponse::TokenMissing(msg) => {
                    format_err(f, "UFORGT", "Token missing", msg)
                }
                HttpErrorResponse::WrongTokenType(msg) => {
                    format_err(f, "WHYDIS", "Wrong token type", msg)
                }

                // 403
                HttpErrorResponse::UserDisallowed(msg) => {
                    format_err(f, "NICTRY", "User disallowed", msg)
                }
                HttpErrorResponse::PendingAction(msg) => {
                    format_err(f, "NOSOUP", "Pending user action", msg)
                }
                HttpErrorResponse::IncorrectNonce(msg) => {
                    format_err(f, "BIGNPE", "Incorrect nonce", msg)
                }
                HttpErrorResponse::TooManyAttempts(msg) => {
                    format_err(f, "COOLIT", "Too many attempts", msg)
                }
                HttpErrorResponse::ReadOnlyAccess(msg) => {
                    format_err(f, "U2COOL", "Read-only access", msg)
                }

                // 404
                HttpErrorResponse::DoesNotExist(msg) => {
                    format_err(f, "ITGONE", "Does not exist", msg)
                }
                HttpErrorResponse::ForeignKeyDoesNotExist(msg) => {
                    format_err(f, "IHIDIT", "Foreign key does not exist", msg)
                }

                // 418
                HttpErrorResponse::InputTooLong(msg) => {
                    format_err(f, "UCRAZY", "Input is too long", msg)
                }

                // 500
                HttpErrorResponse::InternalError(msg) => {
                    format_err(f, "OOPSIE", "Internal error", msg)
                }
            }
        }
    }

    impl actix_web::error::ResponseError for HttpErrorResponse {
        fn error_response(&self) -> HttpResponse {
            HttpResponseBuilder::new(self.status_code())
                .insert_header((header::CONTENT_TYPE, "application/json; charset=utf-8"))
                .body(self.to_string())
        }

        fn status_code(&self) -> StatusCode {
            match *self {
                HttpErrorResponse::IncorrectlyFormed(_)
                | HttpErrorResponse::OutOfDate(_)
                | HttpErrorResponse::InvalidState(_)
                | HttpErrorResponse::ConflictWithExisting(_) => StatusCode::BAD_REQUEST,
                HttpErrorResponse::IncorrectCredential(_)
                | HttpErrorResponse::TokenExpired(_)
                | HttpErrorResponse::TokenMissing(_)
                | HttpErrorResponse::WrongTokenType(_) => StatusCode::UNAUTHORIZED,
                HttpErrorResponse::UserDisallowed(_)
                | HttpErrorResponse::PendingAction(_)
                | HttpErrorResponse::IncorrectNonce(_)
                | HttpErrorResponse::TooManyAttempts(_)
                | HttpErrorResponse::ReadOnlyAccess(_) => StatusCode::FORBIDDEN,
                HttpErrorResponse::DoesNotExist(_)
                | HttpErrorResponse::ForeignKeyDoesNotExist(_) => StatusCode::NOT_FOUND,
                HttpErrorResponse::InputTooLong(_) => StatusCode::IM_A_TEAPOT,
                HttpErrorResponse::InternalError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            }
        }
    }

    impl From<actix_web::error::BlockingError> for HttpErrorResponse {
        fn from(_result: actix_web::error::BlockingError) -> Self {
            HttpErrorResponse::InternalError("Actix thread pool failure")
        }
    }

    impl From<oneshot::error::RecvError> for HttpErrorResponse {
        fn from(_result: oneshot::error::RecvError) -> Self {
            HttpErrorResponse::InternalError("Rayon thread pool failure")
        }
    }

    impl From<std::result::Result<HttpResponse, HttpErrorResponse>> for HttpErrorResponse {
        fn from(result: std::result::Result<HttpResponse, HttpErrorResponse>) -> Self {
            match result {
                Ok(_) => HttpErrorResponse::InternalError("Unknown error"),
                Err(e) => e,
            }
        }
    }

    impl From<TokenError> for HttpErrorResponse {
        fn from(result: TokenError) -> Self {
            match result {
                TokenError::TokenInvalid => HttpErrorResponse::IncorrectlyFormed("Invalid token"),
                TokenError::TokenExpired => HttpErrorResponse::TokenExpired("Token expired"),
                TokenError::TokenMissing => HttpErrorResponse::TokenMissing("Missing token"),
                TokenError::WrongTokenType => HttpErrorResponse::WrongTokenType("Wrong token type"),
            }
        }
    }

    // Take a code
    fn format_err(
        f: &mut fmt::Formatter<'_>,
        error_code: &str,
        error_txt: &str,
        msg: &str,
    ) -> fmt::Result {
        write!(
            f,
            "{{\"error_code\":\"{}\",\"error_msg\":\"{}: {}\"}}",
            error_code, error_txt, msg,
        )
    }
}
