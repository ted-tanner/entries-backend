pub mod auth;
pub mod budget;
pub mod index;
pub mod user;

pub mod verification {
    use actix_web::web;
    use entries_utils::db::{self, DaoError, DbThreadPool};
    use entries_utils::email::{templates::OtpMessage, EmailMessage, EmailSender};
    use entries_utils::otp::Otp;
    use std::str::FromStr;
    use std::sync::Arc;
    use std::time::SystemTime;
    use tokio::sync::oneshot;
    use uuid::Uuid;

    use super::error::HttpErrorResponse;
    use crate::env;

    pub async fn generate_and_email_otp(
        user_id: Uuid,
        user_email: &str,
        db_thread_pool: &DbThreadPool,
        smtp_thread_pool: &EmailSender,
    ) -> Result<(), HttpErrorResponse> {
        let otp_expiration = SystemTime::now() + env::CONF.lifetimes.otp_lifetime;

        let otp = Arc::new(Otp::generate(8));
        let otp_ref = Arc::clone(&otp);

        let mut auth_dao = db::auth::Dao::new(db_thread_pool);
        match web::block(move || auth_dao.save_otp(otp_ref.as_ref(), user_id, otp_expiration))
            .await?
        {
            Ok(a) => a,
            Err(DaoError::QueryFailure(diesel::result::Error::NotFound)) => {
                return Err(HttpErrorResponse::DoesNotExist("User not found"));
            }
            Err(e) => {
                log::error!("{e}");
                return Err(HttpErrorResponse::InternalError("Failed to save OTP"));
            }
        };

        let message = EmailMessage {
            body: OtpMessage::generate(&otp[..4], &otp[4..], env::CONF.lifetimes.otp_lifetime),
            subject: "Your one-time passcode",
            from: env::CONF.email.from_address.clone(),
            reply_to: env::CONF.email.reply_to_address.clone(),
            destination: user_email,
            is_html: true,
        };

        match smtp_thread_pool.send(message).await {
            Ok(_) => (),
            Err(e) => {
                log::error!("{e}");
                return Err(HttpErrorResponse::InternalError(
                    "Failed to send OTP to user's email address",
                ));
            }
        };

        Ok(())
    }

    pub async fn verify_otp(
        otp: &str,
        user_id: Uuid,
        db_thread_pool: &DbThreadPool,
    ) -> Result<(), HttpErrorResponse> {
        const WRONG_OR_EXPIRED_OTP_MSG: &str = "OTP was incorrect or has expired";

        let mut auth_dao = db::auth::Dao::new(db_thread_pool);
        let saved_otp = match web::block(move || auth_dao.get_otp(user_id)).await? {
            Ok(o) => o,
            Err(DaoError::QueryFailure(diesel::result::Error::NotFound)) => {
                return Err(HttpErrorResponse::IncorrectCredential(
                    WRONG_OR_EXPIRED_OTP_MSG,
                ));
            }
            Err(e) => {
                log::error!("{e}");
                return Err(HttpErrorResponse::InternalError("Failed to check OTP"));
            }
        };

        let now = SystemTime::now();

        if now > saved_otp.expiration {
            return Err(HttpErrorResponse::IncorrectCredential(
                WRONG_OR_EXPIRED_OTP_MSG,
            ));
        }

        if !Otp::are_equal(otp, &saved_otp.otp) {
            return Err(HttpErrorResponse::IncorrectCredential(
                WRONG_OR_EXPIRED_OTP_MSG,
            ));
        }

        Ok(())
    }

    pub async fn verify_auth_string(
        auth_string: &[u8],
        user_email: &str,
        db_thread_pool: &DbThreadPool,
    ) -> Result<(), HttpErrorResponse> {
        if auth_string.len() > 512 {
            return Err(HttpErrorResponse::InputTooLong(
                "Provided password is too long. Max: 512 bytes",
            ));
        }

        let auth_string = Vec::from(auth_string);
        let user_email = String::from(user_email);

        let mut auth_dao = db::auth::Dao::new(db_thread_pool);
        let hash =
            match web::block(move || auth_dao.get_user_auth_string_hash_and_status(&user_email))
                .await?
            {
                Ok(a) => a,
                Err(e) => {
                    log::error!("{e}");
                    return Err(HttpErrorResponse::InternalError(
                        "Failed to get user auth string",
                    ));
                }
            };

        let (sender, receiver) = oneshot::channel();

        rayon::spawn(move || {
            let hash = match argon2_kdf::Hash::from_str(&hash.auth_string_hash) {
                Ok(h) => h,
                Err(e) => {
                    sender.send(Err(e)).expect("Sending to channel failed");
                    return;
                }
            };

            let does_auth_string_match_hash = hash.verify_with_secret(
                &auth_string,
                argon2_kdf::Secret::using_bytes(&env::CONF.keys.hashing_key),
            );

            sender
                .send(Ok(does_auth_string_match_hash))
                .expect("Sending to channel failed");
        });

        match receiver.await? {
            Ok(true) => (),
            Ok(false) => {
                return Err(HttpErrorResponse::IncorrectCredential(
                    "Auth string was incorrect",
                ));
            }
            Err(e) => {
                log::error!("{e}");
                return Err(HttpErrorResponse::InternalError(
                    "Failed to validate auth string",
                ));
            }
        };

        Ok(())
    }
}

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
