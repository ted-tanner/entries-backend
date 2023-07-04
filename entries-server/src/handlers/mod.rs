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
    use zeroize::Zeroizing;

    use super::error::HttpErrorResponse;
    use crate::env;

    pub async fn generate_and_email_otp(
        user_email: &str,
        db_thread_pool: &DbThreadPool,
        smtp_thread_pool: &EmailSender,
    ) -> Result<(), HttpErrorResponse> {
        let otp_expiration = SystemTime::now() + env::CONF.lifetimes.otp_lifetime;

        let user_email_copy = String::from(user_email);

        let otp = Arc::new(Otp::generate(8));
        let otp_ref = Arc::clone(&otp);

        let mut auth_dao = db::auth::Dao::new(db_thread_pool);
        match web::block(move || auth_dao.save_otp(&otp_ref, &user_email_copy, otp_expiration))
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
        user_email: &str,
        db_thread_pool: &DbThreadPool,
    ) -> Result<(), HttpErrorResponse> {
        const WRONG_OR_EXPIRED_OTP_MSG: &str = "OTP was incorrect or has expired";

        if user_email.len() > 255 || otp.len() > 8 {
            return Err(HttpErrorResponse::IncorrectCredential(
                WRONG_OR_EXPIRED_OTP_MSG,
            ));
        }

        let otp_copy = Arc::new(String::from(otp));
        let otp_ref = Arc::new(String::from(otp));
        let user_email_copy = Arc::new(String::from(user_email));
        let user_email_ref = Arc::clone(&user_email_copy);

        let mut auth_dao = db::auth::Dao::new(db_thread_pool);
        let exists_unexpired_otp =
            match web::block(move || auth_dao.check_unexpired_otp(&otp_copy, &user_email_copy))
                .await?
            {
                Ok(e) => e,
                Err(e) => {
                    log::error!("{e}");
                    return Err(HttpErrorResponse::InternalError("Failed to check OTP"));
                }
            };

        if exists_unexpired_otp {
            let mut auth_dao = db::auth::Dao::new(db_thread_pool);
            match web::block(move || auth_dao.delete_otp(&otp_ref, &user_email_ref)).await? {
                Ok(_) => (),
                Err(e) => {
                    log::error!("{e}");
                }
            }
        } else {
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
        if user_email.len() > 255 || auth_string.len() > 512 {
            return Err(HttpErrorResponse::IncorrectCredential(
                "Auth string was incorrect",
            ));
        }

        let user_email_copy = String::from(user_email);
        let auth_string = Zeroizing::new(Vec::from(auth_string));

        let mut auth_dao = db::auth::Dao::new(db_thread_pool);
        let hash = match web::block(move || {
            auth_dao.get_user_auth_string_hash_and_status(&user_email_copy)
        })
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
        MissingHeader(&'static str),
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
                HttpErrorResponse::MissingHeader(msg) => {
                    format_err(f, "NOHEAD", "Missing header", msg)
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
                | HttpErrorResponse::MissingHeader(_)
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

#[cfg(test)]
pub mod test_utils {
    use entries_utils::models::budget::Budget;
    use entries_utils::models::user::User;
    use entries_utils::request_io::{
        InputBudget, InputCategoryWithTempId, InputUser, OutputBudgetFrame, UserInvitationToBudget,
    };
    use entries_utils::schema::budgets::dsl::budgets;
    use entries_utils::schema::users as user_fields;
    use entries_utils::schema::users::dsl::users;
    use entries_utils::token::auth_token::{AuthToken, AuthTokenType, NewAuthTokenClaims};

    use actix_web::http::StatusCode;
    use actix_web::test::{self, TestRequest};
    use actix_web::web::Data;
    use actix_web::App;
    use diesel::{dsl, ExpressionMethods, QueryDsl, RunQueryDsl};
    use ed25519::{Signer, SigningKey};
    use ed25519_dalek as ed25519;
    use entries_utils::token::budget_access_token::BudgetAccessTokenClaims;
    use rand::rngs::OsRng;
    use rand::Rng;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    use uuid::Uuid;

    use crate::env;

    pub fn gen_bytes(count: usize) -> Vec<u8> {
        (0..count)
            .map(|_| rand::thread_rng().gen_range(u8::MIN..u8::MAX))
            .collect()
    }

    pub fn gen_budget_token(budget_id: Uuid, key_id: Uuid) -> String {
        let expiration = SystemTime::now() + Duration::from_secs(10);
        let expiration = expiration.duration_since(UNIX_EPOCH).unwrap().as_secs();

        let claims = BudgetAccessTokenClaims {
            key_id,
            budget_id,
            expiration,
        };

        let claims = serde_json::to_vec(&claims).unwrap();

        let key_pair = ed25519::SigningKey::generate(&mut OsRng);
        let signature = hex::encode(&key_pair.sign(&claims).to_bytes());

        let claims = String::from_utf8_lossy(&claims);
        base64::encode_config(format!("{claims}|{signature}"), base64::URL_SAFE_NO_PAD)
    }

    pub async fn create_user() -> (User, String) {
        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_THREAD_POOL.clone()))
                .app_data(Data::from(env::testing::SMTP_THREAD_POOL.clone()))
                .configure(crate::services::api::configure),
        )
        .await;

        let user_number = rand::thread_rng().gen_range::<u128, _>(u128::MIN..u128::MAX);

        let new_user = InputUser {
            email: format!("test_user{}@test.com", &user_number),

            auth_string: gen_bytes(10),

            auth_string_salt: gen_bytes(10),
            auth_string_memory_cost_kib: 1024,
            auth_string_parallelism_factor: 1,
            auth_string_iters: 2,

            password_encryption_salt: gen_bytes(10),
            password_encryption_memory_cost_kib: 1024,
            password_encryption_parallelism_factor: 1,
            password_encryption_iters: 1,

            recovery_key_salt: gen_bytes(10),
            recovery_key_memory_cost_kib: 1024,
            recovery_key_parallelism_factor: 1,
            recovery_key_iters: 1,

            encryption_key_encrypted_with_password: gen_bytes(10),
            encryption_key_encrypted_with_recovery_key: gen_bytes(10),

            public_key: gen_bytes(10),

            preferences_encrypted: gen_bytes(10),
            user_keystore_encrypted: gen_bytes(10),
        };

        let req = TestRequest::post()
            .uri("/api/user/create")
            .insert_header(("AppVersion", "0.1.0"))
            .set_json(&new_user)
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::CREATED);

        dsl::update(users.filter(user_fields::email.eq(&new_user.email)))
            .set(user_fields::is_verified.eq(true))
            .execute(&mut env::testing::DB_THREAD_POOL.get().unwrap())
            .unwrap();

        let user = users
            .filter(user_fields::email.eq(&new_user.email))
            .first::<User>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
            .unwrap();

        let access_token_claims = NewAuthTokenClaims {
            user_id: user.id,
            user_email: &user.email,
            expiration: SystemTime::now() + env::CONF.lifetimes.access_token_lifetime,
            token_type: AuthTokenType::Access,
        };

        let access_token = AuthToken::sign_new(
            access_token_claims.encrypt(&env::CONF.keys.token_encryption_cipher),
            &env::CONF.keys.token_signing_key,
        );

        (user, access_token)
    }

    pub struct BudgetAndKey {
        budget: Budget,
        key_pair: SigningKey,
        key_id: Uuid,
    }

    pub async fn create_budget(access_token: &str) -> BudgetAndKey {
        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_THREAD_POOL.clone()))
                .app_data(Data::from(env::testing::SMTP_THREAD_POOL.clone()))
                .configure(crate::services::api::configure),
        )
        .await;

        let key_pair = ed25519::SigningKey::generate(&mut OsRng);
        let public_key = key_pair.verifying_key().to_bytes();

        let new_budget = InputBudget {
            encrypted_blob: gen_bytes(32),
            encryption_key_encrypted: gen_bytes(32),
            categories: vec![
                InputCategoryWithTempId {
                    temp_id: 0,
                    encrypted_blob: gen_bytes(40),
                },
                InputCategoryWithTempId {
                    temp_id: 1,
                    encrypted_blob: gen_bytes(60),
                },
            ],
            user_public_budget_key: Vec::from(public_key),
        };

        let req = TestRequest::post()
            .uri("/api/budget/create")
            .insert_header(("AccessToken", access_token))
            .insert_header(("AppVersion", "0.1.0"))
            .set_json(&new_budget)
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::CREATED);

        let budget_data = test::read_body_json::<OutputBudgetFrame, _>(resp).await;
        let budget = budgets
            .find(budget_data.id)
            .get_result(&mut env::testing::DB_THREAD_POOL.get().unwrap())
            .unwrap();

        BudgetAndKey {
            budget,
            key_pair,
            key_id: budget_data.access_key_id,
        }
    }

    pub async fn share_budget(
        budget_id: Uuid,
        recipient_email: &str,
        read_only: bool,
        budget_access_token: &str,
        user_access_token: &str,
    ) {
        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_THREAD_POOL.clone()))
                .app_data(Data::from(env::testing::SMTP_THREAD_POOL.clone()))
                .configure(crate::services::api::configure),
        )
        .await;

        let invite_info = UserInvitationToBudget {
            recipient_user_email: String::from(recipient_email),
            sender_public_key: gen_bytes(22),
            encryption_key_encrypted: gen_bytes(44),
            budget_info_encrypted: gen_bytes(20),
            sender_info_encrypted: gen_bytes(30),
            share_info_symmetric_key_encrypted: gen_bytes(35),
            expiration: SystemTime::now() + Duration::from_secs(10),
            read_only,
        };

        let req = TestRequest::put()
            .uri("/api/budget/invite_user")
            .insert_header(("AccessToken", user_access_token))
            .insert_header(("BudgetAccessToken", budget_access_token))
            .insert_header(("AppVersion", "0.1.0"))
            .set_json(&invite_info)
            .to_request();
        test::call_service(&app, req).await;

        // TODO: Recipient gets all invites
        // TODO: Recipient accepts invite
        // TODO: Recipient
    }
}
