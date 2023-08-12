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
        let otp_expiration = SystemTime::now() + env::CONF.otp_lifetime;

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
            body: OtpMessage::generate(&otp[..4], &otp[4..], env::CONF.otp_lifetime),
            subject: "Your one-time passcode",
            from: env::CONF.email_from_address.clone(),
            reply_to: env::CONF.email_reply_to_address.clone(),
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
        if user_email.len() > 255 || auth_string.len() > 1024 {
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

            let does_auth_string_match_hash =
                hash.verify_with_secret(&auth_string, (&env::CONF.hashing_key).into());

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
    use actix_protobuf::ProtoBufResponseBuilder;
    use entries_utils::messages::{ErrorType, MessageError, ServerErrorResponse};
    use entries_utils::token::TokenError;

    use actix_web::http::{header, StatusCode};
    use actix_web::{HttpResponse, HttpResponseBuilder};
    use std::fmt;
    use tokio::sync::oneshot;

    #[derive(Debug)]
    pub enum HttpErrorResponse {
        // 400
        IncorrectlyFormed(&'static str),
        InvalidMessage(MessageError),
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
        InputTooLarge(&'static str),

        // 500
        InternalError(&'static str),
    }

    impl std::error::Error for HttpErrorResponse {}

    impl fmt::Display for HttpErrorResponse {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            let server_error: ServerErrorResponse = self.into();
            write!(f, "{:?}", server_error)
        }
    }

    impl From<HttpErrorResponse> for ServerErrorResponse {
        fn from(resp: HttpErrorResponse) -> Self {
            (&resp).into()
        }
    }

    impl From<&HttpErrorResponse> for ServerErrorResponse {
        fn from(resp: &HttpErrorResponse) -> Self {
            match resp {
                // 400
                HttpErrorResponse::IncorrectlyFormed(msg) => ServerErrorResponse {
                    err_type: ErrorType::IncorrectlyFormed.into(),
                    err_message: format!("Incorrectly formed request: {msg}"),
                },
                HttpErrorResponse::InvalidMessage(e) => ServerErrorResponse {
                    err_type: ErrorType::InvalidMessage.into(),
                    err_message: format!("Invalid message: {e}"),
                },
                HttpErrorResponse::OutOfDate(msg) => ServerErrorResponse {
                    err_type: ErrorType::OutOfDate.into(),
                    err_message: format!("Out of date: {msg}"),
                },
                HttpErrorResponse::InvalidState(msg) => ServerErrorResponse {
                    err_type: ErrorType::InvalidState.into(),
                    err_message: format!("Invalid state: {msg}"),
                },
                HttpErrorResponse::MissingHeader(msg) => ServerErrorResponse {
                    err_type: ErrorType::MissingHeader.into(),
                    err_message: format!("Missing header: {msg}"),
                },
                HttpErrorResponse::ConflictWithExisting(msg) => ServerErrorResponse {
                    err_type: ErrorType::ConflictWithExisting.into(),
                    err_message: format!("Conflict with existing data: {msg}"),
                },

                // 401
                HttpErrorResponse::IncorrectCredential(msg) => ServerErrorResponse {
                    err_type: ErrorType::IncorrectCredential.into(),
                    err_message: format!("Incorrect credential: {msg}"),
                },
                HttpErrorResponse::TokenExpired(msg) => ServerErrorResponse {
                    err_type: ErrorType::TokenExpired.into(),
                    err_message: format!("Token expired: {msg}"),
                },
                HttpErrorResponse::TokenMissing(msg) => ServerErrorResponse {
                    err_type: ErrorType::TokenMissing.into(),
                    err_message: format!("Token missing: {msg}"),
                },
                HttpErrorResponse::WrongTokenType(msg) => ServerErrorResponse {
                    err_type: ErrorType::WrongTokenType.into(),
                    err_message: format!("Wrong token type: {msg}"),
                },

                // 403
                HttpErrorResponse::UserDisallowed(msg) => ServerErrorResponse {
                    err_type: ErrorType::UserDisallowed.into(),
                    err_message: format!("User disallowed: {msg}"),
                },
                HttpErrorResponse::PendingAction(msg) => ServerErrorResponse {
                    err_type: ErrorType::PendingAction.into(),
                    err_message: format!("Pending user action: {msg}"),
                },
                HttpErrorResponse::IncorrectNonce(msg) => ServerErrorResponse {
                    err_type: ErrorType::IncorrectNonce.into(),
                    err_message: format!("Incorrect nonce: {msg}"),
                },
                HttpErrorResponse::TooManyAttempts(msg) => ServerErrorResponse {
                    err_type: ErrorType::TooManyAttempts.into(),
                    err_message: format!("Too many attempts: {msg}"),
                },
                HttpErrorResponse::ReadOnlyAccess(msg) => ServerErrorResponse {
                    err_type: ErrorType::ReadOnlyAccess.into(),
                    err_message: format!("Read-only access: {msg}"),
                },

                // 404
                HttpErrorResponse::DoesNotExist(msg) => ServerErrorResponse {
                    err_type: ErrorType::DoesNotExist.into(),
                    err_message: format!("Does not exist: {msg}"),
                },
                HttpErrorResponse::ForeignKeyDoesNotExist(msg) => ServerErrorResponse {
                    err_type: ErrorType::ForeignKeyDoesNotExist.into(),
                    err_message: format!("Foreign key does not exist: {msg}"),
                },

                // 418
                HttpErrorResponse::InputTooLarge(msg) => ServerErrorResponse {
                    err_type: ErrorType::InputTooLarge.into(),
                    err_message: format!("Input is too long: {msg}"),
                },

                // 500
                HttpErrorResponse::InternalError(msg) => ServerErrorResponse {
                    err_type: ErrorType::InternalError.into(),
                    err_message: format!("Internal error: {msg}"),
                },
            }
        }
    }

    impl actix_web::error::ResponseError for HttpErrorResponse {
        fn error_response(&self) -> HttpResponse {
            HttpResponseBuilder::new(self.status_code())
                .insert_header((header::CONTENT_TYPE, "application/protobuf"))
                .protobuf::<ServerErrorResponse>(self.into())
                .expect("HttpErrorResponse failed to serialize to ProtoBuf")
        }

        fn status_code(&self) -> StatusCode {
            match *self {
                HttpErrorResponse::IncorrectlyFormed(_)
                | HttpErrorResponse::InvalidMessage(_)
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
                HttpErrorResponse::InputTooLarge(_) => StatusCode::IM_A_TEAPOT,
                HttpErrorResponse::InternalError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            }
        }
    }

    impl From<actix_web::Error> for HttpErrorResponse {
        fn from(_err: actix_web::Error) -> Self {
            HttpErrorResponse::InternalError("Failed to serialize ProtoBuf response")
        }
    }

    impl From<actix_web::error::BlockingError> for HttpErrorResponse {
        fn from(_err: actix_web::error::BlockingError) -> Self {
            HttpErrorResponse::InternalError("Actix thread pool failure")
        }
    }

    impl From<oneshot::error::RecvError> for HttpErrorResponse {
        fn from(_err: oneshot::error::RecvError) -> Self {
            HttpErrorResponse::InternalError("Rayon thread pool failure")
        }
    }

    impl From<MessageError> for HttpErrorResponse {
        fn from(err: MessageError) -> Self {
            HttpErrorResponse::InvalidMessage(err)
        }
    }

    impl From<TokenError> for HttpErrorResponse {
        fn from(err: TokenError) -> Self {
            match err {
                TokenError::TokenInvalid => HttpErrorResponse::IncorrectlyFormed("Invalid token"),
                TokenError::TokenExpired => HttpErrorResponse::TokenExpired("Token expired"),
                TokenError::TokenMissing => HttpErrorResponse::TokenMissing("Missing token"),
                TokenError::WrongTokenType => HttpErrorResponse::WrongTokenType("Wrong token type"),
            }
        }
    }
}

#[cfg(test)]
pub mod test_utils {
    use entries_utils::messages::{
        BudgetFrame, BudgetIdAndEncryptionKey, BudgetShareInviteList, CategoryWithTempId,
        NewBudget, NewUser, PublicKey, UserInvitationToBudget,
    };
    use entries_utils::models::budget::Budget;
    use entries_utils::models::user::User;
    use entries_utils::schema::budgets::dsl::budgets;
    use entries_utils::schema::users as user_fields;
    use entries_utils::schema::users::dsl::users;
    use entries_utils::token::auth_token::{AuthToken, AuthTokenType, NewAuthTokenClaims};

    use actix_web::body::to_bytes;
    use actix_web::http::StatusCode;
    use actix_web::test::{self, TestRequest};
    use actix_web::web::Data;
    use actix_web::App;
    use base64::engine::general_purpose::URL_SAFE as b64_urlsafe;
    use base64::Engine;
    use diesel::{dsl, ExpressionMethods, QueryDsl, RunQueryDsl};
    use ed25519::{Signer, SigningKey};
    use ed25519_dalek as ed25519;
    use entries_utils::token::budget_accept_token::BudgetAcceptTokenClaims;
    use entries_utils::token::budget_access_token::BudgetAccessTokenClaims;
    use prost::Message;
    use rand::rngs::OsRng;
    use rand::Rng;
    use rsa::pkcs8::{DecodePrivateKey, EncodePublicKey};
    use rsa::Pkcs1v15Encrypt;
    use rsa::RsaPrivateKey;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    use uuid::Uuid;

    use crate::env;

    pub fn gen_bytes(count: usize) -> Vec<u8> {
        (0..count)
            .map(|_| rand::thread_rng().gen_range(u8::MIN..u8::MAX))
            .collect()
    }

    pub fn gen_budget_token(budget_id: Uuid, key_id: Uuid, signing_key: &SigningKey) -> String {
        let expiration = SystemTime::now() + Duration::from_secs(10);
        let expiration = expiration.duration_since(UNIX_EPOCH).unwrap().as_secs();

        let claims = BudgetAccessTokenClaims {
            key_id,
            budget_id,
            expiration,
        };

        let claims = serde_json::to_vec(&claims).unwrap();
        let signature = hex::encode(&signing_key.sign(&claims).to_bytes());

        let claims = String::from_utf8_lossy(&claims);
        b64_urlsafe.encode(format!("{claims}|{signature}"))
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

        let new_user = NewUser {
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
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(new_user.encode_to_vec())
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
            expiration: SystemTime::now() + env::CONF.access_token_lifetime,
            token_type: AuthTokenType::Access,
        };

        let access_token = AuthToken::sign_new(
            access_token_claims.encrypt(&env::CONF.token_encryption_cipher),
            &env::CONF.token_signing_key,
        );

        (user, access_token)
    }

    pub fn gen_new_user_rsa_key(user_id: Uuid) -> RsaPrivateKey {
        let keypair = RsaPrivateKey::new(&mut OsRng, 128).unwrap();
        let public_key = keypair.to_public_key().to_public_key_der().unwrap();

        dsl::update(users.find(user_id))
            .set(user_fields::public_key.eq(public_key.as_bytes()))
            .execute(&mut env::testing::DB_THREAD_POOL.get().unwrap())
            .unwrap();

        keypair
    }

    pub async fn create_budget(access_token: &str) -> (Budget, String) {
        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_THREAD_POOL.clone()))
                .app_data(Data::from(env::testing::SMTP_THREAD_POOL.clone()))
                .configure(crate::services::api::configure),
        )
        .await;

        let key_pair = ed25519::SigningKey::generate(&mut OsRng);
        let public_key = key_pair.verifying_key().to_bytes();

        let new_budget = NewBudget {
            encrypted_blob: gen_bytes(32),
            categories: vec![
                CategoryWithTempId {
                    temp_id: 0,
                    encrypted_blob: gen_bytes(40),
                },
                CategoryWithTempId {
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
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(new_budget.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::CREATED);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let budget_data = BudgetFrame::decode(resp_body).unwrap();
        let budget = budgets
            .find(Uuid::try_from(budget_data.id).unwrap())
            .get_result::<Budget>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
            .unwrap();

        let budget_access_token = gen_budget_token(
            budget.id,
            budget_data.access_key_id.try_into().unwrap(),
            &key_pair,
        );

        (budget, budget_access_token)
    }

    pub async fn share_budget(
        budget_id: Uuid,
        recipient_email: &str,
        recipient_private_key: &[u8],
        read_only: bool,
        budget_access_token: &str,
        sender_access_token: &str,
    ) -> String {
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
            expiration: (SystemTime::now() + Duration::from_secs(10))
                .try_into()
                .unwrap(),
            read_only,
        };

        let req = TestRequest::put()
            .uri("/api/budget/invite_user")
            .insert_header(("AccessToken", sender_access_token))
            .insert_header(("BudgetAccessToken", budget_access_token))
            .insert_header(("AppVersion", "0.1.0"))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(invite_info.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let recipient = users
            .filter(user_fields::email.eq(recipient_email))
            .get_result::<User>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
            .unwrap();

        let recipient_access_token_claims = NewAuthTokenClaims {
            user_id: recipient.id,
            user_email: recipient_email,
            expiration: SystemTime::now() + env::CONF.access_token_lifetime,
            token_type: AuthTokenType::Access,
        };
        let recipient_access_token = AuthToken::sign_new(
            recipient_access_token_claims.encrypt(&env::CONF.token_encryption_cipher),
            &env::CONF.token_signing_key,
        );

        let req = TestRequest::get()
            .uri("/api/budget/get_all_pending_invitations")
            .insert_header(("AccessToken", recipient_access_token.as_str()))
            .insert_header(("AppVersion", "0.1.0"))
            .insert_header(("Content-Type", "application/protobuf"))
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let invites = BudgetShareInviteList::decode(resp_body).unwrap().invites;

        let recipient_private_key = RsaPrivateKey::from_pkcs8_der(recipient_private_key).unwrap();

        let accept_private_key = recipient_private_key
            .decrypt(Pkcs1v15Encrypt, &invites[0].budget_accept_key_encrypted)
            .unwrap();
        let accept_private_key_id = recipient_private_key
            .decrypt(Pkcs1v15Encrypt, &invites[0].budget_accept_key_id_encrypted)
            .unwrap();
        let accept_private_key_id = Uuid::from_bytes(accept_private_key_id.try_into().unwrap());

        let accept_token_claims = BudgetAcceptTokenClaims {
            invite_id: (&invites[0].id).try_into().unwrap(),
            key_id: accept_private_key_id,
            budget_id,
            expiration: (SystemTime::now() + Duration::from_secs(10))
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };

        let accept_token_claims = serde_json::to_vec(&accept_token_claims).unwrap();
        let accept_token_claims = String::from_utf8_lossy(&accept_token_claims);
        let accept_private_key = SigningKey::from_bytes(&accept_private_key.try_into().unwrap());
        let signature = hex::encode(
            accept_private_key
                .sign(accept_token_claims.as_bytes())
                .to_bytes(),
        );
        let accept_token = b64_urlsafe.encode(format!("{accept_token_claims}|{signature}"));

        let access_private_key = ed25519::SigningKey::generate(&mut OsRng);
        let access_public_key = access_private_key.verifying_key();
        let access_public_key = PublicKey {
            value: access_public_key.as_bytes().to_vec(),
        };

        let req = TestRequest::get()
            .uri("/api/budget/accept_invitation")
            .insert_header(("BudgetAcceptToken", accept_token))
            .insert_header(("AccessToken", recipient_access_token.as_str()))
            .insert_header(("AppVersion", "0.1.0"))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(access_public_key.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let access_key_id = BudgetIdAndEncryptionKey::decode(resp_body).unwrap();
        let access_key_id = Uuid::try_from(access_key_id.budget_access_key_id).unwrap();

        gen_budget_token(budget_id, access_key_id, &accept_private_key)
    }
}
