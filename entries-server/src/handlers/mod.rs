pub mod auth;
pub mod container;
pub mod health;
pub mod user;

pub mod verification {
    use actix_web::web;
    use entries_common::db::{self, DaoError, DbThreadPool};
    use entries_common::email::{templates::OtpMessage, EmailMessage, EmailSender};
    use entries_common::otp::Otp;
    use std::str::FromStr;
    use std::sync::Arc;
    use std::time::SystemTime;
    use tokio::sync::oneshot;
    use zeroize::Zeroizing;

    use super::error::{DoesNotExistType, HttpErrorResponse};
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

        let auth_dao = db::auth::Dao::new(db_thread_pool);
        match web::block(move || auth_dao.save_otp(&otp_ref, &user_email_copy, otp_expiration))
            .await?
        {
            Ok(a) => a,
            Err(DaoError::QueryFailure(diesel::result::Error::NotFound)) => {
                return Err(HttpErrorResponse::DoesNotExist(
                    String::from("User not found"),
                    DoesNotExistType::User,
                ));
            }
            Err(e) => {
                log::error!("{e}");
                return Err(HttpErrorResponse::InternalError(String::from(
                    "Failed to save OTP",
                )));
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
                return Err(HttpErrorResponse::InternalError(String::from(
                    "Failed to send OTP to user's email address",
                )));
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
            return Err(HttpErrorResponse::IncorrectCredential(String::from(
                WRONG_OR_EXPIRED_OTP_MSG,
            )));
        }

        let otp_copy = Arc::new(String::from(otp));
        let otp_ref = Arc::new(String::from(otp));
        let user_email_copy = Arc::new(String::from(user_email));
        let user_email_ref = Arc::clone(&user_email_copy);

        let auth_dao = db::auth::Dao::new(db_thread_pool);
        let exists_unexpired_otp =
            match web::block(move || auth_dao.check_unexpired_otp(&otp_copy, &user_email_copy))
                .await?
            {
                Ok(e) => e,
                Err(e) => {
                    log::error!("{e}");
                    return Err(HttpErrorResponse::InternalError(String::from(
                        "Failed to check OTP",
                    )));
                }
            };

        if exists_unexpired_otp {
            let auth_dao = db::auth::Dao::new(db_thread_pool);
            match web::block(move || auth_dao.delete_otp(&otp_ref, &user_email_ref)).await? {
                Ok(_) => (),
                Err(e) => {
                    log::error!("{e}");
                }
            }
        } else {
            return Err(HttpErrorResponse::IncorrectCredential(String::from(
                WRONG_OR_EXPIRED_OTP_MSG,
            )));
        }

        Ok(())
    }

    pub async fn verify_auth_string(
        auth_string: &[u8],
        user_email: &str,
        verify_using_recovery_key: bool,
        db_thread_pool: &DbThreadPool,
    ) -> Result<(), HttpErrorResponse> {
        let auth_string_error_text = if verify_using_recovery_key {
            "recovery key hash"
        } else {
            "auth string"
        };

        if user_email.len() > 255 || auth_string.len() > env::CONF.max_auth_string_length {
            return Err(HttpErrorResponse::IncorrectCredential(format!(
                "The {} was incorrect",
                auth_string_error_text,
            )));
        }

        let user_email_copy = String::from(user_email);
        let auth_string = Zeroizing::new(Vec::from(auth_string));

        let auth_dao = db::auth::Dao::new(db_thread_pool);
        let hash_and_status = match web::block(move || {
            if verify_using_recovery_key {
                auth_dao.get_user_recovery_auth_string_hash_and_status(&user_email_copy)
            } else {
                auth_dao.get_user_auth_string_hash_and_status(&user_email_copy)
            }
        })
        .await?
        {
            Ok(a) => a,
            Err(DaoError::QueryFailure(diesel::result::Error::NotFound)) => {
                // Return IncorrectCredential to prevent user enumeration attacks
                return Err(HttpErrorResponse::IncorrectCredential(format!(
                    "The {} was incorrect",
                    auth_string_error_text,
                )));
            }
            Err(e) => {
                log::error!("{e}");
                return Err(HttpErrorResponse::InternalError(format!(
                    "Failed to get user {}",
                    auth_string_error_text,
                )));
            }
        };

        if !hash_and_status.is_user_verified {
            return Err(HttpErrorResponse::InvalidState(String::from(
                "User is not verified",
            )));
        }

        let (sender, receiver) = oneshot::channel();

        rayon::spawn(move || {
            let hash = match argon2_kdf::Hash::from_str(&hash_and_status.auth_string_hash) {
                Ok(h) => h,
                Err(e) => {
                    sender.send(Err(e)).expect("Sending to channel failed");
                    return;
                }
            };

            let does_auth_string_match_hash =
                hash.verify_with_secret(&auth_string, (&env::CONF.auth_string_hash_key).into());

            sender
                .send(Ok(does_auth_string_match_hash))
                .expect("Sending to channel failed");
        });

        match receiver.await? {
            Ok(true) => (),
            Ok(false) => {
                return Err(HttpErrorResponse::IncorrectCredential(format!(
                    "The {} was incorrect",
                    auth_string_error_text,
                )));
            }
            Err(e) => {
                log::error!("{e}");
                return Err(HttpErrorResponse::InternalError(format!(
                    "Failed to validate {}",
                    auth_string_error_text,
                )));
            }
        };

        Ok(())
    }
}

pub mod error {
    use actix_protobuf::ProtoBufResponseBuilder;
    use entries_common::messages::{ErrorType, MessageError, ServerErrorResponse};
    use entries_common::token::TokenError;

    use actix_web::http::{header, StatusCode};
    use actix_web::{HttpResponse, HttpResponseBuilder};
    use std::fmt;
    use tokio::sync::oneshot;

    #[derive(Debug)]
    pub enum DoesNotExistType {
        User,
        Key,
        Container,
        Entry,
        Category,
        Invitation,
    }

    #[derive(Debug)]
    pub enum HttpErrorResponse {
        // 400
        IncorrectlyFormed(String),
        InvalidMessage(MessageError),
        OutOfDate(String),
        InvalidState(String),
        MissingHeader(String),
        ConflictWithExisting(String),

        // 401
        IncorrectCredential(String),
        IncorrectNonce(String),
        BadToken(String),
        TokenExpired(String),
        TokenMissing(String),
        WrongTokenType(String),

        // 403
        UserDisallowed(String),
        PendingAction(String),
        TooManyAttempts(String),
        ReadOnlyAccess(String),

        // 404
        DoesNotExist(String, DoesNotExistType),
        ForeignKeyDoesNotExist(String),

        // 413
        InputTooLarge(String),

        // 418
        TooManyRequested(String),

        // 500
        InternalError(String),
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
                HttpErrorResponse::BadToken(msg) => ServerErrorResponse {
                    err_type: ErrorType::IncorrectCredential.into(),
                    err_message: format!("Bad token: {msg}"),
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
                HttpErrorResponse::DoesNotExist(msg, dne_type) => ServerErrorResponse {
                    err_type: match dne_type {
                        DoesNotExistType::User => ErrorType::UserDoesNotExist,
                        DoesNotExistType::Key => ErrorType::KeyDoesNotExist,
                        DoesNotExistType::Container => ErrorType::ContainerDoesNotExist,
                        DoesNotExistType::Entry => ErrorType::EntryDoesNotExist,
                        DoesNotExistType::Category => ErrorType::CategoryDoesNotExist,
                        DoesNotExistType::Invitation => ErrorType::InvitationDoesNotExist,
                    }
                    .into(),
                    err_message: format!("Does not exist: {msg}"),
                },
                HttpErrorResponse::ForeignKeyDoesNotExist(msg) => ServerErrorResponse {
                    err_type: ErrorType::ForeignKeyDoesNotExist.into(),
                    err_message: format!("Foreign key does not exist: {msg}"),
                },

                // 413
                HttpErrorResponse::InputTooLarge(msg) => ServerErrorResponse {
                    err_type: ErrorType::InputTooLarge.into(),
                    err_message: format!("Input is too long: {msg}"),
                },

                // 418
                HttpErrorResponse::TooManyRequested(msg) => ServerErrorResponse {
                    err_type: ErrorType::TooManyRequested.into(),
                    err_message: format!("Too many requested: {msg}"),
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
                | HttpErrorResponse::IncorrectNonce(_)
                | HttpErrorResponse::BadToken(_)
                | HttpErrorResponse::TokenExpired(_)
                | HttpErrorResponse::TokenMissing(_)
                | HttpErrorResponse::WrongTokenType(_) => StatusCode::UNAUTHORIZED,
                HttpErrorResponse::UserDisallowed(_)
                | HttpErrorResponse::PendingAction(_)
                | HttpErrorResponse::TooManyAttempts(_)
                | HttpErrorResponse::ReadOnlyAccess(_) => StatusCode::FORBIDDEN,
                HttpErrorResponse::DoesNotExist(_, _)
                | HttpErrorResponse::ForeignKeyDoesNotExist(_) => StatusCode::NOT_FOUND,
                HttpErrorResponse::InputTooLarge(_) => StatusCode::PAYLOAD_TOO_LARGE,
                HttpErrorResponse::TooManyRequested(_) => StatusCode::IM_A_TEAPOT,
                HttpErrorResponse::InternalError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            }
        }
    }

    impl From<actix_web::Error> for HttpErrorResponse {
        fn from(_err: actix_web::Error) -> Self {
            HttpErrorResponse::InternalError(String::from("Failed to serialize ProtoBuf response"))
        }
    }

    impl From<actix_web::error::BlockingError> for HttpErrorResponse {
        fn from(_err: actix_web::error::BlockingError) -> Self {
            HttpErrorResponse::InternalError(String::from("Actix thread pool failure"))
        }
    }

    impl From<oneshot::error::RecvError> for HttpErrorResponse {
        fn from(_err: oneshot::error::RecvError) -> Self {
            HttpErrorResponse::InternalError(String::from("Rayon thread pool failure"))
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
                TokenError::TokenInvalid => {
                    HttpErrorResponse::BadToken(String::from("Invalid token"))
                }
                TokenError::TokenExpired => {
                    HttpErrorResponse::TokenExpired(String::from("Token expired"))
                }
                TokenError::TokenMissing => {
                    HttpErrorResponse::TokenMissing(String::from("Missing token"))
                }
                TokenError::WrongTokenType => {
                    HttpErrorResponse::WrongTokenType(String::from("Wrong token type"))
                }
            }
        }
    }
}

#[cfg(test)]
pub mod test_utils {
    use entries_common::db;
    use entries_common::messages::{
        ContainerFrame, ContainerIdAndEncryptionKey, ContainerShareInviteList, NewContainer, NewUser,
        PublicKey, UserInvitationToContainer,
    };
    use entries_common::models::container::Container;
    use entries_common::models::user::User;
    use entries_common::schema::containers::dsl::containers;
    use entries_common::schema::users as user_fields;
    use entries_common::schema::users::dsl::users;
    use entries_common::threadrand::SecureRng;
    use entries_common::token::auth_token::{AuthToken, AuthTokenType, NewAuthTokenClaims};

    use actix_protobuf::ProtoBufConfig;
    use actix_web::body::to_bytes;
    use actix_web::http::StatusCode;
    use actix_web::test::{self, TestRequest};
    use actix_web::web::Data;
    use actix_web::App;
    use base64::engine::general_purpose::URL_SAFE as b64_urlsafe;
    use base64::Engine;
    use diesel::{dsl, ExpressionMethods, QueryDsl, RunQueryDsl};
    use ed25519_dalek as ed25519;
    use ed25519_dalek::Signer;
    use entries_common::token::container_accept_token::ContainerAcceptTokenClaims;
    use entries_common::token::container_access_token::ContainerAccessTokenClaims;
    use openssl::pkey::Private;
    use openssl::rsa::{Padding, Rsa};
    use prost::Message;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    use uuid::Uuid;

    use crate::env;
    use crate::services::api::RouteLimiters;

    pub fn gen_bytes(count: usize) -> Vec<u8> {
        (0..count).map(|_| SecureRng::next_u8()).collect()
    }

    pub fn gen_container_token(
        container_id: Uuid,
        key_id: Uuid,
        signing_key: &ed25519::SigningKey,
    ) -> String {
        let expiration = SystemTime::now() + Duration::from_secs(10);
        let expiration = expiration.duration_since(UNIX_EPOCH).unwrap().as_secs();

        let claims = ContainerAccessTokenClaims {
            key_id,
            container_id,
            expiration,
        };

        let mut token_unencoded =
            serde_json::to_vec(&claims).expect("Failed to transform claims into JSON");

        let signature = signing_key.sign(&token_unencoded);
        token_unencoded.extend_from_slice(&signature.to_bytes());

        b64_urlsafe.encode(&token_unencoded)
    }

    pub async fn create_user() -> (User, String, i64, i64) {
        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_THREAD_POOL.clone()))
                .app_data(Data::new(env::testing::SMTP_THREAD_POOL.clone()))
                .app_data(ProtoBufConfig::default())
                .configure(|cfg| crate::services::api::configure(cfg, RouteLimiters::default())),
        )
        .await;

        let user_number = SecureRng::next_u128();

        let public_key_id = Uuid::now_v7();
        let new_user = NewUser {
            email: format!("test_user{}@test.com", &user_number),

            auth_string: gen_bytes(10),

            auth_string_hash_salt: gen_bytes(10),
            auth_string_hash_mem_cost_kib: 1024,
            auth_string_hash_threads: 1,
            auth_string_hash_iterations: 2,

            password_encryption_key_salt: gen_bytes(10),
            password_encryption_key_mem_cost_kib: 1024,
            password_encryption_key_threads: 1,
            password_encryption_key_iterations: 1,

            recovery_key_hash_salt_for_encryption: gen_bytes(16),
            recovery_key_hash_salt_for_recovery_auth: gen_bytes(16),
            recovery_key_hash_mem_cost_kib: 1024,
            recovery_key_hash_threads: 1,
            recovery_key_hash_iterations: 1,

            recovery_key_auth_hash: gen_bytes(32),

            encryption_key_encrypted_with_password: gen_bytes(10),
            encryption_key_encrypted_with_recovery_key: gen_bytes(10),

            public_key_id: public_key_id.into(),
            public_key: gen_bytes(10),

            preferences_encrypted: gen_bytes(10),
            preferences_version_nonce: SecureRng::next_i64(),
            user_keystore_encrypted: gen_bytes(10),
            user_keystore_version_nonce: SecureRng::next_i64(),
        };

        let req = TestRequest::post()
            .uri("/api/user")
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(new_user.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::CREATED);

        let user = users
            .filter(user_fields::email.eq(&new_user.email))
            .first::<User>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
            .unwrap();

        let user_dao = db::user::Dao::new(&env::testing::DB_THREAD_POOL);
        user_dao.verify_user_creation(user.id).unwrap();

        super::verification::generate_and_email_otp(
            &user.email,
            &env::testing::DB_THREAD_POOL,
            &env::testing::SMTP_THREAD_POOL,
        )
        .await
        .unwrap();

        let access_token_claims = NewAuthTokenClaims {
            user_id: user.id,
            user_email: &user.email,
            expiration: (SystemTime::now() + env::CONF.access_token_lifetime)
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            token_type: AuthTokenType::Access,
        };

        let access_token = AuthToken::sign_new(access_token_claims, &env::CONF.token_signing_key);

        (
            user,
            access_token,
            new_user.preferences_version_nonce,
            new_user.user_keystore_version_nonce,
        )
    }

    pub fn gen_new_user_rsa_key(user_id: Uuid) -> Rsa<Private> {
        let keypair = Rsa::generate(512).unwrap();
        let public_key = keypair.public_key_to_der().unwrap();

        dsl::update(users.find(user_id))
            .set(user_fields::public_key.eq(public_key))
            .execute(&mut env::testing::DB_THREAD_POOL.get().unwrap())
            .unwrap();

        keypair
    }

    pub async fn create_container(access_token: &str) -> (Container, String) {
        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_THREAD_POOL.clone()))
                .app_data(Data::new(env::testing::SMTP_THREAD_POOL.clone()))
                .app_data(ProtoBufConfig::default())
                .configure(|cfg| crate::services::api::configure(cfg, RouteLimiters::default())),
        )
        .await;

        let key_pair = ed25519::SigningKey::generate(SecureRng::get_ref());
        let public_key = key_pair.verifying_key().to_bytes();

        let new_container = NewContainer {
            encrypted_blob: gen_bytes(32),
            version_nonce: SecureRng::next_i64(),
            categories: Vec::new(),
            user_public_container_key: Vec::from(public_key),
        };

        let req = TestRequest::post()
            .uri("/api/container")
            .insert_header(("AccessToken", access_token))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(new_container.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::CREATED);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let container_data = ContainerFrame::decode(resp_body).unwrap();
        let container = containers
            .find(Uuid::try_from(container_data.id).unwrap())
            .get_result::<Container>(&mut env::testing::DB_THREAD_POOL.get().unwrap())
            .unwrap();

        let container_access_token = gen_container_token(
            container.id,
            container_data.access_key_id.try_into().unwrap(),
            &key_pair,
        );

        (container, container_access_token)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn share_container(
        container_id: Uuid,
        recipient_email: &str,
        recipient_private_key: &[u8],
        read_only: bool,
        sender_container_access_token: &str,
        sender_access_token: &str,
        recipient_public_key_id_used_by_sender: Uuid,
        recipient_public_key_id_used_by_server: Uuid,
    ) -> String {
        let app = test::init_service(
            App::new()
                .app_data(Data::new(env::testing::DB_THREAD_POOL.clone()))
                .app_data(Data::new(env::testing::SMTP_THREAD_POOL.clone()))
                .app_data(ProtoBufConfig::default())
                .configure(|cfg| crate::services::api::configure(cfg, RouteLimiters::default())),
        )
        .await;

        let invite_info = UserInvitationToContainer {
            recipient_user_email: String::from(recipient_email),
            recipient_public_key_id_used_by_sender: recipient_public_key_id_used_by_sender.into(),
            recipient_public_key_id_used_by_server: recipient_public_key_id_used_by_server.into(),
            sender_public_key: gen_bytes(22),
            encryption_key_encrypted: gen_bytes(44),
            container_info_encrypted: gen_bytes(20),
            sender_info_encrypted: gen_bytes(30),
            share_info_symmetric_key_encrypted: gen_bytes(35),
            expiration: (SystemTime::now() + Duration::from_secs(10))
                .try_into()
                .unwrap(),
            read_only,
        };

        let req = TestRequest::post()
            .uri("/api/container/invitation")
            .insert_header(("AccessToken", sender_access_token))
            .insert_header(("ContainerAccessToken", sender_container_access_token))
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
            expiration: (SystemTime::now() + env::CONF.access_token_lifetime)
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            token_type: AuthTokenType::Access,
        };
        let recipient_access_token =
            AuthToken::sign_new(recipient_access_token_claims, &env::CONF.token_signing_key);

        let req = TestRequest::get()
            .uri("/api/container/invitation/all_pending")
            .insert_header(("AccessToken", recipient_access_token.as_str()))
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let invites = ContainerShareInviteList::decode(resp_body).unwrap().invites;

        let recipient_private_key = Rsa::private_key_from_der(recipient_private_key).unwrap();

        let mut accept_private_key = vec![0; recipient_private_key.size() as usize];
        let decrypted_size = recipient_private_key
            .private_decrypt(
                &invites[0].container_accept_key_encrypted,
                &mut accept_private_key,
                Padding::PKCS1,
            )
            .unwrap();
        accept_private_key.truncate(decrypted_size);

        let mut accept_private_key_id = vec![0; recipient_private_key.size() as usize];
        let decrypted_size = recipient_private_key
            .private_decrypt(
                &invites[0].container_accept_key_id_encrypted,
                &mut accept_private_key_id,
                Padding::PKCS1,
            )
            .unwrap();
        accept_private_key_id.truncate(decrypted_size);

        let accept_private_key_id = Uuid::from_bytes(accept_private_key_id.try_into().unwrap());

        let accept_token_claims = ContainerAcceptTokenClaims {
            invite_id: (&invites[0].id).try_into().unwrap(),
            key_id: accept_private_key_id,
            container_id,
            expiration: (SystemTime::now() + Duration::from_secs(10))
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };

        let accept_token_claims = serde_json::to_vec(&accept_token_claims).unwrap();
        let accept_private_key =
            ed25519::SigningKey::from_bytes(&accept_private_key.try_into().unwrap());
        let mut token = accept_token_claims.clone();
        let signature = accept_private_key.sign(&accept_token_claims).to_bytes();
        token.extend_from_slice(&signature);
        let accept_token = b64_urlsafe.encode(token);

        let access_private_key = ed25519::SigningKey::generate(SecureRng::get_ref());
        let access_public_key = Vec::from(access_private_key.verifying_key().to_bytes());
        let access_public_key = PublicKey {
            value: access_public_key,
        };

        let req = TestRequest::put()
            .uri("/api/container/invitation/accept")
            .insert_header(("ContainerAcceptToken", accept_token))
            .insert_header(("AccessToken", recipient_access_token.as_str()))
            .insert_header(("Content-Type", "application/protobuf"))
            .set_payload(access_public_key.encode_to_vec())
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let resp_body = to_bytes(resp.into_body()).await.unwrap();
        let access_key_id = ContainerIdAndEncryptionKey::decode(resp_body).unwrap();
        let access_key_id = Uuid::try_from(access_key_id.container_access_key_id).unwrap();

        gen_container_token(container_id, access_key_id, &access_private_key)
    }
}
