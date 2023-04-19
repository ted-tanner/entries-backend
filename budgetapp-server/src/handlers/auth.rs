use budgetapp_utils::db::{DaoError, DbThreadPool};
use budgetapp_utils::request_io::{
    CredentialPair, InputEmail, SigninToken, SigninTokenOtpPair, TokenPair,
};
use budgetapp_utils::token::auth_token::{AuthToken, AuthTokenType};
use budgetapp_utils::token::UserToken;
use budgetapp_utils::validators::Validity;
use budgetapp_utils::{argon2_hasher, db, otp, validators};

use actix_web::{web, HttpResponse};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::env;
use crate::handlers::error::ServerError;
use crate::middleware::app_version::AppVersion;
use crate::middleware::auth::{Access, CheckExp, FromHeader, Refresh, VerifiedToken};

// TODO: Should this mask when a user is not found by returning random data?
pub async fn obtain_nonce_and_auth_string_salt(
    db_thread_pool: web::Data<DbThreadPool>,
    email: web::Query<InputEmail>,
) -> Result<HttpResponse, ServerError> {
    let nonce_data = match web::block(move || {
        let mut auth_dao = db::auth::Dao::new(&db_thread_pool);
        auth_dao.get_auth_string_salt_and_signin_nonce(&email.0.email)
    })
    .await?
    {
        Ok(a) => a,
        Err(DaoError::QueryFailure(diesel::result::Error::NotFound)) => {
            return Err(ServerError::NotFound(Some(String::from("User not found"))));
        }
        Err(e) => {
            log::error!("{}", e);
            return Err(ServerError::DatabaseTransactionError(Some(String::from(
                "Failed to obtain nonce or authentication string data",
            ))));
        }
    };

    Ok(HttpResponse::Ok().json(nonce_data))
}

// TODO: Should this mask when a user is not found by hashing a password and comparing it
//       against a dummy (to prevent timing attacks)?
pub async fn sign_in(
    db_thread_pool: web::Data<DbThreadPool>,
    credentials: web::Json<CredentialPair>,
) -> Result<HttpResponse, ServerError> {
    if let Validity::Invalid(msg) = validators::validate_email_address(&credentials.email) {
        return Err(ServerError::InvalidFormat(Some(msg)));
    }

    let user_email_clone1 = credentials.email.clone();
    let user_email_clone2 = credentials.email.clone();
    let user_email_clone3 = credentials.email.clone();

    let mut auth_dao = db::auth::Dao::new(&db_thread_pool);

    let nonce = match web::block(move || auth_dao.get_and_refresh_signin_nonce(&user_email_clone1))
        .await?
    {
        Ok(a) => a,
        Err(DaoError::QueryFailure(diesel::result::Error::NotFound)) => {
            return Err(ServerError::NotFound(Some(String::from("User not found"))));
        }
        Err(e) => {
            log::error!("{}", e);
            return Err(ServerError::DatabaseTransactionError(Some(String::from(
                "Failed to obtain sign-in nonce",
            ))));
        }
    };

    if nonce != credentials.nonce {
        return Err(ServerError::AccessForbidden(Some(String::from(
            "Incorrect nonce",
        ))));
    }

    let hash_and_attempts = match web::block(move || {
        let mut auth_dao = db::auth::Dao::new(&db_thread_pool);
        auth_dao.get_user_auth_string_hash_and_mark_attempt(
            &user_email_clone2,
            env::CONF.security.authorization_attempts_reset_time,
        )
    })
    .await?
    {
        Ok(a) => a,
        Err(DaoError::QueryFailure(diesel::result::Error::NotFound)) => {
            return Err(ServerError::NotFound(Some(String::from("User not found"))));
        }
        Err(e) => {
            log::error!("{}", e);
            return Err(ServerError::DatabaseTransactionError(Some(String::from(
                "Failed to check authorization attempt count",
            ))));
        }
    };

    if !hash_and_attempts.is_user_verified {
        return Err(ServerError::AccessForbidden(Some(String::from(
            "User has not accepted verification email",
        ))));
    }

    if hash_and_attempts.attempt_count > env::CONF.security.authorization_max_attempts
        && hash_and_attempts.expiration_time >= SystemTime::now()
    {
        return Err(ServerError::AccessForbidden(Some(String::from(
            "Too many login attempts. Try again in a few minutes.",
        ))));
    }

    let does_auth_string_match_hash = web::block(move || {
        argon2_hasher::verify_hash(
            &credentials.auth_string,
            &hash_and_attempts.auth_string_hash,
            &env::CONF.keys.hashing_key,
        )
    })
    .await?;

    if does_auth_string_match_hash {
        let mut signin_token = AuthToken::new(
            user_id,
            &email,
            SystemTime::now() + env::CONF.lifetimes.signin_token_lifetime,
            AuthTokenType::SignIn,
        );

        signin_token.encrypt(&env::CONF.keys.token_encryption_cipher);

        let signin_token = SigninToken {
            signin_token: signin_token.encode_and_sign(&env::CONF.keys.token_signing_key),
        };

        let end_time = SystemTime::now() + env::CONF.lifetimes.otp_lifetime;

        // Add the lifetime of a generated code to the system time so the code doesn't expire quickly after
        // it is sent. The verification endpoint will check the code for the current time as well as a future
        // code. The real lifetime of the code the user gets is somewhere between OTP_LIFETIME_SECS and
        // OTP_LIFETIME_SECS * 2. A user's code will be valid for a maximum of OTP_LIFETIME_SECS * 2.
        let otp = match otp::generate_otp(
            hash_and_attempts.user_id,
            end_time,
            env::CONF.lifetimes.otp_lifetime,
            &env::CONF.keys.otp_key,
        ) {
            Ok(p) => p,
            Err(e) => {
                log::error!("{}", e);
                return Err(ServerError::InternalError(Some(String::from(
                    "Failed to generate OTP",
                ))));
            }
        };

        // TODO: Don't log this, email it!
        println!("\n\nOTP: {}\n\n", &otp);

        Ok(HttpResponse::Ok().json(signin_token))
    } else {
        Err(ServerError::UserUnauthorized(Some(String::from(
            "Incorrect email or auth string",
        ))))
    }
}

pub async fn verify_otp_for_signin(
    db_thread_pool: web::Data<DbThreadPool>,
    app_version: AppVersion,
    otp_and_token: web::Json<SigninTokenOtpPair>,
) -> Result<HttpResponse, ServerError> {
    const TOKEN_INVALID_MSG: &str = "Token is invalid";

    let mut token = match AuthToken::from_str(&otp_and_token.0.signin_token) {
        Ok(t) => t,
        Err(_) => {
            return Err(ServerError::UserUnauthorized(Some(String::from(
                TOKEN_INVALID_MSG,
            ))));
        }
    };

    if !token.verify(&env::CONF.keys.token_signing_key) {
        return Err(ServerError::UserUnauthorized(Some(String::from(
            TOKEN_INVALID_MSG,
        ))));
    }

    if let Err(_) = token.decrypt(&env::CONF.keys.token_encryption_cipher) {
        return Err(ServerError::UserUnauthorized(Some(String::from(
            TOKEN_INVALID_MSG,
        ))));
    }

    let token_claims = token.claims();

    if !matches!(token_claims.token_type, AuthTokenType::SignIn) {
        return Err(ServerError::UserUnauthorized(Some(String::from(
            TOKEN_INVALID_MSG,
        ))));
    }

    let user_id = token_claims.user_id;
    let user_email = token_claims.user_email.clone();

    let mut auth_dao = db::auth::Dao::new(&db_thread_pool);
    match web::block(move || {
        auth_dao.check_is_token_on_blacklist_and_blacklist(
            otp_and_token.0.signin_token.as_str(),
            token_claims,
        )
    })
    .await?
    {
        Ok(false) => (),
        Ok(true) => {
            return Err(ServerError::UserUnauthorized(Some(String::from(
                "Token has expired",
            ))));
        }
        Err(e) => {
            log::error!("{}", e);
            return Err(ServerError::InternalError(Some(String::from(
                "Error verifying token",
            ))));
        }
    };

    let mut auth_dao = db::auth::Dao::new(&db_thread_pool);

    let attempts = match web::block(move || {
        auth_dao.get_and_increment_otp_verification_count(
            user_id,
            env::CONF.security.otp_attempts_reset_time,
        )
    })
    .await?
    {
        Ok(a) => a,
        Err(e) => {
            log::error!("{}", e);
            return Err(ServerError::DatabaseTransactionError(Some(String::from(
                "Failed to check OTP attempt count",
            ))));
        }
    };

    if attempts.attempt_count > env::CONF.security.otp_max_attempts
        && attempts.expiration_time >= SystemTime::now()
    {
        return Err(ServerError::AccessForbidden(Some(String::from(
            "Too many attempts. Try again in a few minutes.",
        ))));
    }

    let is_valid = match web::block(move || {
        let otp = otp::OneTimePasscode::try_from(otp_and_token.0.otp)?;

        let current_time = SystemTime::now();

        let mut is_valid = otp::verify_otp(
            otp,
            user_id,
            current_time,
            env::CONF.lifetimes.otp_lifetime,
            &env::CONF.keys.otp_key,
        )?;

        // A future code gets sent to the user, so check a current and future code
        if !is_valid {
            is_valid = otp::verify_otp(
                otp,
                user_id,
                current_time + env::CONF.lifetimes.otp_lifetime,
                env::CONF.lifetimes.otp_lifetime,
                &env::CONF.keys.otp_key,
            )?;
        }

        Ok(is_valid)
    })
    .await?
    {
        Ok(v) => v,
        Err(e) => match e {
            otp::OtpError::Unauthorized => {
                return Err(ServerError::UserUnauthorized(Some(String::from(
                    "Incorrect passcode",
                ))))
            }
            otp::OtpError::ImproperlyFormatted => {
                return Err(ServerError::InputRejected(Some(String::from(
                    "Invalid passcode",
                ))))
            }
            otp::OtpError::Error(_) => {
                log::error!("{}", e);
                return Err(ServerError::InternalError(Some(String::from(
                    "Validating passcode failed",
                ))));
            }
        },
    };

    if !is_valid {
        return Err(ServerError::UserUnauthorized(Some(String::from(
            "Incorrect passcode",
        ))));
    }

    let now = SystemTime::now();

    let mut refresh_token = AuthToken::new(
        user_id,
        &user_email,
        now + env::CONF.lifetimes.refresh_token_lifetime,
        AuthTokenType::Refresh,
    );

    refresh_token.encrypt(&env::CONF.keys.token_encryption_cipher);

    let mut access_token = AuthToken::new(
        user_id,
        &user_email,
        now + env::CONF.lifetimes.access_token_lifetime,
        AuthTokenType::Access,
    );

    access_token.encrypt(&env::CONF.keys.token_encryption_cipher);

    let token_pair = TokenPair {
        access_token: access_token.sign_and_encode(&env::CONF.keys.token_signing_key),
        refresh_token: refresh_token.sign_and_encode(&env::CONF.keys.token_signing_key),
        server_time: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Failed to fetch system time")
            .as_millis(),
    };

    Ok(HttpResponse::Ok().json(token_pair))
}

pub async fn refresh_tokens(
    db_thread_pool: web::Data<DbThreadPool>,
    app_version: AppVersion,
    token: web::Json<RefreshToken>,
) -> Result<HttpResponse, ServerError> {
    const TOKEN_INVALID_MSG: &str = "Token is invalid";

    let mut refresh_token = match AuthToken::from_str(&token.0.token) {
        Ok(t) => t,
        Err(_) => {
            return Err(ServerError::UserUnauthorized(Some(String::from(
                TOKEN_INVALID_MSG,
            ))));
        }
    };

    if !refresh_token.verify(&env::CONF.keys.token_signing_key) {
        return Err(ServerError::UserUnauthorized(Some(String::from(
            TOKEN_INVALID_MSG,
        ))));
    }

    if let Err(_) = refresh_token.decrypt(&env::CONF.keys.token_encryption_cipher) {
        return Err(ServerError::UserUnauthorized(Some(String::from(
            TOKEN_INVALID_MSG,
        ))));
    }

    let token_claims = refresh_token.claims();

    if !matches!(token_claims.token_type, AuthTokenType::Refresh) {
        return Err(ServerError::UserUnauthorized(Some(String::from(
            ErrorUnauthorized(INVALID_TOKEN_MSG),
        ))));
    }

    let user_id = token_claims.user_id;
    let user_email = token_claims.user_email.clone();

    match web::block(move || {
        let mut auth_dao = db::auth::Dao::new(&db_thread_pool);
        auth_dao.check_is_token_on_blacklist_and_blacklist(&token.0.token, token_claims)
    })
    .await?
    {
        Ok(false) => (),
        Ok(true) => {
            return Err(ServerError::UserUnauthorized(Some(String::from(
                "Token has expired",
            ))));
        }
        Err(e) => {
            log::error!("{}", e);
            return Err(ServerError::InternalError(Some(String::from(
                "Error verifying token",
            ))));
        }
    };

    let mut refresh_token = AuthToken::new(
        user_id,
        &user_email,
        now + env::CONF.lifetimes.refresh_token_lifetime,
        AuthTokenType::Refresh,
    );

    refresh_token.encrypt(&env::CONF.keys.token_encryption_cipher);

    let mut access_token = AuthToken::new(
        user_id,
        &user_email,
        now + env::CONF.lifetimes.access_token_lifetime,
        AuthTokenType::Access,
    );

    access_token.encrypt(&env::CONF.keys.token_encryption_cipher);

    let token_pair = TokenPair {
        access_token: access_token.sign_and_encode(&env::CONF.keys.token_signing_key),
        refresh_token: refresh_token.sign_and_encode(&env::CONF.keys.token_signing_key),
        server_time: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Failed to fetch system time")
            .as_millis(),
    };

    Ok(HttpResponse::Ok().json(token_pair))
}

pub async fn logout(
    db_thread_pool: web::Data<DbThreadPool>,
    user_access_token: VerifiedToken<AccessToken, FromHeader, CheckExp>,
    refresh_token: VerifiedToken<RefreshToken, FromHeader, CheckExp>,
    // TODO: Get refresh token header from request, decode, and copy hash for blacklisting
) -> Result<HttpResponse, ServerError> {
    if refresh_token.0.user_id != user_access_token.0.user_id {
        return Err(ServerError::AccessForbidden(Some(String::from(
            "Refresh token does not belong to user.",
        ))));
    }

    match web::block(move || {
        let mut auth_dao = db::auth::Dao::new(&db_thread_pool);
        auth_dao.blacklist_token(&refresh_token.0.token, token_claims)
    })
    .await?
    {
        Ok(_) => (),
        Err(e) => {
            log::error!("{}", e);
            return Err(ServerError::DatabaseTransactionError(Some(String::from(
                "Failed to blacklist token",
            ))));
        }
    }

    Ok(HttpResponse::Ok().finish())
}
