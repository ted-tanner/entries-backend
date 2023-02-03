use budgetapp_utils::db::{DaoError, DbThreadPool};
use budgetapp_utils::request_io::{
    CredentialPair, RefreshToken, SigninToken, SigninTokenOtpPair, TokenPair,
};
use budgetapp_utils::validators::Validity;
use budgetapp_utils::{auth_token, db, otp, password_hasher, validators};

use actix_web::{web, HttpResponse};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::env;
use crate::handlers::error::ServerError;
use crate::middleware::auth::AuthorizedUserClaims;

pub async fn sign_in(
    db_thread_pool: web::Data<DbThreadPool>,
    credentials: web::Json<CredentialPair>,
) -> Result<HttpResponse, ServerError> {
    if let Validity::Invalid(msg) = validators::validate_email_address(&credentials.email) {
        return Err(ServerError::InvalidFormat(Some(msg)));
    }

    let user_email_clone1 = credentials.email.clone();
    let user_email_clone2 = credentials.email.clone();

    let hash_and_attempts = match web::block(move || {
        let mut auth_dao = db::auth::Dao::new(&db_thread_pool);
        auth_dao.get_user_auth_string_hash_and_mark_attempt(
            &user_email_clone1,
            Duration::from_secs(env::CONF.security.password_attempts_reset_mins * 60),
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
                "Failed to check password attempt count",
            ))));
        }
    };

    if !hash_and_attempts.is_user_verified {
        return Err(ServerError::AccessForbidden(Some(String::from(
            "User has not accepted verification email",
        ))));
    }

    if hash_and_attempts.attempt_count > env::CONF.security.password_max_attempts
        && hash_and_attempts.expiration_time >= SystemTime::now()
    {
        return Err(ServerError::AccessForbidden(Some(String::from(
            "Too many login attempts. Try again in a few minutes.",
        ))));
    }

    let does_password_match_hash = web::block(move || {
        password_hasher::verify_hash(
            &credentials.auth_string,
            &hash_and_attempts.auth_string_hash,
            env::CONF.keys.hashing_key.as_bytes(),
        )
    })
    .await?;

    if does_password_match_hash {
        let signin_token = auth_token::generate_signin_token(
            &auth_token::TokenParams {
                user_id: &hash_and_attempts.user_id,
                user_email: &user_email_clone2,
            },
            Duration::from_secs(env::CONF.lifetimes.access_token_lifetime_mins * 60),
            env::CONF.keys.token_signing_key.as_bytes(),
        );

        let signin_token = match signin_token {
            Ok(signin_token) => signin_token,
            Err(e) => {
                log::error!("{}", e);
                return Err(ServerError::InternalError(Some(String::from(
                    "Failed to generate sign-in token for user",
                ))));
            }
        };

        let signin_token = SigninToken {
            signin_token: signin_token.to_string(),
        };

        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Failed to fetch system time")
            .as_secs();

        // Add the lifetime of a generated code to the system time so the code doesn't expire quickly after
        // it is sent. The verification endpoint will check the code for the current time as well as a future
        // code. The real lifetime of the code the user gets is somewhere between OTP_LIFETIME_SECS and
        // OTP_LIFETIME_SECS * 2. A user's code will be valid for a maximum of OTP_LIFETIME_SECS * 2.
        let otp = match otp::generate_otp(
            hash_and_attempts.user_id,
            current_time + env::CONF.lifetimes.otp_lifetime_mins * 60,
            Duration::from_secs(env::CONF.lifetimes.otp_lifetime_mins * 60),
            env::CONF.keys.otp_key.as_bytes(),
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
            "Incorrect email or password",
        ))))
    }
}

pub async fn verify_otp_for_signin(
    db_thread_pool: web::Data<DbThreadPool>,
    otp_and_token: web::Json<SigninTokenOtpPair>,
) -> Result<HttpResponse, ServerError> {
    let token_claims = match web::block(move || {
        auth_token::validate_signin_token(
            &otp_and_token.0.signin_token,
            env::CONF.keys.token_signing_key.as_bytes(),
        )
    })
    .await?
    {
        Ok(t) => t,
        Err(e) => match e {
            auth_token::TokenError::TokenInvalid => {
                return Err(ServerError::UserUnauthorized(Some(String::from(
                    "Token is invalid",
                ))));
            }
            auth_token::TokenError::TokenExpired => {
                return Err(ServerError::UserUnauthorized(Some(String::from(
                    "Token has expired",
                ))));
            }
            auth_token::TokenError::TokenBlacklisted => {
                return Err(ServerError::UserUnauthorized(Some(String::from(
                    "Token has been blacklisted",
                ))));
            }
            auth_token::TokenError::WrongTokenType => {
                return Err(ServerError::UserUnauthorized(Some(String::from(
                    "Incorrect token type",
                ))));
            }
            e => {
                log::error!("{}", e);
                return Err(ServerError::InternalError(Some(String::from(
                    "Error verifying token",
                ))));
            }
        },
    };

    let mut auth_dao = db::auth::Dao::new(&db_thread_pool);

    let attempts = match web::block(move || {
        auth_dao.get_and_increment_otp_verification_count(
            token_claims.uid,
            Duration::from_secs(env::CONF.security.otp_attempts_reset_mins * 60),
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

        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Failed to fetch system time")
            .as_secs();

        let mut is_valid = otp::verify_otp(
            otp,
            token_claims.uid,
            current_time,
            Duration::from_secs(env::CONF.lifetimes.otp_lifetime_mins * 60),
            env::CONF.keys.otp_key.as_bytes(),
        )?;

        // A future code gets sent to the user, so check a current and future code
        if !is_valid {
            is_valid = otp::verify_otp(
                otp,
                token_claims.uid,
                current_time + env::CONF.lifetimes.otp_lifetime_mins * 60,
                Duration::from_secs(env::CONF.lifetimes.otp_lifetime_mins * 60),
                env::CONF.keys.otp_key.as_bytes(),
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

    let token_pair = auth_token::generate_token_pair(
        &auth_token::TokenParams {
            user_id: &token_claims.uid,
            user_email: &token_claims.eml,
        },
        Duration::from_secs(env::CONF.lifetimes.access_token_lifetime_mins * 60),
        Duration::from_secs(env::CONF.lifetimes.refresh_token_lifetime_days * 60 * 60 * 24),
        env::CONF.keys.token_signing_key.as_bytes(),
    );

    let token_pair = match token_pair {
        Ok(token_pair) => token_pair,
        Err(e) => {
            log::error!("{}", e);
            return Err(ServerError::InternalError(Some(String::from(
                "Failed to generate tokens for new user",
            ))));
        }
    };

    let token_pair = TokenPair {
        access_token: token_pair.access_token.to_string(),
        refresh_token: token_pair.refresh_token.to_string(),
        server_time: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Failed to fetch system time")
            .as_millis(),
    };

    let mut user_dao = db::user::Dao::new(&db_thread_pool);

    // TODO: Make it so users don't have to wait for this
    match web::block(move || user_dao.set_last_token_refresh_now(token_claims.uid)).await? {
        Ok(_) => (),
        Err(e) => log::error!("{}", e),
    };

    Ok(HttpResponse::Ok().json(token_pair))
}

pub async fn refresh_tokens(
    db_thread_pool: web::Data<DbThreadPool>,
    token: web::Json<RefreshToken>,
) -> Result<HttpResponse, ServerError> {
    let refresh_token = token.0.token.clone();
    let mut auth_dao = db::auth::Dao::new(&db_thread_pool);

    let claims = match web::block(move || {
        auth_token::validate_refresh_token(
            token.0.token.as_str(),
            env::CONF.keys.token_signing_key.as_bytes(),
            &mut auth_dao,
        )
    })
    .await?
    {
        Ok(c) => c,
        Err(e) => match e {
            auth_token::TokenError::TokenInvalid => {
                return Err(ServerError::UserUnauthorized(Some(String::from(
                    "Token is invalid",
                ))));
            }
            auth_token::TokenError::TokenBlacklisted => {
                return Err(ServerError::UserUnauthorized(Some(String::from(
                    "Token has been blacklisted",
                ))));
            }
            auth_token::TokenError::TokenExpired => {
                return Err(ServerError::UserUnauthorized(Some(String::from(
                    "Token has expired",
                ))));
            }
            auth_token::TokenError::WrongTokenType => {
                return Err(ServerError::UserUnauthorized(Some(String::from(
                    "Incorrect token type",
                ))));
            }
            e => {
                log::error!("{}", e);
                return Err(ServerError::InternalError(Some(String::from(
                    "Error verifying token",
                ))));
            }
        },
    };

    let mut auth_dao = db::auth::Dao::new(&db_thread_pool);

    // TODO: Make it so users don't have to wait for this
    match web::block(move || auth_token::blacklist_token(refresh_token.as_str(), &mut auth_dao))
        .await?
    {
        Ok(_) => {}
        Err(e) => {
            log::error!("{}", e);
            return Err(ServerError::DatabaseTransactionError(Some(String::from(
                "Failed to blacklist token",
            ))));
        }
    }

    let token_pair = auth_token::generate_token_pair(
        &auth_token::TokenParams {
            user_id: &claims.uid,
            user_email: &claims.eml,
        },
        Duration::from_secs(env::CONF.lifetimes.access_token_lifetime_mins * 60),
        Duration::from_secs(env::CONF.lifetimes.refresh_token_lifetime_days * 60 * 60 * 24),
        env::CONF.keys.token_signing_key.as_bytes(),
    );

    let token_pair = match token_pair {
        Ok(token_pair) => token_pair,
        Err(e) => {
            log::error!("{}", e);
            return Err(ServerError::InternalError(Some(String::from(
                "Failed to generate tokens for new user",
            ))));
        }
    };

    let token_pair = TokenPair {
        access_token: token_pair.access_token.to_string(),
        refresh_token: token_pair.refresh_token.to_string(),
        server_time: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Failed to fetch system time")
            .as_millis(),
    };

    let mut user_dao = db::user::Dao::new(&db_thread_pool);

    // TODO: Make it so users don't have to wait for this
    match web::block(move || user_dao.set_last_token_refresh_now(claims.uid)).await? {
        Ok(_) => (),
        Err(e) => log::error!("{}", e),
    };

    Ok(HttpResponse::Ok().json(token_pair))
}

pub async fn logout(
    db_thread_pool: web::Data<DbThreadPool>,
    auth_user_claims: AuthorizedUserClaims,
    refresh_token: web::Json<RefreshToken>,
) -> Result<HttpResponse, ServerError> {
    let refresh_token_clone = refresh_token.token.clone();
    let mut auth_dao = db::auth::Dao::new(&db_thread_pool);

    let refresh_token_claims = match web::block(move || {
        auth_token::validate_refresh_token(
            &refresh_token_clone,
            env::CONF.keys.token_signing_key.as_bytes(),
            &mut auth_dao,
        )
    })
    .await?
    {
        Ok(tc) => tc,
        Err(e) => match e {
            auth_token::TokenError::TokenInvalid => {
                return Err(ServerError::UserUnauthorized(Some(String::from(
                    "Token is invalid",
                ))))
            }
            auth_token::TokenError::TokenBlacklisted => {
                return Err(ServerError::UserUnauthorized(Some(String::from(
                    "Token has been blacklisted",
                ))))
            }
            auth_token::TokenError::TokenExpired => {
                return Err(ServerError::UserUnauthorized(Some(String::from(
                    "Token has expired",
                ))))
            }
            auth_token::TokenError::WrongTokenType => {
                return Err(ServerError::UserUnauthorized(Some(String::from(
                    "Incorrect token type",
                ))))
            }
            e => {
                log::error!("{}", e);
                return Err(ServerError::InternalError(Some(String::from(
                    "Error verifying token",
                ))));
            }
        },
    };

    if refresh_token_claims.uid != auth_user_claims.0.uid {
        return Err(ServerError::AccessForbidden(Some(String::from(
            "Refresh token does not belong to user.",
        ))));
    }

    let mut auth_dao = db::auth::Dao::new(&db_thread_pool);

    match web::block(move || {
        auth_token::blacklist_token(refresh_token.0.token.as_str(), &mut auth_dao)
    })
    .await
    {
        Ok(_) => Ok(HttpResponse::Ok().finish()),
        Err(e) => {
            log::error!("{}", e);
            Err(ServerError::InternalError(Some(String::from(
                "Failed to blacklist token",
            ))))
        }
    }
}
