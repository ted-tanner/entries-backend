use diesel::{dsl, ExpressionMethods, JoinOnDsl, NullableExpressionMethods, QueryDsl, RunQueryDsl};
use rand::{rngs::OsRng, Rng};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use uuid::Uuid;

use crate::auth_token::TokenClaims;
use crate::db::{DaoError, DbThreadPool};
use crate::models::authorization_attempts::{AuthorizationAttempts, NewAuthorizationAttempts};
use crate::models::blacklisted_token::NewBlacklistedToken;
use crate::models::otp_attempts::{NewOtpAttempts, OtpAttempts};
use crate::request_io::OutputSigninNonceData;
use crate::schema::authorization_attempts as authorization_attempt_fields;
use crate::schema::authorization_attempts::dsl::authorization_attempts;
use crate::schema::blacklisted_tokens as blacklisted_token_fields;
use crate::schema::blacklisted_tokens::dsl::blacklisted_tokens;
use crate::schema::otp_attempts as otp_attempt_fields;
use crate::schema::otp_attempts::dsl::otp_attempts;
use crate::schema::signin_nonces as signin_nonce_fields;
use crate::schema::signin_nonces::dsl::signin_nonces;
use crate::schema::user_security_data as user_security_data_fields;
use crate::schema::user_security_data::dsl::user_security_data;
use crate::schema::users as user_fields;
use crate::schema::users::dsl::users;

pub struct UserAuthStringHashAndAuthAttempts {
    pub user_id: Uuid,
    pub is_user_verified: bool,
    pub auth_string_hash: String,
    pub attempt_count: i16,
    pub expiration_time: SystemTime,
}

pub struct Dao {
    db_thread_pool: DbThreadPool,
}

impl Dao {
    pub fn new(db_thread_pool: &DbThreadPool) -> Self {
        Self {
            db_thread_pool: db_thread_pool.clone(),
        }
    }

    pub fn get_user_auth_string_hash_and_mark_attempt(
        &mut self,
        user_email: &str,
        attempts_lifetime: Duration,
    ) -> Result<UserAuthStringHashAndAuthAttempts, DaoError> {
        let mut db_connection = self.db_thread_pool.get()?;

        let hash_and_attempts = db_connection
            .build_transaction()
            .run::<_, diesel::result::Error, _>(|conn| {
                let (user_id, is_user_verified, auth_string_hash) = users
                    .left_join(
                        user_security_data
                            .on(user_security_data_fields::user_id.eq(user_fields::id)),
                    )
                    .select((
                        user_fields::id,
                        user_fields::is_verified,
                        user_security_data_fields::auth_string_hash.nullable(),
                    ))
                    .filter(user_fields::email.eq(user_email))
                    .get_result::<(Uuid, bool, Option<String>)>(conn)?;

                if !is_user_verified {
                    return Ok(UserAuthStringHashAndAuthAttempts {
                        user_id,
                        is_user_verified,
                        auth_string_hash: String::new(),
                        attempt_count: 0,
                        expiration_time: UNIX_EPOCH,
                    });
                }

                let auth_string_hash = auth_string_hash.unwrap_or(String::new());

                if auth_string_hash.is_empty() {
                    return Err(diesel::result::Error::NotFound);
                }

                let expiration_time = SystemTime::now() + attempts_lifetime;

                let new_attempt = NewAuthorizationAttempts {
                    user_id,
                    attempt_count: 1,
                    expiration_time,
                };

                let attempts = dsl::insert_into(authorization_attempts)
                    .values(&new_attempt)
                    .on_conflict(authorization_attempt_fields::user_id)
                    .do_update()
                    .set(
                        authorization_attempt_fields::attempt_count
                            .eq(authorization_attempt_fields::attempt_count + 1),
                    )
                    .get_result::<AuthorizationAttempts>(conn)?;

                Ok(UserAuthStringHashAndAuthAttempts {
                    user_id,
                    is_user_verified,
                    auth_string_hash,
                    attempt_count: attempts.attempt_count,
                    expiration_time: attempts.expiration_time,
                })
            })?;

        Ok(hash_and_attempts)
    }

    pub fn blacklist_token(
        &mut self,
        token: &str,
        token_claims: TokenClaims,
    ) -> Result<(), DaoError> {
        let expiration = UNIX_EPOCH + Duration::from_secs(token_claims.exp);

        let blacklisted_token = NewBlacklistedToken {
            token,
            user_id: token_claims.uid,
            token_expiration_time: expiration,
        };

        dsl::insert_into(blacklisted_tokens)
            .values(&blacklisted_token)
            .execute(&mut self.db_thread_pool.get()?)?;

        Ok(())
    }

    pub fn check_is_token_on_blacklist_and_blacklist(
        &mut self,
        token: &str,
        token_claims: TokenClaims,
    ) -> Result<bool, DaoError> {
        let count = blacklisted_tokens
            .filter(blacklisted_token_fields::token.eq(token))
            .count()
            .get_result::<i64>(&mut self.db_thread_pool.get()?)?;

        if count > 0 {
            Ok(true)
        } else {
            let expiration = UNIX_EPOCH + Duration::from_secs(token_claims.exp);

            let blacklisted_token = NewBlacklistedToken {
                token,
                user_id: token_claims.uid,
                token_expiration_time: expiration,
            };

            dsl::insert_into(blacklisted_tokens)
                .values(&blacklisted_token)
                .execute(&mut self.db_thread_pool.get()?)?;

            Ok(false)
        }
    }

    pub fn clear_all_expired_tokens(&mut self) -> Result<usize, DaoError> {
        // Add two minutes to current time to prevent slight clock differences/inaccuracies from
        // opening a window for an attacker to use an expired refresh token
        Ok(diesel::delete(
            blacklisted_tokens
                .filter(blacklisted_token_fields::token_expiration_time.lt(SystemTime::now())),
        )
        .execute(&mut self.db_thread_pool.get()?)?)
    }

    pub fn clear_otp_verification_count(
        &mut self,
        attempts_lifetime: Duration,
    ) -> Result<usize, DaoError> {
        let expiration_cut_off = SystemTime::now() - attempts_lifetime;

        Ok(diesel::delete(
            otp_attempts.filter(otp_attempt_fields::expiration_time.lt(expiration_cut_off)),
        )
        .execute(&mut self.db_thread_pool.get()?)?)
    }

    pub fn clear_authorization_attempt_count(
        &mut self,
        attempts_lifetime: Duration,
    ) -> Result<usize, DaoError> {
        let expiration_cut_off = SystemTime::now() - attempts_lifetime;

        Ok(diesel::delete(
            authorization_attempts
                .filter(authorization_attempt_fields::expiration_time.lt(expiration_cut_off)),
        )
        .execute(&mut self.db_thread_pool.get()?)?)
    }

    pub fn get_and_increment_otp_verification_count(
        &mut self,
        user_id: Uuid,
        attempts_lifetime: Duration,
    ) -> Result<OtpAttempts, DaoError> {
        let expiration_time = SystemTime::now() + attempts_lifetime;

        let new_attempt = NewOtpAttempts {
            user_id,
            attempt_count: 1,
            expiration_time,
        };

        Ok(dsl::insert_into(otp_attempts)
            .values(&new_attempt)
            .on_conflict(otp_attempt_fields::user_id)
            .do_update()
            .set(otp_attempt_fields::attempt_count.eq(otp_attempt_fields::attempt_count + 1))
            .get_result::<OtpAttempts>(&mut self.db_thread_pool.get()?)?)
    }

    pub fn get_and_refresh_signin_nonce(&mut self, user_email: &str) -> Result<i32, DaoError> {
        let mut db_connection = self.db_thread_pool.get()?;

        let nonce = db_connection
            .build_transaction()
            .run::<_, diesel::result::Error, _>(|conn| {
                let nonce = signin_nonces
                    .select(signin_nonce_fields::nonce)
                    .find(user_email)
                    .get_result::<i32>(conn)?;

                dsl::update(signin_nonces.find(user_email))
                    .set(signin_nonce_fields::nonce.eq(OsRng.gen::<i32>()))
                    .execute(conn)?;

                Ok(nonce)
            })?;

        Ok(nonce)
    }

    pub fn get_auth_string_salt_and_signin_nonce(
        &mut self,
        user_email: &str,
    ) -> Result<OutputSigninNonceData, DaoError> {
        let (auth_string_salt, auth_string_iters, signin_nonce) = user_security_data
            .left_join(users.on(user_fields::id.eq(user_security_data_fields::user_id)))
            .left_join(signin_nonces.on(signin_nonce_fields::user_email.eq(user_fields::email)))
            .filter(user_fields::email.eq(user_email))
            .select((
                user_security_data_fields::auth_string_salt,
                user_security_data_fields::auth_string_iters,
                signin_nonce_fields::nonce.nullable(),
            ))
            .first::<(Vec<u8>, i32, Option<i32>)>(&mut self.db_thread_pool.get()?)?;

        if let Some(nonce) = signin_nonce {
            Ok(OutputSigninNonceData {
                auth_string_salt,
                auth_string_iters,
                nonce,
            })
        } else {
            Err(DaoError::QueryFailure(diesel::result::Error::NotFound))
        }
    }
}
