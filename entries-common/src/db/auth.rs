use diesel::{dsl, ExpressionMethods, JoinOnDsl, NullableExpressionMethods, QueryDsl, RunQueryDsl};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use uuid::Uuid;

use crate::db::{DaoError, DbThreadPool};
use crate::messages::SigninNonceAndHashParams;
use crate::models::blacklisted_token::NewBlacklistedToken;
use crate::models::user_backup_code::NewUserBackupCode;
use crate::models::user_otp::NewUserOtp;
use crate::schema::blacklisted_tokens as blacklisted_token_fields;
use crate::schema::blacklisted_tokens::dsl::blacklisted_tokens;
use crate::schema::signin_nonces as signin_nonce_fields;
use crate::schema::signin_nonces::dsl::signin_nonces;
use crate::schema::user_backup_codes as user_backup_code_fields;
use crate::schema::user_backup_codes::dsl::user_backup_codes;
use crate::schema::user_otps as user_otp_fields;
use crate::schema::user_otps::dsl::user_otps;
use crate::schema::users as user_fields;
use crate::schema::users::dsl::users;
use crate::threadrand::SecureRng;

pub struct UserAuthStringHashAndStatus {
    pub user_id: Uuid,
    pub is_user_verified: bool,
    pub auth_string_hash: String,
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

    pub fn get_user_auth_string_hash_and_status(
        &self,
        user_email: &str,
    ) -> Result<UserAuthStringHashAndStatus, DaoError> {
        let (user_id, is_user_verified, auth_string_hash) = users
            .select((
                user_fields::id,
                user_fields::is_verified,
                user_fields::auth_string_hash,
            ))
            .filter(user_fields::email.eq(user_email))
            .get_result::<(Uuid, bool, String)>(&mut self.db_thread_pool.get()?)?;

        if !is_user_verified {
            return Ok(UserAuthStringHashAndStatus {
                user_id,
                is_user_verified,
                auth_string_hash: String::new(),
            });
        }

        Ok(UserAuthStringHashAndStatus {
            user_id,
            is_user_verified,
            auth_string_hash,
        })
    }

    pub fn blacklist_token(
        &self,
        token_signature: &[u8],
        token_expiration: u64,
    ) -> Result<(), DaoError> {
        let token_expiration = UNIX_EPOCH + Duration::from_secs(token_expiration);

        let blacklisted_token = NewBlacklistedToken {
            token_signature,
            token_expiration,
        };

        dsl::insert_into(blacklisted_tokens)
            .values(&blacklisted_token)
            .execute(&mut self.db_thread_pool.get()?)?;

        Ok(())
    }

    pub fn check_is_token_on_blacklist_and_blacklist(
        &self,
        token_signature: &[u8],
        token_expiration: u64,
    ) -> Result<bool, DaoError> {
        let count = blacklisted_tokens
            .filter(blacklisted_token_fields::token_signature.eq(token_signature))
            .count()
            .get_result::<i64>(&mut self.db_thread_pool.get()?)?;

        if count > 0 {
            Ok(true)
        } else {
            let token_expiration = UNIX_EPOCH + Duration::from_secs(token_expiration);

            let blacklisted_token = NewBlacklistedToken {
                token_signature,
                token_expiration,
            };

            dsl::insert_into(blacklisted_tokens)
                .values(&blacklisted_token)
                .execute(&mut self.db_thread_pool.get()?)?;

            Ok(false)
        }
    }

    pub fn save_otp(
        &self,
        otp: &str,
        user_email: &str,
        expiration: SystemTime,
    ) -> Result<(), DaoError> {
        let new_otp = NewUserOtp {
            user_email,
            otp,
            expiration,
        };

        dsl::insert_into(user_otps)
            .values(&new_otp)
            .on_conflict(user_otp_fields::user_email)
            .do_update()
            .set((
                user_otp_fields::otp.eq(otp),
                user_otp_fields::expiration.eq(expiration),
            ))
            .execute(&mut self.db_thread_pool.get()?)?;

        Ok(())
    }

    pub fn check_unexpired_otp(&self, otp: &str, user_email: &str) -> Result<bool, DaoError> {
        Ok(dsl::select(dsl::exists(
            user_otps
                .find(user_email)
                .filter(user_otp_fields::otp.eq(otp))
                .filter(user_otp_fields::expiration.gt(SystemTime::now())),
        ))
        .get_result(&mut self.db_thread_pool.get()?)?)
    }

    pub fn delete_otp(&self, otp: &str, user_email: &str) -> Result<(), DaoError> {
        diesel::delete(
            user_otps
                .find(user_email)
                .filter(user_otp_fields::otp.eq(otp)),
        )
        .execute(&mut self.db_thread_pool.get()?)?;

        Ok(())
    }

    pub fn delete_all_expired_otps(&self) -> Result<(), DaoError> {
        dsl::delete(user_otps.filter(user_otp_fields::expiration.lt(SystemTime::now())))
            .execute(&mut self.db_thread_pool.get()?)?;

        Ok(())
    }

    pub fn replace_backup_codes(&self, user_id: Uuid, codes: &[String]) -> Result<(), DaoError> {
        let codes = codes
            .iter()
            .map(|code| NewUserBackupCode { user_id, code })
            .collect::<Vec<_>>();

        let mut db_connection = self.db_thread_pool.get()?;

        db_connection
            .build_transaction()
            .run::<_, DaoError, _>(|conn| {
                diesel::delete(
                    user_backup_codes.filter(user_backup_code_fields::user_id.eq(user_id)),
                )
                .execute(conn)?;

                dsl::insert_into(user_backup_codes)
                    .values(&codes)
                    .execute(conn)?;

                Ok(())
            })?;

        Ok(())
    }

    pub fn delete_backup_code(&self, code: &str, user_id: Uuid) -> Result<(), DaoError> {
        diesel::delete(user_backup_codes.find((user_id, code)))
            .execute(&mut self.db_thread_pool.get()?)?;

        Ok(())
    }

    pub fn clear_all_expired_tokens(&self) -> Result<usize, DaoError> {
        // Add two minutes to current time to prevent slight clock differences/inaccuracies from
        // opening a window for an attacker to use an expired refresh token
        Ok(diesel::delete(
            blacklisted_tokens
                .filter(blacklisted_token_fields::token_expiration.lt(SystemTime::now())),
        )
        .execute(&mut self.db_thread_pool.get()?)?)
    }

    pub fn get_and_refresh_signin_nonce(&self, user_email: &str) -> Result<i32, DaoError> {
        let mut db_connection = self.db_thread_pool.get()?;

        let nonce = db_connection
            .build_transaction()
            .run::<_, diesel::result::Error, _>(|conn| {
                let nonce = signin_nonces
                    .select(signin_nonce_fields::nonce)
                    .find(user_email)
                    .get_result::<i32>(conn)?;

                dsl::update(signin_nonces.find(user_email))
                    .set(signin_nonce_fields::nonce.eq(SecureRng::next_i32()))
                    .execute(conn)?;

                Ok(nonce)
            })?;

        Ok(nonce)
    }

    pub fn get_auth_string_data_signin_nonce(
        &self,
        user_email: &str,
    ) -> Result<SigninNonceAndHashParams, DaoError> {
        let (salt, mem_cost, parallel, iters, nonce) = users
            .left_join(signin_nonces.on(signin_nonce_fields::user_email.eq(user_fields::email)))
            .filter(user_fields::email.eq(user_email))
            .select((
                user_fields::auth_string_hash_salt,
                user_fields::auth_string_hash_mem_cost_kib,
                user_fields::auth_string_hash_parallelism_factor,
                user_fields::auth_string_hash_iterations,
                signin_nonce_fields::nonce.nullable(),
            ))
            .first::<(Vec<u8>, i32, i32, i32, Option<i32>)>(&mut self.db_thread_pool.get()?)?;

        if let Some(n) = nonce {
            Ok(SigninNonceAndHashParams {
                auth_string_hash_salt: salt,
                auth_string_hash_mem_cost_kib: mem_cost,
                auth_string_hash_threads: parallel,
                auth_string_hash_iterations: iters,
                nonce: n,
            })
        } else {
            Err(DaoError::QueryFailure(diesel::result::Error::NotFound))
        }
    }
}
