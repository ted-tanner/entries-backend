use diesel::{dsl, ExpressionMethods, JoinOnDsl, NullableExpressionMethods, QueryDsl};
use diesel_async::RunQueryDsl;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use uuid::Uuid;

use crate::db::{DaoError, DbAsyncPool};
use crate::messages::SigninNonceAndHashParams;
use crate::models::blacklisted_token::NewBlacklistedToken;
use crate::models::user::User;
use crate::models::user_otp::NewUserOtp;
use crate::schema::blacklisted_tokens as blacklisted_token_fields;
use crate::schema::blacklisted_tokens::dsl::blacklisted_tokens;
use crate::schema::signin_nonces as signin_nonce_fields;
use crate::schema::signin_nonces::dsl::signin_nonces;
use crate::schema::user_otps as user_otp_fields;
use crate::schema::user_otps::dsl::user_otps;
use crate::schema::users as user_fields;
use crate::schema::users::dsl::users;
use crate::threadrand::SecureRng;

pub struct UserAuthStringHashAndStatus {
    pub user_id: Uuid,
    pub is_user_verified: bool,
    pub auth_string_hash: String,
    pub created_timestamp: SystemTime,
}

pub struct Dao {
    db_pool: DbAsyncPool,
}

impl Dao {
    pub fn new(db_pool: &DbAsyncPool) -> Self {
        Self {
            db_pool: db_pool.clone(),
        }
    }

    pub async fn get_user_auth_string_hash_and_status(
        &self,
        user_email: &str,
    ) -> Result<UserAuthStringHashAndStatus, DaoError> {
        let mut conn = self.db_pool.get().await?;

        let (user_id, is_user_verified, auth_string_hash, created_timestamp) = users
            .select((
                user_fields::id,
                user_fields::is_verified,
                user_fields::auth_string_hash,
                user_fields::created_timestamp,
            ))
            .filter(user_fields::email.eq(user_email))
            .get_result::<(Uuid, bool, String, SystemTime)>(&mut conn)
            .await?;

        if !is_user_verified {
            return Ok(UserAuthStringHashAndStatus {
                user_id,
                is_user_verified,
                auth_string_hash: String::new(),
                created_timestamp,
            });
        }

        Ok(UserAuthStringHashAndStatus {
            user_id,
            is_user_verified,
            auth_string_hash,
            created_timestamp,
        })
    }

    pub async fn get_user_recovery_auth_string_hash_and_status(
        &self,
        user_email: &str,
    ) -> Result<UserAuthStringHashAndStatus, DaoError> {
        let mut conn = self.db_pool.get().await?;

        let (user_id, is_user_verified, recovery_key_auth_hash_rehashed, created_timestamp) = users
            .select((
                user_fields::id,
                user_fields::is_verified,
                user_fields::recovery_key_auth_hash_rehashed_with_auth_string_params,
                user_fields::created_timestamp,
            ))
            .filter(user_fields::email.eq(user_email))
            .get_result::<(Uuid, bool, String, SystemTime)>(&mut conn)
            .await?;

        if !is_user_verified {
            return Ok(UserAuthStringHashAndStatus {
                user_id,
                is_user_verified,
                auth_string_hash: String::new(),
                created_timestamp,
            });
        }

        Ok(UserAuthStringHashAndStatus {
            user_id,
            is_user_verified,
            auth_string_hash: recovery_key_auth_hash_rehashed,
            created_timestamp,
        })
    }

    pub async fn blacklist_token(
        &self,
        token_signature: &[u8],
        token_expiration: u64,
    ) -> Result<(), DaoError> {
        let mut conn = self.db_pool.get().await?;

        let token_expiration = UNIX_EPOCH + Duration::from_secs(token_expiration);

        let blacklisted_token = NewBlacklistedToken {
            token_signature,
            token_expiration,
        };

        dsl::insert_into(blacklisted_tokens)
            .values(&blacklisted_token)
            .execute(&mut conn)
            .await?;

        Ok(())
    }

    pub async fn check_is_token_on_blacklist_and_blacklist(
        &self,
        token_signature: &[u8],
        token_expiration: u64,
    ) -> Result<bool, DaoError> {
        let mut conn = self.db_pool.get().await?;

        let count = blacklisted_tokens
            .filter(blacklisted_token_fields::token_signature.eq(token_signature))
            .count()
            .get_result::<i64>(&mut conn)
            .await?;

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
                .execute(&mut conn)
                .await?;

            Ok(false)
        }
    }

    pub async fn save_otp(
        &self,
        otp: &str,
        user_email: &str,
        expiration: SystemTime,
    ) -> Result<(), DaoError> {
        let mut conn = self.db_pool.get().await?;

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
            .execute(&mut conn)
            .await?;

        Ok(())
    }

    pub async fn check_unexpired_otp(&self, otp: &str, user_email: &str) -> Result<bool, DaoError> {
        let mut conn = self.db_pool.get().await?;

        Ok(dsl::select(dsl::exists(
            user_otps
                .find(user_email)
                .filter(user_otp_fields::otp.eq(otp))
                .filter(user_otp_fields::expiration.gt(SystemTime::now())),
        ))
        .get_result(&mut conn)
        .await?)
    }

    pub async fn delete_otp(&self, otp: &str, user_email: &str) -> Result<(), DaoError> {
        let mut conn = self.db_pool.get().await?;

        diesel::delete(
            user_otps
                .find(user_email)
                .filter(user_otp_fields::otp.eq(otp)),
        )
        .execute(&mut conn)
        .await?;

        Ok(())
    }

    pub async fn delete_all_expired_otps(&self) -> Result<(), DaoError> {
        let mut conn = self.db_pool.get().await?;

        dsl::delete(user_otps.filter(user_otp_fields::expiration.lt(SystemTime::now())))
            .execute(&mut conn)
            .await?;

        Ok(())
    }

    pub async fn clear_all_expired_tokens(&self) -> Result<usize, DaoError> {
        let mut conn = self.db_pool.get().await?;

        // Subtract two minutes from current time to prevent slight clock differences/inaccuracies from
        // opening a window for an attacker to use an expired refresh token
        let current_time_minus_two_minutes = SystemTime::now() - Duration::from_secs(120);
        Ok(diesel::delete(
            blacklisted_tokens.filter(
                blacklisted_token_fields::token_expiration.lt(current_time_minus_two_minutes),
            ),
        )
        .execute(&mut conn)
        .await?)
    }

    pub async fn get_and_refresh_signin_nonce(&self, user_email: &str) -> Result<i32, DaoError> {
        let mut conn = self.db_pool.get().await?;

        let nonce = conn
            .build_transaction()
            .run::<_, diesel::result::Error, _>(|conn| {
                Box::pin(async move {
                    let nonce = signin_nonces
                        .select(signin_nonce_fields::nonce)
                        .find(user_email)
                        .get_result::<i32>(conn)
                        .await?;

                    dsl::update(signin_nonces.find(user_email))
                        .set(signin_nonce_fields::nonce.eq(SecureRng::next_i32()))
                        .execute(conn)
                        .await?;

                    Ok(nonce)
                })
            })
            .await?;

        Ok(nonce)
    }

    pub async fn get_auth_string_data_signin_nonce(
        &self,
        user_email: &str,
    ) -> Result<SigninNonceAndHashParams, DaoError> {
        let mut conn = self.db_pool.get().await?;

        let (salt, mem_cost, parallel, iters, nonce) = users
            .left_join(signin_nonces.on(signin_nonce_fields::user_email.eq(user_fields::email)))
            .filter(user_fields::email.eq(user_email))
            .select((
                user_fields::auth_string_hash_salt,
                user_fields::auth_string_hash_mem_cost_kib,
                user_fields::auth_string_hash_threads,
                user_fields::auth_string_hash_iterations,
                signin_nonce_fields::nonce.nullable(),
            ))
            .first::<(Vec<u8>, i32, i32, i32, Option<i32>)>(&mut conn)
            .await?;

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

    #[allow(clippy::too_many_arguments)]
    pub async fn update_recovery_key_and_auth_string_and_email(
        &self,
        user_email: &str,
        new_user_email: Option<&str>,
        rehashed_new_auth_string: &str,
        new_auth_string_hash_salt: &[u8],
        new_auth_string_hash_mem_cost_kib: i32,
        new_auth_string_hash_threads: i32,
        new_auth_string_hash_iterations: i32,
        new_recovery_key_hash_salt_for_encryption: &[u8],
        new_recovery_key_hash_salt_for_recovery_auth: &[u8],
        new_recovery_key_hash_mem_cost_kib: i32,
        new_recovery_key_hash_threads: i32,
        new_recovery_key_hash_iterations: i32,
        rehashed_recovery_key_auth_hash: &str,
        encryption_key_encrypted_with_new_password: &[u8],
        encryption_key_encrypted_with_new_recovery_key: &[u8],
    ) -> Result<(), DaoError> {
        let mut conn = self.db_pool.get().await?;

        conn.build_transaction()
            .run::<_, DaoError, _>(|conn| {
                Box::pin(async move {
                    let user: User = users
                        .filter(user_fields::email.eq(user_email))
                        .first(conn)
                        .await?;

                    diesel::update(users.filter(user_fields::id.eq(user.id)))
                        .set((
                            user_fields::auth_string_hash.eq(rehashed_new_auth_string),
                            user_fields::auth_string_hash_salt.eq(new_auth_string_hash_salt),
                            user_fields::auth_string_hash_mem_cost_kib
                                .eq(new_auth_string_hash_mem_cost_kib),
                            user_fields::auth_string_hash_threads.eq(new_auth_string_hash_threads),
                            user_fields::auth_string_hash_iterations
                                .eq(new_auth_string_hash_iterations),
                            user_fields::encryption_key_encrypted_with_password
                                .eq(encryption_key_encrypted_with_new_password),
                        ))
                        .execute(conn)
                        .await?;

                    diesel::update(users.filter(user_fields::id.eq(user.id)))
                        .set((
                            user_fields::recovery_key_hash_salt_for_encryption
                                .eq(new_recovery_key_hash_salt_for_encryption),
                            user_fields::recovery_key_hash_salt_for_recovery_auth
                                .eq(new_recovery_key_hash_salt_for_recovery_auth),
                            user_fields::recovery_key_hash_mem_cost_kib
                                .eq(new_recovery_key_hash_mem_cost_kib),
                            user_fields::recovery_key_hash_threads
                                .eq(new_recovery_key_hash_threads),
                            user_fields::recovery_key_hash_iterations
                                .eq(new_recovery_key_hash_iterations),
                            user_fields::recovery_key_auth_hash_rehashed_with_auth_string_params
                                .eq(rehashed_recovery_key_auth_hash),
                            user_fields::encryption_key_encrypted_with_recovery_key
                                .eq(encryption_key_encrypted_with_new_recovery_key),
                        ))
                        .execute(conn)
                        .await?;

                    if let Some(new_email) = new_user_email {
                        diesel::update(users.filter(user_fields::id.eq(user.id)))
                            .set(user_fields::email.eq(new_email))
                            .execute(conn)
                            .await?;
                    }

                    Ok(())
                })
            })
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::test_utils::{self, TestUserData};
    use crate::schema::signin_nonces as signin_nonce_fields;
    use crate::schema::signin_nonces::dsl::signin_nonces;
    use diesel::{dsl, ExpressionMethods, QueryDsl};

    fn dao() -> Dao {
        Dao::new(test_utils::db_async_pool())
    }

    async fn create_verified_user() -> (Uuid, TestUserData) {
        let user_dao = crate::db::user::Dao::new(test_utils::db_async_pool());
        let inserted = test_utils::create_user_with_dao(&user_dao).await;
        let mut conn = test_utils::db_async_conn().await;
        diesel_async::RunQueryDsl::execute(
            dsl::update(users.find(inserted.id)).set(user_fields::is_verified.eq(true)),
            &mut conn,
        )
        .await
        .unwrap();
        (inserted.id, inserted.data)
    }

    #[tokio::test]
    #[ignore = "Needs async pool setup"]
    async fn auth_string_queries_respect_verification_status() {
        let dao = dao();
        let (user_id, data) = create_verified_user().await;

        diesel_async::RunQueryDsl::execute(
            dsl::update(users.find(user_id)).set(user_fields::is_verified.eq(false)),
            &mut test_utils::db_async_conn().await,
        )
        .await
        .unwrap();

        let result = dao
            .get_user_auth_string_hash_and_status(&data.email)
            .await
            .unwrap();
        assert!(!result.is_user_verified);
        assert!(result.auth_string_hash.is_empty());

        diesel_async::RunQueryDsl::execute(
            dsl::update(users.find(user_id)).set(user_fields::is_verified.eq(true)),
            &mut test_utils::db_async_conn().await,
        )
        .await
        .unwrap();

        let verified_auth = dao
            .get_user_auth_string_hash_and_status(&data.email)
            .await
            .unwrap();
        assert!(verified_auth.is_user_verified);
        assert_eq!(verified_auth.auth_string_hash, data.auth_string_hash);

        let recovery = dao
            .get_user_recovery_auth_string_hash_and_status(&data.email)
            .await
            .unwrap();
        assert_eq!(
            recovery.auth_string_hash,
            data.recovery_key_auth_hash_rehashed_with_auth_string_params
        );

        test_utils::delete_user(user_id).await;
    }

    #[tokio::test]
    #[ignore = "Needs async pool setup"]
    async fn blacklist_and_token_checks_work() {
        let dao = dao();
        let token_signature = test_utils::random_bytes(16);
        let expiration = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 60;

        dao.blacklist_token(&token_signature, expiration)
            .await
            .unwrap();
        let already_blacklisted = dao
            .check_is_token_on_blacklist_and_blacklist(&token_signature, expiration)
            .await
            .unwrap();
        assert!(already_blacklisted);

        let new_signature = test_utils::random_bytes(16);
        let was_listed = dao
            .check_is_token_on_blacklist_and_blacklist(&new_signature, expiration)
            .await
            .unwrap();
        assert!(!was_listed);

        // Ensure expired entries removed
        dao.clear_all_expired_tokens().await.unwrap();
    }

    #[tokio::test]
    #[ignore = "Needs async pool setup"]
    async fn otp_lifecycle_and_expiration_cleanup() {
        let dao = dao();
        let (user_id, data) = create_verified_user().await;
        let otp = "12345678";

        dao.save_otp(
            otp,
            &data.email,
            SystemTime::now() + Duration::from_secs(60),
        )
        .await
        .unwrap();
        assert!(dao.check_unexpired_otp(otp, &data.email).await.unwrap());

        // Update existing OTP
        dao.save_otp(
            otp,
            &data.email,
            SystemTime::now() + Duration::from_secs(120),
        )
        .await
        .unwrap();

        dao.delete_otp(otp, &data.email).await.unwrap();
        assert!(!dao.check_unexpired_otp(otp, &data.email).await.unwrap());

        dao.save_otp(
            otp,
            &data.email,
            SystemTime::now() - Duration::from_secs(10),
        )
        .await
        .unwrap();
        dao.delete_all_expired_otps().await.unwrap();
        assert!(!dao.check_unexpired_otp(otp, &data.email).await.unwrap());
        test_utils::delete_user(user_id).await;
    }

    #[tokio::test]
    #[ignore = "Needs async pool setup"]
    async fn signin_nonce_and_hash_params_are_returned_and_refreshed() {
        let dao = dao();
        let (user_id, data) = create_verified_user().await;

        let original_nonce = {
            let mut conn = test_utils::db_async_conn().await;
            diesel_async::RunQueryDsl::first::<i32>(
                signin_nonces
                    .select(signin_nonce_fields::nonce)
                    .find(&data.email),
                &mut conn,
            )
            .await
            .unwrap()
        };

        let fetched_nonce = dao.get_and_refresh_signin_nonce(&data.email).await.unwrap();
        assert_eq!(fetched_nonce, original_nonce);

        let auth_data = dao
            .get_auth_string_data_signin_nonce(&data.email)
            .await
            .unwrap();
        assert_eq!(
            auth_data.auth_string_hash_iterations,
            data.auth_string_hash_iterations
        );

        let new_nonce = {
            let mut conn = test_utils::db_async_conn().await;
            diesel_async::RunQueryDsl::first::<i32>(
                signin_nonces
                    .select(signin_nonce_fields::nonce)
                    .find(&data.email),
                &mut conn,
            )
            .await
            .unwrap()
        };
        assert_ne!(new_nonce, original_nonce);

        test_utils::delete_user(user_id).await;
    }

    #[tokio::test]
    #[ignore = "Needs async pool setup"]
    async fn update_recovery_key_and_auth_string_and_email_updates_all_fields() {
        let dao = dao();
        let (user_id, data) = create_verified_user().await;
        let new_email = "updated@example.com";

        dao.update_recovery_key_and_auth_string_and_email(
            &data.email,
            Some(new_email),
            "new-auth",
            &test_utils::random_bytes(8),
            2048,
            2,
            5,
            &test_utils::random_bytes(8),
            &test_utils::random_bytes(8),
            4096,
            2,
            5,
            "new-recovery",
            &test_utils::random_bytes(12),
            &test_utils::random_bytes(12),
        )
        .await
        .unwrap();

        let mut conn = test_utils::db_async_conn().await;
        let updated_user = diesel_async::RunQueryDsl::first::<User>(users.find(user_id), &mut conn)
            .await
            .unwrap();
        assert_eq!(updated_user.email, new_email);
        assert_eq!(updated_user.auth_string_hash, "new-auth");
        assert_eq!(
            updated_user.recovery_key_auth_hash_rehashed_with_auth_string_params,
            "new-recovery"
        );

        test_utils::delete_user(user_id).await;
    }
}
