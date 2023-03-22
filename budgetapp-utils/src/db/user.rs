use diesel::{dsl, ExpressionMethods, QueryDsl, RunQueryDsl};
use rand::{rngs::OsRng, Rng};
use sha1::{Digest, Sha1};
use std::time::{Duration, SystemTime};
use uuid::Uuid;

use crate::db::{DaoError, DbThreadPool};
use crate::models::signin_nonce::NewSigninNonce;
use crate::models::user::NewUser;
use crate::models::user_deletion_request::{NewUserDeletionRequest, UserDeletionRequest};
use crate::models::user_preferences::NewUserPreferences;
use crate::models::user_security_data::NewUserSecurityData;
use crate::models::user_tombstone::{NewUserTombstone, UserTombstone};

use crate::request_io::InputUser;
use crate::schema::budgets as budget_fields;
use crate::schema::budgets::dsl::budgets;
use crate::schema::signin_nonces::dsl::signin_nonces;
use crate::schema::user_budgets as user_budget_fields;
use crate::schema::user_budgets::dsl::user_budgets;
use crate::schema::user_deletion_requests as user_deletion_request_fields;
use crate::schema::user_deletion_requests::dsl::user_deletion_requests;
use crate::schema::user_preferences as user_preferences_fields;
use crate::schema::user_preferences::dsl::user_preferences;
use crate::schema::user_security_data as user_security_data_fields;
use crate::schema::user_security_data::dsl::user_security_data;
use crate::schema::user_tombstones as user_tombstone_fields;
use crate::schema::user_tombstones::dsl::user_tombstones;
use crate::schema::users as user_fields;
use crate::schema::users::dsl::users;

pub struct Dao {
    db_thread_pool: DbThreadPool,
}

impl Dao {
    pub fn new(db_thread_pool: &DbThreadPool) -> Self {
        Self {
            db_thread_pool: db_thread_pool.clone(),
        }
    }

    pub fn create_user(
        &mut self,
        user_data: InputUser,
        auth_string_hash: &str,
    ) -> Result<Uuid, DaoError> {
        let current_time = SystemTime::now();
        let user_id = Uuid::new_v4();

        let new_user = NewUser {
            id: user_id,
            email: &user_data.email.to_lowercase(),
            is_verified: false,
            created_timestamp: current_time,
        };

        let new_user_security_data = NewUserSecurityData {
            user_id,

            auth_string_hash,
            auth_string_salt: &user_data.auth_string_salt,
            auth_string_iters: user_data.auth_string_iters,

            password_encryption_salt: &user_data.password_encryption_salt,
            password_encryption_iters: user_data.password_encryption_iters,

            recovery_key_salt: &user_data.recovery_key_salt,
            recovery_key_iters: user_data.recovery_key_iters,

            encryption_key_user_password_encrypted: &user_data
                .encryption_key_user_password_encrypted,
            encryption_key_recovery_key_encrypted: &user_data.encryption_key_recovery_key_encrypted,

            public_rsa_key: &user_data.public_rsa_key,
            private_rsa_key_encrypted: &user_data.private_rsa_key_encrypted,
            rsa_key_created_timestamp: SystemTime::now(),

            last_token_refresh_timestamp: current_time,
            modified_timestamp: current_time,
        };

        let mut sha1_hasher = Sha1::new();
        sha1_hasher.update(&user_data.preferences_encrypted);

        let new_user_preferences = NewUserPreferences {
            user_id,
            encrypted_blob: &user_data.preferences_encrypted,
            encrypted_blob_sha1_hash: &sha1_hasher.finalize(),
            modified_timestamp: current_time,
        };

        let new_signin_nonce = NewSigninNonce {
            user_email: &user_data.email.to_lowercase(),
            nonce: OsRng.gen(),
        };

        let mut db_connection = self.db_thread_pool.get()?;

        db_connection
            .build_transaction()
            .run::<_, diesel::result::Error, _>(|conn| {
                dsl::insert_into(users).values(&new_user).execute(conn)?;

                dsl::insert_into(user_security_data)
                    .values(&new_user_security_data)
                    .execute(conn)?;

                dsl::insert_into(user_preferences)
                    .values(&new_user_preferences)
                    .execute(conn)?;

                dsl::insert_into(signin_nonces)
                    .values(&new_signin_nonce)
                    .execute(conn)?;

                Ok(())
            })?;

        Ok(user_id)
    }

    pub fn verify_user_creation(&mut self, user_id: Uuid) -> Result<(), DaoError> {
        dsl::update(users.find(user_id))
            .set(user_fields::is_verified.eq(true))
            .execute(&mut self.db_thread_pool.get()?)?;

        Ok(())
    }

    pub fn clear_unverified_users(
        &mut self,
        max_unverified_user_age: Duration,
    ) -> Result<(), DaoError> {
        diesel::delete(users.filter(user_fields::is_verified.eq(false)).filter(
            user_fields::created_timestamp.lt(SystemTime::now() - max_unverified_user_age),
        ))
        .execute(&mut self.db_thread_pool.get()?)?;

        Ok(())
    }

    pub fn update_user_prefs(
        &mut self,
        user_id: Uuid,
        prefs_encrypted_blob: &[u8],
    ) -> Result<(), DaoError> {
        dsl::update(user_preferences.find(user_id))
            .set((
                user_preferences_fields::encrypted_blob.eq(prefs_encrypted_blob),
                user_preferences_fields::modified_timestamp.eq(SystemTime::now()),
            ))
            .execute(&mut self.db_thread_pool.get()?)?;

        Ok(())
    }

    pub fn set_last_token_refresh_now(&mut self, user_id: Uuid) -> Result<(), DaoError> {
        dsl::update(user_security_data.filter(user_security_data_fields::user_id.eq(user_id)))
            .set(user_security_data_fields::last_token_refresh_timestamp.eq(SystemTime::now()))
            .execute(&mut self.db_thread_pool.get()?)?;

        Ok(())
    }

    pub fn update_password(
        &mut self,
        user_id: Uuid,
        new_auth_string_hash: &str,
        new_auth_string_salt: &[u8],
        new_auth_string_iters: i32,
        encrypted_encryption_key: &[u8],
    ) -> Result<(), DaoError> {
        dsl::update(user_security_data.filter(user_security_data_fields::user_id.eq(user_id)))
            .set((
                user_security_data_fields::auth_string_hash.eq(new_auth_string_hash),
                user_security_data_fields::auth_string_salt.eq(new_auth_string_salt),
                user_security_data_fields::auth_string_iters.eq(new_auth_string_iters),
                user_security_data_fields::encryption_key_user_password_encrypted
                    .eq(encrypted_encryption_key),
            ))
            .execute(&mut self.db_thread_pool.get()?)?;

        Ok(())
    }

    pub fn initiate_user_deletion(
        &mut self,
        user_id: Uuid,
        time_until_deletion: Duration,
    ) -> Result<(), DaoError> {
        let new_request = NewUserDeletionRequest {
            user_id,
            deletion_request_time: SystemTime::now(),
            ready_for_deletion_time: SystemTime::now() + time_until_deletion,
        };

        dsl::insert_into(user_deletion_requests)
            .values(&new_request)
            .execute(&mut self.db_thread_pool.get()?)?;

        Ok(())
    }

    pub fn cancel_user_deletion(&mut self, user_id: Uuid) -> Result<(), DaoError> {
        diesel::delete(user_deletion_requests.find(user_id))
            .execute(&mut self.db_thread_pool.get()?)?;

        Ok(())
    }

    pub fn delete_user(&mut self, request: &UserDeletionRequest) -> Result<(), DaoError> {
        let mut db_connection = self.db_thread_pool.get()?;

        let new_tombstone = NewUserTombstone {
            user_id: request.user_id,
            deletion_timestamp: SystemTime::now(),
        };

        db_connection
            .build_transaction()
            .run::<_, diesel::result::Error, _>(|conn| {
                dsl::insert_into(user_tombstones)
                    .values(&new_tombstone)
                    .execute(conn)?;

                diesel::delete(
                    budgets
                        .filter(
                            budget_fields::id.eq_any(
                                user_budgets
                                    .select(user_budget_fields::budget_id)
                                    .filter(user_budget_fields::user_id.eq(request.user_id)),
                            ),
                        )
                        .filter(
                            user_budgets
                                .filter(user_budget_fields::budget_id.eq(budget_fields::id))
                                .filter(user_budget_fields::user_id.ne(request.user_id))
                                .count()
                                .single_value()
                                .eq(0),
                        ),
                )
                .execute(conn)?;

                diesel::delete(users.find(request.user_id)).execute(conn)?;

                Ok(())
            })?;

        Ok(())
    }

    pub fn get_all_users_ready_for_deletion(
        &mut self,
    ) -> Result<Vec<UserDeletionRequest>, DaoError> {
        Ok(user_deletion_requests
            .filter(user_deletion_request_fields::ready_for_deletion_time.lt(SystemTime::now()))
            .get_results(&mut self.db_thread_pool.get()?)?)
    }

    pub fn check_is_user_listed_for_deletion(&mut self, user_id: Uuid) -> Result<bool, DaoError> {
        Ok(
            dsl::select(dsl::exists(user_deletion_requests.find(user_id)))
                .get_result(&mut self.db_thread_pool.get()?)?,
        )
    }

    pub fn get_user_tombstone(&mut self, user_id: Uuid) -> Result<UserTombstone, DaoError> {
        Ok(user_tombstones
            .filter(user_tombstone_fields::user_id.eq(user_id))
            .get_result::<UserTombstone>(&mut self.db_thread_pool.get()?)?)
    }
}
