use diesel::{dsl, ExpressionMethods, QueryDsl, RunQueryDsl};
use std::time::{Duration, SystemTime};
use uuid::Uuid;

use crate::db::{DaoError, DbThreadPool};
use crate::messages::UserPublicKey;
use crate::models::signin_nonce::NewSigninNonce;
use crate::models::user::NewUser;
use crate::models::user_deletion_request::{NewUserDeletionRequest, UserDeletionRequest};
use crate::models::user_deletion_request_container_key::NewUserDeletionRequestContainerKey;
use crate::models::user_keystore::NewUserKeystore;
use crate::models::user_preferences::NewUserPreferences;
use crate::threadrand::SecureRng;

use crate::schema::container_access_keys as container_access_key_fields;
use crate::schema::container_access_keys::dsl::container_access_keys;
use crate::schema::containers::dsl::containers;
use crate::schema::signin_nonces::dsl::signin_nonces;
use crate::schema::user_deletion_request_container_keys as user_deletion_request_container_key_fields;
use crate::schema::user_deletion_request_container_keys::dsl::user_deletion_request_container_keys;
use crate::schema::user_deletion_requests as user_deletion_request_fields;
use crate::schema::user_deletion_requests::dsl::user_deletion_requests;
use crate::schema::user_keystores as user_keystore_fields;
use crate::schema::user_keystores::dsl::user_keystores;
use crate::schema::user_preferences as user_preferences_fields;
use crate::schema::user_preferences::dsl::user_preferences;
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

    pub fn get_user_public_key(&self, user_email: &str) -> Result<UserPublicKey, DaoError> {
        let (key_id, key) = users
            .select((user_fields::public_key_id, user_fields::public_key))
            .filter(user_fields::email.eq(user_email))
            .first::<(Uuid, Vec<u8>)>(&mut self.db_thread_pool.get()?)?;

        Ok(UserPublicKey {
            id: key_id.into(),
            value: key,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn create_user(
        &self,
        email: &str,
        auth_string_hash: &str,
        auth_string_hash_salt: &[u8],
        auth_string_hash_mem_cost_kib: i32,
        auth_string_hash_threads: i32,
        auth_string_hash_iterations: i32,
        password_encryption_key_salt: &[u8],
        password_encryption_key_mem_cost_kib: i32,
        password_encryption_key_threads: i32,
        password_encryption_key_iterations: i32,
        recovery_key_hash_salt_for_encryption: &[u8],
        recovery_key_hash_salt_for_recovery_auth: &[u8],
        recovery_key_hash_mem_cost_kib: i32,
        recovery_key_hash_threads: i32,
        recovery_key_hash_iterations: i32,
        recovery_key_auth_hash_rehashed_with_auth_string_params: &str,
        encryption_key_encrypted_with_password: &[u8],
        encryption_key_encrypted_with_recovery_key: &[u8],
        public_key_id: Uuid,
        public_key: &[u8],
        preferences_encrypted: &[u8],
        preferences_version_nonce: i64,
        user_keystore_encrypted: &[u8],
        user_keystore_version_nonce: i64,
    ) -> Result<Uuid, DaoError> {
        let current_time = SystemTime::now();
        let user_id = Uuid::now_v7();

        let email_lowercase = email.to_lowercase();

        let new_user = NewUser {
            id: user_id,
            email: &email_lowercase,
            is_verified: false,

            created_timestamp: current_time,

            public_key_id,
            public_key,

            auth_string_hash,
            auth_string_hash_salt,
            auth_string_hash_mem_cost_kib,
            auth_string_hash_threads,
            auth_string_hash_iterations,

            password_encryption_key_salt,
            password_encryption_key_mem_cost_kib,
            password_encryption_key_threads,
            password_encryption_key_iterations,

            recovery_key_hash_salt_for_encryption,
            recovery_key_hash_salt_for_recovery_auth,
            recovery_key_hash_mem_cost_kib,
            recovery_key_hash_threads,
            recovery_key_hash_iterations,

            recovery_key_auth_hash_rehashed_with_auth_string_params,

            encryption_key_encrypted_with_password,
            encryption_key_encrypted_with_recovery_key,
        };

        let new_user_preferences = NewUserPreferences {
            user_id,
            encrypted_blob: preferences_encrypted,
            version_nonce: preferences_version_nonce,
        };

        let new_user_keystore = NewUserKeystore {
            user_id,
            encrypted_blob: user_keystore_encrypted,
            version_nonce: user_keystore_version_nonce,
        };

        let new_signin_nonce = NewSigninNonce {
            user_email: &email_lowercase,
            nonce: SecureRng::next_i32(),
        };

        let mut db_connection = self.db_thread_pool.get()?;

        db_connection
            .build_transaction()
            .run::<_, diesel::result::Error, _>(|conn| {
                dsl::insert_into(users).values(&new_user).execute(conn)?;

                dsl::insert_into(user_preferences)
                    .values(&new_user_preferences)
                    .execute(conn)?;

                dsl::insert_into(user_keystores)
                    .values(&new_user_keystore)
                    .execute(conn)?;

                dsl::insert_into(signin_nonces)
                    .values(&new_signin_nonce)
                    .execute(conn)?;

                Ok(())
            })?;

        Ok(user_id)
    }

    pub fn verify_user_creation(&self, user_id: Uuid) -> Result<(), DaoError> {
        dsl::update(users.find(user_id))
            .set(user_fields::is_verified.eq(true))
            .execute(&mut self.db_thread_pool.get()?)?;

        Ok(())
    }

    pub fn clear_unverified_users(
        &self,
        max_unverified_user_age: Duration,
    ) -> Result<(), DaoError> {
        diesel::delete(users.filter(user_fields::is_verified.eq(false)).filter(
            user_fields::created_timestamp.lt(SystemTime::now() - max_unverified_user_age),
        ))
        .execute(&mut self.db_thread_pool.get()?)?;

        Ok(())
    }

    pub fn rotate_user_public_key(
        &self,
        user_id: Uuid,
        public_key_id: Uuid,
        public_key: &[u8],
        expected_previous_public_key_id: Uuid,
    ) -> Result<(), DaoError> {
        let mut db_connection = self.db_thread_pool.get()?;

        db_connection
            .build_transaction()
            .repeatable_read()
            .run::<_, DaoError, _>(|conn| {
                let affected_row_count = dsl::update(
                    users
                        .find(user_id)
                        .filter(user_fields::public_key_id.eq(expected_previous_public_key_id)),
                )
                .set((
                    user_fields::public_key_id.eq(public_key_id),
                    user_fields::public_key.eq(public_key),
                ))
                .execute(conn)?;

                if affected_row_count == 0 {
                    // Check whether the update failed because the record wasn't found or because
                    // the key ID was out-of-date
                    let current_key_id = users
                        .select(user_fields::public_key_id)
                        .find(user_id)
                        .first::<Uuid>(conn);

                    match current_key_id {
                        Ok(current_key_id) => {
                            if current_key_id != expected_previous_public_key_id {
                                return Err(DaoError::OutOfDate);
                            }

                            // This case should never happen because we filtered on version_nonce
                            // in the update query
                            unreachable!();
                        }
                        Err(e) => return Err(DaoError::from(e)),
                    }
                }

                Ok(())
            })
    }

    pub fn update_user_prefs(
        &self,
        user_id: Uuid,
        prefs_encrypted_blob: &[u8],
        version_nonce: i64,
        expected_previous_version_nonce: i64,
    ) -> Result<(), DaoError> {
        let mut db_connection = self.db_thread_pool.get()?;

        db_connection
            .build_transaction()
            .repeatable_read()
            .run::<_, DaoError, _>(|conn| {
                let affected_row_count = dsl::update(user_preferences.find(user_id).filter(
                    user_preferences_fields::version_nonce.eq(expected_previous_version_nonce),
                ))
                .set((
                    user_preferences_fields::encrypted_blob.eq(prefs_encrypted_blob),
                    user_preferences_fields::version_nonce.eq(version_nonce),
                ))
                .execute(conn)?;

                if affected_row_count == 0 {
                    // Check whether the update failed because the record wasn't found or because
                    // the version_nonce was out-of-date
                    let current_version_nonce = user_preferences
                        .select(user_preferences_fields::version_nonce)
                        .find(user_id)
                        .first::<i64>(conn);

                    match current_version_nonce {
                        Ok(current_version_nonce) => {
                            if current_version_nonce != expected_previous_version_nonce {
                                return Err(DaoError::OutOfDate);
                            }

                            // This case should never happen because we filtered on version_nonce
                            // in the update query
                            unreachable!();
                        }
                        Err(e) => return Err(DaoError::from(e)),
                    }
                }

                Ok(())
            })
    }

    pub fn update_user_keystore(
        &self,
        user_id: Uuid,
        keystore_encrypted_blob: &[u8],
        version_nonce: i64,
        expected_previous_version_nonce: i64,
    ) -> Result<(), DaoError> {
        let mut db_connection = self.db_thread_pool.get()?;

        db_connection
            .build_transaction()
            .repeatable_read()
            .run::<_, DaoError, _>(|conn| {
                let affected_row_count = dsl::update(user_keystores.find(user_id).filter(
                    user_keystore_fields::version_nonce.eq(expected_previous_version_nonce),
                ))
                .set((
                    user_keystore_fields::encrypted_blob.eq(keystore_encrypted_blob),
                    user_keystore_fields::version_nonce.eq(version_nonce),
                ))
                .execute(conn)?;

                if affected_row_count == 0 {
                    // Check whether the update failed because the record wasn't found or because
                    // the version_nonce was out-of-date
                    let current_version_nonce = user_keystores
                        .select(user_keystore_fields::version_nonce)
                        .find(user_id)
                        .first::<i64>(conn);

                    match current_version_nonce {
                        Ok(current_version_nonce) => {
                            if current_version_nonce != expected_previous_version_nonce {
                                return Err(DaoError::OutOfDate);
                            }

                            // This case should never happen because we filtered on version_nonce
                            // in the update query
                            unreachable!();
                        }
                        Err(e) => return Err(DaoError::from(e)),
                    }
                }

                Ok(())
            })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn update_password(
        &self,
        user_email: &str,
        new_auth_string_hash: &str,
        new_auth_string_hash_salt: &[u8],
        new_auth_string_hash_mem_cost_kib: i32,
        new_auth_string_hash_threads: i32,
        new_auth_string_hash_iterations: i32,
        new_password_encryption_key_salt: &[u8],
        new_password_encryption_key_mem_cost_kib: i32,
        new_password_encryption_key_threads: i32,
        new_password_encryption_key_iterations: i32,
        encrypted_encryption_key: &[u8],
    ) -> Result<(), DaoError> {
        dsl::update(users.filter(user_fields::email.eq(user_email)))
            .set((
                user_fields::auth_string_hash.eq(new_auth_string_hash),
                user_fields::auth_string_hash_salt.eq(new_auth_string_hash_salt),
                user_fields::auth_string_hash_mem_cost_kib.eq(new_auth_string_hash_mem_cost_kib),
                user_fields::auth_string_hash_threads.eq(new_auth_string_hash_threads),
                user_fields::auth_string_hash_iterations.eq(new_auth_string_hash_iterations),
                user_fields::password_encryption_key_salt.eq(new_password_encryption_key_salt),
                user_fields::password_encryption_key_mem_cost_kib
                    .eq(new_password_encryption_key_mem_cost_kib),
                user_fields::password_encryption_key_threads
                    .eq(new_password_encryption_key_threads),
                user_fields::password_encryption_key_iterations
                    .eq(new_password_encryption_key_iterations),
                user_fields::encryption_key_encrypted_with_password.eq(encrypted_encryption_key),
            ))
            .execute(&mut self.db_thread_pool.get()?)?;

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn update_recovery_key(
        &self,
        user_id: Uuid,
        new_recovery_key_hash_salt_for_encryption: &[u8],
        new_recovery_key_hash_salt_for_recovery_auth: &[u8],
        new_recovery_key_hash_mem_cost_kib: i32,
        new_recovery_key_hash_threads: i32,
        new_recovery_key_hash_iterations: i32,
        new_recovery_key_auth_hash_rehashed_with_auth_string_params: &str,
        encrypted_encryption_key: &[u8],
    ) -> Result<(), DaoError> {
        dsl::update(users.find(user_id))
            .set((
                user_fields::recovery_key_hash_salt_for_encryption
                    .eq(new_recovery_key_hash_salt_for_encryption),
                user_fields::recovery_key_hash_salt_for_recovery_auth
                    .eq(new_recovery_key_hash_salt_for_recovery_auth),
                user_fields::recovery_key_hash_mem_cost_kib.eq(new_recovery_key_hash_mem_cost_kib),
                user_fields::recovery_key_hash_threads.eq(new_recovery_key_hash_threads),
                user_fields::recovery_key_hash_iterations.eq(new_recovery_key_hash_iterations),
                user_fields::recovery_key_auth_hash_rehashed_with_auth_string_params
                    .eq(new_recovery_key_auth_hash_rehashed_with_auth_string_params),
                user_fields::encryption_key_encrypted_with_recovery_key
                    .eq(encrypted_encryption_key),
            ))
            .execute(&mut self.db_thread_pool.get()?)?;

        Ok(())
    }

    pub fn update_email(&self, user_id: Uuid, new_email: &str) -> Result<(), DaoError> {
        dsl::update(users.find(user_id))
            .set(user_fields::email.eq(new_email))
            .execute(&mut self.db_thread_pool.get()?)?;

        Ok(())
    }

    pub fn save_user_deletion_container_keys(
        &self,
        container_access_key_ids: &[Uuid],
        user_id: Uuid,
        delete_me_time: SystemTime,
    ) -> Result<(), DaoError> {
        let deletion_request_container_keys = container_access_key_ids
            .iter()
            .map(|key_id| NewUserDeletionRequestContainerKey {
                key_id: *key_id,
                user_id,
                delete_me_time,
            })
            .collect::<Vec<_>>();

        dsl::insert_into(user_deletion_request_container_keys)
            .values(&deletion_request_container_keys)
            .execute(&mut self.db_thread_pool.get()?)?;

        Ok(())
    }

    pub fn initiate_user_deletion(
        &self,
        user_id: Uuid,
        time_until_deletion: Duration,
    ) -> Result<(), DaoError> {
        let new_request = NewUserDeletionRequest {
            user_id,
            ready_for_deletion_time: SystemTime::now() + time_until_deletion,
        };

        dsl::insert_into(user_deletion_requests)
            .values(&new_request)
            .execute(&mut self.db_thread_pool.get()?)?;

        Ok(())
    }

    pub fn cancel_user_deletion(&self, user_id: Uuid) -> Result<(), DaoError> {
        diesel::delete(user_deletion_requests.find(user_id))
            .execute(&mut self.db_thread_pool.get()?)?;

        Ok(())
    }

    pub fn delete_user(&self, user_deletion_request: &UserDeletionRequest) -> Result<(), DaoError> {
        let mut db_connection = self.db_thread_pool.get()?;

        db_connection
            .build_transaction()
            .run::<_, diesel::result::Error, _>(|conn| {
                let container_key_ids = user_deletion_request_container_keys
                    .select(user_deletion_request_container_key_fields::key_id)
                    .filter(
                        user_deletion_request_container_key_fields::user_id
                            .eq(user_deletion_request.user_id),
                    )
                    .load::<Uuid>(conn)?;

                let container_ids = diesel::delete(
                    container_access_keys
                        .filter(container_access_key_fields::key_id.eq_any(container_key_ids)),
                )
                .returning(container_access_key_fields::container_id)
                .load::<Uuid>(conn)?;

                for container_id in container_ids {
                    let users_remaining_in_container = container_access_keys
                        .filter(container_access_key_fields::container_id.eq(container_id))
                        .count()
                        .get_result::<i64>(conn)?;

                    if users_remaining_in_container == 0 {
                        diesel::delete(containers.find(container_id)).execute(conn)?;
                    }
                }

                diesel::delete(users.find(user_deletion_request.user_id)).execute(conn)
            })?;

        Ok(())
    }

    pub fn get_all_users_ready_for_deletion(&self) -> Result<Vec<UserDeletionRequest>, DaoError> {
        Ok(user_deletion_requests
            .filter(user_deletion_request_fields::ready_for_deletion_time.lt(SystemTime::now()))
            .get_results(&mut self.db_thread_pool.get()?)?)
    }

    pub fn check_is_user_listed_for_deletion(&self, user_id: Uuid) -> Result<bool, DaoError> {
        Ok(
            dsl::select(dsl::exists(user_deletion_requests.find(user_id)))
                .get_result(&mut self.db_thread_pool.get()?)?,
        )
    }

    pub fn delete_old_user_deletion_requests(&self) -> Result<(), DaoError> {
        let mut db_connection = self.db_thread_pool.get()?;

        db_connection
            .build_transaction()
            .run::<_, diesel::result::Error, _>(|conn| {
                let user_ids = diesel::delete(
                    user_deletion_request_container_keys.filter(
                        user_deletion_request_container_key_fields::delete_me_time
                            .le(SystemTime::now()),
                    ),
                )
                .returning(user_deletion_request_container_key_fields::user_id)
                .get_results::<Uuid>(conn)?;

                diesel::delete(
                    user_deletion_requests
                        .filter(user_deletion_request_fields::user_id.eq_any(user_ids)),
                )
                .execute(conn)?;

                Ok(())
            })?;

        Ok(())
    }

    pub fn get_user_prefs_and_keystore(
        &self,
        user_id: Uuid,
    ) -> Result<(Vec<u8>, i64, Vec<u8>, i64), DaoError> {
        let (prefs_blob, prefs_version_nonce) = user_preferences
            .select((
                user_preferences_fields::encrypted_blob,
                user_preferences_fields::version_nonce,
            ))
            .find(user_id)
            .first::<(Vec<u8>, i64)>(&mut self.db_thread_pool.get()?)?;

        let (keystore_blob, keystore_version_nonce) = user_keystores
            .select((
                user_keystore_fields::encrypted_blob,
                user_keystore_fields::version_nonce,
            ))
            .find(user_id)
            .first::<(Vec<u8>, i64)>(&mut self.db_thread_pool.get()?)?;

        Ok((
            prefs_blob,
            prefs_version_nonce,
            keystore_blob,
            keystore_version_nonce,
        ))
    }
}
