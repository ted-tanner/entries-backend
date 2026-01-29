use diesel::{dsl, ExpressionMethods, JoinOnDsl, QueryDsl, Queryable};
use diesel_async::RunQueryDsl;
use std::time::{Duration, SystemTime};
use uuid::Uuid;

use crate::db::{DaoError, DbAsyncPool};
use crate::messages::UserPublicKey;
use crate::models::signin_nonce::NewSigninNonce;
use crate::models::user::NewUser;
use crate::models::user_deletion_request::{NewUserDeletionRequest, UserDeletionRequest};
use crate::models::user_deletion_request_container_key::NewUserDeletionRequestContainerKey;
use crate::models::user_flags::NewUserFlags;
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
use crate::schema::user_flags::dsl::user_flags;
use crate::schema::user_keystores as user_keystore_fields;
use crate::schema::user_keystores::dsl::user_keystores;
use crate::schema::user_preferences as user_preferences_fields;
use crate::schema::user_preferences::dsl::user_preferences;
use crate::schema::users as user_fields;
use crate::schema::users::dsl::users;

#[derive(Queryable)]
pub struct ProtectedUserData {
    pub preferences_encrypted: Vec<u8>,
    pub preferences_version_nonce: i64,
    pub user_keystore_encrypted: Vec<u8>,
    pub user_keystore_version_nonce: i64,
    pub password_encryption_key_salt: Vec<u8>,
    pub password_encryption_key_mem_cost_kib: i32,
    pub password_encryption_key_threads: i32,
    pub password_encryption_key_iterations: i32,
    pub encryption_key_encrypted_with_password: Vec<u8>,
}

pub struct Dao {
    db_async_pool: DbAsyncPool,
}

impl Dao {
    pub fn new(db_async_pool: &DbAsyncPool) -> Self {
        Self {
            db_async_pool: db_async_pool.clone(),
        }
    }

    pub async fn get_user_public_key(&self, user_email: &str) -> Result<UserPublicKey, DaoError> {
        let mut conn = self.db_async_pool.get().await?;
        let (key_id, key) = users
            .select((user_fields::public_key_id, user_fields::public_key))
            .filter(user_fields::email.eq(user_email))
            .first::<(Uuid, Vec<u8>)>(&mut conn)
            .await?;

        Ok(UserPublicKey {
            id: key_id.into(),
            value: key,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn create_user(
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

        let new_user_flags = NewUserFlags {
            user_id,
            has_performed_bulk_upload: false,
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

        let mut db_connection = self.db_async_pool.get().await?;

        db_connection
            .build_transaction()
            .run::<_, diesel::result::Error, _>(|conn| {
                Box::pin(async move {
                    dsl::insert_into(users)
                        .values(&new_user)
                        .execute(conn)
                        .await?;

                    dsl::insert_into(user_flags)
                        .values(&new_user_flags)
                        .execute(conn)
                        .await?;

                    dsl::insert_into(user_preferences)
                        .values(&new_user_preferences)
                        .execute(conn)
                        .await?;

                    dsl::insert_into(user_keystores)
                        .values(&new_user_keystore)
                        .execute(conn)
                        .await?;

                    dsl::insert_into(signin_nonces)
                        .values(&new_signin_nonce)
                        .execute(conn)
                        .await?;

                    Ok(())
                })
            })
            .await?;

        Ok(user_id)
    }

    pub async fn verify_user_creation(&self, user_id: Uuid) -> Result<(), DaoError> {
        let mut conn = self.db_async_pool.get().await?;
        dsl::update(users.find(user_id))
            .set(user_fields::is_verified.eq(true))
            .execute(&mut conn)
            .await?;

        Ok(())
    }

    pub async fn clear_unverified_users(
        &self,
        max_unverified_user_age: Duration,
    ) -> Result<(), DaoError> {
        let mut conn = self.db_async_pool.get().await?;
        diesel::delete(users.filter(user_fields::is_verified.eq(false)).filter(
            user_fields::created_timestamp.lt(SystemTime::now() - max_unverified_user_age),
        ))
        .execute(&mut conn)
        .await?;

        Ok(())
    }

    pub async fn rotate_user_public_key(
        &self,
        user_id: Uuid,
        public_key_id: Uuid,
        public_key: &[u8],
        expected_previous_public_key_id: Uuid,
    ) -> Result<(), DaoError> {
        let mut db_connection = self.db_async_pool.get().await?;

        db_connection
            .build_transaction()
            .repeatable_read()
            .run::<_, DaoError, _>(|conn| {
                Box::pin(async move {
                    let affected_row_count =
                        dsl::update(users.find(user_id).filter(
                            user_fields::public_key_id.eq(expected_previous_public_key_id),
                        ))
                        .set((
                            user_fields::public_key_id.eq(public_key_id),
                            user_fields::public_key.eq(public_key),
                        ))
                        .execute(conn)
                        .await?;

                    if affected_row_count == 0 {
                        // Check whether the update failed because the record wasn't found or because
                        // the key ID was out-of-date
                        let current_key_id = users
                            .select(user_fields::public_key_id)
                            .find(user_id)
                            .first::<Uuid>(conn)
                            .await;

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
            })
            .await
    }

    pub async fn update_user_prefs(
        &self,
        user_id: Uuid,
        prefs_encrypted_blob: &[u8],
        version_nonce: i64,
        expected_previous_version_nonce: i64,
    ) -> Result<(), DaoError> {
        let mut db_connection = self.db_async_pool.get().await?;

        db_connection
            .build_transaction()
            .repeatable_read()
            .run::<_, DaoError, _>(|conn| {
                Box::pin(async move {
                    let affected_row_count = dsl::update(user_preferences.find(user_id).filter(
                        user_preferences_fields::version_nonce.eq(expected_previous_version_nonce),
                    ))
                    .set((
                        user_preferences_fields::encrypted_blob.eq(prefs_encrypted_blob),
                        user_preferences_fields::version_nonce.eq(version_nonce),
                    ))
                    .execute(conn)
                    .await?;

                    if affected_row_count == 0 {
                        // Check whether the update failed because the record wasn't found or because
                        // the version_nonce was out-of-date
                        let current_version_nonce = user_preferences
                            .select(user_preferences_fields::version_nonce)
                            .find(user_id)
                            .first::<i64>(conn)
                            .await;

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
            })
            .await
    }

    pub async fn update_user_keystore(
        &self,
        user_id: Uuid,
        keystore_encrypted_blob: &[u8],
        version_nonce: i64,
        expected_previous_version_nonce: i64,
    ) -> Result<(), DaoError> {
        let mut db_connection = self.db_async_pool.get().await?;

        db_connection
            .build_transaction()
            .repeatable_read()
            .run::<_, DaoError, _>(|conn| {
                Box::pin(async move {
                    let affected_row_count = dsl::update(user_keystores.find(user_id).filter(
                        user_keystore_fields::version_nonce.eq(expected_previous_version_nonce),
                    ))
                    .set((
                        user_keystore_fields::encrypted_blob.eq(keystore_encrypted_blob),
                        user_keystore_fields::version_nonce.eq(version_nonce),
                    ))
                    .execute(conn)
                    .await?;

                    if affected_row_count == 0 {
                        // Check whether the update failed because the record wasn't found or because
                        // the version_nonce was out-of-date
                        let current_version_nonce = user_keystores
                            .select(user_keystore_fields::version_nonce)
                            .find(user_id)
                            .first::<i64>(conn)
                            .await;

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
            })
            .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn update_password(
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
        let mut conn = self.db_async_pool.get().await?;
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
            .execute(&mut conn)
            .await?;

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn update_recovery_key(
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
        let mut conn = self.db_async_pool.get().await?;
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
            .execute(&mut conn)
            .await?;

        Ok(())
    }

    pub async fn update_email(&self, user_id: Uuid, new_email: &str) -> Result<(), DaoError> {
        let mut conn = self.db_async_pool.get().await?;
        dsl::update(users.find(user_id))
            .set(user_fields::email.eq(new_email))
            .execute(&mut conn)
            .await?;

        Ok(())
    }

    pub async fn save_user_deletion_container_keys(
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

        let mut conn = self.db_async_pool.get().await?;
        dsl::insert_into(user_deletion_request_container_keys)
            .values(&deletion_request_container_keys)
            .execute(&mut conn)
            .await?;

        Ok(())
    }

    pub async fn initiate_user_deletion(
        &self,
        user_id: Uuid,
        time_until_deletion: Duration,
    ) -> Result<(), DaoError> {
        let new_request = NewUserDeletionRequest {
            user_id,
            ready_for_deletion_time: SystemTime::now() + time_until_deletion,
        };

        let mut conn = self.db_async_pool.get().await?;
        dsl::insert_into(user_deletion_requests)
            .values(&new_request)
            .execute(&mut conn)
            .await?;

        Ok(())
    }

    pub async fn cancel_user_deletion(&self, user_id: Uuid) -> Result<(), DaoError> {
        let mut conn = self.db_async_pool.get().await?;
        diesel::delete(user_deletion_requests.find(user_id))
            .execute(&mut conn)
            .await?;

        Ok(())
    }

    pub async fn delete_user(
        &self,
        user_deletion_request: &UserDeletionRequest,
    ) -> Result<(), DaoError> {
        let mut db_connection = self.db_async_pool.get().await?;

        db_connection
            .build_transaction()
            .run::<_, diesel::result::Error, _>(|conn| {
                Box::pin(async move {
                    let container_key_ids = user_deletion_request_container_keys
                        .select(user_deletion_request_container_key_fields::key_id)
                        .filter(
                            user_deletion_request_container_key_fields::user_id
                                .eq(user_deletion_request.user_id),
                        )
                        .load::<Uuid>(conn)
                        .await?;

                    let container_ids = diesel::delete(
                        container_access_keys
                            .filter(container_access_key_fields::key_id.eq_any(container_key_ids)),
                    )
                    .returning(container_access_key_fields::container_id)
                    .load::<Uuid>(conn)
                    .await?;

                    for container_id in container_ids {
                        let users_remaining_in_container = container_access_keys
                            .filter(container_access_key_fields::container_id.eq(container_id))
                            .count()
                            .get_result::<i64>(conn)
                            .await?;

                        if users_remaining_in_container == 0 {
                            // Hard delete. The only user in the container is being deleted
                            diesel::delete(containers.find(container_id))
                                .execute(conn)
                                .await?;
                        }
                    }

                    diesel::delete(users.find(user_deletion_request.user_id))
                        .execute(conn)
                        .await
                })
            })
            .await?;

        Ok(())
    }

    pub async fn get_all_users_ready_for_deletion(
        &self,
    ) -> Result<Vec<UserDeletionRequest>, DaoError> {
        let mut conn = self.db_async_pool.get().await?;
        Ok(user_deletion_requests
            .filter(user_deletion_request_fields::ready_for_deletion_time.lt(SystemTime::now()))
            .get_results(&mut conn)
            .await?)
    }

    pub async fn check_is_user_listed_for_deletion(&self, user_id: Uuid) -> Result<bool, DaoError> {
        let mut conn = self.db_async_pool.get().await?;
        Ok(
            dsl::select(dsl::exists(user_deletion_requests.find(user_id)))
                .get_result(&mut conn)
                .await?,
        )
    }

    pub async fn delete_old_user_deletion_requests(&self) -> Result<(), DaoError> {
        let mut db_connection = self.db_async_pool.get().await?;

        db_connection
            .build_transaction()
            .run::<_, diesel::result::Error, _>(|conn| {
                Box::pin(async move {
                    let user_ids = diesel::delete(
                        user_deletion_request_container_keys.filter(
                            user_deletion_request_container_key_fields::delete_me_time
                                .le(SystemTime::now()),
                        ),
                    )
                    .returning(user_deletion_request_container_key_fields::user_id)
                    .get_results::<Uuid>(conn)
                    .await?;

                    diesel::delete(
                        user_deletion_requests
                            .filter(user_deletion_request_fields::user_id.eq_any(user_ids)),
                    )
                    .execute(conn)
                    .await?;

                    Ok(())
                })
            })
            .await?;

        Ok(())
    }

    pub async fn get_protected_user_data(
        &self,
        user_id: Uuid,
    ) -> Result<ProtectedUserData, DaoError> {
        let mut conn = self.db_async_pool.get().await?;
        let protected_data = users
            .inner_join(user_preferences.on(user_preferences_fields::user_id.eq(user_fields::id)))
            .inner_join(user_keystores.on(user_keystore_fields::user_id.eq(user_fields::id)))
            .select((
                user_preferences_fields::encrypted_blob,
                user_preferences_fields::version_nonce,
                user_keystore_fields::encrypted_blob,
                user_keystore_fields::version_nonce,
                user_fields::password_encryption_key_salt,
                user_fields::password_encryption_key_mem_cost_kib,
                user_fields::password_encryption_key_threads,
                user_fields::password_encryption_key_iterations,
                user_fields::encryption_key_encrypted_with_password,
            ))
            .filter(user_fields::id.eq(user_id))
            .first::<ProtectedUserData>(&mut conn)
            .await?;

        Ok(protected_data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::test_utils::{self, TestUserData};
    use crate::models::container::Container;
    use crate::models::signin_nonce::SigninNonce;
    use crate::models::user::User;
    use crate::models::user_deletion_request::UserDeletionRequest;
    use crate::models::user_deletion_request_container_key::UserDeletionRequestContainerKey;
    use crate::models::user_keystore::UserKeystore;
    use crate::models::user_preferences::UserPreferences;
    use crate::schema::container_access_keys as container_access_key_fields;
    use crate::schema::container_access_keys::dsl::container_access_keys;
    use crate::schema::containers::dsl::containers;
    use crate::schema::signin_nonces::dsl::signin_nonces;
    use crate::schema::user_deletion_request_container_keys as user_deletion_request_container_key_fields;
    use crate::schema::user_deletion_request_container_keys::dsl::user_deletion_request_container_keys;
    use crate::schema::user_deletion_requests::dsl::user_deletion_requests;
    use crate::schema::user_keystores::dsl::user_keystores;
    use crate::schema::user_preferences::dsl::user_preferences;
    use crate::schema::users as user_fields;
    use crate::schema::users::dsl::users;
    use crate::threadrand::SecureRng;
    use diesel::{dsl, ExpressionMethods, QueryDsl};
    use diesel_async::RunQueryDsl;
    use std::time::{Duration, SystemTime};
    use uuid::Uuid;

    fn dao() -> Dao {
        Dao::new(test_utils::db_async_pool())
    }

    async fn create_user_and_blueprint(dao: &Dao) -> (Uuid, TestUserData) {
        let inserted = test_utils::create_user_with_dao(dao).await;
        (inserted.id, inserted.data)
    }

    async fn delete_user_row(user_id: Uuid) {
        test_utils::delete_user(user_id).await;
    }

    async fn delete_container_row(container_id: Uuid) {
        let mut conn = test_utils::db_async_conn().await;
        let _ = diesel::delete(containers.find(container_id))
            .execute(&mut conn)
            .await;
    }

    async fn fetch_user(user_id: Uuid) -> User {
        let mut conn = test_utils::db_async_conn().await;
        users.find(user_id).first(&mut conn).await.unwrap()
    }

    async fn fetch_preferences(user_id: Uuid) -> UserPreferences {
        let mut conn = test_utils::db_async_conn().await;
        user_preferences
            .find(user_id)
            .first(&mut conn)
            .await
            .unwrap()
    }

    async fn fetch_keystore(user_id: Uuid) -> UserKeystore {
        let mut conn = test_utils::db_async_conn().await;
        user_keystores.find(user_id).first(&mut conn).await.unwrap()
    }

    fn very_long_duration() -> Duration {
        Duration::from_secs(60 * 60 * 24 * 365 * 100)
    }

    async fn prepare_container_with_keys(key_ids: &[Uuid]) -> Uuid {
        let mut conn = test_utils::db_async_conn().await;
        let container_id = test_utils::insert_container(&mut conn).await;
        for key_id in key_ids {
            test_utils::insert_container_access_key(&mut conn, container_id, *key_id).await;
        }
        container_id
    }

    #[tokio::test]
    async fn get_user_public_key_returns_expected_key() {
        let dao = dao();
        let (user_id, blueprint) = create_user_and_blueprint(&dao).await;

        let public_key = dao.get_user_public_key(&blueprint.email).await.unwrap();

        assert_eq!(
            public_key.id.value.as_slice(),
            blueprint.public_key_id.as_bytes()
        );
        assert_eq!(public_key.value, blueprint.public_key.clone());

        delete_user_row(user_id).await;
    }

    #[tokio::test]
    async fn create_user_persists_related_records() {
        let dao = dao();
        let blueprint = TestUserData::random();
        let before = SystemTime::now();
        let user_id = blueprint.insert(&dao).await;
        let after = SystemTime::now();

        let mut conn = test_utils::db_async_conn().await;
        let user = users.find(user_id).first::<User>(&mut conn).await.unwrap();

        assert_eq!(user.email, blueprint.email);
        assert!(!user.is_verified);
        assert!(user.created_timestamp.duration_since(before).is_ok());
        assert!(after.duration_since(user.created_timestamp).is_ok());
        assert_eq!(user.public_key_id, blueprint.public_key_id);
        assert_eq!(user.public_key, blueprint.public_key.clone());
        assert_eq!(user.auth_string_hash, blueprint.auth_string_hash);
        assert_eq!(user.auth_string_hash_salt, blueprint.auth_string_hash_salt);
        assert_eq!(
            user.auth_string_hash_mem_cost_kib,
            blueprint.auth_string_hash_mem_cost_kib
        );
        assert_eq!(
            user.auth_string_hash_threads,
            blueprint.auth_string_hash_threads
        );
        assert_eq!(
            user.auth_string_hash_iterations,
            blueprint.auth_string_hash_iterations
        );
        assert_eq!(
            user.password_encryption_key_salt,
            blueprint.password_encryption_key_salt
        );
        assert_eq!(
            user.password_encryption_key_mem_cost_kib,
            blueprint.password_encryption_key_mem_cost_kib
        );
        assert_eq!(
            user.password_encryption_key_threads,
            blueprint.password_encryption_key_threads
        );
        assert_eq!(
            user.password_encryption_key_iterations,
            blueprint.password_encryption_key_iterations
        );
        assert_eq!(
            user.recovery_key_hash_salt_for_encryption,
            blueprint.recovery_key_hash_salt_for_encryption
        );
        assert_eq!(
            user.recovery_key_hash_salt_for_recovery_auth,
            blueprint.recovery_key_hash_salt_for_recovery_auth
        );
        assert_eq!(
            user.recovery_key_hash_mem_cost_kib,
            blueprint.recovery_key_hash_mem_cost_kib
        );
        assert_eq!(
            user.recovery_key_hash_threads,
            blueprint.recovery_key_hash_threads
        );
        assert_eq!(
            user.recovery_key_hash_iterations,
            blueprint.recovery_key_hash_iterations
        );
        assert_eq!(
            user.recovery_key_auth_hash_rehashed_with_auth_string_params,
            blueprint.recovery_key_auth_hash_rehashed_with_auth_string_params
        );
        assert_eq!(
            user.encryption_key_encrypted_with_password,
            blueprint.encryption_key_encrypted_with_password
        );
        assert_eq!(
            user.encryption_key_encrypted_with_recovery_key,
            blueprint.encryption_key_encrypted_with_recovery_key
        );

        let prefs = user_preferences
            .find(user_id)
            .first::<UserPreferences>(&mut conn)
            .await
            .unwrap();
        assert_eq!(prefs.encrypted_blob, blueprint.preferences_encrypted);
        assert_eq!(prefs.version_nonce, blueprint.preferences_version_nonce);

        let keystore = user_keystores
            .find(user_id)
            .first::<UserKeystore>(&mut conn)
            .await
            .unwrap();
        assert_eq!(keystore.encrypted_blob, blueprint.user_keystore_encrypted);
        assert_eq!(
            keystore.version_nonce,
            blueprint.user_keystore_version_nonce
        );

        let signin_nonce = signin_nonces
            .find(blueprint.email.clone())
            .first::<SigninNonce>(&mut conn)
            .await
            .unwrap();
        assert_eq!(signin_nonce.user_email, blueprint.email);

        delete_user_row(user_id).await;
    }

    #[tokio::test]
    async fn verify_user_creation_sets_flag() {
        let dao = dao();
        let (user_id, _) = create_user_and_blueprint(&dao).await;

        dao.verify_user_creation(user_id).await.unwrap();

        assert!(fetch_user(user_id).await.is_verified);

        delete_user_row(user_id).await;
    }

    #[tokio::test]
    async fn clear_unverified_users_removes_only_stale_records() {
        let dao = dao();
        let (stale_id, _) = create_user_and_blueprint(&dao).await;
        let (fresh_id, _) = create_user_and_blueprint(&dao).await;

        {
            let mut conn = test_utils::db_async_conn().await;
            let old_timestamp =
                SystemTime::UNIX_EPOCH - Duration::from_secs(60 * 60 * 24 * 365 * 200);
            dsl::update(users.find(stale_id))
                .set(user_fields::created_timestamp.eq(old_timestamp))
                .execute(&mut conn)
                .await
                .unwrap();
        }

        dao.clear_unverified_users(very_long_duration())
            .await
            .unwrap();

        {
            let mut conn = test_utils::db_async_conn().await;
            assert!(
                diesel_async::RunQueryDsl::first::<User>(users.find(stale_id), &mut conn)
                    .await
                    .is_err()
            );
            assert!(
                diesel_async::RunQueryDsl::first::<User>(users.find(fresh_id), &mut conn)
                    .await
                    .is_ok()
            );
        }

        delete_user_row(fresh_id).await;
    }

    #[tokio::test]
    async fn rotate_user_public_key_updates_record() {
        let dao = dao();
        let (user_id, blueprint) = create_user_and_blueprint(&dao).await;
        let new_key_id = Uuid::now_v7();
        let new_key = test_utils::random_bytes(32);

        dao.rotate_user_public_key(user_id, new_key_id, &new_key, blueprint.public_key_id)
            .await
            .unwrap();

        let user = fetch_user(user_id).await;
        assert_eq!(user.public_key_id, new_key_id);
        assert_eq!(user.public_key, new_key);

        delete_user_row(user_id).await;
    }

    #[tokio::test]
    async fn rotate_user_public_key_detects_out_of_date() {
        let dao = dao();
        let (user_id, blueprint) = create_user_and_blueprint(&dao).await;

        let result = dao
            .rotate_user_public_key(
                user_id,
                Uuid::now_v7(),
                &test_utils::random_bytes(16),
                Uuid::now_v7(),
            )
            .await;

        assert!(matches!(result, Err(DaoError::OutOfDate)));
        assert_eq!(
            fetch_user(user_id).await.public_key_id,
            blueprint.public_key_id
        );

        delete_user_row(user_id).await;
    }

    #[tokio::test]
    async fn update_user_prefs_updates_blob() {
        let dao = dao();
        let (user_id, blueprint) = create_user_and_blueprint(&dao).await;
        let new_blob = test_utils::random_bytes(48);
        let new_nonce = blueprint.preferences_version_nonce + 1;

        dao.update_user_prefs(
            user_id,
            &new_blob,
            new_nonce,
            blueprint.preferences_version_nonce,
        )
        .await
        .unwrap();

        let prefs = fetch_preferences(user_id).await;
        assert_eq!(prefs.encrypted_blob, new_blob);
        assert_eq!(prefs.version_nonce, new_nonce);

        delete_user_row(user_id).await;
    }

    #[tokio::test]
    async fn update_user_prefs_detects_out_of_date() {
        let dao = dao();
        let (user_id, blueprint) = create_user_and_blueprint(&dao).await;

        let result = dao
            .update_user_prefs(
                user_id,
                &test_utils::random_bytes(24),
                blueprint.preferences_version_nonce + 1,
                blueprint.preferences_version_nonce - 1,
            )
            .await;

        assert!(matches!(result, Err(DaoError::OutOfDate)));
        let prefs = fetch_preferences(user_id).await;
        assert_eq!(prefs.version_nonce, blueprint.preferences_version_nonce);

        delete_user_row(user_id).await;
    }

    #[tokio::test]
    async fn update_user_keystore_updates_blob() {
        let dao = dao();
        let (user_id, blueprint) = create_user_and_blueprint(&dao).await;
        let new_blob = test_utils::random_bytes(48);
        let new_nonce = blueprint.user_keystore_version_nonce + 1;

        dao.update_user_keystore(
            user_id,
            &new_blob,
            new_nonce,
            blueprint.user_keystore_version_nonce,
        )
        .await
        .unwrap();

        let keystore = fetch_keystore(user_id).await;
        assert_eq!(keystore.encrypted_blob, new_blob);
        assert_eq!(keystore.version_nonce, new_nonce);

        delete_user_row(user_id).await;
    }

    #[tokio::test]
    async fn update_user_keystore_detects_out_of_date() {
        let dao = dao();
        let (user_id, blueprint) = create_user_and_blueprint(&dao).await;

        let result = dao
            .update_user_keystore(
                user_id,
                &test_utils::random_bytes(24),
                blueprint.user_keystore_version_nonce + 1,
                blueprint.user_keystore_version_nonce - 1,
            )
            .await;

        assert!(matches!(result, Err(DaoError::OutOfDate)));
        let keystore = fetch_keystore(user_id).await;
        assert_eq!(
            keystore.version_nonce,
            blueprint.user_keystore_version_nonce
        );

        delete_user_row(user_id).await;
    }

    #[tokio::test]
    async fn update_password_updates_all_fields() {
        let dao = dao();
        let (user_id, blueprint) = create_user_and_blueprint(&dao).await;

        let new_auth_hash = format!("new-auth-{}", SecureRng::next_u128());
        let new_auth_salt = test_utils::random_bytes(20);
        let new_auth_mem_cost = 2048;
        let new_auth_threads = 2;
        let new_auth_iterations = 6;
        let new_pw_salt = test_utils::random_bytes(20);
        let new_pw_mem_cost = 2048;
        let new_pw_threads = 2;
        let new_pw_iterations = 6;
        let new_encrypted_key = test_utils::random_bytes(40);

        dao.update_password(
            &blueprint.email,
            &new_auth_hash,
            &new_auth_salt,
            new_auth_mem_cost,
            new_auth_threads,
            new_auth_iterations,
            &new_pw_salt,
            new_pw_mem_cost,
            new_pw_threads,
            new_pw_iterations,
            &new_encrypted_key,
        )
        .await
        .unwrap();

        let user = fetch_user(user_id).await;
        assert_eq!(user.auth_string_hash, new_auth_hash);
        assert_eq!(user.auth_string_hash_salt, new_auth_salt);
        assert_eq!(user.auth_string_hash_mem_cost_kib, new_auth_mem_cost);
        assert_eq!(user.auth_string_hash_threads, new_auth_threads);
        assert_eq!(user.auth_string_hash_iterations, new_auth_iterations);
        assert_eq!(user.password_encryption_key_salt, new_pw_salt);
        assert_eq!(user.password_encryption_key_mem_cost_kib, new_pw_mem_cost);
        assert_eq!(user.password_encryption_key_threads, new_pw_threads);
        assert_eq!(user.password_encryption_key_iterations, new_pw_iterations);
        assert_eq!(
            user.encryption_key_encrypted_with_password,
            new_encrypted_key
        );

        delete_user_row(user_id).await;
    }

    #[tokio::test]
    async fn update_recovery_key_updates_all_fields() {
        let dao = dao();
        let (user_id, _) = create_user_and_blueprint(&dao).await;

        let new_salt_encryption = test_utils::random_bytes(24);
        let new_salt_recovery = test_utils::random_bytes(24);
        let new_mem_cost = 4096;
        let new_threads = 2;
        let new_iterations = 7;
        let new_auth_hash = format!("recovery-updated-{}", SecureRng::next_u128());
        let new_encrypted_key = test_utils::random_bytes(40);

        dao.update_recovery_key(
            user_id,
            &new_salt_encryption,
            &new_salt_recovery,
            new_mem_cost,
            new_threads,
            new_iterations,
            &new_auth_hash,
            &new_encrypted_key,
        )
        .await
        .unwrap();

        let user = fetch_user(user_id).await;
        assert_eq!(
            user.recovery_key_hash_salt_for_encryption,
            new_salt_encryption
        );
        assert_eq!(
            user.recovery_key_hash_salt_for_recovery_auth,
            new_salt_recovery
        );
        assert_eq!(user.recovery_key_hash_mem_cost_kib, new_mem_cost);
        assert_eq!(user.recovery_key_hash_threads, new_threads);
        assert_eq!(user.recovery_key_hash_iterations, new_iterations);
        assert_eq!(
            user.recovery_key_auth_hash_rehashed_with_auth_string_params,
            new_auth_hash
        );
        assert_eq!(
            user.encryption_key_encrypted_with_recovery_key,
            new_encrypted_key
        );

        delete_user_row(user_id).await;
    }

    #[tokio::test]
    async fn update_email_changes_value() {
        let dao = dao();
        let (user_id, _) = create_user_and_blueprint(&dao).await;
        let new_email = format!("updated-{}", test_utils::unique_email());

        dao.update_email(user_id, &new_email).await.unwrap();

        assert_eq!(fetch_user(user_id).await.email, new_email);

        delete_user_row(user_id).await;
    }

    #[tokio::test]
    async fn save_user_deletion_container_keys_persists_rows() {
        let dao = dao();
        let (user_id, _) = create_user_and_blueprint(&dao).await;
        let key_ids = vec![Uuid::now_v7(), Uuid::now_v7()];
        let container_id = prepare_container_with_keys(&key_ids).await;
        let delete_me_time = SystemTime::now() + Duration::from_secs(60);

        dao.save_user_deletion_container_keys(&key_ids, user_id, delete_me_time)
            .await
            .unwrap();

        let mut conn = test_utils::db_async_conn().await;
        let stored: Vec<UserDeletionRequestContainerKey> = user_deletion_request_container_keys
            .filter(user_deletion_request_container_key_fields::user_id.eq(user_id))
            .load(&mut conn)
            .await
            .unwrap();
        assert_eq!(stored.len(), key_ids.len());
        for record in stored {
            assert!(key_ids.contains(&record.key_id));
        }

        delete_user_row(user_id).await;
        delete_container_row(container_id).await;
    }

    #[tokio::test]
    async fn initiate_and_cancel_user_deletion_cycle() {
        let dao = dao();
        let (user_id, _) = create_user_and_blueprint(&dao).await;

        assert!(!dao
            .check_is_user_listed_for_deletion(user_id)
            .await
            .unwrap());

        dao.initiate_user_deletion(user_id, Duration::from_secs(5))
            .await
            .unwrap();
        assert!(dao
            .check_is_user_listed_for_deletion(user_id)
            .await
            .unwrap());

        {
            let mut conn = test_utils::db_async_conn().await;
            let request = user_deletion_requests
                .find(user_id)
                .first::<UserDeletionRequest>(&mut conn)
                .await
                .unwrap();
            assert!(request
                .ready_for_deletion_time
                .duration_since(SystemTime::now())
                .is_ok());
        }

        dao.cancel_user_deletion(user_id).await.unwrap();
        assert!(!dao
            .check_is_user_listed_for_deletion(user_id)
            .await
            .unwrap());

        delete_user_row(user_id).await;
    }

    #[tokio::test]
    async fn get_all_users_ready_for_deletion_filters_by_time() {
        let dao = dao();
        let (ready_id, _) = create_user_and_blueprint(&dao).await;
        let (pending_id, _) = create_user_and_blueprint(&dao).await;

        dao.initiate_user_deletion(ready_id, Duration::from_secs(0))
            .await
            .unwrap();
        dao.initiate_user_deletion(pending_id, Duration::from_secs(60))
            .await
            .unwrap();

        let ready_requests = dao.get_all_users_ready_for_deletion().await.unwrap();
        let ready_ids: Vec<Uuid> = ready_requests.into_iter().map(|req| req.user_id).collect();
        assert!(ready_ids.contains(&ready_id));
        assert!(!ready_ids.contains(&pending_id));

        dao.cancel_user_deletion(ready_id).await.unwrap();
        dao.cancel_user_deletion(pending_id).await.unwrap();

        delete_user_row(ready_id).await;
        delete_user_row(pending_id).await;
    }

    #[tokio::test]
    async fn delete_user_removes_user_and_related_data() {
        let dao = dao();
        let (user_id, _) = create_user_and_blueprint(&dao).await;

        let key_only_container_key = Uuid::now_v7();
        let shared_container_key = Uuid::now_v7();
        let survivor_key = Uuid::now_v7();

        let solo_container = prepare_container_with_keys(&[key_only_container_key]).await;
        let shared_container =
            prepare_container_with_keys(&[shared_container_key, survivor_key]).await;

        let delete_me_time = SystemTime::now();
        dao.save_user_deletion_container_keys(
            &[key_only_container_key, shared_container_key],
            user_id,
            delete_me_time,
        )
        .await
        .unwrap();
        dao.initiate_user_deletion(user_id, Duration::from_secs(0))
            .await
            .unwrap();

        let request = {
            let mut conn = test_utils::db_async_conn().await;
            user_deletion_requests
                .find(user_id)
                .first::<UserDeletionRequest>(&mut conn)
                .await
                .unwrap()
        };

        dao.delete_user(&request).await.unwrap();

        let mut conn = test_utils::db_async_conn().await;
        assert!(
            diesel_async::RunQueryDsl::first::<User>(users.find(user_id), &mut conn)
                .await
                .is_err()
        );
        assert!(diesel_async::RunQueryDsl::first::<Container>(
            containers.find(solo_container),
            &mut conn
        )
        .await
        .is_err());
        assert!(diesel_async::RunQueryDsl::first::<UserDeletionRequest>(
            user_deletion_requests.find(user_id),
            &mut conn
        )
        .await
        .is_err());

        let shared_key_count: i64 = container_access_keys
            .filter(container_access_key_fields::container_id.eq(shared_container))
            .count()
            .get_result(&mut conn)
            .await
            .unwrap();
        assert_eq!(shared_key_count, 1);

        delete_container_row(shared_container).await;
    }

    #[ignore]
    #[tokio::test]
    async fn delete_old_user_deletion_requests_removes_expired_rows() {
        let dao = dao();
        let (user_id, _) = create_user_and_blueprint(&dao).await;
        let key_id = Uuid::now_v7();
        let container_id = prepare_container_with_keys(&[key_id]).await;

        dao.initiate_user_deletion(user_id, Duration::from_secs(0))
            .await
            .unwrap();
        dao.save_user_deletion_container_keys(
            &[key_id],
            user_id,
            SystemTime::now() - Duration::from_secs(60),
        )
        .await
        .unwrap();

        dao.delete_old_user_deletion_requests().await.unwrap();

        let mut conn = test_utils::db_async_conn().await;
        assert!(user_deletion_requests
            .find(user_id)
            .first::<UserDeletionRequest>(&mut conn)
            .await
            .is_err());
        assert!(user_deletion_request_container_keys
            .filter(user_deletion_request_container_key_fields::user_id.eq(user_id))
            .first::<UserDeletionRequestContainerKey>(&mut conn)
            .await
            .is_err());

        delete_user_row(user_id).await;
        delete_container_row(container_id).await;
    }

    #[tokio::test]
    async fn get_protected_user_data_returns_joined_data() {
        let dao = dao();
        let (user_id, blueprint) = create_user_and_blueprint(&dao).await;

        let protected = dao.get_protected_user_data(user_id).await.unwrap();

        assert_eq!(
            protected.preferences_encrypted,
            blueprint.preferences_encrypted
        );
        assert_eq!(
            protected.preferences_version_nonce,
            blueprint.preferences_version_nonce
        );
        assert_eq!(
            protected.user_keystore_encrypted,
            blueprint.user_keystore_encrypted
        );
        assert_eq!(
            protected.user_keystore_version_nonce,
            blueprint.user_keystore_version_nonce
        );
        assert_eq!(
            protected.password_encryption_key_salt,
            blueprint.password_encryption_key_salt
        );
        assert_eq!(
            protected.password_encryption_key_mem_cost_kib,
            blueprint.password_encryption_key_mem_cost_kib
        );
        assert_eq!(
            protected.password_encryption_key_threads,
            blueprint.password_encryption_key_threads
        );
        assert_eq!(
            protected.password_encryption_key_iterations,
            blueprint.password_encryption_key_iterations
        );
        assert_eq!(
            protected.encryption_key_encrypted_with_password,
            blueprint.encryption_key_encrypted_with_password
        );

        delete_user_row(user_id).await;
    }
}
